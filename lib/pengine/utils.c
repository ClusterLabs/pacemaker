/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/util.h>

#include <glib.h>
#include <stdbool.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>
#include "pe_status_private.h"

extern bool pcmk__is_daemon;

void print_str_str(gpointer key, gpointer value, gpointer user_data);
gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data);
static void unpack_operation(pe_action_t * action, xmlNode * xml_obj, pe_resource_t * container,
                             pe_working_set_t * data_set, guint interval_ms);
static xmlNode *find_rsc_op_entry_helper(pe_resource_t * rsc, const char *key,
                                         gboolean include_disabled);

#if ENABLE_VERSIONED_ATTRS
pe_rsc_action_details_t *
pe_rsc_action_details(pe_action_t *action)
{
    pe_rsc_action_details_t *details;

    CRM_CHECK(action != NULL, return NULL);

    if (action->action_details == NULL) {
        action->action_details = calloc(1, sizeof(pe_rsc_action_details_t));
        CRM_CHECK(action->action_details != NULL, return NULL);
    }

    details = (pe_rsc_action_details_t *) action->action_details;
    if (details->versioned_parameters == NULL) {
        details->versioned_parameters = create_xml_node(NULL,
                                                        XML_TAG_OP_VER_ATTRS);
    }
    if (details->versioned_meta == NULL) {
        details->versioned_meta = create_xml_node(NULL, XML_TAG_OP_VER_META);
    }
    return details;
}

static void
pe_free_rsc_action_details(pe_action_t *action)
{
    pe_rsc_action_details_t *details;

    if ((action == NULL) || (action->action_details == NULL)) {
        return;
    }

    details = (pe_rsc_action_details_t *) action->action_details;

    if (details->versioned_parameters) {
        free_xml(details->versioned_parameters);
    }
    if (details->versioned_meta) {
        free_xml(details->versioned_meta);
    }

    action->action_details = NULL;
}
#endif

/*!
 * \internal
 * \brief Check whether we can fence a particular node
 *
 * \param[in] data_set  Working set for cluster
 * \param[in] node      Name of node to check
 *
 * \return true if node can be fenced, false otherwise
 */
bool
pe_can_fence(pe_working_set_t *data_set, pe_node_t *node)
{
    if (pe__is_guest_node(node)) {
        /* Guest nodes are fenced by stopping their container resource. We can
         * do that if the container's host is either online or fenceable.
         */
        pe_resource_t *rsc = node->details->remote_rsc->container;

        for (GList *n = rsc->running_on; n != NULL; n = n->next) {
            pe_node_t *container_node = n->data;

            if (!container_node->details->online
                && !pe_can_fence(data_set, container_node)) {
                return false;
            }
        }
        return true;

    } else if (!pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
        return false; /* Turned off */

    } else if (!pcmk_is_set(data_set->flags, pe_flag_have_stonith_resource)) {
        return false; /* No devices */

    } else if (pcmk_is_set(data_set->flags, pe_flag_have_quorum)) {
        return true;

    } else if (data_set->no_quorum_policy == no_quorum_ignore) {
        return true;

    } else if(node == NULL) {
        return false;

    } else if(node->details->online) {
        crm_notice("We can fence %s without quorum because they're in our membership", node->details->uname);
        return true;
    }

    crm_trace("Cannot fence %s", node->details->uname);
    return false;
}

/*!
 * \internal
 * \brief Copy a node object
 *
 * \param[in] this_node  Node object to copy
 *
 * \return Newly allocated shallow copy of this_node
 * \note This function asserts on errors and is guaranteed to return non-NULL.
 */
pe_node_t *
pe__copy_node(const pe_node_t *this_node)
{
    pe_node_t *new_node = NULL;

    CRM_ASSERT(this_node != NULL);

    new_node = calloc(1, sizeof(pe_node_t));
    CRM_ASSERT(new_node != NULL);

    new_node->rsc_discover_mode = this_node->rsc_discover_mode;
    new_node->weight = this_node->weight;
    new_node->fixed = this_node->fixed;
    new_node->details = this_node->details;

    return new_node;
}

/* any node in list1 or list2 and not in the other gets a score of -INFINITY */
void
node_list_exclude(GHashTable * hash, GList *list, gboolean merge_scores)
{
    GHashTable *result = hash;
    pe_node_t *other_node = NULL;
    GList *gIter = list;

    GHashTableIter iter;
    pe_node_t *node = NULL;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {

        other_node = pe_find_node_id(list, node->details->id);
        if (other_node == NULL) {
            node->weight = -INFINITY;
        } else if (merge_scores) {
            node->weight = pe__add_scores(node->weight, other_node->weight);
        }
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        other_node = pe_hash_table_lookup(result, node->details->id);

        if (other_node == NULL) {
            pe_node_t *new_node = pe__copy_node(node);

            new_node->weight = -INFINITY;
            g_hash_table_insert(result, (gpointer) new_node->details->id, new_node);
        }
    }
}

/*!
 * \internal
 * \brief Create a node hash table from a node list
 *
 * \param[in] list  Node list
 *
 * \return Hash table equivalent of node list
 */
GHashTable *
pe__node_list2table(GList *list)
{
    GHashTable *result = NULL;

    result = pcmk__strkey_table(NULL, free);
    for (GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        pe_node_t *new_node = pe__copy_node((pe_node_t *) gIter->data);

        g_hash_table_insert(result, (gpointer) new_node->details->id, new_node);
    }
    return result;
}

gint
sort_node_uname(gconstpointer a, gconstpointer b)
{
    return pcmk__numeric_strcasecmp(((const pe_node_t *) a)->details->uname,
                                    ((const pe_node_t *) b)->details->uname);
}

/*!
 * \internal
 * \brief Output node weights to stdout
 *
 * \param[in] rsc       Use allowed nodes for this resource
 * \param[in] comment   Text description to prefix lines with
 * \param[in] nodes     If rsc is not specified, use these nodes
 */
static void
pe__output_node_weights(pe_resource_t *rsc, const char *comment,
                        GHashTable *nodes, pe_working_set_t *data_set)
{
    pcmk__output_t *out = data_set->priv;
    char score[128]; // Stack-allocated since this is called frequently

    // Sort the nodes so the output is consistent for regression tests
    GList *list = g_list_sort(g_hash_table_get_values(nodes), sort_node_uname);

    for (GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        score2char_stack(node->weight, score, sizeof(score));
        out->message(out, "node-weight", rsc, comment, node->details->uname, score);
    }
    g_list_free(list);
}

/*!
 * \internal
 * \brief Log node weights at trace level
 *
 * \param[in] file      Caller's filename
 * \param[in] function  Caller's function name
 * \param[in] line      Caller's line number
 * \param[in] rsc       Use allowed nodes for this resource
 * \param[in] comment   Text description to prefix lines with
 * \param[in] nodes     If rsc is not specified, use these nodes
 */
static void
pe__log_node_weights(const char *file, const char *function, int line,
                     pe_resource_t *rsc, const char *comment, GHashTable *nodes)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;
    char score[128]; // Stack-allocated since this is called frequently

    // Don't waste time if we're not tracing at this point
    pcmk__log_else(LOG_TRACE, return);

    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        score2char_stack(node->weight, score, sizeof(score));
        if (rsc) {
            qb_log_from_external_source(function, file,
                                        "%s: %s allocation score on %s: %s",
                                        LOG_TRACE, line, 0,
                                        comment, rsc->id,
                                        node->details->uname, score);
        } else {
            qb_log_from_external_source(function, file, "%s: %s = %s",
                                        LOG_TRACE, line, 0,
                                        comment, node->details->uname,
                                        score);
        }
    }
}

/*!
 * \internal
 * \brief Log or output node weights
 *
 * \param[in] file      Caller's filename
 * \param[in] function  Caller's function name
 * \param[in] line      Caller's line number
 * \param[in] to_log    Log if true, otherwise output
 * \param[in] rsc       Use allowed nodes for this resource
 * \param[in] comment   Text description to prefix lines with
 * \param[in] nodes     Use these nodes
 */
void
pe__show_node_weights_as(const char *file, const char *function, int line,
                         bool to_log, pe_resource_t *rsc, const char *comment,
                         GHashTable *nodes, pe_working_set_t *data_set)
{
    if (rsc != NULL && pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        // Don't show allocation scores for orphans
        return;
    }
    if (nodes == NULL) {
        // Nothing to show
        return;
    }

    if (to_log) {
        pe__log_node_weights(file, function, line, rsc, comment, nodes);
    } else {
        pe__output_node_weights(rsc, comment, nodes, data_set);
    }

    // If this resource has children, repeat recursively for each
    if (rsc && rsc->children) {
        for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            pe__show_node_weights_as(file, function, line, to_log, child,
                                     comment, child->allowed_nodes, data_set);
        }
    }
}

gint
sort_rsc_index(gconstpointer a, gconstpointer b)
{
    const pe_resource_t *resource1 = (const pe_resource_t *)a;
    const pe_resource_t *resource2 = (const pe_resource_t *)b;

    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (resource1->sort_index > resource2->sort_index) {
        return -1;
    }

    if (resource1->sort_index < resource2->sort_index) {
        return 1;
    }

    return 0;
}

gint
sort_rsc_priority(gconstpointer a, gconstpointer b)
{
    const pe_resource_t *resource1 = (const pe_resource_t *)a;
    const pe_resource_t *resource2 = (const pe_resource_t *)b;

    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (resource1->priority > resource2->priority) {
        return -1;
    }

    if (resource1->priority < resource2->priority) {
        return 1;
    }

    return 0;
}

static enum pe_quorum_policy
effective_quorum_policy(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    enum pe_quorum_policy policy = data_set->no_quorum_policy;

    if (pcmk_is_set(data_set->flags, pe_flag_have_quorum)) {
        policy = no_quorum_ignore;

    } else if (data_set->no_quorum_policy == no_quorum_demote) {
        switch (rsc->role) {
            case RSC_ROLE_PROMOTED:
            case RSC_ROLE_UNPROMOTED:
                if (rsc->next_role > RSC_ROLE_UNPROMOTED) {
                    pe__set_next_role(rsc, RSC_ROLE_UNPROMOTED,
                                      "no-quorum-policy=demote");
                }
                policy = no_quorum_ignore;
                break;
            default:
                policy = no_quorum_stop;
                break;
        }
    }
    return policy;
}

static void
add_singleton(pe_working_set_t *data_set, pe_action_t *action)
{
    if (data_set->singletons == NULL) {
        data_set->singletons = pcmk__strkey_table(NULL, NULL);
    }
    g_hash_table_insert(data_set->singletons, action->uuid, action);
}

static pe_action_t *
lookup_singleton(pe_working_set_t *data_set, const char *action_uuid)
{
    if (data_set->singletons == NULL) {
        return NULL;
    }
    return g_hash_table_lookup(data_set->singletons, action_uuid);
}

/*!
 * \internal
 * \brief Find an existing action that matches arguments
 *
 * \param[in] key        Action key to match
 * \param[in] rsc        Resource to match (if any)
 * \param[in] node       Node to match (if any)
 * \param[in] data_set   Cluster working set
 *
 * \return Existing action that matches arguments (or NULL if none)
 */
static pe_action_t *
find_existing_action(const char *key, pe_resource_t *rsc, pe_node_t *node,
                     pe_working_set_t *data_set)
{
    GList *matches = NULL;
    pe_action_t *action = NULL;

    /* When rsc is NULL, it would be quicker to check data_set->singletons,
     * but checking all data_set->actions takes the node into account.
     */
    matches = find_actions(((rsc == NULL)? data_set->actions : rsc->actions),
                           key, node);
    if (matches == NULL) {
        return NULL;
    }
    CRM_LOG_ASSERT(!pcmk__list_of_multiple(matches));

    action = matches->data;
    g_list_free(matches);
    return action;
}

/*!
 * \internal
 * \brief Create a new action object
 *
 * \param[in] key        Action key
 * \param[in] task       Action name
 * \param[in] rsc        Resource that action is for (if any)
 * \param[in] node       Node that action is on (if any)
 * \param[in] optional   Whether action should be considered optional
 * \param[in] for_graph  Whether action should be recorded in transition graph
 * \param[in] data_set   Cluster working set
 *
 * \return Newly allocated action
 * \note This function takes ownership of \p key. It is the caller's
 *       responsibility to free the return value with pe_free_action().
 */
static pe_action_t *
new_action(char *key, const char *task, pe_resource_t *rsc, pe_node_t *node,
           bool optional, bool for_graph, pe_working_set_t *data_set)
{
    pe_action_t *action = calloc(1, sizeof(pe_action_t));

    CRM_ASSERT(action != NULL);

    action->rsc = rsc;
    action->task = strdup(task); CRM_ASSERT(action->task != NULL);
    action->uuid = key;
    action->extra = pcmk__strkey_table(free, free);
    action->meta = pcmk__strkey_table(free, free);

    if (node) {
        action->node = pe__copy_node(node);
    }

    if (pcmk__str_eq(task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
        // Resource history deletion for a node can be done on the DC
        pe__set_action_flags(action, pe_action_dc);
    }

    pe__set_action_flags(action, pe_action_runnable);
    if (optional) {
        pe__set_action_flags(action, pe_action_optional);
    } else {
        pe__clear_action_flags(action, pe_action_optional);
    }

    if (rsc != NULL) {
        guint interval_ms = 0;

        action->op_entry = find_rsc_op_entry_helper(rsc, key, TRUE);
        parse_op_key(key, NULL, NULL, &interval_ms);
        unpack_operation(action, action->op_entry, rsc->container, data_set,
                         interval_ms);
    }

    if (for_graph) {
        pe_rsc_trace(rsc, "Created %s action %d (%s): %s for %s on %s",
                     (optional? "optional" : "required"),
                     data_set->action_id, key, task,
                     ((rsc == NULL)? "no resource" : rsc->id),
                     ((node == NULL)? "no node" : node->details->uname));
        action->id = data_set->action_id++;

        data_set->actions = g_list_prepend(data_set->actions, action);
        if (rsc == NULL) {
            add_singleton(data_set, action);
        } else {
            rsc->actions = g_list_prepend(rsc->actions, action);
        }
    }
    return action;
}

/*!
 * \internal
 * \brief Evaluate node attribute values for an action
 *
 * \param[in] action    Action to unpack attributes for
 * \param[in] data_set  Cluster working set
 */
static void
unpack_action_node_attributes(pe_action_t *action, pe_working_set_t *data_set)
{
    if (!pcmk_is_set(action->flags, pe_action_have_node_attrs)
        && (action->op_entry != NULL)) {

        pe_rule_eval_data_t rule_data = {
            .node_hash = action->node->details->attrs,
            .role = RSC_ROLE_UNKNOWN,
            .now = data_set->now,
            .match_data = NULL,
            .rsc_data = NULL,
            .op_data = NULL
        };

        pe__set_action_flags(action, pe_action_have_node_attrs);
        pe__unpack_dataset_nvpairs(action->op_entry, XML_TAG_ATTR_SETS,
                                   &rule_data, action->extra, NULL,
                                   FALSE, data_set);
    }
}

/*!
 * \internal
 * \brief Update an action's optional flag
 *
 * \param[in] action    Action to update
 * \param[in] optional  Requested optional status
 */
static void
update_action_optional(pe_action_t *action, gboolean optional)
{
    // Force a non-recurring action to be optional if its resource is unmanaged
    if ((action->rsc != NULL) && (action->node != NULL)
        && !pcmk_is_set(action->flags, pe_action_pseudo)
        && !pcmk_is_set(action->rsc->flags, pe_rsc_managed)
        && (g_hash_table_lookup(action->meta,
                                XML_LRM_ATTR_INTERVAL_MS) == NULL)) {
            pe_rsc_debug(action->rsc, "%s on %s is optional (%s is unmanaged)",
                         action->uuid, action->node->details->uname,
                         action->rsc->id);
            pe__set_action_flags(action, pe_action_optional);
            // We shouldn't clear runnable here because ... something

    // Otherwise require the action if requested
    } else if (!optional) {
        pe__clear_action_flags(action, pe_action_optional);
    }
}

/*!
 * \internal
 * \brief Update a resource action's runnable flag
 *
 * \param[in] action     Action to update
 * \param[in] for_graph  Whether action should be recorded in transition graph
 * \param[in] data_set   Cluster working set
 *
 * \note This may also schedule fencing if a stop is unrunnable.
 */
static void
update_resource_action_runnable(pe_action_t *action, bool for_graph,
                                pe_working_set_t *data_set)
{
    if (pcmk_is_set(action->flags, pe_action_pseudo)) {
        return;
    }

    if (action->node == NULL) {
        pe_rsc_trace(action->rsc, "%s is unrunnable (unallocated)",
                     action->uuid);
        pe__clear_action_flags(action, pe_action_runnable);

    } else if (!pcmk_is_set(action->flags, pe_action_dc)
               && !(action->node->details->online)
               && (!pe__is_guest_node(action->node)
                   || action->node->details->remote_requires_reset)) {
        pe__clear_action_flags(action, pe_action_runnable);
        do_crm_log((for_graph? LOG_WARNING: LOG_TRACE),
                   "%s on %s is unrunnable (node is offline)",
                   action->uuid, action->node->details->uname);
        if (pcmk_is_set(action->rsc->flags, pe_rsc_managed)
            && for_graph
            && pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)
            && !(action->node->details->unclean)) {
            pe_fence_node(data_set, action->node, "stop is unrunnable", false);
        }

    } else if (!pcmk_is_set(action->flags, pe_action_dc)
               && action->node->details->pending) {
        pe__clear_action_flags(action, pe_action_runnable);
        do_crm_log((for_graph? LOG_WARNING: LOG_TRACE),
                   "Action %s on %s is unrunnable (node is pending)",
                   action->uuid, action->node->details->uname);

    } else if (action->needs == rsc_req_nothing) {
        pe_action_set_reason(action, NULL, TRUE);
        if (pe__is_guest_node(action->node)
            && !pe_can_fence(data_set, action->node)) {
            /* An action that requires nothing usually does not require any
             * fencing in order to be runnable. However, there is an exception:
             * such an action cannot be completed if it is on a guest node whose
             * host is unclean and cannot be fenced.
             */
            pe_rsc_debug(action->rsc, "%s on %s is unrunnable "
                         "(node's host cannot be fenced)",
                         action->uuid, action->node->details->uname);
            pe__clear_action_flags(action, pe_action_runnable);
        } else {
            pe_rsc_trace(action->rsc,
                         "%s on %s does not require fencing or quorum",
                         action->uuid, action->node->details->uname);
            pe__set_action_flags(action, pe_action_runnable);
        }

    } else {
        switch (effective_quorum_policy(action->rsc, data_set)) {
            case no_quorum_stop:
                pe_rsc_debug(action->rsc, "%s on %s is unrunnable (no quorum)",
                             action->uuid, action->node->details->uname);
                pe__clear_action_flags(action, pe_action_runnable);
                pe_action_set_reason(action, "no quorum", true);
                break;

            case no_quorum_freeze:
                if (!action->rsc->fns->active(action->rsc, TRUE)
                    || (action->rsc->next_role > action->rsc->role)) {
                    pe_rsc_debug(action->rsc,
                                 "%s on %s is unrunnable (no quorum)",
                                 action->uuid, action->node->details->uname);
                    pe__clear_action_flags(action, pe_action_runnable);
                    pe_action_set_reason(action, "quorum freeze", true);
                }
                break;

            default:
                //pe_action_set_reason(action, NULL, TRUE);
                pe__set_action_flags(action, pe_action_runnable);
                break;
        }
    }
}

/*!
 * \internal
 * \brief Update a resource object's flags for a new action on it
 *
 * \param[in] rsc        Resource that action is for (if any)
 * \param[in] action     New action
 */
static void
update_resource_flags_for_action(pe_resource_t *rsc, pe_action_t *action)
{
    /* @COMPAT pe_rsc_starting and pe_rsc_stopping are not actually used
     * within Pacemaker, and should be deprecated and eventually removed
     */
    if (pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        pe__set_resource_flags(rsc, pe_rsc_stopping);

    } else if (pcmk__str_eq(action->task, CRMD_ACTION_START, pcmk__str_casei)) {
        if (pcmk_is_set(action->flags, pe_action_runnable)) {
            pe__set_resource_flags(rsc, pe_rsc_starting);
        } else {
            pe__clear_resource_flags(rsc, pe_rsc_starting);
        }
    }
}

/*!
 * \brief Create or update an action object
 *
 * \param[in] rsc          Resource that action is for (if any)
 * \param[in] key          Action key (must be non-NULL)
 * \param[in] task         Action name (must be non-NULL)
 * \param[in] on_node      Node that action is on (if any)
 * \param[in] optional     Whether action should be considered optional
 * \param[in] save_action  Whether action should be recorded in transition graph
 * \param[in] data_set     Cluster working set
 *
 * \return Action object corresponding to arguments
 * \note This function takes ownership of (and might free) \p key. If
 *       \p save_action is true, \p data_set will own the returned action,
 *       otherwise it is the caller's responsibility to free the return value
 *       with pe_free_action().
 */
pe_action_t *
custom_action(pe_resource_t *rsc, char *key, const char *task,
              pe_node_t *on_node, gboolean optional, gboolean save_action,
              pe_working_set_t *data_set)
{
    pe_action_t *action = NULL;

    CRM_ASSERT((key != NULL) && (task != NULL) && (data_set != NULL));

    if (save_action) {
        action = find_existing_action(key, rsc, on_node, data_set);
    }

    if (action == NULL) {
        action = new_action(key, task, rsc, on_node, optional, save_action,
                            data_set);
    } else {
        free(key);
    }

    update_action_optional(action, optional);

    if (rsc != NULL) {
        if (action->node != NULL) {
            unpack_action_node_attributes(action, data_set);
        }

        update_resource_action_runnable(action, save_action, data_set);

        if (save_action) {
            update_resource_flags_for_action(rsc, action);
        }
    }

    return action;
}

static bool
valid_stop_on_fail(const char *value)
{
    return !pcmk__strcase_any_of(value, "standby", "demote", "stop", NULL);
}

static const char *
unpack_operation_on_fail(pe_action_t * action)
{

    const char *name = NULL;
    const char *role = NULL;
    const char *on_fail = NULL;
    const char *interval_spec = NULL;
    const char *value = g_hash_table_lookup(action->meta, XML_OP_ATTR_ON_FAIL);

    if (pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)
        && !valid_stop_on_fail(value)) {

        pcmk__config_err("Resetting '" XML_OP_ATTR_ON_FAIL "' for %s stop "
                         "action to default value because '%s' is not "
                         "allowed for stop", action->rsc->id, value);
        return NULL;

    } else if (pcmk__str_eq(action->task, CRMD_ACTION_DEMOTE, pcmk__str_casei) && !value) {
        // demote on_fail defaults to monitor value for promoted role if present
        xmlNode *operation = NULL;

        CRM_CHECK(action->rsc != NULL, return NULL);

        for (operation = pcmk__xe_first_child(action->rsc->ops_xml);
             (operation != NULL) && (value == NULL);
             operation = pcmk__xe_next(operation)) {
            bool enabled = false;

            if (!pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
                continue;
            }
            name = crm_element_value(operation, "name");
            role = crm_element_value(operation, "role");
            on_fail = crm_element_value(operation, XML_OP_ATTR_ON_FAIL);
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!on_fail) {
                continue;
            } else if (pcmk__xe_get_bool_attr(operation, "enabled", &enabled) == pcmk_rc_ok && !enabled) {
                continue;
            } else if (!pcmk__str_eq(name, "monitor", pcmk__str_casei)
                       || !pcmk__strcase_any_of(role, RSC_ROLE_PROMOTED_S,
                                                RSC_ROLE_PROMOTED_LEGACY_S,
                                                NULL)) {
                continue;
            } else if (crm_parse_interval_spec(interval_spec) == 0) {
                continue;
            } else if (pcmk__str_eq(on_fail, "demote", pcmk__str_casei)) {
                continue;
            }

            value = on_fail;
        }
    } else if (pcmk__str_eq(action->task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
        value = "ignore";

    } else if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        name = crm_element_value(action->op_entry, "name");
        role = crm_element_value(action->op_entry, "role");
        interval_spec = crm_element_value(action->op_entry,
                                          XML_LRM_ATTR_INTERVAL);

        if (!pcmk__str_eq(name, CRMD_ACTION_PROMOTE, pcmk__str_casei)
            && (!pcmk__str_eq(name, CRMD_ACTION_STATUS, pcmk__str_casei)
                || !pcmk__strcase_any_of(role, RSC_ROLE_PROMOTED_S,
                                         RSC_ROLE_PROMOTED_LEGACY_S, NULL)
                || (crm_parse_interval_spec(interval_spec) == 0))) {
            pcmk__config_err("Resetting '" XML_OP_ATTR_ON_FAIL "' for %s %s "
                             "action to default value because 'demote' is not "
                             "allowed for it", action->rsc->id, name);
            return NULL;
        }
    }

    return value;
}

static xmlNode *
find_min_interval_mon(pe_resource_t * rsc, gboolean include_disabled)
{
    guint interval_ms = 0;
    guint min_interval_ms = G_MAXUINT;
    const char *name = NULL;
    const char *interval_spec = NULL;
    xmlNode *op = NULL;
    xmlNode *operation = NULL;

    for (operation = pcmk__xe_first_child(rsc->ops_xml);
         operation != NULL;
         operation = pcmk__xe_next(operation)) {

        if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
            bool enabled = false;

            name = crm_element_value(operation, "name");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!include_disabled && pcmk__xe_get_bool_attr(operation, "enabled", &enabled) == pcmk_rc_ok &&
                !enabled) {
                continue;
            }

            if (!pcmk__str_eq(name, RSC_STATUS, pcmk__str_casei)) {
                continue;
            }

            interval_ms = crm_parse_interval_spec(interval_spec);

            if (interval_ms && (interval_ms < min_interval_ms)) {
                min_interval_ms = interval_ms;
                op = operation;
            }
        }
    }

    return op;
}

static int
unpack_start_delay(const char *value, GHashTable *meta)
{
    int start_delay = 0;

    if (value != NULL) {
        start_delay = crm_get_msec(value);

        if (start_delay < 0) {
            start_delay = 0;
        }

        if (meta) {
            g_hash_table_replace(meta, strdup(XML_OP_ATTR_START_DELAY),
                                 pcmk__itoa(start_delay));
        }
    }

    return start_delay;
}

// true if value contains valid, non-NULL interval origin for recurring op
static bool
unpack_interval_origin(const char *value, xmlNode *xml_obj, guint interval_ms,
                       crm_time_t *now, long long *start_delay)
{
    long long result = 0;
    guint interval_sec = interval_ms / 1000;
    crm_time_t *origin = NULL;

    // Ignore unspecified values and non-recurring operations
    if ((value == NULL) || (interval_ms == 0) || (now == NULL)) {
        return false;
    }

    // Parse interval origin from text
    origin = crm_time_new(value);
    if (origin == NULL) {
        pcmk__config_err("Ignoring '" XML_OP_ATTR_ORIGIN "' for operation "
                         "'%s' because '%s' is not valid",
                         (ID(xml_obj)? ID(xml_obj) : "(missing ID)"), value);
        return false;
    }

    // Get seconds since origin (negative if origin is in the future)
    result = crm_time_get_seconds(now) - crm_time_get_seconds(origin);
    crm_time_free(origin);

    // Calculate seconds from closest interval to now
    result = result % interval_sec;

    // Calculate seconds remaining until next interval
    result = ((result <= 0)? 0 : interval_sec) - result;
    crm_info("Calculated a start delay of %llds for operation '%s'",
             result,
             (ID(xml_obj)? ID(xml_obj) : "(unspecified)"));

    if (start_delay != NULL) {
        *start_delay = result * 1000; // milliseconds
    }
    return true;
}

static int
unpack_timeout(const char *value)
{
    int timeout_ms = crm_get_msec(value);

    if (timeout_ms < 0) {
        timeout_ms = crm_get_msec(CRM_DEFAULT_OP_TIMEOUT_S);
    }
    return timeout_ms;
}

int
pe_get_configured_timeout(pe_resource_t *rsc, const char *action, pe_working_set_t *data_set)
{
    xmlNode *child = NULL;
    GHashTable *action_meta = NULL;
    const char *timeout_spec = NULL;
    int timeout_ms = 0;

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = NULL,
        .op_data = NULL
    };

    for (child = first_named_child(rsc->ops_xml, XML_ATTR_OP);
         child != NULL; child = crm_next_same_xml(child)) {
        if (pcmk__str_eq(action, crm_element_value(child, XML_NVPAIR_ATTR_NAME),
                pcmk__str_casei)) {
            timeout_spec = crm_element_value(child, XML_ATTR_TIMEOUT);
            break;
        }
    }

    if (timeout_spec == NULL && data_set->op_defaults) {
        action_meta = pcmk__strkey_table(free, free);
        pe__unpack_dataset_nvpairs(data_set->op_defaults, XML_TAG_META_SETS,
                                   &rule_data, action_meta, NULL, FALSE, data_set);
        timeout_spec = g_hash_table_lookup(action_meta, XML_ATTR_TIMEOUT);
    }

    // @TODO check meta-attributes (including versioned meta-attributes)
    // @TODO maybe use min-interval monitor timeout as default for monitors

    timeout_ms = crm_get_msec(timeout_spec);
    if (timeout_ms < 0) {
        timeout_ms = crm_get_msec(CRM_DEFAULT_OP_TIMEOUT_S);
    }

    if (action_meta != NULL) {
        g_hash_table_destroy(action_meta);
    }
    return timeout_ms;
}

#if ENABLE_VERSIONED_ATTRS
static void
unpack_versioned_meta(xmlNode *versioned_meta, xmlNode *xml_obj,
                      guint interval_ms, crm_time_t *now)
{
    xmlNode *attrs = NULL;
    xmlNode *attr = NULL;

    for (attrs = pcmk__xe_first_child(versioned_meta); attrs != NULL;
         attrs = pcmk__xe_next(attrs)) {

        for (attr = pcmk__xe_first_child(attrs); attr != NULL;
             attr = pcmk__xe_next(attr)) {

            const char *name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);
            const char *value = crm_element_value(attr, XML_NVPAIR_ATTR_VALUE);

            if (pcmk__str_eq(name, XML_OP_ATTR_START_DELAY, pcmk__str_casei)) {
                int start_delay = unpack_start_delay(value, NULL);

                crm_xml_add_int(attr, XML_NVPAIR_ATTR_VALUE, start_delay);
            } else if (pcmk__str_eq(name, XML_OP_ATTR_ORIGIN, pcmk__str_casei)) {
                long long start_delay = 0;

                if (unpack_interval_origin(value, xml_obj, interval_ms, now,
                                           &start_delay)) {
                    crm_xml_add(attr, XML_NVPAIR_ATTR_NAME,
                                XML_OP_ATTR_START_DELAY);
                    crm_xml_add_ll(attr, XML_NVPAIR_ATTR_VALUE, start_delay);
                }
            } else if (pcmk__str_eq(name, XML_ATTR_TIMEOUT, pcmk__str_casei)) {
                int timeout_ms = unpack_timeout(value);

                crm_xml_add_int(attr, XML_NVPAIR_ATTR_VALUE, timeout_ms);
            }
        }
    }
}
#endif

/*!
 * \brief Unpack operation XML into an action structure
 *
 * Unpack an operation's meta-attributes (normalizing the interval, timeout,
 * and start delay values as integer milliseconds), requirements, and
 * failure policy.
 *
 * \param[in,out] action      Action to unpack into
 * \param[in]     xml_obj     Operation XML (or NULL if all defaults)
 * \param[in]     container   Resource that contains affected resource, if any
 * \param[in]     data_set    Cluster state
 * \param[in]     interval_ms How frequently to perform the operation
 */
static void
unpack_operation(pe_action_t * action, xmlNode * xml_obj, pe_resource_t * container,
                 pe_working_set_t * data_set, guint interval_ms)
{
    int timeout_ms = 0;
    const char *value = NULL;
    bool is_probe = false;
#if ENABLE_VERSIONED_ATTRS
    pe_rsc_action_details_t *rsc_details = NULL;
#endif

    pe_rsc_eval_data_t rsc_rule_data = {
        .standard = crm_element_value(action->rsc->xml, XML_AGENT_ATTR_CLASS),
        .provider = crm_element_value(action->rsc->xml, XML_AGENT_ATTR_PROVIDER),
        .agent = crm_element_value(action->rsc->xml, XML_EXPR_ATTR_TYPE)
    };

    pe_op_eval_data_t op_rule_data = {
        .op_name = action->task,
        .interval = interval_ms
    };

    pe_rule_eval_data_t rule_data = {
        .node_hash = NULL,
        .role = RSC_ROLE_UNKNOWN,
        .now = data_set->now,
        .match_data = NULL,
        .rsc_data = &rsc_rule_data,
        .op_data = &op_rule_data
    };

    CRM_CHECK(action && action->rsc, return);

    is_probe = pcmk_is_probe(action->task, interval_ms);

    // Cluster-wide <op_defaults> <meta_attributes>
    pe__unpack_dataset_nvpairs(data_set->op_defaults, XML_TAG_META_SETS, &rule_data,
                               action->meta, NULL, FALSE, data_set);

    // Determine probe default timeout differently
    if (is_probe) {
        xmlNode *min_interval_mon = find_min_interval_mon(action->rsc, FALSE);

        if (min_interval_mon) {
            value = crm_element_value(min_interval_mon, XML_ATTR_TIMEOUT);
            if (value) {
                crm_trace("\t%s: Setting default timeout to minimum-interval "
                          "monitor's timeout '%s'", action->uuid, value);
                g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT),
                                     strdup(value));
            }
        }
    }

    if (xml_obj) {
        xmlAttrPtr xIter = NULL;

        // <op> <meta_attributes> take precedence over defaults
        pe__unpack_dataset_nvpairs(xml_obj, XML_TAG_META_SETS, &rule_data,
                                   action->meta, NULL, TRUE, data_set);

#if ENABLE_VERSIONED_ATTRS
        rsc_details = pe_rsc_action_details(action);

        pe_eval_versioned_attributes(data_set->input, xml_obj,
                                     XML_TAG_ATTR_SETS, &rule_data,
                                     rsc_details->versioned_parameters,
                                     NULL);
        pe_eval_versioned_attributes(data_set->input, xml_obj,
                                     XML_TAG_META_SETS, &rule_data,
                                     rsc_details->versioned_meta,
                                     NULL);
#endif

        /* Anything set as an <op> XML property has highest precedence.
         * This ensures we use the name and interval from the <op> tag.
         */
        for (xIter = xml_obj->properties; xIter; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;
            const char *prop_value = crm_element_value(xml_obj, prop_name);

            g_hash_table_replace(action->meta, strdup(prop_name), strdup(prop_value));
        }
    }

    g_hash_table_remove(action->meta, "id");

    // Normalize interval to milliseconds
    if (interval_ms > 0) {
        g_hash_table_replace(action->meta, strdup(XML_LRM_ATTR_INTERVAL),
                             crm_strdup_printf("%u", interval_ms));
    } else {
        g_hash_table_remove(action->meta, XML_LRM_ATTR_INTERVAL);
    }

    /*
     * Timeout order of precedence:
     *   1. pcmk_monitor_timeout (if rsc has pcmk_ra_cap_fence_params
     *      and task is start or a probe; pcmk_monitor_timeout works
     *      by default for a recurring monitor)
     *   2. explicit op timeout on the primitive
     *   3. default op timeout
     *      a. if probe, then min-interval monitor's timeout
     *      b. else, in XML_CIB_TAG_OPCONFIG
     *   4. CRM_DEFAULT_OP_TIMEOUT_S
     *
     * #1 overrides general rule of <op> XML property having highest
     * precedence.
     */
    if (pcmk_is_set(pcmk_get_ra_caps(rsc_rule_data.standard),
                    pcmk_ra_cap_fence_params)
        && (pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)
            || is_probe)) {

        GHashTable *params = pe_rsc_params(action->rsc, action->node, data_set);

        value = g_hash_table_lookup(params, "pcmk_monitor_timeout");

        if (value) {
            crm_trace("\t%s: Setting timeout to pcmk_monitor_timeout '%s', "
                      "overriding default", action->uuid, value);
            g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT),
                                 strdup(value));
        }
    }

    // Normalize timeout to positive milliseconds
    value = g_hash_table_lookup(action->meta, XML_ATTR_TIMEOUT);
    timeout_ms = unpack_timeout(value);
    g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT),
                         pcmk__itoa(timeout_ms));

    if (!pcmk__strcase_any_of(action->task, RSC_START, RSC_PROMOTE, NULL)) {
        action->needs = rsc_req_nothing;
        value = "nothing (not start or promote)";

    } else if (pcmk_is_set(action->rsc->flags, pe_rsc_needs_fencing)) {
        action->needs = rsc_req_stonith;
        value = "fencing";

    } else if (pcmk_is_set(action->rsc->flags, pe_rsc_needs_quorum)) {
        action->needs = rsc_req_quorum;
        value = "quorum";

    } else {
        action->needs = rsc_req_nothing;
        value = "nothing";
    }
    pe_rsc_trace(action->rsc, "%s requires %s", action->uuid, value);

    value = unpack_operation_on_fail(action);

    if (value == NULL) {

    } else if (pcmk__str_eq(value, "block", pcmk__str_casei)) {
        action->on_fail = action_fail_block;
        g_hash_table_insert(action->meta, strdup(XML_OP_ATTR_ON_FAIL), strdup("block"));
        value = "block"; // The above could destroy the original string

    } else if (pcmk__str_eq(value, "fence", pcmk__str_casei)) {
        action->on_fail = action_fail_fence;
        value = "node fencing";

        if (!pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            pcmk__config_err("Resetting '" XML_OP_ATTR_ON_FAIL "' for "
                             "operation '%s' to 'stop' because 'fence' is not "
                             "valid when fencing is disabled", action->uuid);
            action->on_fail = action_fail_stop;
            action->fail_role = RSC_ROLE_STOPPED;
            value = "stop resource";
        }

    } else if (pcmk__str_eq(value, "standby", pcmk__str_casei)) {
        action->on_fail = action_fail_standby;
        value = "node standby";

    } else if (pcmk__strcase_any_of(value, "ignore", "nothing", NULL)) {
        action->on_fail = action_fail_ignore;
        value = "ignore";

    } else if (pcmk__str_eq(value, "migrate", pcmk__str_casei)) {
        action->on_fail = action_fail_migrate;
        value = "force migration";

    } else if (pcmk__str_eq(value, "stop", pcmk__str_casei)) {
        action->on_fail = action_fail_stop;
        action->fail_role = RSC_ROLE_STOPPED;
        value = "stop resource";

    } else if (pcmk__str_eq(value, "restart", pcmk__str_casei)) {
        action->on_fail = action_fail_recover;
        value = "restart (and possibly migrate)";

    } else if (pcmk__str_eq(value, "restart-container", pcmk__str_casei)) {
        if (container) {
            action->on_fail = action_fail_restart_container;
            value = "restart container (and possibly migrate)";

        } else {
            value = NULL;
        }

    } else if (pcmk__str_eq(value, "demote", pcmk__str_casei)) {
        action->on_fail = action_fail_demote;
        value = "demote instance";

    } else {
        pe_err("Resource %s: Unknown failure type (%s)", action->rsc->id, value);
        value = NULL;
    }

    /* defaults */
    if (value == NULL && container) {
        action->on_fail = action_fail_restart_container;
        value = "restart container (and possibly migrate) (default)";

    /* For remote nodes, ensure that any failure that results in dropping an
     * active connection to the node results in fencing of the node.
     *
     * There are only two action failures that don't result in fencing.
     * 1. probes - probe failures are expected.
     * 2. start - a start failure indicates that an active connection does not already
     * exist. The user can set op on-fail=fence if they really want to fence start
     * failures. */
    } else if (((value == NULL) || !pcmk_is_set(action->rsc->flags, pe_rsc_managed))
               && pe__resource_is_remote_conn(action->rsc, data_set)
               && !(pcmk__str_eq(action->task, CRMD_ACTION_STATUS, pcmk__str_casei)
                    && (interval_ms == 0))
               && !pcmk__str_eq(action->task, CRMD_ACTION_START, pcmk__str_casei)) {

        if (!pcmk_is_set(action->rsc->flags, pe_rsc_managed)) {
            action->on_fail = action_fail_stop;
            action->fail_role = RSC_ROLE_STOPPED;
            value = "stop unmanaged remote node (enforcing default)";

        } else {
            if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
                value = "fence remote node (default)";
            } else {
                value = "recover remote node connection (default)";
            }

            if (action->rsc->remote_reconnect_ms) {
                action->fail_role = RSC_ROLE_STOPPED;
            }
            action->on_fail = action_fail_reset_remote;
        }

    } else if (value == NULL && pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        if (pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            action->on_fail = action_fail_fence;
            value = "resource fence (default)";

        } else {
            action->on_fail = action_fail_block;
            value = "resource block (default)";
        }

    } else if (value == NULL) {
        action->on_fail = action_fail_recover;
        value = "restart (and possibly migrate) (default)";
    }

    pe_rsc_trace(action->rsc, "%s failure handling: %s",
                 action->uuid, value);

    value = NULL;
    if (xml_obj != NULL) {
        value = g_hash_table_lookup(action->meta, "role_after_failure");
        if (value) {
            pe_warn_once(pe_wo_role_after,
                        "Support for role_after_failure is deprecated and will be removed in a future release");
        }
    }
    if (value != NULL && action->fail_role == RSC_ROLE_UNKNOWN) {
        action->fail_role = text2role(value);
    }
    /* defaults */
    if (action->fail_role == RSC_ROLE_UNKNOWN) {
        if (pcmk__str_eq(action->task, CRMD_ACTION_PROMOTE, pcmk__str_casei)) {
            action->fail_role = RSC_ROLE_UNPROMOTED;
        } else {
            action->fail_role = RSC_ROLE_STARTED;
        }
    }
    pe_rsc_trace(action->rsc, "%s failure results in: %s",
                 action->uuid, role2text(action->fail_role));

    value = g_hash_table_lookup(action->meta, XML_OP_ATTR_START_DELAY);
    if (value) {
        unpack_start_delay(value, action->meta);
    } else {
        long long start_delay = 0;

        value = g_hash_table_lookup(action->meta, XML_OP_ATTR_ORIGIN);
        if (unpack_interval_origin(value, xml_obj, interval_ms, data_set->now,
                                   &start_delay)) {
            g_hash_table_replace(action->meta, strdup(XML_OP_ATTR_START_DELAY),
                                 crm_strdup_printf("%lld", start_delay));
        }
    }

#if ENABLE_VERSIONED_ATTRS
    unpack_versioned_meta(rsc_details->versioned_meta, xml_obj, interval_ms,
                          data_set->now);
#endif
}

static xmlNode *
find_rsc_op_entry_helper(pe_resource_t * rsc, const char *key, gboolean include_disabled)
{
    guint interval_ms = 0;
    gboolean do_retry = TRUE;
    char *local_key = NULL;
    const char *name = NULL;
    const char *interval_spec = NULL;
    char *match_key = NULL;
    xmlNode *op = NULL;
    xmlNode *operation = NULL;

  retry:
    for (operation = pcmk__xe_first_child(rsc->ops_xml); operation != NULL;
         operation = pcmk__xe_next(operation)) {

        if (pcmk__str_eq((const char *)operation->name, "op", pcmk__str_none)) {
            bool enabled = false;

            name = crm_element_value(operation, "name");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!include_disabled && pcmk__xe_get_bool_attr(operation, "enabled", &enabled) == pcmk_rc_ok &&
                !enabled) {
                continue;
            }

            interval_ms = crm_parse_interval_spec(interval_spec);
            match_key = pcmk__op_key(rsc->id, name, interval_ms);
            if (pcmk__str_eq(key, match_key, pcmk__str_casei)) {
                op = operation;
            }
            free(match_key);

            if (rsc->clone_name) {
                match_key = pcmk__op_key(rsc->clone_name, name, interval_ms);
                if (pcmk__str_eq(key, match_key, pcmk__str_casei)) {
                    op = operation;
                }
                free(match_key);
            }

            if (op != NULL) {
                free(local_key);
                return op;
            }
        }
    }

    free(local_key);
    if (do_retry == FALSE) {
        return NULL;
    }

    do_retry = FALSE;
    if (strstr(key, CRMD_ACTION_MIGRATE) || strstr(key, CRMD_ACTION_MIGRATED)) {
        local_key = pcmk__op_key(rsc->id, "migrate", 0);
        key = local_key;
        goto retry;

    } else if (strstr(key, "_notify_")) {
        local_key = pcmk__op_key(rsc->id, "notify", 0);
        key = local_key;
        goto retry;
    }

    return NULL;
}

xmlNode *
find_rsc_op_entry(pe_resource_t * rsc, const char *key)
{
    return find_rsc_op_entry_helper(rsc, key, FALSE);
}

/*
 * Used by the HashTable for-loop
 */
void
print_str_str(gpointer key, gpointer value, gpointer user_data)
{
    crm_trace("%s%s %s ==> %s",
              user_data == NULL ? "" : (char *)user_data,
              user_data == NULL ? "" : ": ", (char *)key, (char *)value);
}

void
pe_free_action(pe_action_t * action)
{
    if (action == NULL) {
        return;
    }
    g_list_free_full(action->actions_before, free);     /* pe_action_wrapper_t* */
    g_list_free_full(action->actions_after, free);      /* pe_action_wrapper_t* */
    if (action->extra) {
        g_hash_table_destroy(action->extra);
    }
    if (action->meta) {
        g_hash_table_destroy(action->meta);
    }
#if ENABLE_VERSIONED_ATTRS
    if (action->rsc) {
        pe_free_rsc_action_details(action);
    }
#endif
    free(action->cancel_task);
    free(action->reason);
    free(action->task);
    free(action->uuid);
    free(action->node);
    free(action);
}

GList *
find_recurring_actions(GList *input, pe_node_t * not_on_node)
{
    const char *value = NULL;
    GList *result = NULL;
    GList *gIter = input;

    CRM_CHECK(input != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        value = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL_MS);
        if (value == NULL) {
            /* skip */
        } else if (pcmk__str_eq(value, "0", pcmk__str_casei)) {
            /* skip */
        } else if (pcmk__str_eq(CRMD_ACTION_CANCEL, action->task, pcmk__str_casei)) {
            /* skip */
        } else if (not_on_node == NULL) {
            crm_trace("(null) Found: %s", action->uuid);
            result = g_list_prepend(result, action);

        } else if (action->node == NULL) {
            /* skip */
        } else if (action->node->details != not_on_node->details) {
            crm_trace("Found: %s", action->uuid);
            result = g_list_prepend(result, action);
        }
    }

    return result;
}

enum action_tasks
get_complex_task(pe_resource_t * rsc, const char *name, gboolean allow_non_atomic)
{
    enum action_tasks task = text2task(name);

    if (rsc == NULL) {
        return task;

    } else if (allow_non_atomic == FALSE || rsc->variant == pe_native) {
        switch (task) {
            case stopped_rsc:
            case started_rsc:
            case action_demoted:
            case action_promoted:
                crm_trace("Folding %s back into its atomic counterpart for %s", name, rsc->id);
                return task - 1;
            default:
                break;
        }
    }
    return task;
}

pe_action_t *
find_first_action(GList *input, const char *uuid, const char *task, pe_node_t * on_node)
{
    GList *gIter = NULL;

    CRM_CHECK(uuid || task, return NULL);

    for (gIter = input; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (uuid != NULL && !pcmk__str_eq(uuid, action->uuid, pcmk__str_casei)) {
            continue;

        } else if (task != NULL && !pcmk__str_eq(task, action->task, pcmk__str_casei)) {
            continue;

        } else if (on_node == NULL) {
            return action;

        } else if (action->node == NULL) {
            continue;

        } else if (on_node->details == action->node->details) {
            return action;
        }
    }

    return NULL;
}

GList *
find_actions(GList *input, const char *key, const pe_node_t *on_node)
{
    GList *gIter = input;
    GList *result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (!pcmk__str_eq(key, action->uuid, pcmk__str_casei)) {
            continue;

        } else if (on_node == NULL) {
            crm_trace("Action %s matches (ignoring node)", key);
            result = g_list_prepend(result, action);

        } else if (action->node == NULL) {
            crm_trace("Action %s matches (unallocated, assigning to %s)",
                      key, on_node->details->uname);

            action->node = pe__copy_node(on_node);
            result = g_list_prepend(result, action);

        } else if (on_node->details == action->node->details) {
            crm_trace("Action %s on %s matches", key, on_node->details->uname);
            result = g_list_prepend(result, action);
        }
    }

    return result;
}

GList *
find_actions_exact(GList *input, const char *key, const pe_node_t *on_node)
{
    GList *result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    if (on_node == NULL) {
        return NULL;
    }

    for (GList *gIter = input; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if ((action->node != NULL)
            && pcmk__str_eq(key, action->uuid, pcmk__str_casei)
            && pcmk__str_eq(on_node->details->id, action->node->details->id,
                            pcmk__str_casei)) {

            crm_trace("Action %s on %s matches", key, on_node->details->uname);
            result = g_list_prepend(result, action);
        }
    }

    return result;
}

/*!
 * \brief Find all actions of given type for a resource
 *
 * \param[in] rsc           Resource to search
 * \param[in] node          Find only actions scheduled on this node
 * \param[in] task          Action name to search for
 * \param[in] require_node  If TRUE, NULL node or action node will not match
 *
 * \return List of actions found (or NULL if none)
 * \note If node is not NULL and require_node is FALSE, matching actions
 *       without a node will be assigned to node.
 */
GList *
pe__resource_actions(const pe_resource_t *rsc, const pe_node_t *node,
                     const char *task, bool require_node)
{
    GList *result = NULL;
    char *key = pcmk__op_key(rsc->id, task, 0);

    if (require_node) {
        result = find_actions_exact(rsc->actions, key, node);
    } else {
        result = find_actions(rsc->actions, key, node);
    }
    free(key);
    return result;
}

static void
resource_node_score(pe_resource_t * rsc, pe_node_t * node, int score, const char *tag)
{
    pe_node_t *match = NULL;

    if ((rsc->exclusive_discover || (node->rsc_discover_mode == pe_discover_never))
        && pcmk__str_eq(tag, "symmetric_default", pcmk__str_casei)) {
        /* This string comparision may be fragile, but exclusive resources and
         * exclusive nodes should not have the symmetric_default constraint
         * applied to them.
         */
        return;

    } else if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            resource_node_score(child_rsc, node, score, tag);
        }
    }

    pe_rsc_trace(rsc, "Setting %s for %s on %s: %d", tag, rsc->id, node->details->uname, score);
    match = pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);
    if (match == NULL) {
        match = pe__copy_node(node);
        g_hash_table_insert(rsc->allowed_nodes, (gpointer) match->details->id, match);
    }
    match->weight = pe__add_scores(match->weight, score);
}

void
resource_location(pe_resource_t * rsc, pe_node_t * node, int score, const char *tag,
                  pe_working_set_t * data_set)
{
    if (node != NULL) {
        resource_node_score(rsc, node, score, tag);

    } else if (data_set != NULL) {
        GList *gIter = data_set->nodes;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node_iter = (pe_node_t *) gIter->data;

            resource_node_score(rsc, node_iter, score, tag);
        }

    } else {
        GHashTableIter iter;
        pe_node_t *node_iter = NULL;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node_iter)) {
            resource_node_score(rsc, node_iter, score, tag);
        }
    }

    if (node == NULL && score == -INFINITY) {
        if (rsc->allocated_to) {
            crm_info("Deallocating %s from %s", rsc->id, rsc->allocated_to->details->uname);
            free(rsc->allocated_to);
            rsc->allocated_to = NULL;
        }
    }
}

#define sort_return(an_int, why) do {					\
	free(a_uuid);						\
	free(b_uuid);						\
	crm_trace("%s (%d) %c %s (%d) : %s",				\
		  a_xml_id, a_call_id, an_int>0?'>':an_int<0?'<':'=',	\
		  b_xml_id, b_call_id, why);				\
	return an_int;							\
    } while(0)

gint
sort_op_by_callid(gconstpointer a, gconstpointer b)
{
    int a_call_id = -1;
    int b_call_id = -1;

    char *a_uuid = NULL;
    char *b_uuid = NULL;

    const xmlNode *xml_a = a;
    const xmlNode *xml_b = b;

    const char *a_xml_id = crm_element_value(xml_a, XML_ATTR_ID);
    const char *b_xml_id = crm_element_value(xml_b, XML_ATTR_ID);

    if (pcmk__str_eq(a_xml_id, b_xml_id, pcmk__str_casei)) {
        /* We have duplicate lrm_rsc_op entries in the status
         * section which is unlikely to be a good thing
         *    - we can handle it easily enough, but we need to get
         *    to the bottom of why it's happening.
         */
        pe_err("Duplicate lrm_rsc_op entries named %s", a_xml_id);
        sort_return(0, "duplicate");
    }

    crm_element_value_int(xml_a, XML_LRM_ATTR_CALLID, &a_call_id);
    crm_element_value_int(xml_b, XML_LRM_ATTR_CALLID, &b_call_id);

    if (a_call_id == -1 && b_call_id == -1) {
        /* both are pending ops so it doesn't matter since
         *   stops are never pending
         */
        sort_return(0, "pending");

    } else if (a_call_id >= 0 && a_call_id < b_call_id) {
        sort_return(-1, "call id");

    } else if (b_call_id >= 0 && a_call_id > b_call_id) {
        sort_return(1, "call id");

    } else if (b_call_id >= 0 && a_call_id == b_call_id) {
        /*
         * The op and last_failed_op are the same
         * Order on last-rc-change
         */
        time_t last_a = -1;
        time_t last_b = -1;

        crm_element_value_epoch(xml_a, XML_RSC_OP_LAST_CHANGE, &last_a);
        crm_element_value_epoch(xml_b, XML_RSC_OP_LAST_CHANGE, &last_b);

        crm_trace("rc-change: %lld vs %lld",
                  (long long) last_a, (long long) last_b);
        if (last_a >= 0 && last_a < last_b) {
            sort_return(-1, "rc-change");

        } else if (last_b >= 0 && last_a > last_b) {
            sort_return(1, "rc-change");
        }
        sort_return(0, "rc-change");

    } else {
        /* One of the inputs is a pending operation
         * Attempt to use XML_ATTR_TRANSITION_MAGIC to determine its age relative to the other
         */

        int a_id = -1;
        int b_id = -1;

        const char *a_magic = crm_element_value(xml_a, XML_ATTR_TRANSITION_MAGIC);
        const char *b_magic = crm_element_value(xml_b, XML_ATTR_TRANSITION_MAGIC);

        CRM_CHECK(a_magic != NULL && b_magic != NULL, sort_return(0, "No magic"));
        if (!decode_transition_magic(a_magic, &a_uuid, &a_id, NULL, NULL, NULL,
                                     NULL)) {
            sort_return(0, "bad magic a");
        }
        if (!decode_transition_magic(b_magic, &b_uuid, &b_id, NULL, NULL, NULL,
                                     NULL)) {
            sort_return(0, "bad magic b");
        }
        /* try to determine the relative age of the operation...
         * some pending operations (e.g. a start) may have been superseded
         *   by a subsequent stop
         *
         * [a|b]_id == -1 means it's a shutdown operation and _always_ comes last
         */
        if (!pcmk__str_eq(a_uuid, b_uuid, pcmk__str_casei) || a_id == b_id) {
            /*
             * some of the logic in here may be redundant...
             *
             * if the UUID from the TE doesn't match then one better
             *   be a pending operation.
             * pending operations don't survive between elections and joins
             *   because we query the LRM directly
             */

            if (b_call_id == -1) {
                sort_return(-1, "transition + call");

            } else if (a_call_id == -1) {
                sort_return(1, "transition + call");
            }

        } else if ((a_id >= 0 && a_id < b_id) || b_id == -1) {
            sort_return(-1, "transition");

        } else if ((b_id >= 0 && a_id > b_id) || a_id == -1) {
            sort_return(1, "transition");
        }
    }

    /* we should never end up here */
    CRM_CHECK(FALSE, sort_return(0, "default"));

}

time_t
get_effective_time(pe_working_set_t * data_set)
{
    if(data_set) {
        if (data_set->now == NULL) {
            crm_trace("Recording a new 'now'");
            data_set->now = crm_time_new(NULL);
        }
        return crm_time_get_seconds_since_epoch(data_set->now);
    }

    crm_trace("Defaulting to 'now'");
    return time(NULL);
}

gboolean
get_target_role(pe_resource_t * rsc, enum rsc_role_e * role)
{
    enum rsc_role_e local_role = RSC_ROLE_UNKNOWN;
    const char *value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);

    CRM_CHECK(role != NULL, return FALSE);

    if (pcmk__str_eq(value, "started", pcmk__str_null_matches | pcmk__str_casei)
        || pcmk__str_eq("default", value, pcmk__str_casei)) {
        return FALSE;
    }

    local_role = text2role(value);
    if (local_role == RSC_ROLE_UNKNOWN) {
        pcmk__config_err("Ignoring '" XML_RSC_ATTR_TARGET_ROLE "' for %s "
                         "because '%s' is not valid", rsc->id, value);
        return FALSE;

    } else if (local_role > RSC_ROLE_STARTED) {
        if (pcmk_is_set(uber_parent(rsc)->flags, pe_rsc_promotable)) {
            if (local_role > RSC_ROLE_UNPROMOTED) {
                /* This is what we'd do anyway, just leave the default to avoid messing up the placement algorithm */
                return FALSE;
            }

        } else {
            pcmk__config_err("Ignoring '" XML_RSC_ATTR_TARGET_ROLE "' for %s "
                             "because '%s' only makes sense for promotable "
                             "clones", rsc->id, value);
            return FALSE;
        }
    }

    *role = local_role;
    return TRUE;
}

gboolean
order_actions(pe_action_t * lh_action, pe_action_t * rh_action, enum pe_ordering order)
{
    GList *gIter = NULL;
    pe_action_wrapper_t *wrapper = NULL;
    GList *list = NULL;

    if (order == pe_order_none) {
        return FALSE;
    }

    if (lh_action == NULL || rh_action == NULL) {
        return FALSE;
    }

    crm_trace("Creating action wrappers for ordering: %s then %s",
              lh_action->uuid, rh_action->uuid);

    /* Ensure we never create a dependency on ourselves... it's happened */
    CRM_ASSERT(lh_action != rh_action);

    /* Filter dups, otherwise update_action_states() has too much work to do */
    gIter = lh_action->actions_after;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_wrapper_t *after = (pe_action_wrapper_t *) gIter->data;

        if (after->action == rh_action && (after->type & order)) {
            return FALSE;
        }
    }

    wrapper = calloc(1, sizeof(pe_action_wrapper_t));
    wrapper->action = rh_action;
    wrapper->type = order;
    list = lh_action->actions_after;
    list = g_list_prepend(list, wrapper);
    lh_action->actions_after = list;

    wrapper = calloc(1, sizeof(pe_action_wrapper_t));
    wrapper->action = lh_action;
    wrapper->type = order;
    list = rh_action->actions_before;
    list = g_list_prepend(list, wrapper);
    rh_action->actions_before = list;
    return TRUE;
}

pe_action_t *
get_pseudo_op(const char *name, pe_working_set_t * data_set)
{
    pe_action_t *op = lookup_singleton(data_set, name);

    if (op == NULL) {
        op = custom_action(NULL, strdup(name), name, NULL, TRUE, TRUE, data_set);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);
    }
    return op;
}

void
destroy_ticket(gpointer data)
{
    pe_ticket_t *ticket = data;

    if (ticket->state) {
        g_hash_table_destroy(ticket->state);
    }
    free(ticket->id);
    free(ticket);
}

pe_ticket_t *
ticket_new(const char *ticket_id, pe_working_set_t * data_set)
{
    pe_ticket_t *ticket = NULL;

    if (pcmk__str_empty(ticket_id)) {
        return NULL;
    }

    if (data_set->tickets == NULL) {
        data_set->tickets = pcmk__strkey_table(free, destroy_ticket);
    }

    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);
    if (ticket == NULL) {

        ticket = calloc(1, sizeof(pe_ticket_t));
        if (ticket == NULL) {
            crm_err("Cannot allocate ticket '%s'", ticket_id);
            return NULL;
        }

        crm_trace("Creaing ticket entry for %s", ticket_id);

        ticket->id = strdup(ticket_id);
        ticket->granted = FALSE;
        ticket->last_granted = -1;
        ticket->standby = FALSE;
        ticket->state = pcmk__strkey_table(free, free);

        g_hash_table_insert(data_set->tickets, strdup(ticket->id), ticket);
    }

    return ticket;
}

const char *rsc_printable_id(pe_resource_t *rsc)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        return ID(rsc->xml);
    }
    return rsc->id;
}

void
pe__clear_resource_flags_recursive(pe_resource_t *rsc, uint64_t flags)
{
    pe__clear_resource_flags(rsc, flags);
    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe__clear_resource_flags_recursive((pe_resource_t *) gIter->data, flags);
    }
}

void
pe__clear_resource_flags_on_all(pe_working_set_t *data_set, uint64_t flag)
{
    for (GList *lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;
        pe__clear_resource_flags_recursive(r, flag);
    }
}

void
pe__set_resource_flags_recursive(pe_resource_t *rsc, uint64_t flags)
{
    pe__set_resource_flags(rsc, flags);
    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe__set_resource_flags_recursive((pe_resource_t *) gIter->data, flags);
    }
}

static GList *
find_unfencing_devices(GList *candidates, GList *matches) 
{
    for (GList *gIter = candidates; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *candidate = gIter->data;
        const char *provides = g_hash_table_lookup(candidate->meta,
                                                   PCMK_STONITH_PROVIDES);
        const char *requires = g_hash_table_lookup(candidate->meta, XML_RSC_ATTR_REQUIRES);

        if(candidate->children) {
            matches = find_unfencing_devices(candidate->children, matches);
        } else if (!pcmk_is_set(candidate->flags, pe_rsc_fence_device)) {
            continue;

        } else if (pcmk__str_eq(provides, "unfencing", pcmk__str_casei) || pcmk__str_eq(requires, "unfencing", pcmk__str_casei)) {
            matches = g_list_prepend(matches, candidate);
        }
    }
    return matches;
}

static int
node_priority_fencing_delay(pe_node_t * node, pe_working_set_t * data_set)
{
    int member_count = 0;
    int online_count = 0;
    int top_priority = 0;
    int lowest_priority = 0;
    GList *gIter = NULL;

    // `priority-fencing-delay` is disabled
    if (data_set->priority_fencing_delay <= 0) {
        return 0;
    }

    /* No need to request a delay if the fencing target is not a normal cluster
     * member, for example if it's a remote node or a guest node. */
    if (node->details->type != node_member) {
        return 0;
    }

    // No need to request a delay if the fencing target is in our partition
    if (node->details->online) {
        return 0;
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *n =  gIter->data;

        if (n->details->type != node_member) {
            continue;
        }

        member_count ++;

        if (n->details->online) {
            online_count++;
        }

        if (member_count == 1
            || n->details->priority > top_priority) {
            top_priority = n->details->priority;
        }

        if (member_count == 1
            || n->details->priority < lowest_priority) {
            lowest_priority = n->details->priority;
        }
    }

    // No need to delay if we have more than half of the cluster members
    if (online_count > member_count / 2) {
        return 0;
    }

    /* All the nodes have equal priority.
     * Any configured corresponding `pcmk_delay_base/max` will be applied. */
    if (lowest_priority == top_priority) {
        return 0;
    }

    if (node->details->priority < top_priority) {
        return 0;
    }

    return data_set->priority_fencing_delay;
}

pe_action_t *
pe_fence_op(pe_node_t * node, const char *op, bool optional, const char *reason,
            bool priority_delay, pe_working_set_t * data_set)
{
    char *op_key = NULL;
    pe_action_t *stonith_op = NULL;

    if(op == NULL) {
        op = data_set->stonith_action;
    }

    op_key = crm_strdup_printf("%s-%s-%s", CRM_OP_FENCE, node->details->uname, op);

    stonith_op = lookup_singleton(data_set, op_key);
    if(stonith_op == NULL) {
        stonith_op = custom_action(NULL, op_key, CRM_OP_FENCE, node, TRUE, TRUE, data_set);

        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET, node->details->uname);
        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET_UUID, node->details->id);
        add_hash_param(stonith_op->meta, "stonith_action", op);

        if (pe__is_guest_or_remote_node(node)
            && pcmk_is_set(data_set->flags, pe_flag_enable_unfencing)) {
            /* Extra work to detect device changes on remotes
             *
             * We may do this for all nodes in the future, but for now
             * the check_action_definition() based stuff works fine.
             */
            long max = 1024;
            long digests_all_offset = 0;
            long digests_secure_offset = 0;

            char *digests_all = calloc(max, sizeof(char));
            char *digests_secure = calloc(max, sizeof(char));
            GList *matches = find_unfencing_devices(data_set->resources, NULL);

            for (GList *gIter = matches; gIter != NULL; gIter = gIter->next) {
                pe_resource_t *match = gIter->data;
                const char *agent = g_hash_table_lookup(match->meta,
                                                        XML_ATTR_TYPE);
                op_digest_cache_t *data = NULL;

                data = pe__compare_fencing_digest(match, agent, node, data_set);
                if(data->rc == RSC_DIGEST_ALL) {
                    optional = FALSE;
                    crm_notice("Unfencing %s (remote): because the definition of %s changed", node->details->uname, match->id);
                    if (!pcmk__is_daemon && data_set->priv != NULL) {
                        pcmk__output_t *out = data_set->priv;
                        out->info(out, "notice: Unfencing %s (remote): because the definition of %s changed",
                                  node->details->uname, match->id);
                    }
                }

                digests_all_offset += snprintf(
                    digests_all+digests_all_offset, max-digests_all_offset,
                    "%s:%s:%s,", match->id, agent, data->digest_all_calc);

                digests_secure_offset += snprintf(
                    digests_secure+digests_secure_offset, max-digests_secure_offset,
                    "%s:%s:%s,", match->id, agent, data->digest_secure_calc);
            }
            g_hash_table_insert(stonith_op->meta,
                                strdup(XML_OP_ATTR_DIGESTS_ALL),
                                digests_all);
            g_hash_table_insert(stonith_op->meta,
                                strdup(XML_OP_ATTR_DIGESTS_SECURE),
                                digests_secure);
        }

    } else {
        free(op_key);
    }

    if (data_set->priority_fencing_delay > 0

            /* It's a suitable case where `priority-fencing-delay` applies.
             * At least add `priority-fencing-delay` field as an indicator. */
        && (priority_delay

            /* Re-calculate priority delay for the suitable case when
             * pe_fence_op() is called again by stage6() after node priority has
             * been actually calculated with native_add_running() */
            || g_hash_table_lookup(stonith_op->meta,
                                   XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY) != NULL)) {

            /* Add `priority-fencing-delay` to the fencing op even if it's 0 for
             * the targeting node. So that it takes precedence over any possible
             * `pcmk_delay_base/max`.
             */
            char *delay_s = pcmk__itoa(node_priority_fencing_delay(node, data_set));

            g_hash_table_insert(stonith_op->meta,
                                strdup(XML_CONFIG_ATTR_PRIORITY_FENCING_DELAY),
                                delay_s);
    }

    if(optional == FALSE && pe_can_fence(data_set, node)) {
        pe__clear_action_flags(stonith_op, pe_action_optional);
        pe_action_set_reason(stonith_op, reason, false);

    } else if(reason && stonith_op->reason == NULL) {
        stonith_op->reason = strdup(reason);
    }

    return stonith_op;
}

void
trigger_unfencing(
    pe_resource_t * rsc, pe_node_t *node, const char *reason, pe_action_t *dependency, pe_working_set_t * data_set) 
{
    if (!pcmk_is_set(data_set->flags, pe_flag_enable_unfencing)) {
        /* No resources require it */
        return;

    } else if ((rsc != NULL)
               && !pcmk_is_set(rsc->flags, pe_rsc_fence_device)) {
        /* Wasn't a stonith device */
        return;

    } else if(node
              && node->details->online
              && node->details->unclean == FALSE
              && node->details->shutdown == FALSE) {
        pe_action_t *unfence = pe_fence_op(node, "on", FALSE, reason, FALSE, data_set);

        if(dependency) {
            order_actions(unfence, dependency, pe_order_optional);
        }

    } else if(rsc) {
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if(node->details->online && node->details->unclean == FALSE && node->details->shutdown == FALSE) {
                trigger_unfencing(rsc, node, reason, dependency, data_set);
            }
        }
    }
}

gboolean
add_tag_ref(GHashTable * tags, const char * tag_name,  const char * obj_ref)
{
    pe_tag_t *tag = NULL;
    GList *gIter = NULL;
    gboolean is_existing = FALSE;

    CRM_CHECK(tags && tag_name && obj_ref, return FALSE);

    tag = g_hash_table_lookup(tags, tag_name);
    if (tag == NULL) {
        tag = calloc(1, sizeof(pe_tag_t));
        if (tag == NULL) {
            return FALSE;
        }
        tag->id = strdup(tag_name);
        tag->refs = NULL;
        g_hash_table_insert(tags, strdup(tag_name), tag);
    }

    for (gIter = tag->refs; gIter != NULL; gIter = gIter->next) {
        const char *existing_ref = (const char *) gIter->data;

        if (pcmk__str_eq(existing_ref, obj_ref, pcmk__str_none)){
            is_existing = TRUE;
            break;
        }
    }

    if (is_existing == FALSE) {
        tag->refs = g_list_append(tag->refs, strdup(obj_ref));
        crm_trace("Added: tag=%s ref=%s", tag->id, obj_ref);
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Create an action reason string based on the action itself
 *
 * \param[in] action  Action to create reason string for
 * \param[in] flag    Action flag that was cleared
 *
 * \return Newly allocated string suitable for use as action reason
 * \note It is the caller's responsibility to free() the result.
 */
char *
pe__action2reason(pe_action_t *action, enum pe_action_flags flag)
{
    const char *change = NULL;

    switch (flag) {
        case pe_action_runnable:
        case pe_action_migrate_runnable:
            change = "unrunnable";
            break;
        case pe_action_optional:
            change = "required";
            break;
        default:
            // Bug: caller passed unsupported flag
            CRM_CHECK(change != NULL, change = "");
            break;
    }
    return crm_strdup_printf("%s%s%s %s", change,
                             (action->rsc == NULL)? "" : " ",
                             (action->rsc == NULL)? "" : action->rsc->id,
                             action->task);
}

void pe_action_set_reason(pe_action_t *action, const char *reason, bool overwrite) 
{
    if (action->reason != NULL && overwrite) {
        pe_rsc_trace(action->rsc, "Changing %s reason from '%s' to '%s'",
                     action->uuid, action->reason, crm_str(reason));
        free(action->reason);
    } else if (action->reason == NULL) {
        pe_rsc_trace(action->rsc, "Set %s reason to '%s'",
                     action->uuid, crm_str(reason));
    } else {
        // crm_assert(action->reason != NULL && !overwrite);
        return;
    }

    if (reason != NULL) {
        action->reason = strdup(reason);
    } else {
        action->reason = NULL;
    }
}

/*!
 * \internal
 * \brief Check whether shutdown has been requested for a node
 *
 * \param[in] node  Node to check
 *
 * \return TRUE if node has shutdown attribute set and nonzero, FALSE otherwise
 * \note This differs from simply using node->details->shutdown in that it can
 *       be used before that has been determined (and in fact to determine it),
 *       and it can also be used to distinguish requested shutdown from implicit
 *       shutdown of remote nodes by virtue of their connection stopping.
 */
bool
pe__shutdown_requested(pe_node_t *node)
{
    const char *shutdown = pe_node_attribute_raw(node, XML_CIB_ATTR_SHUTDOWN);

    return !pcmk__str_eq(shutdown, "0", pcmk__str_null_matches);
}

/*!
 * \internal
 * \brief Update a data set's "recheck by" time
 *
 * \param[in]     recheck   Epoch time when recheck should happen
 * \param[in,out] data_set  Current working set
 */
void
pe__update_recheck_time(time_t recheck, pe_working_set_t *data_set)
{
    if ((recheck > get_effective_time(data_set))
        && ((data_set->recheck_by == 0)
            || (data_set->recheck_by > recheck))) {
        data_set->recheck_by = recheck;
    }
}

/*!
 * \internal
 * \brief Wrapper for pe_unpack_nvpairs() using a cluster working set
 */
void
pe__unpack_dataset_nvpairs(xmlNode *xml_obj, const char *set_name,
                           pe_rule_eval_data_t *rule_data, GHashTable *hash,
                           const char *always_first, gboolean overwrite,
                           pe_working_set_t *data_set)
{
    crm_time_t *next_change = crm_time_new_undefined();

    pe_eval_nvpairs(data_set->input, xml_obj, set_name, rule_data, hash,
                    always_first, overwrite, next_change);
    if (crm_time_is_defined(next_change)) {
        time_t recheck = (time_t) crm_time_get_seconds_since_epoch(next_change);

        pe__update_recheck_time(recheck, data_set);
    }
    crm_time_free(next_change);
}

bool
pe__resource_is_disabled(pe_resource_t *rsc)
{
    const char *target_role = NULL;

    CRM_CHECK(rsc != NULL, return false);
    target_role = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    if (target_role) {
        enum rsc_role_e target_role_e = text2role(target_role);

        if ((target_role_e == RSC_ROLE_STOPPED)
            || ((target_role_e == RSC_ROLE_UNPROMOTED)
                && pcmk_is_set(uber_parent(rsc)->flags, pe_rsc_promotable))) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Create an action to clear a resource's history from CIB
 *
 * \param[in] rsc   Resource to clear
 * \param[in] node  Node to clear history on
 *
 * \return New action to clear resource history
 */
pe_action_t *
pe__clear_resource_history(pe_resource_t *rsc, pe_node_t *node,
                           pe_working_set_t *data_set)
{
    char *key = NULL;

    CRM_ASSERT(rsc && node);
    key = pcmk__op_key(rsc->id, CRM_OP_LRM_DELETE, 0);
    return custom_action(rsc, key, CRM_OP_LRM_DELETE, node, FALSE, TRUE,
                         data_set);
}

bool
pe__rsc_running_on_any(pe_resource_t *rsc, GList *node_list)
{
    for (GList *ele = rsc->running_on; ele; ele = ele->next) {
        pe_node_t *node = (pe_node_t *) ele->data;
        if (pcmk__str_in_list(node->details->uname, node_list,
                              pcmk__str_star_matches|pcmk__str_casei)) {
            return true;
        }
    }

    return false;
}

bool
pcmk__rsc_filtered_by_node(pe_resource_t *rsc, GList *only_node)
{
    return (rsc->fns->active(rsc, FALSE) && !pe__rsc_running_on_any(rsc, only_node));
}

GList *
pe__filter_rsc_list(GList *rscs, GList *filter)
{
    GList *retval = NULL;

    for (GList *gIter = rscs; gIter; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        /* I think the second condition is safe here for all callers of this
         * function.  If not, it needs to move into pe__node_text.
         */
        if (pcmk__str_in_list(rsc_printable_id(rsc), filter, pcmk__str_star_matches) ||
            (rsc->parent && pcmk__str_in_list(rsc_printable_id(rsc->parent), filter, pcmk__str_star_matches))) {
            retval = g_list_prepend(retval, rsc);
        }
    }

    return retval;
}

GList *
pe__build_node_name_list(pe_working_set_t *data_set, const char *s) {
    GList *nodes = NULL;

    if (pcmk__str_eq(s, "*", pcmk__str_null_matches)) {
        /* Nothing was given so return a list of all node names.  Or, '*' was
         * given.  This would normally fall into the pe__unames_with_tag branch
         * where it will return an empty list.  Catch it here instead.
         */
        nodes = g_list_prepend(nodes, strdup("*"));
    } else {
        pe_node_t *node = pe_find_node(data_set->nodes, s);

        if (node) {
            /* The given string was a valid uname for a node.  Return a
             * singleton list containing just that uname.
             */
            nodes = g_list_prepend(nodes, strdup(s));
        } else {
            /* The given string was not a valid uname.  It's either a tag or
             * it's a typo or something.  In the first case, we'll return a
             * list of all the unames of the nodes with the given tag.  In the
             * second case, we'll return a NULL pointer and nothing will
             * get displayed.
             */
            nodes = pe__unames_with_tag(data_set, s);
        }
    }

    return nodes;
}

GList *
pe__build_rsc_list(pe_working_set_t *data_set, const char *s) {
    GList *resources = NULL;

    if (pcmk__str_eq(s, "*", pcmk__str_null_matches)) {
        resources = g_list_prepend(resources, strdup("*"));
    } else {
        pe_resource_t *rsc = pe_find_resource_with_flags(data_set->resources, s,
                                                         pe_find_renamed|pe_find_any);

        if (rsc) {
            /* A colon in the name we were given means we're being asked to filter
             * on a specific instance of a cloned resource.  Put that exact string
             * into the filter list.  Otherwise, use the printable ID of whatever
             * resource was found that matches what was asked for.
             */
            if (strstr(s, ":") != NULL) {
                resources = g_list_prepend(resources, strdup(rsc->id));
            } else {
                resources = g_list_prepend(resources, strdup(rsc_printable_id(rsc)));
            }
        } else {
            /* The given string was not a valid resource name.  It's either
             * a tag or it's a typo or something.  See build_uname_list for
             * more detail.
             */
            resources = pe__rscs_with_tag(data_set, s);
        }
    }

    return resources;
}

xmlNode *
pe__failed_probe_for_rsc(pe_resource_t *rsc, const char *name)
{
    pe_resource_t *parent = uber_parent(rsc);
    const char *rsc_id = rsc->id;

    if (rsc->variant == pe_clone) {
        rsc_id = pe__clone_child_id(rsc);
    } else if (parent->variant == pe_clone) {
        rsc_id = pe__clone_child_id(parent);
    }

    for (xmlNode *xml_op = pcmk__xml_first_child(rsc->cluster->failed); xml_op != NULL;
         xml_op = pcmk__xml_next(xml_op)) {
        const char *value = NULL;
        char *op_id = NULL;

        /* This resource operation is not a failed probe. */
        if (!pcmk_xe_mask_probe_failure(xml_op)) {
            continue;
        }

        /* This resource operation was not run on the given node.  Note that if name is
         * NULL, this will always succeed.
         */
        value = crm_element_value(xml_op, XML_LRM_ATTR_TARGET);
        if (value == NULL || !pcmk__str_eq(value, name, pcmk__str_casei|pcmk__str_null_matches)) {
            continue;
        }

        /* This resource operation has no operation_key. */
        value = crm_element_value(xml_op, XML_LRM_ATTR_TASK_KEY);
        if (!parse_op_key(value ? value : ID(xml_op), &op_id, NULL, NULL)) {
            continue;
        }

        /* This resource operation's ID does not match the rsc_id we are looking for. */
        if (!pcmk__str_eq(op_id, rsc_id, pcmk__str_none)) {
            free(op_id);
            continue;
        }

        free(op_id);
        return xml_op;
    }

    return NULL;
}
