/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdbool.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>

#include "pe_status_private.h"

extern bool pcmk__is_daemon;

gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data);

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
pe_can_fence(const pe_working_set_t *data_set, const pe_node_t *node)
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
        crm_notice("We can fence %s without quorum because they're in our membership",
                   pe__node_name(node));
        return true;
    }

    crm_trace("Cannot fence %s", pe__node_name(node));
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
    new_node->fixed = this_node->fixed; // @COMPAT deprecated and unused
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
            node->weight = pcmk__add_scores(node->weight, other_node->weight);
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

/*!
 * \internal
 * \brief Compare two nodes by name, with numeric portions sorted numerically
 *
 * Sort two node names case-insensitively like strcasecmp(), but with any
 * numeric portions of the name sorted numerically. For example, "node10" will
 * sort higher than "node9" but lower than "remotenode9".
 *
 * \param[in] a  First node to compare (can be \c NULL)
 * \param[in] b  Second node to compare (can be \c NULL)
 *
 * \retval -1 \c a comes before \c b (or \c a is \c NULL and \c b is not)
 * \retval  0 \c a and \c b are equal (or both are \c NULL)
 * \retval  1 \c a comes after \c b (or \c b is \c NULL and \c a is not)
 */
gint
pe__cmp_node_name(gconstpointer a, gconstpointer b)
{
    const pe_node_t *node1 = (const pe_node_t *) a;
    const pe_node_t *node2 = (const pe_node_t *) b;

    if ((node1 == NULL) && (node2 == NULL)) {
        return 0;
    }

    if (node1 == NULL) {
        return -1;
    }

    if (node2 == NULL) {
        return 1;
    }

    return pcmk__numeric_strcasecmp(node1->details->uname,
                                    node2->details->uname);
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

    // Sort the nodes so the output is consistent for regression tests
    GList *list = g_list_sort(g_hash_table_get_values(nodes),
                              pe__cmp_node_name);

    for (GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        out->message(out, "node-weight", rsc, comment, node->details->uname,
                     pcmk_readable_score(node->weight));
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

    // Don't waste time if we're not tracing at this point
    pcmk__log_else(LOG_TRACE, return);

    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if (rsc) {
            qb_log_from_external_source(function, file,
                                        "%s: %s allocation score on %s: %s",
                                        LOG_TRACE, line, 0,
                                        comment, rsc->id,
                                        pe__node_name(node),
                                        pcmk_readable_score(node->weight));
        } else {
            qb_log_from_external_source(function, file, "%s: %s = %s",
                                        LOG_TRACE, line, 0,
                                        comment, pe__node_name(node),
                                        pcmk_readable_score(node->weight));
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

/*!
 * \internal
 * \brief Compare two resources by priority
 *
 * \param[in] a  First resource to compare (can be \c NULL)
 * \param[in] b  Second resource to compare (can be \c NULL)
 *
 * \retval -1 \c a->priority > \c b->priority (or \c b is \c NULL and \c a is
 *            not)
 * \retval  0 \c a->priority == \c b->priority (or both \c a and \c b are
 *            \c NULL)
 * \retval  1 \c a->priority < \c b->priority (or \c a is \c NULL and \c b is
 *            not)
 */
gint
pe__cmp_rsc_priority(gconstpointer a, gconstpointer b)
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

    pe_rsc_trace(rsc, "Setting %s for %s on %s: %d",
                 tag, rsc->id, pe__node_name(node), score);
    match = pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);
    if (match == NULL) {
        match = pe__copy_node(node);
        g_hash_table_insert(rsc->allowed_nodes, (gpointer) match->details->id, match);
    }
    match->weight = pcmk__add_scores(match->weight, score);
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
            crm_info("Deallocating %s from %s",
                     rsc->id, pe__node_name(rsc->allocated_to));
            free(rsc->allocated_to);
            rsc->allocated_to = NULL;
        }
    }
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

void
trigger_unfencing(pe_resource_t *rsc, const pe_node_t *node,
                  const char *reason, pe_action_t *dependency,
                  pe_working_set_t *data_set)
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
pe__unpack_dataset_nvpairs(const xmlNode *xml_obj, const char *set_name,
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
            /* The given string was not a valid resource name. It's a tag or a
             * typo or something. See pe__build_node_name_list() for more
             * detail.
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
