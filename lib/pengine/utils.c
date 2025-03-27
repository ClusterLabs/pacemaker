/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <crm/common/xml.h>
#include <crm/pengine/internal.h>

#include "pe_status_private.h"

extern bool pcmk__is_daemon;

gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data);

/*!
 * \internal
 * \brief Check whether we can fence a particular node
 *
 * \param[in] scheduler  Scheduler data
 * \param[in] node       Name of node to check
 *
 * \return true if node can be fenced, false otherwise
 */
bool
pe_can_fence(const pcmk_scheduler_t *scheduler, const pcmk_node_t *node)
{
    if (pcmk__is_guest_or_bundle_node(node)) {
        /* A guest or bundle node is fenced by stopping its launcher, which is
         * possible if the launcher's host is either online or fenceable.
         */
        pcmk_resource_t *rsc = node->priv->remote->priv->launcher;

        for (GList *n = rsc->priv->active_nodes; n != NULL; n = n->next) {
            pcmk_node_t *launcher_node = n->data;

            if (!launcher_node->details->online
                && !pe_can_fence(scheduler, launcher_node)) {
                return false;
            }
        }
        return true;

    } else if (!pcmk_is_set(scheduler->flags, pcmk__sched_fencing_enabled)) {
        return false; /* Turned off */

    } else if (!pcmk_is_set(scheduler->flags, pcmk__sched_have_fencing)) {
        return false; /* No devices */

    } else if (pcmk_is_set(scheduler->flags, pcmk__sched_quorate)) {
        return true;

    } else if (scheduler->no_quorum_policy == pcmk_no_quorum_ignore) {
        return true;

    } else if(node == NULL) {
        return false;

    } else if(node->details->online) {
        crm_notice("We can fence %s without quorum because they're in our membership",
                   pcmk__node_name(node));
        return true;
    }

    crm_trace("Cannot fence %s", pcmk__node_name(node));
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
 *       The caller is responsible for freeing the result using
 *       pcmk__free_node_copy().
 */
pcmk_node_t *
pe__copy_node(const pcmk_node_t *this_node)
{
    pcmk_node_t *new_node = NULL;

    pcmk__assert(this_node != NULL);

    new_node = pcmk__assert_alloc(1, sizeof(pcmk_node_t));
    new_node->assign = pcmk__assert_alloc(1,
                                          sizeof(struct pcmk__node_assignment));

    new_node->assign->probe_mode = this_node->assign->probe_mode;
    new_node->assign->score = this_node->assign->score;
    new_node->assign->count = this_node->assign->count;
    new_node->details = this_node->details;
    new_node->priv = this_node->priv;

    return new_node;
}

/*!
 * \internal
 * \brief Create a hash table of node copies from a list of nodes
 *
 * \param[in] list  Node list
 *
 * \return Hash table equivalent of node list
 */
GHashTable *
pe__node_list2table(const GList *list)
{
    GHashTable *result = NULL;

    result = pcmk__strkey_table(NULL, pcmk__free_node_copy);
    for (const GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        pcmk_node_t *new_node = NULL;

        new_node = pe__copy_node((const pcmk_node_t *) gIter->data);
        g_hash_table_insert(result, (gpointer) new_node->priv->id, new_node);
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
    const pcmk_node_t *node1 = (const pcmk_node_t *) a;
    const pcmk_node_t *node2 = (const pcmk_node_t *) b;

    if ((node1 == NULL) && (node2 == NULL)) {
        return 0;
    }

    if (node1 == NULL) {
        return -1;
    }

    if (node2 == NULL) {
        return 1;
    }

    return pcmk__numeric_strcasecmp(node1->priv->name, node2->priv->name);
}

/*!
 * \internal
 * \brief Output node weights to stdout
 *
 * \param[in]     rsc        Use allowed nodes for this resource
 * \param[in]     comment    Text description to prefix lines with
 * \param[in]     nodes      If rsc is not specified, use these nodes
 * \param[in,out] scheduler  Scheduler data
 */
static void
pe__output_node_weights(const pcmk_resource_t *rsc, const char *comment,
                        GHashTable *nodes, pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = scheduler->priv->out;

    // Sort the nodes so the output is consistent for regression tests
    GList *list = g_list_sort(g_hash_table_get_values(nodes),
                              pe__cmp_node_name);

    for (const GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        const pcmk_node_t *node = (const pcmk_node_t *) gIter->data;

        out->message(out, "node-weight", rsc, comment, node->priv->name,
                     pcmk_readable_score(node->assign->score));
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
 * \param[in] rsc       If not NULL, include this resource's ID in logs
 * \param[in] comment   Text description to prefix lines with
 * \param[in] nodes     Nodes whose scores should be logged
 */
static void
pe__log_node_weights(const char *file, const char *function, int line,
                     const pcmk_resource_t *rsc, const char *comment,
                     GHashTable *nodes)
{
    GHashTableIter iter;
    pcmk_node_t *node = NULL;

    // Don't waste time if we're not tracing at this point
    pcmk__if_tracing({}, return);

    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if (rsc) {
            qb_log_from_external_source(function, file,
                                        "%s: %s allocation score on %s: %s",
                                        LOG_TRACE, line, 0,
                                        comment, rsc->id,
                                        pcmk__node_name(node),
                                        pcmk_readable_score(node->assign->score));
        } else {
            qb_log_from_external_source(function, file, "%s: %s = %s",
                                        LOG_TRACE, line, 0,
                                        comment, pcmk__node_name(node),
                                        pcmk_readable_score(node->assign->score));
        }
    }
}

/*!
 * \internal
 * \brief Log or output node weights
 *
 * \param[in]     file       Caller's filename
 * \param[in]     function   Caller's function name
 * \param[in]     line       Caller's line number
 * \param[in]     to_log     Log if true, otherwise output
 * \param[in]     rsc        If not NULL, use this resource's ID in logs,
 *                           and show scores recursively for any children
 * \param[in]     comment    Text description to prefix lines with
 * \param[in]     nodes      Nodes whose scores should be shown
 * \param[in,out] scheduler  Scheduler data
 */
void
pe__show_node_scores_as(const char *file, const char *function, int line,
                        bool to_log, const pcmk_resource_t *rsc,
                        const char *comment, GHashTable *nodes,
                        pcmk_scheduler_t *scheduler)
{
    if ((rsc != NULL) && pcmk_is_set(rsc->flags, pcmk__rsc_removed)) {
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
        pe__output_node_weights(rsc, comment, nodes, scheduler);
    }

    if (rsc == NULL) {
        return;
    }

    // If this resource has children, repeat recursively for each
    for (GList *gIter = rsc->priv->children;
         gIter != NULL; gIter = gIter->next) {

        pcmk_resource_t *child = (pcmk_resource_t *) gIter->data;

        pe__show_node_scores_as(file, function, line, to_log, child, comment,
                                child->priv->allowed_nodes, scheduler);
    }
}

/*!
 * \internal
 * \brief Compare two resources by priority
 *
 * \param[in] a  First resource to compare (can be \c NULL)
 * \param[in] b  Second resource to compare (can be \c NULL)
 *
 * \retval -1 a's priority > b's priority (or \c b is \c NULL and \c a is not)
 * \retval  0 a's priority == b's priority (or both \c a and \c b are \c NULL)
 * \retval  1 a's priority < b's priority (or \c a is \c NULL and \c b is not)
 */
gint
pe__cmp_rsc_priority(gconstpointer a, gconstpointer b)
{
    const pcmk_resource_t *resource1 = (const pcmk_resource_t *)a;
    const pcmk_resource_t *resource2 = (const pcmk_resource_t *)b;

    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (resource1->priv->priority > resource2->priv->priority) {
        return -1;
    }

    if (resource1->priv->priority < resource2->priv->priority) {
        return 1;
    }

    return 0;
}

static void
resource_node_score(pcmk_resource_t *rsc, const pcmk_node_t *node, int score,
                    const char *tag)
{
    pcmk_node_t *match = NULL;

    if ((pcmk_is_set(rsc->flags, pcmk__rsc_exclusive_probes)
         || (node->assign->probe_mode == pcmk__probe_never))
        && pcmk__str_eq(tag, "symmetric_default", pcmk__str_casei)) {
        /* This string comparision may be fragile, but exclusive resources and
         * exclusive nodes should not have the symmetric_default constraint
         * applied to them.
         */
        return;

    } else {
        for (GList *gIter = rsc->priv->children;
             gIter != NULL; gIter = gIter->next) {

            pcmk_resource_t *child_rsc = (pcmk_resource_t *) gIter->data;

            resource_node_score(child_rsc, node, score, tag);
        }
    }

    match = g_hash_table_lookup(rsc->priv->allowed_nodes, node->priv->id);
    if (match == NULL) {
        match = pe__copy_node(node);
        g_hash_table_insert(rsc->priv->allowed_nodes,
                            (gpointer) match->priv->id, match);
    }
    match->assign->score = pcmk__add_scores(match->assign->score, score);
    pcmk__rsc_trace(rsc,
                    "Enabling %s preference (%s) for %s on %s (now %s)",
                    tag, pcmk_readable_score(score), rsc->id,
                    pcmk__node_name(node),
                    pcmk_readable_score(match->assign->score));
}

void
resource_location(pcmk_resource_t *rsc, const pcmk_node_t *node, int score,
                  const char *tag, pcmk_scheduler_t *scheduler)
{
    if (node != NULL) {
        resource_node_score(rsc, node, score, tag);

    } else if (scheduler != NULL) {
        GList *gIter = scheduler->nodes;

        for (; gIter != NULL; gIter = gIter->next) {
            pcmk_node_t *node_iter = (pcmk_node_t *) gIter->data;

            resource_node_score(rsc, node_iter, score, tag);
        }

    } else {
        GHashTableIter iter;
        pcmk_node_t *node_iter = NULL;

        g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node_iter)) {
            resource_node_score(rsc, node_iter, score, tag);
        }
    }

    if ((node == NULL) && (score == -PCMK_SCORE_INFINITY)
        && (rsc->priv->assigned_node != NULL)) {

        // @TODO Should this be more like pcmk__unassign_resource()?
        crm_info("Unassigning %s from %s",
                 rsc->id, pcmk__node_name(rsc->priv->assigned_node));
        pcmk__free_node_copy(rsc->priv->assigned_node);
        rsc->priv->assigned_node = NULL;
    }
}

gboolean
get_target_role(const pcmk_resource_t *rsc, enum rsc_role_e *role)
{
    enum rsc_role_e local_role = pcmk_role_unknown;
    const char *value = g_hash_table_lookup(rsc->priv->meta,
                                            PCMK_META_TARGET_ROLE);

    CRM_CHECK(role != NULL, return FALSE);

    if (pcmk__str_eq(value, PCMK_ROLE_STARTED,
                     pcmk__str_null_matches|pcmk__str_casei)) {
        return FALSE;
    }
    if (pcmk__str_eq(PCMK_VALUE_DEFAULT, value, pcmk__str_casei)) {
        // @COMPAT Deprecated since 2.1.8
        pcmk__config_warn("Support for setting " PCMK_META_TARGET_ROLE
                          " to the explicit value '" PCMK_VALUE_DEFAULT
                          "' is deprecated and will be removed in a "
                          "future release (just leave it unset)");
        return FALSE;
    }

    local_role = pcmk_parse_role(value);
    if (local_role == pcmk_role_unknown) {
        pcmk__config_err("Ignoring '" PCMK_META_TARGET_ROLE "' for %s "
                         "because '%s' is not valid", rsc->id, value);
        return FALSE;

    } else if (local_role > pcmk_role_started) {
        if (pcmk_is_set(pe__const_top_resource(rsc, false)->flags,
                        pcmk__rsc_promotable)) {
            if (local_role > pcmk_role_unpromoted) {
                /* This is what we'd do anyway, just leave the default to avoid messing up the placement algorithm */
                return FALSE;
            }

        } else {
            pcmk__config_err("Ignoring '" PCMK_META_TARGET_ROLE "' for %s "
                             "because '%s' only makes sense for promotable "
                             "clones", rsc->id, value);
            return FALSE;
        }
    }

    *role = local_role;
    return TRUE;
}

gboolean
order_actions(pcmk_action_t *first, pcmk_action_t *then, uint32_t flags)
{
    GList *gIter = NULL;
    pcmk__related_action_t *wrapper = NULL;
    GList *list = NULL;

    if (flags == pcmk__ar_none) {
        return FALSE;
    }

    if ((first == NULL) || (then == NULL)) {
        return FALSE;
    }

    crm_trace("Creating action wrappers for ordering: %s then %s",
              first->uuid, then->uuid);

    /* Ensure we never create a dependency on ourselves... it's happened */
    pcmk__assert(first != then);

    /* Filter dups, otherwise update_action_states() has too much work to do */
    gIter = first->actions_after;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__related_action_t *after = gIter->data;

        if ((after->action == then)
            && pcmk_any_flags_set(after->flags, flags)) {
            return FALSE;
        }
    }

    wrapper = pcmk__assert_alloc(1, sizeof(pcmk__related_action_t));
    wrapper->action = then;
    wrapper->flags = flags;
    list = first->actions_after;
    list = g_list_prepend(list, wrapper);
    first->actions_after = list;

    wrapper = pcmk__assert_alloc(1, sizeof(pcmk__related_action_t));
    wrapper->action = first;
    wrapper->flags = flags;
    list = then->actions_before;
    list = g_list_prepend(list, wrapper);
    then->actions_before = list;
    return TRUE;
}

void
destroy_ticket(gpointer data)
{
    pcmk__ticket_t *ticket = data;

    if (ticket->state) {
        g_hash_table_destroy(ticket->state);
    }
    free(ticket->id);
    free(ticket);
}

pcmk__ticket_t *
ticket_new(const char *ticket_id, pcmk_scheduler_t *scheduler)
{
    pcmk__ticket_t *ticket = NULL;

    if (pcmk__str_empty(ticket_id)) {
        return NULL;
    }

    if (scheduler->priv->ticket_constraints == NULL) {
        scheduler->priv->ticket_constraints =
            pcmk__strkey_table(free, destroy_ticket);
    }

    ticket = g_hash_table_lookup(scheduler->priv->ticket_constraints,
                                 ticket_id);
    if (ticket == NULL) {

        ticket = calloc(1, sizeof(pcmk__ticket_t));
        if (ticket == NULL) {
            pcmk__sched_err(scheduler, "Cannot allocate ticket '%s'",
                            ticket_id);
            return NULL;
        }

        crm_trace("Creating ticket entry for %s", ticket_id);

        ticket->id = strdup(ticket_id);
        ticket->last_granted = -1;
        ticket->state = pcmk__strkey_table(free, free);

        g_hash_table_insert(scheduler->priv->ticket_constraints,
                            pcmk__str_copy(ticket->id), ticket);
    }

    return ticket;
}

const char *
rsc_printable_id(const pcmk_resource_t *rsc)
{
    if (pcmk_is_set(rsc->flags, pcmk__rsc_unique)) {
        return rsc->id;
    }
    return pcmk__xe_id(rsc->priv->xml);
}

void
pe__clear_resource_flags_recursive(pcmk_resource_t *rsc, uint64_t flags)
{
    pcmk__clear_rsc_flags(rsc, flags);

    for (GList *gIter = rsc->priv->children;
         gIter != NULL; gIter = gIter->next) {

        pe__clear_resource_flags_recursive((pcmk_resource_t *) gIter->data,
                                           flags);
    }
}

void
pe__clear_resource_flags_on_all(pcmk_scheduler_t *scheduler, uint64_t flag)
{
    for (GList *lpc = scheduler->priv->resources;
         lpc != NULL; lpc = lpc->next) {

        pcmk_resource_t *r = (pcmk_resource_t *) lpc->data;

        pe__clear_resource_flags_recursive(r, flag);
    }
}

void
pe__set_resource_flags_recursive(pcmk_resource_t *rsc, uint64_t flags)
{
    pcmk__set_rsc_flags(rsc, flags);

    for (GList *gIter = rsc->priv->children;
         gIter != NULL; gIter = gIter->next) {

        pe__set_resource_flags_recursive((pcmk_resource_t *) gIter->data,
                                         flags);
    }
}

void
trigger_unfencing(pcmk_resource_t *rsc, pcmk_node_t *node, const char *reason,
                  pcmk_action_t *dependency, pcmk_scheduler_t *scheduler)
{
    if (!pcmk_is_set(scheduler->flags, pcmk__sched_enable_unfencing)) {
        /* No resources require it */
        return;

    } else if ((rsc != NULL)
               && !pcmk_is_set(rsc->flags, pcmk__rsc_fence_device)) {
        /* Wasn't a stonith device */
        return;

    } else if(node
              && node->details->online
              && node->details->unclean == FALSE
              && node->details->shutdown == FALSE) {
        pcmk_action_t *unfence = pe_fence_op(node, PCMK_ACTION_ON, FALSE,
                                             reason, FALSE, scheduler);

        if(dependency) {
            order_actions(unfence, dependency, pcmk__ar_ordered);
        }

    } else if(rsc) {
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if(node->details->online && node->details->unclean == FALSE && node->details->shutdown == FALSE) {
                trigger_unfencing(rsc, node, reason, dependency, scheduler);
            }
        }
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
pe__shutdown_requested(const pcmk_node_t *node)
{
    const char *shutdown = pcmk__node_attr(node, PCMK__NODE_ATTR_SHUTDOWN, NULL,
                                           pcmk__rsc_node_current);

    return !pcmk__str_eq(shutdown, "0", pcmk__str_null_matches);
}

/*!
 * \internal
 * \brief Extract nvpair blocks contained by a CIB XML element into a hash table
 *
 * \param[in]     xml_obj       XML element containing blocks of nvpair elements
 * \param[in]     set_name      If not NULL, only use blocks of this element
 * \param[in]     rule_input    Values used to evaluate rule criteria
 *                              (node_attrs member must be NULL if \p set_name
 *                              is PCMK_XE_META_ATTRIBUTES)
 * \param[out]    hash          Where to store extracted name/value pairs
 * \param[in]     always_first  If not NULL, process block with this ID first
 * \param[in,out] scheduler     Scheduler data containing \p xml_obj
 */
void
pe__unpack_dataset_nvpairs(const xmlNode *xml_obj, const char *set_name,
                           const pcmk_rule_input_t *rule_input,
                           GHashTable *hash, const char *always_first,
                           pcmk_scheduler_t *scheduler)
{
    crm_time_t *next_change = NULL;

    CRM_CHECK((set_name != NULL) && (rule_input != NULL) && (hash != NULL)
              && (scheduler != NULL), return);

    // Node attribute expressions are not allowed for meta-attributes
    CRM_CHECK((rule_input->node_attrs == NULL)
              || (strcmp(set_name, PCMK_XE_META_ATTRIBUTES) != 0), return);

    if (xml_obj == NULL) {
        return;
    }

    next_change = crm_time_new_undefined();
    pcmk_unpack_nvpair_blocks(xml_obj, set_name, always_first, rule_input, hash,
                              next_change);
    if (crm_time_is_defined(next_change)) {
        time_t recheck = (time_t) crm_time_get_seconds_since_epoch(next_change);

        pcmk__update_recheck_time(recheck, scheduler, "rule evaluation");
    }
    crm_time_free(next_change);
}

bool
pe__resource_is_disabled(const pcmk_resource_t *rsc)
{
    const char *target_role = NULL;

    CRM_CHECK(rsc != NULL, return false);
    target_role = g_hash_table_lookup(rsc->priv->meta,
                                      PCMK_META_TARGET_ROLE);
    if (target_role) {
        // If invalid, we've already logged an error when unpacking
        enum rsc_role_e target_role_e = pcmk_parse_role(target_role);

        if ((target_role_e == pcmk_role_stopped)
            || ((target_role_e == pcmk_role_unpromoted)
                && pcmk_is_set(pe__const_top_resource(rsc, false)->flags,
                               pcmk__rsc_promotable))) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether a resource is running only on given node
 *
 * \param[in] rsc   Resource to check
 * \param[in] node  Node to check
 *
 * \return true if \p rsc is running only on \p node, otherwise false
 */
bool
pe__rsc_running_on_only(const pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    return (rsc != NULL) && pcmk__list_of_1(rsc->priv->active_nodes)
           && pcmk__same_node((const pcmk_node_t *)
                              rsc->priv->active_nodes->data, node);
}

bool
pe__rsc_running_on_any(pcmk_resource_t *rsc, GList *node_list)
{
    if (rsc != NULL) {
        for (GList *ele = rsc->priv->active_nodes; ele; ele = ele->next) {
            pcmk_node_t *node = (pcmk_node_t *) ele->data;
            if (pcmk__str_in_list(node->priv->name, node_list,
                                  pcmk__str_star_matches|pcmk__str_casei)) {
                return true;
            }
        }
    }
    return false;
}

bool
pcmk__rsc_filtered_by_node(pcmk_resource_t *rsc, GList *only_node)
{
    return rsc->priv->fns->active(rsc, false)
           && !pe__rsc_running_on_any(rsc, only_node);
}

GList *
pe__filter_rsc_list(GList *rscs, GList *filter)
{
    GList *retval = NULL;

    for (GList *gIter = rscs; gIter; gIter = gIter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) gIter->data;

        /* I think the second condition is safe here for all callers of this
         * function.  If not, it needs to move into pe__node_text.
         */
        if (pcmk__str_in_list(rsc_printable_id(rsc), filter, pcmk__str_star_matches) ||
            ((rsc->priv->parent != NULL)
             && pcmk__str_in_list(rsc_printable_id(rsc->priv->parent),
                                  filter, pcmk__str_star_matches))) {
            retval = g_list_prepend(retval, rsc);
        }
    }

    return retval;
}

GList *
pe__build_node_name_list(pcmk_scheduler_t *scheduler, const char *s)
{
    GList *nodes = NULL;

    if (pcmk__str_eq(s, "*", pcmk__str_null_matches)) {
        /* Nothing was given so return a list of all node names.  Or, '*' was
         * given.  This would normally fall into the pe__unames_with_tag branch
         * where it will return an empty list.  Catch it here instead.
         */
        nodes = g_list_prepend(nodes, strdup("*"));
    } else {
        pcmk_node_t *node = pcmk_find_node(scheduler, s);

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
            nodes = pe__unames_with_tag(scheduler, s);
        }
    }

    return nodes;
}

GList *
pe__build_rsc_list(pcmk_scheduler_t *scheduler, const char *s)
{
    GList *resources = NULL;

    if (pcmk__str_eq(s, "*", pcmk__str_null_matches)) {
        resources = g_list_prepend(resources, strdup("*"));
    } else {
        const uint32_t flags = pcmk_rsc_match_history|pcmk_rsc_match_basename;
        pcmk_resource_t *rsc =
            pe_find_resource_with_flags(scheduler->priv->resources, s, flags);

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
            resources = pe__rscs_with_tag(scheduler, s);
        }
    }

    return resources;
}

xmlNode *
pe__failed_probe_for_rsc(const pcmk_resource_t *rsc, const char *name)
{
    const pcmk_resource_t *parent = pe__const_top_resource(rsc, false);
    const char *rsc_id = rsc->id;
    const pcmk_scheduler_t *scheduler = rsc->priv->scheduler;

    if (pcmk__is_clone(parent)) {
        rsc_id = pe__clone_child_id(parent);
    }

    for (xmlNode *xml_op = pcmk__xe_first_child(scheduler->priv->failed,
                                                NULL, NULL, NULL);
         xml_op != NULL; xml_op = pcmk__xe_next(xml_op, NULL)) {

        const char *value = NULL;
        char *op_id = NULL;

        /* This resource operation is not a failed probe. */
        if (!pcmk_xe_mask_probe_failure(xml_op)) {
            continue;
        }

        /* This resource operation was not run on the given node.  Note that if name is
         * NULL, this will always succeed.
         */
        value = pcmk__xe_get(xml_op, PCMK__META_ON_NODE);
        if (value == NULL || !pcmk__str_eq(value, name, pcmk__str_casei|pcmk__str_null_matches)) {
            continue;
        }

        if (!parse_op_key(pcmk__xe_history_key(xml_op), &op_id, NULL, NULL)) {
            continue; // This history entry is missing an operation key
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
