/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>

#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>

#include "pe_status_private.h"

typedef struct {
    const pcmk_resource_t *rsc;
    const pcmk_node_t *node;
} notify_entry_t;

/*!
 * \internal
 * \brief Compare two notification entries
 *
 * Compare two notification entries, where the one with the alphabetically first
 * resource name (or if equal, node ID) sorts as first, with NULL sorting as
 * less than non-NULL.
 *
 * \param[in] a  First notification entry to compare
 * \param[in] b  Second notification entry to compare
 *
 * \return -1 if \p a sorts before \p b, 0 if they are equal, otherwise 1
 */
static gint
compare_notify_entries(gconstpointer a, gconstpointer b)
{
    int tmp;
    const notify_entry_t *entry_a = a;
    const notify_entry_t *entry_b = b;

    // NULL a or b is not actually possible
    if ((entry_a == NULL) && (entry_b == NULL)) {
        return 0;
    }
    if (entry_a == NULL) {
        return 1;
    }
    if (entry_b == NULL) {
        return -1;
    }

    // NULL resources sort first
    if ((entry_a->rsc == NULL) && (entry_b->rsc == NULL)) {
        return 0;
    }
    if (entry_a->rsc == NULL) {
        return 1;
    }
    if (entry_b->rsc == NULL) {
        return -1;
    }

    // Compare resource names
    tmp = strcmp(entry_a->rsc->id, entry_b->rsc->id);
    if (tmp != 0) {
        return tmp;
    }

    // Otherwise NULL nodes sort first
    if ((entry_a->node == NULL) && (entry_b->node == NULL)) {
        return 0;
    }
    if (entry_a->node == NULL) {
        return 1;
    }
    if (entry_b->node == NULL) {
        return -1;
    }

    // Finally, compare node IDs
    return strcmp(entry_a->node->priv->id, entry_b->node->priv->id);
}

/*!
 * \internal
 * \brief Duplicate a notification entry
 *
 * \param[in] entry  Entry to duplicate
 *
 * \return Newly allocated duplicate of \p entry
 * \note It is the caller's responsibility to free the return value.
 */
static notify_entry_t *
dup_notify_entry(const notify_entry_t *entry)
{
    notify_entry_t *dup = pcmk__assert_alloc(1, sizeof(notify_entry_t));

    dup->rsc = entry->rsc;
    dup->node = entry->node;
    return dup;
}

/*!
 * \internal
 * \brief Given a list of nodes, create strings with node names
 *
 * \param[in]  list             List of nodes (as pcmk_node_t *)
 * \param[out] all_node_names   If not NULL, will be set to space-separated list
 *                              of the names of all nodes in \p list
 * \param[out] host_node_names  Same as \p all_node_names, except active
 *                              guest nodes will list the name of their host
 *
 * \note The caller is responsible for freeing the output argument values using
 *       \p g_string_free().
 */
static void
get_node_names(const GList *list, GString **all_node_names,
               GString **host_node_names)
{
    if (all_node_names != NULL) {
        *all_node_names = NULL;
    }
    if (host_node_names != NULL) {
        *host_node_names = NULL;
    }

    for (const GList *iter = list; iter != NULL; iter = iter->next) {
        const pcmk_node_t *node = (const pcmk_node_t *) iter->data;

        if (node->priv->name == NULL) {
            /* @TODO This breaks the comparability of the various notification
             * variables and thus any agent relying on it. Maybe add "UNKNOWN"
             * or something like that.
             */
            continue;
        }

        // Always add to list of all node names
        if (all_node_names != NULL) {
            pcmk__add_word(all_node_names, 1024, node->priv->name);
        }

        // Add to host node name list if appropriate
        if (host_node_names != NULL) {
            if (pcmk__is_guest_or_bundle_node(node)) {
                const pcmk_resource_t *launcher = NULL;

                launcher = node->priv->remote->priv->launcher;
                if (launcher->priv->active_nodes != NULL) {
                    node = pcmk__current_node(launcher);
                    if (node->priv->name == NULL) {
                        continue;
                    }
                }
            }
            pcmk__add_word(host_node_names, 1024, node->priv->name);
        }
    }

    if ((all_node_names != NULL) && (*all_node_names == NULL)) {
        *all_node_names = g_string_new(" ");
    }
    if ((host_node_names != NULL) && (*host_node_names == NULL)) {
        *host_node_names = g_string_new(" ");
    }
}

/*!
 * \internal
 * \brief Create strings of instance and node names from notification entries
 *
 * \param[in,out] list        List of notification entries (will be sorted here)
 * \param[out]    rsc_names   If not NULL, will be set to space-separated list
 *                            of clone instances from \p list
 * \param[out]    node_names  If not NULL, will be set to space-separated list
 *                            of node names from \p list
 *
 * \return (Possibly new) head of sorted \p list
 * \note The caller is responsible for freeing the output argument values using
 *       \p g_list_free_full() and \p g_string_free().
 */
static GList *
notify_entries_to_strings(GList *list, GString **rsc_names,
                          GString **node_names)
{
    const char *last_rsc_id = NULL;

    // Initialize output lists to NULL
    if (rsc_names != NULL) {
        *rsc_names = NULL;
    }
    if (node_names != NULL) {
        *node_names = NULL;
    }

    // Sort input list for user-friendliness (and ease of filtering duplicates)
    list = g_list_sort(list, compare_notify_entries);

    for (GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        notify_entry_t *entry = (notify_entry_t *) gIter->data;

        // Entry must have a resource (with ID)
        CRM_LOG_ASSERT((entry != NULL) && (entry->rsc != NULL)
                       && (entry->rsc->id != NULL));
        if ((entry == NULL) || (entry->rsc == NULL)
            || (entry->rsc->id == NULL)) {
            continue;
        }

        // Entry must have a node unless listing inactive resources
        CRM_LOG_ASSERT((node_names == NULL) || (entry->node != NULL));
        if ((node_names != NULL) && (entry->node == NULL)) {
            continue;
        }

        // Don't add duplicates of a particular clone instance
        if (pcmk__str_eq(entry->rsc->id, last_rsc_id, pcmk__str_none)) {
            continue;
        }
        last_rsc_id = entry->rsc->id;

        if (rsc_names != NULL) {
            pcmk__add_word(rsc_names, 1024, entry->rsc->id);
        }
        if ((node_names != NULL) && (entry->node->priv->name != NULL)) {
            pcmk__add_word(node_names, 1024, entry->node->priv->name);
        }
    }

    // If there are no entries, return "empty" lists
    if ((rsc_names != NULL) && (*rsc_names == NULL)) {
        *rsc_names = g_string_new(" ");
    }
    if ((node_names != NULL) && (*node_names == NULL)) {
        *node_names = g_string_new(" ");
    }

    return list;
}

/*!
 * \internal
 * \brief Copy a meta-attribute into a notify action
 *
 * \param[in]     key        Name of meta-attribute to copy
 * \param[in]     value      Value of meta-attribute to copy
 * \param[in,out] user_data  Notify action to copy into
 */
static void
copy_meta_to_notify(gpointer key, gpointer value, gpointer user_data)
{
    pcmk_action_t *notify = (pcmk_action_t *) user_data;

    /* Any existing meta-attributes (for example, the action timeout) are for
     * the notify action itself, so don't override those.
     */
    if (g_hash_table_lookup(notify->meta, (const char *) key) != NULL) {
        return;
    }

    pcmk__insert_dup(notify->meta, (const char *) key, (const char *) value);
}

static void
add_notify_data_to_action_meta(const notify_data_t *n_data,
                               pcmk_action_t *action)
{
    for (const GSList *item = n_data->keys; item; item = item->next) {
        const pcmk_nvpair_t *nvpair = (const pcmk_nvpair_t *) item->data;

        pcmk__insert_meta(action, nvpair->name, nvpair->value);
    }
}

/*!
 * \internal
 * \brief Create a new notify pseudo-action for a clone resource
 *
 * \param[in,out] rsc           Clone resource that notification is for
 * \param[in]     action        Action to use in notify action key
 * \param[in]     notif_action  PCMK_ACTION_NOTIFY or PCMK_ACTION_NOTIFIED
 * \param[in]     notif_type    "pre", "post", "confirmed-pre", "confirmed-post"
 *
 * \return Newly created notify pseudo-action
 */
static pcmk_action_t *
new_notify_pseudo_action(pcmk_resource_t *rsc, const pcmk_action_t *action,
                         const char *notif_action, const char *notif_type)
{
    pcmk_action_t *notify = NULL;

    notify = custom_action(rsc,
                           pcmk__notify_key(rsc->id, notif_type, action->task),
                           notif_action, NULL,
                           pcmk__is_set(action->flags, pcmk__action_optional),
                           rsc->priv->scheduler);
    pcmk__set_action_flags(notify, pcmk__action_pseudo);
    pcmk__insert_meta(notify, "notify_key_type", notif_type);
    pcmk__insert_meta(notify, "notify_key_operation", action->task);
    return notify;
}

/*!
 * \internal
 * \brief Create a new notify action for a clone instance
 *
 * \param[in,out] rsc          Clone instance that notification is for
 * \param[in]     node         Node that notification is for
 * \param[in,out] op           Action that notification is for
 * \param[in,out] notify_done  Parent pseudo-action for notifications complete
 * \param[in]     n_data       Notification values to add to action meta-data
 *
 * \return Newly created notify action
 */
static pcmk_action_t *
new_notify_action(pcmk_resource_t *rsc, const pcmk_node_t *node,
                  pcmk_action_t *op, pcmk_action_t *notify_done,
                  const notify_data_t *n_data)
{
    char *key = NULL;
    pcmk_action_t *notify_action = NULL;
    const char *value = NULL;
    const char *task = NULL;
    const char *skip_reason = NULL;

    CRM_CHECK((rsc != NULL) && (node != NULL), return NULL);

    // Ensure we have all the info we need
    if (op == NULL) {
        skip_reason = "no action";
    } else if (notify_done == NULL) {
        skip_reason = "no parent notification";
    } else if (!node->details->online) {
        skip_reason = "node offline";
    } else if (!pcmk__is_set(op->flags, pcmk__action_runnable)) {
        skip_reason = "original action not runnable";
    }
    if (skip_reason != NULL) {
        pcmk__rsc_trace(rsc, "Skipping notify action for %s on %s: %s",
                        rsc->id, pcmk__node_name(node), skip_reason);
        return NULL;
    }

    value = g_hash_table_lookup(op->meta, "notify_type");     // "pre" or "post"
    task = g_hash_table_lookup(op->meta, "notify_operation"); // original action

    pcmk__rsc_trace(rsc, "Creating notify action for %s on %s (%s-%s)",
                    rsc->id, pcmk__node_name(node), value, task);

    // Create the notify action
    key = pcmk__notify_key(rsc->id, value, task);
    notify_action = custom_action(rsc, key, op->task, node,
                                  pcmk__is_set(op->flags,
                                               pcmk__action_optional),
                                  rsc->priv->scheduler);

    // Add meta-data to notify action
    g_hash_table_foreach(op->meta, copy_meta_to_notify, notify_action);
    add_notify_data_to_action_meta(n_data, notify_action);

    // Order notify after original action and before parent notification
    order_actions(op, notify_action, pcmk__ar_ordered);
    order_actions(notify_action, notify_done, pcmk__ar_ordered);
    return notify_action;
}

/*!
 * \internal
 * \brief Create a new "post-" notify action for a clone instance
 *
 * \param[in,out] rsc     Clone instance that notification is for
 * \param[in]     node    Node that notification is for
 * \param[in,out] n_data  Notification values to add to action meta-data
 */
static void
new_post_notify_action(pcmk_resource_t *rsc, const pcmk_node_t *node,
                       notify_data_t *n_data)
{
    pcmk_action_t *notify = NULL;

    pcmk__assert(n_data != NULL);

    // Create the "post-" notify action for specified instance
    notify = new_notify_action(rsc, node, n_data->post, n_data->post_done,
                               n_data);
    if (notify != NULL) {
        notify->priority = PCMK_SCORE_INFINITY;
    }

    // Order recurring monitors after all "post-" notifications complete
    if (n_data->post_done == NULL) {
        return;
    }
    for (GList *iter = rsc->priv->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *mon = (pcmk_action_t *) iter->data;
        const char *interval_ms_s = NULL;

        interval_ms_s = g_hash_table_lookup(mon->meta, PCMK_META_INTERVAL);
        if (pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches)
            || pcmk__str_eq(mon->task, PCMK_ACTION_CANCEL, pcmk__str_none)) {
            continue; // Not a recurring monitor
        }
        order_actions(n_data->post_done, mon, pcmk__ar_ordered);
    }
}

/*!
 * \internal
 * \brief Create and order notification pseudo-actions for a clone action
 *
 * In addition to the actual notify actions needed for each clone instance,
 * clone notifications also require pseudo-actions to provide ordering points
 * in the notification process. This creates the notification data, along with
 * appropriate pseudo-actions and their orderings.
 *
 * For example, the ordering sequence for starting a clone is:
 *
 *     "pre-" notify pseudo-action for clone
 *     -> "pre-" notify actions for each clone instance
 *     -> "pre-" notifications complete pseudo-action for clone
 *     -> start actions for each clone instance
 *     -> "started" pseudo-action for clone
 *     -> "post-" notify pseudo-action for clone
 *     -> "post-" notify actions for each clone instance
 *     -> "post-" notifications complete pseudo-action for clone
 *
 * \param[in,out] rsc       Clone that notifications are for
 * \param[in]     task      Name of action that notifications are for
 * \param[in,out] action    If not NULL, create a "pre-" pseudo-action ordered
 *                          before a "pre-" complete pseudo-action, ordered
 *                          before this action
 * \param[in,out] complete  If not NULL, create a "post-" pseudo-action ordered
 *                          after this action, and a "post-" complete
 *                          pseudo-action ordered after that
 *
 * \return Newly created notification data
 */
notify_data_t *
pe__action_notif_pseudo_ops(pcmk_resource_t *rsc, const char *task,
                            pcmk_action_t *action, pcmk_action_t *complete)
{
    notify_data_t *n_data = NULL;

    if (!pcmk__is_set(rsc->flags, pcmk__rsc_notify)) {
        return NULL;
    }

    n_data = pcmk__assert_alloc(1, sizeof(notify_data_t));

    n_data->action = task;

    if (action != NULL) { // Need "pre-" pseudo-actions

        // Create "pre-" notify pseudo-action for clone
        n_data->pre = new_notify_pseudo_action(rsc, action, PCMK_ACTION_NOTIFY,
                                               "pre");
        pcmk__set_action_flags(n_data->pre, pcmk__action_runnable);
        pcmk__insert_meta(n_data->pre, "notify_type", "pre");
        pcmk__insert_meta(n_data->pre, "notify_operation", n_data->action);

        // Create "pre-" notifications complete pseudo-action for clone
        n_data->pre_done = new_notify_pseudo_action(rsc, action,
                                                    PCMK_ACTION_NOTIFIED,
                                                    "confirmed-pre");
        pcmk__set_action_flags(n_data->pre_done, pcmk__action_runnable);
        pcmk__insert_meta(n_data->pre_done, "notify_type", "pre");
        pcmk__insert_meta(n_data->pre_done, "notify_operation", n_data->action);

        // Order "pre-" -> "pre-" complete -> original action
        order_actions(n_data->pre, n_data->pre_done, pcmk__ar_ordered);
        order_actions(n_data->pre_done, action, pcmk__ar_ordered);
    }

    if (complete != NULL) { // Need "post-" pseudo-actions

        // Create "post-" notify pseudo-action for clone
        n_data->post = new_notify_pseudo_action(rsc, complete,
                                                PCMK_ACTION_NOTIFY, "post");
        n_data->post->priority = PCMK_SCORE_INFINITY;
        if (pcmk__is_set(complete->flags, pcmk__action_runnable)) {
            pcmk__set_action_flags(n_data->post, pcmk__action_runnable);
        } else {
            pcmk__clear_action_flags(n_data->post, pcmk__action_runnable);
        }
        pcmk__insert_meta(n_data->post, "notify_type", "post");
        pcmk__insert_meta(n_data->post, "notify_operation", n_data->action);

        // Create "post-" notifications complete pseudo-action for clone
        n_data->post_done = new_notify_pseudo_action(rsc, complete,
                                                     PCMK_ACTION_NOTIFIED,
                                                     "confirmed-post");
        n_data->post_done->priority = PCMK_SCORE_INFINITY;
        if (pcmk__is_set(complete->flags, pcmk__action_runnable)) {
            pcmk__set_action_flags(n_data->post_done, pcmk__action_runnable);
        } else {
            pcmk__clear_action_flags(n_data->post_done, pcmk__action_runnable);
        }
        pcmk__insert_meta(n_data->post_done, "notify_type", "post");
        pcmk__insert_meta(n_data->post_done,
                          "notify_operation", n_data->action);

        /* Order original action complete -> "post-" -> "post-" complete
         *
         * @TODO Should we add |pcmk__ar_unrunnable_first_blocks to these?
         * Otherwise we might get an invalid transition due to unresolved
         * dependencies when "complete" is a fencing op (which can happen at
         * least for bundles) but that op is unrunnable (due to lack of quorum,
         * for example).
         */
        order_actions(complete, n_data->post, pcmk__ar_first_implies_then);
        order_actions(n_data->post, n_data->post_done,
                      pcmk__ar_first_implies_then);
    }

    // If we created both, order "pre-" complete -> "post-"
    if ((action != NULL) && (complete != NULL)) {
        order_actions(n_data->pre_done, n_data->post, pcmk__ar_ordered);
    }
    return n_data;
}

/*!
 * \internal
 * \brief Create a new notification entry
 *
 * \param[in] rsc   Resource for notification
 * \param[in] node  Node for notification
 *
 * \return Newly allocated notification entry
 * \note The caller is responsible for freeing the return value.
 */
static notify_entry_t *
new_notify_entry(const pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    notify_entry_t *entry = pcmk__assert_alloc(1, sizeof(notify_entry_t));

    entry->rsc = rsc;
    entry->node = node;
    return entry;
}

/*!
 * \internal
 * \brief Add notification data for resource state and optionally actions
 *
 * \param[in,out] rsc       Clone or clone instance being notified
 * \param[in]     activity  Whether to add notification entries for actions
 * \param[in,out] n_data    Notification data for clone
 */
static void
collect_resource_data(pcmk_resource_t *rsc, bool activity,
                      notify_data_t *n_data)
{
    const GList *iter = NULL;
    notify_entry_t *entry = NULL;
    const pcmk_node_t *node = NULL;

    if (n_data == NULL) {
        return;
    }

    if (n_data->allowed_nodes == NULL) {
        n_data->allowed_nodes = rsc->priv->allowed_nodes;
    }

    // If this is a clone, call recursively for each instance
    if (rsc->priv->children != NULL) {
        for (iter = rsc->priv->children; iter != NULL; iter = iter->next) {
            pcmk_resource_t *child = iter->data;

            collect_resource_data(child, activity, n_data);
        }
        return;
    }

    // This is a notification for a single clone instance

    if (rsc->priv->active_nodes != NULL) {
        node = rsc->priv->active_nodes->data; // First is sufficient
    }
    entry = new_notify_entry(rsc, node);

    // Add notification indicating the resource state
    switch (rsc->priv->orig_role) {
        case pcmk_role_stopped:
            n_data->inactive = g_list_prepend(n_data->inactive, entry);
            break;

        case pcmk_role_started:
            n_data->active = g_list_prepend(n_data->active, entry);
            break;

        case pcmk_role_unpromoted:
            n_data->unpromoted = g_list_prepend(n_data->unpromoted, entry);
            n_data->active = g_list_prepend(n_data->active,
                                            dup_notify_entry(entry));
            break;

        case pcmk_role_promoted:
            n_data->promoted = g_list_prepend(n_data->promoted, entry);
            n_data->active = g_list_prepend(n_data->active,
                                            dup_notify_entry(entry));
            break;

        default:
            pcmk__sched_err(rsc->priv->scheduler,
                            "Resource %s role on %s (%s) is not supported for "
                            "notifications (bug?)",
                            rsc->id, pcmk__node_name(node),
                            pcmk_role_text(rsc->priv->orig_role));
            free(entry);
            break;
    }

    if (!activity) {
        return;
    }

    // Add notification entries for each of the resource's actions
    for (iter = rsc->priv->actions; iter != NULL; iter = iter->next) {
        const pcmk_action_t *op = (const pcmk_action_t *) iter->data;

        if (!pcmk__is_set(op->flags, pcmk__action_optional)
            && (op->node != NULL)) {
            enum pcmk__action_type task = pcmk__parse_action(op->task);

            if ((task == pcmk__action_stop) && op->node->details->unclean) {
                // Create anyway (additional noise if node can't be fenced)
            } else if (!pcmk__is_set(op->flags, pcmk__action_runnable)) {
                continue;
            }

            entry = new_notify_entry(rsc, op->node);

            switch (task) {
                case pcmk__action_start:
                    n_data->start = g_list_prepend(n_data->start, entry);
                    break;
                case pcmk__action_stop:
                    n_data->stop = g_list_prepend(n_data->stop, entry);
                    break;
                case pcmk__action_promote:
                    n_data->promote = g_list_prepend(n_data->promote, entry);
                    break;
                case pcmk__action_demote:
                    n_data->demote = g_list_prepend(n_data->demote, entry);
                    break;
                default:
                    free(entry);
                    break;
            }
        }
    }
}

// For (char *) value
#define add_notify_env(n_data, key, value) do {                         \
         n_data->keys = pcmk_prepend_nvpair(n_data->keys, key, value);  \
    } while (0)

// For (GString *) value
#define add_notify_env_gs(n_data, key, value) do {                      \
         n_data->keys = pcmk_prepend_nvpair(n_data->keys, key,          \
                                            (const char *) value->str); \
    } while (0)

// For (GString *) value
#define add_notify_env_free_gs(n_data, key, value) do {                 \
         n_data->keys = pcmk_prepend_nvpair(n_data->keys, key,          \
                                            (const char *) value->str); \
         g_string_free(value, TRUE); value = NULL;                      \
    } while (0)

/*!
 * \internal
 * \brief Create notification name/value pairs from structured data
 *
 * \param[in]     rsc       Resource that notification is for
 * \param[in,out] n_data    Notification data
 */
static void
add_notif_keys(const pcmk_resource_t *rsc, notify_data_t *n_data)
{
    bool required = false; // Whether to make notify actions required
    GString *rsc_list = NULL;
    GString *node_list = NULL;
    GString *metal_list = NULL;
    const char *source = NULL;
    GList *nodes = NULL;

    n_data->stop = notify_entries_to_strings(n_data->stop,
                                             &rsc_list, &node_list);
    if ((strcmp(" ", (const char *) rsc_list->str) != 0)
        && pcmk__str_eq(n_data->action, PCMK_ACTION_STOP, pcmk__str_none)) {
        required = true;
    }
    add_notify_env_free_gs(n_data, "notify_stop_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_stop_uname", node_list);

    if ((n_data->start != NULL)
        && pcmk__str_eq(n_data->action, PCMK_ACTION_START, pcmk__str_none)) {
        required = true;
    }
    n_data->start = notify_entries_to_strings(n_data->start,
                                              &rsc_list, &node_list);
    add_notify_env_free_gs(n_data, "notify_start_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_start_uname", node_list);

    if ((n_data->demote != NULL)
        && pcmk__str_eq(n_data->action, PCMK_ACTION_DEMOTE, pcmk__str_none)) {
        required = true;
    }
    n_data->demote = notify_entries_to_strings(n_data->demote,
                                               &rsc_list, &node_list);
    add_notify_env_free_gs(n_data, "notify_demote_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_demote_uname", node_list);

    if ((n_data->promote != NULL)
        && pcmk__str_eq(n_data->action, PCMK_ACTION_PROMOTE, pcmk__str_none)) {
        required = true;
    }
    n_data->promote = notify_entries_to_strings(n_data->promote,
                                                &rsc_list, &node_list);
    add_notify_env_free_gs(n_data, "notify_promote_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_promote_uname", node_list);

    n_data->active = notify_entries_to_strings(n_data->active,
                                               &rsc_list, &node_list);
    add_notify_env_free_gs(n_data, "notify_active_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_active_uname", node_list);

    n_data->unpromoted = notify_entries_to_strings(n_data->unpromoted,
                                                   &rsc_list, &node_list);
    add_notify_env_gs(n_data, "notify_unpromoted_resource", rsc_list);
    add_notify_env_gs(n_data, "notify_unpromoted_uname", node_list);

    // Deprecated: kept for backward compatibility with older resource agents
    add_notify_env_free_gs(n_data, "notify_slave_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_slave_uname", node_list);

    n_data->promoted = notify_entries_to_strings(n_data->promoted,
                                                 &rsc_list, &node_list);
    add_notify_env_gs(n_data, "notify_promoted_resource", rsc_list);
    add_notify_env_gs(n_data, "notify_promoted_uname", node_list);

    // Deprecated: kept for backward compatibility with older resource agents
    add_notify_env_free_gs(n_data, "notify_master_resource", rsc_list);
    add_notify_env_free_gs(n_data, "notify_master_uname", node_list);

    n_data->inactive = notify_entries_to_strings(n_data->inactive,
                                                 &rsc_list, NULL);
    add_notify_env_free_gs(n_data, "notify_inactive_resource", rsc_list);

    nodes = g_hash_table_get_values(n_data->allowed_nodes);
    if (!pcmk__is_daemon) {
        /* For display purposes, sort the node list, for consistent
         * regression test output (while avoiding the performance hit
         * for the live cluster).
         */
        nodes = g_list_sort(nodes, pe__cmp_node_name);
    }
    get_node_names(nodes, &node_list, NULL);
    add_notify_env_free_gs(n_data, "notify_available_uname", node_list);
    g_list_free(nodes);

    source = g_hash_table_lookup(rsc->priv->meta,
                                 PCMK_META_CONTAINER_ATTRIBUTE_TARGET);
    if (pcmk__str_eq(PCMK_VALUE_HOST, source, pcmk__str_none)) {
        get_node_names(rsc->priv->scheduler->nodes, &node_list, &metal_list);
        add_notify_env_free_gs(n_data, "notify_all_hosts", metal_list);
    } else {
        get_node_names(rsc->priv->scheduler->nodes, &node_list, NULL);
    }
    add_notify_env_free_gs(n_data, "notify_all_uname", node_list);

    if (required && (n_data->pre != NULL)) {
        pcmk__clear_action_flags(n_data->pre, pcmk__action_optional);
        pcmk__clear_action_flags(n_data->pre_done, pcmk__action_optional);
    }

    if (required && (n_data->post != NULL)) {
        pcmk__clear_action_flags(n_data->post, pcmk__action_optional);
        pcmk__clear_action_flags(n_data->post_done, pcmk__action_optional);
    }
}

/*
 * \internal
 * \brief Find any remote connection start relevant to an action
 *
 * \param[in] action  Action to check
 *
 * \return If action is behind a remote connection, connection's start
 */
static pcmk_action_t *
find_remote_start(pcmk_action_t *action)
{
    if ((action != NULL) && (action->node != NULL)) {
        pcmk_resource_t *remote_rsc = action->node->priv->remote;

        if (remote_rsc != NULL) {
            return find_first_action(remote_rsc->priv->actions, NULL,
                                     PCMK_ACTION_START,
                                     NULL);
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Create notify actions, and add notify data to original actions
 *
 * \param[in,out] rsc     Clone or clone instance that notification is for
 * \param[in,out] n_data  Clone notification data for some action
 */
static void
create_notify_actions(pcmk_resource_t *rsc, notify_data_t *n_data)
{
    GList *iter = NULL;
    pcmk_action_t *stop = NULL;
    pcmk_action_t *start = NULL;
    enum pcmk__action_type task = pcmk__parse_action(n_data->action);

    // If this is a clone, call recursively for each instance
    if (rsc->priv->children != NULL) {
        g_list_foreach(rsc->priv->children, (GFunc) create_notify_actions,
                       n_data);
        return;
    }

    // Add notification meta-attributes to original actions
    for (iter = rsc->priv->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *op = (pcmk_action_t *) iter->data;

        if (!pcmk__is_set(op->flags, pcmk__action_optional)
            && (op->node != NULL)) {
            switch (pcmk__parse_action(op->task)) {
                case pcmk__action_start:
                case pcmk__action_stop:
                case pcmk__action_promote:
                case pcmk__action_demote:
                    add_notify_data_to_action_meta(n_data, op);
                    break;
                default:
                    break;
            }
        }
    }

    // Skip notify action itself if original action was not needed
    switch (task) {
        case pcmk__action_start:
            if (n_data->start == NULL) {
                pcmk__rsc_trace(rsc, "No notify action needed for %s %s",
                                rsc->id, n_data->action);
                return;
            }
            break;

        case pcmk__action_promote:
            if (n_data->promote == NULL) {
                pcmk__rsc_trace(rsc, "No notify action needed for %s %s",
                                rsc->id, n_data->action);
                return;
            }
            break;

        case pcmk__action_demote:
            if (n_data->demote == NULL) {
                pcmk__rsc_trace(rsc, "No notify action needed for %s %s",
                                rsc->id, n_data->action);
                return;
            }
            break;

        default:
            // We cannot do same for stop because it might be implied by fencing
            break;
    }

    pcmk__rsc_trace(rsc, "Creating notify actions for %s %s",
                    rsc->id, n_data->action);

    // Create notify actions for stop or demote
    if ((rsc->priv->orig_role != pcmk_role_stopped)
        && ((task == pcmk__action_stop) || (task == pcmk__action_demote))) {

        stop = find_first_action(rsc->priv->actions, NULL, PCMK_ACTION_STOP,
                                 NULL);

        for (iter = rsc->priv->active_nodes;
             iter != NULL; iter = iter->next) {

            pcmk_node_t *current_node = (pcmk_node_t *) iter->data;

            /* If a stop is a pseudo-action implied by fencing, don't try to
             * notify the node getting fenced.
             */
            if ((stop != NULL)
                && pcmk__is_set(stop->flags, pcmk__action_pseudo)
                && (current_node->details->unclean
                    || pcmk__is_set(current_node->priv->flags,
                                    pcmk__node_remote_reset))) {
                continue;
            }

            new_notify_action(rsc, current_node, n_data->pre,
                              n_data->pre_done, n_data);

            if ((task == pcmk__action_demote) || (stop == NULL)
                || pcmk__is_set(stop->flags, pcmk__action_optional)) {
                new_post_notify_action(rsc, current_node, n_data);
            }
        }
    }

    // Create notify actions for start or promote
    if ((rsc->priv->next_role != pcmk_role_stopped)
        && ((task == pcmk__action_start) || (task == pcmk__action_promote))) {

        start = find_first_action(rsc->priv->actions, NULL,
                                  PCMK_ACTION_START, NULL);
        if (start != NULL) {
            pcmk_action_t *remote_start = find_remote_start(start);

            if ((remote_start != NULL)
                && !pcmk__is_set(remote_start->flags, pcmk__action_runnable)) {
                /* Start and promote actions for a clone instance behind
                 * a Pacemaker Remote connection happen after the
                 * connection starts. If the connection start is blocked, do
                 * not schedule notifications for these actions.
                 */
                return;
            }
        }
        if (rsc->priv->assigned_node == NULL) {
            pcmk__sched_err(rsc->priv->scheduler,
                            "Next role '%s' but %s is not allocated",
                            pcmk_role_text(rsc->priv->next_role), rsc->id);
            return;
        }
        if ((task != pcmk__action_start) || (start == NULL)
            || pcmk__is_set(start->flags, pcmk__action_optional)) {

            new_notify_action(rsc, rsc->priv->assigned_node, n_data->pre,
                              n_data->pre_done, n_data);
        }
        new_post_notify_action(rsc, rsc->priv->assigned_node, n_data);
    }
}

/*!
 * \internal
 * \brief Create notification data and actions for one clone action
 *
 * \param[in,out] rsc     Clone resource that notification is for
 * \param[in,out] n_data  Clone notification data for some action
 */
void
pe__create_action_notifications(pcmk_resource_t *rsc, notify_data_t *n_data)
{
    if ((rsc == NULL) || (n_data == NULL)) {
        return;
    }
    collect_resource_data(rsc, true, n_data);
    add_notif_keys(rsc, n_data);
    create_notify_actions(rsc, n_data);
}

/*!
 * \internal
 * \brief Free notification data for one action
 *
 * \param[in,out] n_data  Notification data to free
 */
void
pe__free_action_notification_data(notify_data_t *n_data)
{
    if (n_data == NULL) {
        return;
    }
    g_list_free_full(n_data->stop, free);
    g_list_free_full(n_data->start, free);
    g_list_free_full(n_data->demote, free);
    g_list_free_full(n_data->promote, free);
    g_list_free_full(n_data->promoted, free);
    g_list_free_full(n_data->unpromoted, free);
    g_list_free_full(n_data->active, free);
    g_list_free_full(n_data->inactive, free);
    pcmk_free_nvpairs(n_data->keys);
    free(n_data);
}

/*!
 * \internal
 * \brief Order clone "notifications complete" pseudo-action after fencing
 *
 * If a stop action is implied by fencing, the usual notification pseudo-actions
 * will not be sufficient to order things properly, or even create all needed
 * notifications if the clone is also stopping on another node, and another
 * clone is ordered after it. This function creates new notification
 * pseudo-actions relative to the fencing to ensure everything works properly.
 *
 * \param[in]     stop     Stop action implied by fencing
 * \param[in,out] rsc      Clone resource that notification is for
 * \param[in,out] fencing  Fencing action that implies \p stop
 */
void
pe__order_notifs_after_fencing(const pcmk_action_t *stop, pcmk_resource_t *rsc,
                               pcmk_action_t *fencing)
{
    notify_data_t *n_data;

    pcmk__info("Ordering notifications for implied %s after fencing",
               stop->uuid);

    n_data = pe__action_notif_pseudo_ops(rsc, PCMK_ACTION_STOP, NULL, fencing);
    if (n_data != NULL) {
        collect_resource_data(rsc, false, n_data);
        add_notify_env(n_data, "notify_stop_resource", rsc->id);
        add_notify_env(n_data, "notify_stop_uname", stop->node->priv->name);
        create_notify_actions(uber_parent(rsc), n_data);
        pe__free_action_notification_data(n_data);
    }
}
