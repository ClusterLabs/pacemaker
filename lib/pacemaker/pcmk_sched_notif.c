/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

typedef struct notify_entry_s {
    pe_resource_t *rsc;
    pe_node_t *node;
} notify_entry_t;

/*!
 * \internal
 * \brief Compare two notification entries
 *
 * Compare two notification entries, where the one with the alphabetically first
 * resource name (or if equal, node name) sorts as first, with NULL sorting as
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

    // Finally, compare node names
    return strcmp(entry_a->node->details->id, entry_b->node->details->id);
}

static notify_entry_t *dup_notify_entry(notify_entry_t *entry)
{
    notify_entry_t *dup = malloc(sizeof(notify_entry_t));

    CRM_ASSERT(dup != NULL);
    dup->rsc = entry->rsc;
    dup->node = entry->node;
    return dup;
}

static void
expand_node_list(GList *list, char **uname, char **metal)
{
    GList *gIter = NULL;
    char *node_list = NULL;
    char *metal_list = NULL;
    size_t node_list_len = 0;
    size_t metal_list_len = 0;

    CRM_ASSERT(uname != NULL);
    if (list == NULL) {
        *uname = strdup(" ");
        if(metal) {
            *metal = strdup(" ");
        }
        return;
    }

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (node->details->uname == NULL) {
            continue;
        }
        pcmk__add_word(&node_list, &node_list_len, node->details->uname);
        if(metal) {
            if(node->details->remote_rsc
               && node->details->remote_rsc->container
               && node->details->remote_rsc->container->running_on) {
                node = pe__current_node(node->details->remote_rsc->container);
            }

            if (node->details->uname == NULL) {
                continue;
            }
            pcmk__add_word(&metal_list, &metal_list_len, node->details->uname);
        }
    }

    *uname = node_list;
    if(metal) {
        *metal = metal_list;
    }
}

/*!
 * \internal
 * \brief Separate a list of notification entries into resource and node strings
 *
 * \param[in,out] list       List of notify_entry_t* (will be sorted here)
 * \param[out]    rsc_list   String list of clone instances from \p list
 * \param[out]    node_list  String list of nodes from \p list
 *
 * \return (Possibly new head of) sorted \p list
 */
static GList *
expand_list(GList *list, char **rsc_list, char **node_list)
{
    const char *last_rsc_id = NULL;
    size_t rsc_list_len = 0;
    size_t node_list_len = 0;

    CRM_CHECK(rsc_list != NULL, return list);

    // If there are no entries, return "empty" lists
    if (list == NULL) {
        *rsc_list = strdup(" ");
        if (node_list) {
            *node_list = strdup(" ");
        }
        return list;
    }

    // Initialize output lists to NULL
    *rsc_list = NULL;
    if (node_list) {
        *node_list = NULL;
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
        CRM_LOG_ASSERT((node_list == NULL) || (entry->node != NULL));
        if ((node_list != NULL) && (entry->node == NULL)) {
            continue;
        }

        // Don't add duplicates of a particular clone instance
        if (pcmk__str_eq(entry->rsc->id, last_rsc_id, pcmk__str_none)) {
            continue;
        }
        last_rsc_id = entry->rsc->id;
        pcmk__add_word(rsc_list, &rsc_list_len, entry->rsc->id);
        if ((node_list != NULL) && (entry->node->details->uname != NULL)) {
            pcmk__add_word(node_list, &node_list_len,
                           entry->node->details->uname);
        }
    }
    return list;
}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    add_hash_param(user_data, key, value);
}

static void
add_notify_data_to_action_meta(notify_data_t *n_data, pe_action_t *action)
{
    for (GSList *item = n_data->keys; item; item = item->next) {
        pcmk_nvpair_t *nvpair = item->data;

        add_hash_param(action->meta, nvpair->name, nvpair->value);
    }
}

static pe_action_t *
pe_notify(pe_resource_t * rsc, pe_node_t * node, pe_action_t * op, pe_action_t * confirm,
          notify_data_t * n_data, pe_working_set_t * data_set)
{
    char *key = NULL;
    pe_action_t *trigger = NULL;
    const char *value = NULL;
    const char *task = NULL;

    if (op == NULL || confirm == NULL) {
        pe_rsc_trace(rsc, "Op=%p confirm=%p", op, confirm);
        return NULL;
    }

    CRM_CHECK(rsc != NULL, return NULL);
    CRM_CHECK(node != NULL, return NULL);

    if (node->details->online == FALSE) {
        pe_rsc_trace(rsc, "Skipping notification for %s: node offline", rsc->id);
        return NULL;
    } else if (!pcmk_is_set(op->flags, pe_action_runnable)) {
        pe_rsc_trace(rsc, "Skipping notification for %s: not runnable", op->uuid);
        return NULL;
    }

    value = g_hash_table_lookup(op->meta, "notify_type");
    task = g_hash_table_lookup(op->meta, "notify_operation");

    pe_rsc_trace(rsc, "Creating notify actions for %s: %s (%s-%s)", op->uuid, rsc->id, value, task);

    key = pcmk__notify_key(rsc->id, value, task);
    trigger = custom_action(rsc, key, op->task, node,
                            pcmk_is_set(op->flags, pe_action_optional),
                            TRUE, data_set);
    g_hash_table_foreach(op->meta, dup_attr, trigger->meta);
    add_notify_data_to_action_meta(n_data, trigger);

    /* pseudo_notify before notify */
    pe_rsc_trace(rsc, "Ordering %s before %s (%d->%d)", op->uuid, trigger->uuid, trigger->id,
                 op->id);

    order_actions(op, trigger, pe_order_optional);
    order_actions(trigger, confirm, pe_order_optional);
    return trigger;
}

static void
pe_post_notify(pe_resource_t * rsc, pe_node_t * node, notify_data_t * n_data, pe_working_set_t * data_set)
{
    pe_action_t *notify = NULL;

    CRM_CHECK(rsc != NULL, return);

    if (n_data->post == NULL) {
        return;                 /* Nothing to do */
    }

    notify = pe_notify(rsc, node, n_data->post, n_data->post_done, n_data, data_set);

    if (notify != NULL) {
        notify->priority = INFINITY;
    }

    if (n_data->post_done) {
        GList *gIter = rsc->actions;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_action_t *mon = (pe_action_t *) gIter->data;
            const char *interval_ms_s = g_hash_table_lookup(mon->meta,
                                                            XML_LRM_ATTR_INTERVAL_MS);

            if (pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches | pcmk__str_casei)) {
                pe_rsc_trace(rsc, "Skipping %s: interval", mon->uuid);
                continue;
            } else if (pcmk__str_eq(mon->task, RSC_CANCEL, pcmk__str_casei)) {
                pe_rsc_trace(rsc, "Skipping %s: cancel", mon->uuid);
                continue;
            }

            order_actions(n_data->post_done, mon, pe_order_optional);
        }
    }
}

notify_data_t *
create_notification_boundaries(pe_resource_t * rsc, const char *action, pe_action_t * start,
                               pe_action_t * end, pe_working_set_t * data_set)
{
    /* Create the pseudo ops that precede and follow the actual notifications */

    /*
     * Creates two sequences (conditional on start and end being supplied):
     *   pre_notify -> pre_notify_complete -> start, and
     *   end -> post_notify -> post_notify_complete
     *
     * 'start' and 'end' may be the same event or ${X} and ${X}ed as per clones
     */
    char *key = NULL;
    notify_data_t *n_data = NULL;

    if (!pcmk_is_set(rsc->flags, pe_rsc_notify)) {
        return NULL;
    }

    n_data = calloc(1, sizeof(notify_data_t));
    n_data->action = action;

    if (start) {
        /* create pre-event notification wrappers */
        key = pcmk__notify_key(rsc->id, "pre", start->task);
        n_data->pre =
            custom_action(rsc, key, RSC_NOTIFY, NULL,
                          pcmk_is_set(start->flags, pe_action_optional),
                          TRUE, data_set);
        pe__set_action_flags(n_data->pre, pe_action_pseudo|pe_action_runnable);

        add_hash_param(n_data->pre->meta, "notify_type", "pre");
        add_hash_param(n_data->pre->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->pre->meta, "notify_key_type", "pre");
        add_hash_param(n_data->pre->meta, "notify_key_operation", start->task);

        /* create pre_notify_complete */
        key = pcmk__notify_key(rsc->id, "confirmed-pre", start->task);
        n_data->pre_done = custom_action(rsc, key, RSC_NOTIFIED, NULL,
                                         pcmk_is_set(start->flags, pe_action_optional),
                                         TRUE, data_set);
        pe__set_action_flags(n_data->pre_done,
                             pe_action_pseudo|pe_action_runnable);

        add_hash_param(n_data->pre_done->meta, "notify_type", "pre");
        add_hash_param(n_data->pre_done->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->pre_done->meta, "notify_key_type", "confirmed-pre");
        add_hash_param(n_data->pre_done->meta, "notify_key_operation", start->task);

        order_actions(n_data->pre_done, start, pe_order_optional);
        order_actions(n_data->pre, n_data->pre_done, pe_order_optional);
    }

    if (end) {
        /* create post-event notification wrappers */
        key = pcmk__notify_key(rsc->id, "post", end->task);
        n_data->post = custom_action(rsc, key, RSC_NOTIFY, NULL,
                                     pcmk_is_set(end->flags, pe_action_optional),
                                     TRUE, data_set);

        n_data->post->priority = INFINITY;
        pe__set_action_flags(n_data->post, pe_action_pseudo);
        if (pcmk_is_set(end->flags, pe_action_runnable)) {
            pe__set_action_flags(n_data->post, pe_action_runnable);
        } else {
            pe__clear_action_flags(n_data->post, pe_action_runnable);
        }

        add_hash_param(n_data->post->meta, "notify_type", "post");
        add_hash_param(n_data->post->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->post->meta, "notify_key_type", "post");
        add_hash_param(n_data->post->meta, "notify_key_operation", end->task);

        /* create post_notify_complete */
        key = pcmk__notify_key(rsc->id, "confirmed-post", end->task);
        n_data->post_done = custom_action(rsc, key, RSC_NOTIFIED, NULL,
                                          pcmk_is_set(end->flags, pe_action_optional),
                                          TRUE, data_set);

        n_data->post_done->priority = INFINITY;
        pe__set_action_flags(n_data->post_done, pe_action_pseudo);
        if (pcmk_is_set(end->flags, pe_action_runnable)) {
            pe__set_action_flags(n_data->post_done, pe_action_runnable);
        } else {
            pe__clear_action_flags(n_data->post_done, pe_action_runnable);
        }

        add_hash_param(n_data->post_done->meta, "notify_type", "post");
        add_hash_param(n_data->post_done->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->post_done->meta, "notify_key_type", "confirmed-post");
        add_hash_param(n_data->post_done->meta, "notify_key_operation", end->task);

        order_actions(end, n_data->post, pe_order_implies_then);
        order_actions(n_data->post, n_data->post_done, pe_order_implies_then);
    }

    if (start && end) {
        order_actions(n_data->pre_done, n_data->post, pe_order_optional);
    }
    return n_data;
}

void
collect_notification_data(pe_resource_t * rsc, gboolean state, gboolean activity,
                          notify_data_t * n_data)
{

    if(n_data->allowed_nodes == NULL) {
        n_data->allowed_nodes = rsc->allowed_nodes;
    }

    if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            collect_notification_data(child, state, activity, n_data);
        }
        return;
    }

    if (state) {
        notify_entry_t *entry = NULL;

        entry = calloc(1, sizeof(notify_entry_t));
        entry->rsc = rsc;
        if (rsc->running_on) {
            /* we only take the first one */
            entry->node = rsc->running_on->data;
        }

        pe_rsc_trace(rsc, "%s state: %s", rsc->id, role2text(rsc->role));

        switch (rsc->role) {
            case RSC_ROLE_STOPPED:
                n_data->inactive = g_list_prepend(n_data->inactive, entry);
                break;
            case RSC_ROLE_STARTED:
                n_data->active = g_list_prepend(n_data->active, entry);
                break;
            case RSC_ROLE_UNPROMOTED:
                n_data->unpromoted = g_list_prepend(n_data->unpromoted, entry);
                n_data->active = g_list_prepend(n_data->active,
                                                dup_notify_entry(entry));
                break;
            case RSC_ROLE_PROMOTED:
                n_data->promoted = g_list_prepend(n_data->promoted, entry);
                n_data->active = g_list_prepend(n_data->active,
                                                dup_notify_entry(entry));
                break;
            default:
                crm_err("Unsupported notify role");
                free(entry);
                break;
        }
    }

    if (activity) {
        notify_entry_t *entry = NULL;
        enum action_tasks task;

        GList *gIter = rsc->actions;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_action_t *op = (pe_action_t *) gIter->data;

            if (!pcmk_is_set(op->flags, pe_action_optional)
                && (op->node != NULL)) {

                task = text2task(op->task);

                if(task == stop_rsc && op->node->details->unclean) {
                    // Create anyway (additional noise if node can't be fenced)
                } else if (!pcmk_is_set(op->flags, pe_action_runnable)) {
                    continue;
                }

                entry = calloc(1, sizeof(notify_entry_t));
                entry->node = op->node;
                entry->rsc = rsc;

                switch (task) {
                    case start_rsc:
                        n_data->start = g_list_prepend(n_data->start, entry);
                        break;
                    case stop_rsc:
                        n_data->stop = g_list_prepend(n_data->stop, entry);
                        break;
                    case action_promote:
                        n_data->promote = g_list_prepend(n_data->promote, entry);
                        break;
                    case action_demote:
                        n_data->demote = g_list_prepend(n_data->demote, entry);
                        break;
                    default:
                        free(entry);
                        break;
                }
            }
        }
    }
}

#define add_notify_env(n_data, key, value) do {                         \
         n_data->keys = pcmk_prepend_nvpair(n_data->keys, key, value);  \
    } while (0)

#define add_notify_env_free(n_data, key, value) do {                    \
         n_data->keys = pcmk_prepend_nvpair(n_data->keys, key, value);  \
         free(value); value = NULL;                                     \
    } while (0)

/*!
 * \internal
 * \brief Create notification name/value pairs from raw data
 *
 * \param[in]     rsc       Resource that notification is for
 * \param[in,out] n_data    Notification data
 * \param[in]     data_set  Cluster working set
 */
void
pcmk__create_notification_keys(pe_resource_t *rsc,
                               notify_data_t *n_data,
                               pe_working_set_t *data_set)
{
    bool required = false; // Whether to make notify actions required
    char *rsc_list = NULL;
    char *node_list = NULL;
    char *metal_list = NULL;
    const char *source = NULL;
    GList *nodes = NULL;

    n_data->stop = expand_list(n_data->stop, &rsc_list, &node_list);
    if (!pcmk__str_eq(" ", rsc_list, pcmk__str_null_matches)
        && pcmk__str_eq(n_data->action, RSC_STOP, pcmk__str_casei)) {
        required = true;
    }
    add_notify_env_free(n_data, "notify_stop_resource", rsc_list);
    add_notify_env_free(n_data, "notify_stop_uname", node_list);

    if ((n_data->start != NULL)
        && pcmk__str_eq(n_data->action, RSC_START, pcmk__str_casei)) {
        required = true;
    }
    n_data->start = expand_list(n_data->start, &rsc_list, &node_list);
    add_notify_env_free(n_data, "notify_start_resource", rsc_list);
    add_notify_env_free(n_data, "notify_start_uname", node_list);

    if ((n_data->demote != NULL)
        && pcmk__str_eq(n_data->action, RSC_DEMOTE, pcmk__str_casei)) {
        required = true;
    }
    n_data->demote = expand_list(n_data->demote, &rsc_list, &node_list);
    add_notify_env_free(n_data, "notify_demote_resource", rsc_list);
    add_notify_env_free(n_data, "notify_demote_uname", node_list);

    if ((n_data->promote != NULL)
        && pcmk__str_eq(n_data->action, RSC_PROMOTE, pcmk__str_casei)) {
        required = true;
    }
    n_data->promote = expand_list(n_data->promote, &rsc_list, &node_list);
    add_notify_env_free(n_data, "notify_promote_resource", rsc_list);
    add_notify_env_free(n_data, "notify_promote_uname", node_list);

    n_data->active = expand_list(n_data->active, &rsc_list, &node_list);
    add_notify_env_free(n_data, "notify_active_resource", rsc_list);
    add_notify_env_free(n_data, "notify_active_uname", node_list);

    n_data->unpromoted = expand_list(n_data->unpromoted, &rsc_list, &node_list);
    add_notify_env(n_data, "notify_unpromoted_resource", rsc_list);
    add_notify_env(n_data, "notify_unpromoted_uname", node_list);

    // Deprecated: kept for backward compatibility with older resource agents
    add_notify_env_free(n_data, "notify_slave_resource", rsc_list);
    add_notify_env_free(n_data, "notify_slave_uname", node_list);

    n_data->promoted = expand_list(n_data->promoted, &rsc_list, &node_list);
    add_notify_env(n_data, "notify_promoted_resource", rsc_list);
    add_notify_env(n_data, "notify_promoted_uname", node_list);

    // Deprecated: kept for backward compatibility with older resource agents
    add_notify_env_free(n_data, "notify_master_resource", rsc_list);
    add_notify_env_free(n_data, "notify_master_uname", node_list);

    n_data->inactive = expand_list(n_data->inactive, &rsc_list, NULL);
    add_notify_env_free(n_data, "notify_inactive_resource", rsc_list);

    nodes = g_hash_table_get_values(n_data->allowed_nodes);
    if (!pcmk__is_daemon) {
        /* If printing to stdout, sort the node list, for consistent
         * regression test output (while avoiding the performance hit
         * for the live cluster).
         */
        nodes = g_list_sort(nodes, sort_node_uname);
    }
    expand_node_list(nodes, &node_list, NULL);
    add_notify_env_free(n_data, "notify_available_uname", node_list);
    g_list_free(nodes);

    source = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET);
    if (pcmk__str_eq("host", source, pcmk__str_casei)) {
        expand_node_list(data_set->nodes, &node_list, &metal_list);
        add_notify_env_free(n_data, "notify_all_hosts", metal_list);
    } else {
        expand_node_list(data_set->nodes, &node_list, NULL);
    }
    add_notify_env_free(n_data, "notify_all_uname", node_list);

    if (required && n_data->pre) {
        pe__clear_action_flags(n_data->pre, pe_action_optional);
        pe__clear_action_flags(n_data->pre_done, pe_action_optional);
    }

    if (required && n_data->post) {
        pe__clear_action_flags(n_data->post, pe_action_optional);
        pe__clear_action_flags(n_data->post_done, pe_action_optional);
    }
}

/*
 * \internal
 * \brief Find any remote connection start relevant to an action
 *
 * \param[in] action  Action to chek
 *
 * \return If action is behind a remote connection, connection's start
 */
static pe_action_t *
find_remote_start(pe_action_t *action)
{
    if (action && action->node) {
        pe_resource_t *remote_rsc = action->node->details->remote_rsc;

        if (remote_rsc) {
            return find_first_action(remote_rsc->actions, NULL, RSC_START,
                                     NULL);
        }
    }
    return NULL;
}

void
create_notifications(pe_resource_t * rsc, notify_data_t * n_data, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    pe_action_t *stop = NULL;
    pe_action_t *start = NULL;
    enum action_tasks task = text2task(n_data->action);

    if (rsc->children) {
        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            create_notifications(child, n_data, data_set);
        }
        return;
    }

    /* Copy notification details into standard ops */

    for (gIter = rsc->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *op = (pe_action_t *) gIter->data;

        if (!pcmk_is_set(op->flags, pe_action_optional)
            && (op->node != NULL)) {

            enum action_tasks t = text2task(op->task);

            switch (t) {
                case start_rsc:
                case stop_rsc:
                case action_promote:
                case action_demote:
                    add_notify_data_to_action_meta(n_data, op);
                    break;
                default:
                    break;
            }
        }
    }

    switch (task) {
        case start_rsc:
            if (n_data->start == NULL) {
                pe_rsc_trace(rsc, "Skipping empty notification for: %s.%s (%s->%s)",
                             n_data->action, rsc->id, role2text(rsc->role), role2text(rsc->next_role));
                return;
            }
            break;
        case action_promote:
            if (n_data->promote == NULL) {
                pe_rsc_trace(rsc, "Skipping empty notification for: %s.%s (%s->%s)",
                             n_data->action, rsc->id, role2text(rsc->role), role2text(rsc->next_role));
                return;
            }
            break;
        case action_demote:
            if (n_data->demote == NULL) {
                pe_rsc_trace(rsc, "Skipping empty notification for: %s.%s (%s->%s)",
                             n_data->action, rsc->id, role2text(rsc->role), role2text(rsc->next_role));
                return;
            }
            break;
        default:
            /* We cannot do the same for stop_rsc/n_data->stop at it
             * might be implied by fencing
             */
            break;
    }

    pe_rsc_trace(rsc, "Creating notifications for: %s.%s (%s->%s)",
                 n_data->action, rsc->id, role2text(rsc->role), role2text(rsc->next_role));

    stop = find_first_action(rsc->actions, NULL, RSC_STOP, NULL);
    start = find_first_action(rsc->actions, NULL, RSC_START, NULL);

    /* stop / demote */
    if (rsc->role != RSC_ROLE_STOPPED) {
        if (task == stop_rsc || task == action_demote) {
            gIter = rsc->running_on;
            for (; gIter != NULL; gIter = gIter->next) {
                pe_node_t *current_node = (pe_node_t *) gIter->data;

                /* if this stop action is a pseudo action as a result of the current
                 * node being fenced, this stop action is implied by the fencing 
                 * action. There's no reason to send the fenced node a stop notification */ 
                if (stop && pcmk_is_set(stop->flags, pe_action_pseudo) &&
                    (current_node->details->unclean || current_node->details->remote_requires_reset) ) {

                    continue;
                }

                pe_notify(rsc, current_node, n_data->pre, n_data->pre_done, n_data, data_set);
                if (task == action_demote || stop == NULL
                    || pcmk_is_set(stop->flags, pe_action_optional)) {
                    pe_post_notify(rsc, current_node, n_data, data_set);
                }
            }
        }
    }

    /* start / promote */
    if (rsc->next_role != RSC_ROLE_STOPPED) {
        if (rsc->allocated_to == NULL) {
            pe_proc_err("Next role '%s' but %s is not allocated", role2text(rsc->next_role),
                        rsc->id);

        } else if (task == start_rsc || task == action_promote) {

            if (start) {
                pe_action_t *remote_start = find_remote_start(start);

                if (remote_start
                    && !pcmk_is_set(remote_start->flags, pe_action_runnable)) {
                    /* Start and promote actions for a clone instance behind
                     * a Pacemaker Remote connection happen after the
                     * connection starts. If the connection start is blocked, do
                     * not schedule notifications for these actions.
                     */
                    return;
                }
            }
            if ((task != start_rsc) || (start == NULL)
                || pcmk_is_set(start->flags, pe_action_optional)) {

                pe_notify(rsc, rsc->allocated_to, n_data->pre, n_data->pre_done, n_data, data_set);
            }
            pe_post_notify(rsc, rsc->allocated_to, n_data, data_set);
        }
    }
}

void
free_notification_data(notify_data_t * n_data)
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

void
create_secondary_notification(pe_action_t *action, pe_resource_t *rsc,
                              pe_action_t *stonith_op,
                              pe_working_set_t *data_set)
{
    notify_data_t *n_data;

    crm_info("Creating secondary notification for %s", action->uuid);
    n_data = create_notification_boundaries(rsc, RSC_STOP, NULL, stonith_op,
                                            data_set);
    collect_notification_data(rsc, TRUE, FALSE, n_data);
    add_notify_env(n_data, "notify_stop_resource", rsc->id);
    add_notify_env(n_data, "notify_stop_uname", action->node->details->uname);
    create_notifications(uber_parent(rsc), n_data, data_set);
    free_notification_data(n_data);
}
