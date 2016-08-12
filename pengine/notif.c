/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <allocate.h>
#include <notif.h>
#include <utils.h>

typedef struct notify_entry_s {
    resource_t *rsc;
    node_t *node;
} notify_entry_t;

static gint
sort_notify_entries(gconstpointer a, gconstpointer b)
{
    int tmp;
    const notify_entry_t *entry_a = a;
    const notify_entry_t *entry_b = b;

    if (entry_a == NULL && entry_b == NULL) {
        return 0;
    }
    if (entry_a == NULL) {
        return 1;
    }
    if (entry_b == NULL) {
        return -1;
    }

    if (entry_a->rsc == NULL && entry_b->rsc == NULL) {
        return 0;
    }
    if (entry_a->rsc == NULL) {
        return 1;
    }
    if (entry_b->rsc == NULL) {
        return -1;
    }

    tmp = strcmp(entry_a->rsc->id, entry_b->rsc->id);
    if (tmp != 0) {
        return tmp;
    }

    if (entry_a->node == NULL && entry_b->node == NULL) {
        return 0;
    }
    if (entry_a->node == NULL) {
        return 1;
    }
    if (entry_b->node == NULL) {
        return -1;
    }

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

static char *
expand_node_list(GListPtr list)
{
    GListPtr gIter = NULL;
    char *node_list = NULL;

    if (list == NULL) {
        return strdup(" ");
    }

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        if (node->details->uname) {
            int existing_len = 0;
            int len = 2 + strlen(node->details->uname);

            if(node_list) {
                existing_len = strlen(node_list);
            }
            crm_trace("Adding %s (%dc) at offset %d", node->details->uname, len - 2, existing_len);
            node_list = realloc_safe(node_list, len + existing_len);
            sprintf(node_list + existing_len, "%s%s", existing_len == 0 ? "":" ", node->details->uname);
        }
    }

    return node_list;
}

static void
expand_list(GListPtr list, char **rsc_list, char **node_list)
{
    GListPtr gIter = NULL;
    const char *uname = NULL;
    const char *rsc_id = NULL;
    const char *last_rsc_id = NULL;

    if (rsc_list) {
        *rsc_list = NULL;
    }

    if (list == NULL) {
        if (rsc_list) {
            *rsc_list = strdup(" ");
        }
        if (node_list) {
            *node_list = strdup(" ");
        }
        return;
    }

    if (node_list) {
        *node_list = NULL;
    }

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        notify_entry_t *entry = (notify_entry_t *) gIter->data;

        CRM_LOG_ASSERT(entry != NULL);
        CRM_LOG_ASSERT(entry && entry->rsc != NULL);

        if(entry == NULL || entry->rsc == NULL) {
            continue;
        }

        /* Uh, why? */
        CRM_LOG_ASSERT(node_list == NULL || entry->node != NULL);
        if(node_list != NULL && entry->node == NULL) {
            continue;
        }

        uname = NULL;
        rsc_id = entry->rsc->id;
        CRM_ASSERT(rsc_id != NULL);

        /* filter dups */
        if (safe_str_eq(rsc_id, last_rsc_id)) {
            continue;
        }
        last_rsc_id = rsc_id;

        if (rsc_list != NULL) {
            int existing_len = 0;
            int len = 2 + strlen(rsc_id);       /* +1 space, +1 EOS */

            if (rsc_list && *rsc_list) {
                existing_len = strlen(*rsc_list);
            }

            crm_trace("Adding %s (%dc) at offset %d", rsc_id, len - 2, existing_len);
            *rsc_list = realloc_safe(*rsc_list, len + existing_len);
            sprintf(*rsc_list + existing_len, "%s%s", existing_len == 0 ? "":" ", rsc_id);
        }

        if (entry->node != NULL) {
            uname = entry->node->details->uname;
        }

        if (node_list != NULL && uname) {
            int existing_len = 0;
            int len = 2 + strlen(uname);

            if (node_list && *node_list) {
                existing_len = strlen(*node_list);
            }

            crm_trace("Adding %s (%dc) at offset %d", uname, len - 2, existing_len);
            *node_list = realloc_safe(*node_list, len + existing_len);
            sprintf(*node_list + existing_len, "%s%s", existing_len == 0 ? "":" ", uname);
        }
    }

}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    add_hash_param(user_data, key, value);
}

static action_t *
pe_notify(resource_t * rsc, node_t * node, action_t * op, action_t * confirm,
          notify_data_t * n_data, pe_working_set_t * data_set)
{
    char *key = NULL;
    action_t *trigger = NULL;
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
    } else if (is_set(op->flags, pe_action_runnable) == FALSE) {
        pe_rsc_trace(rsc, "Skipping notification for %s: not runnable", op->uuid);
        return NULL;
    }

    value = g_hash_table_lookup(op->meta, "notify_type");
    task = g_hash_table_lookup(op->meta, "notify_operation");

    pe_rsc_trace(rsc, "Creating notify actions for %s: %s (%s-%s)", op->uuid, rsc->id, value, task);

    key = generate_notify_key(rsc->id, value, task);
    trigger = custom_action(rsc, key, op->task, node,
                            is_set(op->flags, pe_action_optional), TRUE, data_set);
    g_hash_table_foreach(op->meta, dup_attr, trigger->meta);
    g_hash_table_foreach(n_data->keys, dup_attr, trigger->meta);

    /* pseudo_notify before notify */
    pe_rsc_trace(rsc, "Ordering %s before %s (%d->%d)", op->uuid, trigger->uuid, trigger->id,
                 op->id);

    order_actions(op, trigger, pe_order_optional);
    order_actions(trigger, confirm, pe_order_optional);
    return trigger;
}

static void
pe_post_notify(resource_t * rsc, node_t * node, notify_data_t * n_data, pe_working_set_t * data_set)
{
    action_t *notify = NULL;

    CRM_CHECK(rsc != NULL, return);

    if (n_data->post == NULL) {
        return;                 /* Nothing to do */
    }

    notify = pe_notify(rsc, node, n_data->post, n_data->post_done, n_data, data_set);

    if (notify != NULL) {
        notify->priority = INFINITY;
    }

    if (n_data->post_done) {
        GListPtr gIter = rsc->actions;

        for (; gIter != NULL; gIter = gIter->next) {
            action_t *mon = (action_t *) gIter->data;
            const char *interval = g_hash_table_lookup(mon->meta, "interval");

            if (interval == NULL || safe_str_eq(interval, "0")) {
                pe_rsc_trace(rsc, "Skipping %s: interval", mon->uuid);
                continue;
            } else if (safe_str_eq(mon->task, RSC_CANCEL)) {
                pe_rsc_trace(rsc, "Skipping %s: cancel", mon->uuid);
                continue;
            }

            order_actions(n_data->post_done, mon, pe_order_optional);
        }
    }
}

notify_data_t *
create_notification_boundaries(resource_t * rsc, const char *action, action_t * start,
                               action_t * end, pe_working_set_t * data_set)
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

    if (is_not_set(rsc->flags, pe_rsc_notify)) {
        return NULL;
    }

    n_data = calloc(1, sizeof(notify_data_t));
    n_data->action = action;
    n_data->keys =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    if (start) {
        /* create pre-event notification wrappers */
        key = generate_notify_key(rsc->id, "pre", start->task);
        n_data->pre =
            custom_action(rsc, key, RSC_NOTIFY, NULL, is_set(start->flags, pe_action_optional),
                          TRUE, data_set);

        update_action_flags(n_data->pre, pe_action_pseudo, __FUNCTION__);
        update_action_flags(n_data->pre, pe_action_runnable, __FUNCTION__);

        add_hash_param(n_data->pre->meta, "notify_type", "pre");
        add_hash_param(n_data->pre->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->pre->meta, "notify_key_type", "pre");
        add_hash_param(n_data->pre->meta, "notify_key_operation", start->task);

        /* create pre_notify_complete */
        key = generate_notify_key(rsc->id, "confirmed-pre", start->task);
        n_data->pre_done =
            custom_action(rsc, key, RSC_NOTIFIED, NULL, is_set(start->flags, pe_action_optional),
                          TRUE, data_set);

        update_action_flags(n_data->pre_done, pe_action_pseudo, __FUNCTION__);
        update_action_flags(n_data->pre_done, pe_action_runnable, __FUNCTION__);

        add_hash_param(n_data->pre_done->meta, "notify_type", "pre");
        add_hash_param(n_data->pre_done->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->pre_done->meta, "notify_key_type", "confirmed-pre");
        add_hash_param(n_data->pre_done->meta, "notify_key_operation", start->task);

        order_actions(n_data->pre_done, start, pe_order_optional);
        order_actions(n_data->pre, n_data->pre_done, pe_order_optional);
    }

    if (end) {
        /* create post-event notification wrappers */
        key = generate_notify_key(rsc->id, "post", end->task);
        n_data->post =
            custom_action(rsc, key, RSC_NOTIFY, NULL, is_set(end->flags, pe_action_optional), TRUE,
                          data_set);

        n_data->post->priority = INFINITY;
        update_action_flags(n_data->post, pe_action_pseudo, __FUNCTION__);
        if (is_set(end->flags, pe_action_runnable)) {
            update_action_flags(n_data->post, pe_action_runnable, __FUNCTION__);
        } else {
            update_action_flags(n_data->post, pe_action_runnable | pe_action_clear, __FUNCTION__);
        }

        add_hash_param(n_data->post->meta, "notify_type", "post");
        add_hash_param(n_data->post->meta, "notify_operation", n_data->action);

        add_hash_param(n_data->post->meta, "notify_key_type", "post");
        add_hash_param(n_data->post->meta, "notify_key_operation", end->task);

        /* create post_notify_complete */
        key = generate_notify_key(rsc->id, "confirmed-post", end->task);
        n_data->post_done =
            custom_action(rsc, key, RSC_NOTIFIED, NULL, is_set(end->flags, pe_action_optional),
                          TRUE, data_set);

        n_data->post_done->priority = INFINITY;
        update_action_flags(n_data->post_done, pe_action_pseudo, __FUNCTION__);
        if (is_set(end->flags, pe_action_runnable)) {
            update_action_flags(n_data->post_done, pe_action_runnable, __FUNCTION__);
        } else {
            update_action_flags(n_data->post_done, pe_action_runnable | pe_action_clear, __FUNCTION__);
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

    if (safe_str_eq(action, RSC_STOP)) {
        action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);

        order_actions(n_data->post_done, all_stopped, pe_order_optional);
    }

    return n_data;
}

void
collect_notification_data(resource_t * rsc, gboolean state, gboolean activity,
                          notify_data_t * n_data)
{

    if(n_data->allowed_nodes == NULL) {
        n_data->allowed_nodes = rsc->allowed_nodes;
    }

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

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
            case RSC_ROLE_SLAVE:
                n_data->slave = g_list_prepend(n_data->slave, entry);
                n_data->active = g_list_prepend(n_data->active,
                                                dup_notify_entry(entry));
                break;
            case RSC_ROLE_MASTER:
                n_data->master = g_list_prepend(n_data->master, entry);
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

        GListPtr gIter = rsc->actions;

        for (; gIter != NULL; gIter = gIter->next) {
            action_t *op = (action_t *) gIter->data;

            if (is_set(op->flags, pe_action_optional) == FALSE && op->node != NULL) {

                entry = calloc(1, sizeof(notify_entry_t));
                entry->node = op->node;
                entry->rsc = rsc;

                task = text2task(op->task);
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

gboolean
expand_notification_data(notify_data_t * n_data, pe_working_set_t * data_set)
{
    /* Expand the notification entries into a key=value hashtable
     * This hashtable is later used in action2xml()
     */
    gboolean required = FALSE;
    char *rsc_list = NULL;
    char *node_list = NULL;
    GListPtr nodes = NULL;

    if (n_data->stop) {
        n_data->stop = g_list_sort(n_data->stop, sort_notify_entries);
    }
    expand_list(n_data->stop, &rsc_list, &node_list);
    if (rsc_list != NULL && safe_str_neq(" ", rsc_list)) {
        if (safe_str_eq(n_data->action, RSC_STOP)) {
            required = TRUE;
        }
    }
    g_hash_table_insert(n_data->keys, strdup("notify_stop_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_stop_uname"), node_list);

    if (n_data->start) {
        n_data->start = g_list_sort(n_data->start, sort_notify_entries);
        if (rsc_list && safe_str_eq(n_data->action, RSC_START)) {
            required = TRUE;
        }
    }
    expand_list(n_data->start, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, strdup("notify_start_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_start_uname"), node_list);

    if (n_data->demote) {
        n_data->demote = g_list_sort(n_data->demote, sort_notify_entries);
        if (safe_str_eq(n_data->action, RSC_DEMOTE)) {
            required = TRUE;
        }
    }

    expand_list(n_data->demote, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, strdup("notify_demote_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_demote_uname"), node_list);

    if (n_data->promote) {
        n_data->promote = g_list_sort(n_data->promote, sort_notify_entries);
        if (safe_str_eq(n_data->action, RSC_PROMOTE)) {
            required = TRUE;
        }
    }
    expand_list(n_data->promote, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, strdup("notify_promote_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_promote_uname"), node_list);

    if (n_data->active) {
        n_data->active = g_list_sort(n_data->active, sort_notify_entries);
    }
    expand_list(n_data->active, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, strdup("notify_active_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_active_uname"), node_list);

    if (n_data->slave) {
        n_data->slave = g_list_sort(n_data->slave, sort_notify_entries);
    }
    expand_list(n_data->slave, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, strdup("notify_slave_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_slave_uname"), node_list);

    if (n_data->master) {
        n_data->master = g_list_sort(n_data->master, sort_notify_entries);
    }
    expand_list(n_data->master, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, strdup("notify_master_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, strdup("notify_master_uname"), node_list);

    if (n_data->inactive) {
        n_data->inactive = g_list_sort(n_data->inactive, sort_notify_entries);
    }
    expand_list(n_data->inactive, &rsc_list, NULL);
    g_hash_table_insert(n_data->keys, strdup("notify_inactive_resource"), rsc_list);

    nodes = g_hash_table_get_values(n_data->allowed_nodes);
    node_list = expand_node_list(nodes);
    g_hash_table_insert(n_data->keys, strdup("notify_available_uname"), node_list);
    g_list_free(nodes);

    node_list = expand_node_list(data_set->nodes);
    g_hash_table_insert(n_data->keys, strdup("notify_all_uname"), node_list);

    if (required && n_data->pre) {
        update_action_flags(n_data->pre, pe_action_optional | pe_action_clear, __FUNCTION__);
        update_action_flags(n_data->pre_done, pe_action_optional | pe_action_clear, __FUNCTION__);
    }

    if (required && n_data->post) {
        update_action_flags(n_data->post, pe_action_optional | pe_action_clear, __FUNCTION__);
        update_action_flags(n_data->post_done, pe_action_optional | pe_action_clear, __FUNCTION__);
    }
    return required;
}

void
create_notifications(resource_t * rsc, notify_data_t * n_data, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    action_t *stop = NULL;
    action_t *start = NULL;
    enum action_tasks task = text2task(n_data->action);

    if (rsc->children) {
        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            create_notifications(child, n_data, data_set);
        }
        return;
    }

    /* Copy notification details into standard ops */

    gIter = rsc->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *op = (action_t *) gIter->data;

        if (is_set(op->flags, pe_action_optional) == FALSE && op->node != NULL) {
            enum action_tasks t = text2task(op->task);

            switch (t) {
                case start_rsc:
                case stop_rsc:
                case action_promote:
                case action_demote:
                    g_hash_table_foreach(n_data->keys, dup_attr, op->meta);
                    break;
                default:
                    break;
            }
        }
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
                node_t *current_node = (node_t *) gIter->data;

                /* if this stop action is a pseudo action as a result of the current
                 * node being fenced, this stop action is implied by the fencing 
                 * action. There's no reason to send the fenced node a stop notification */ 
                if (stop &&
                    is_set(stop->flags, pe_action_pseudo) &&
                    current_node->details->unclean) {

                    continue;
                }

                pe_notify(rsc, current_node, n_data->pre, n_data->pre_done, n_data, data_set);
                if (task == action_demote || stop == NULL
                    || is_set(stop->flags, pe_action_optional)) {
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
            if (task != start_rsc || start == NULL || is_set(start->flags, pe_action_optional)) {
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
    g_list_free_full(n_data->master, free);
    g_list_free_full(n_data->slave, free);
    g_list_free_full(n_data->active, free);
    g_list_free_full(n_data->inactive, free);
    g_hash_table_destroy(n_data->keys);
    free(n_data);
}

void
create_secondary_notification(pe_action_t *action, resource_t *rsc,
                              pe_action_t *stonith_op,
                              pe_working_set_t *data_set)
{
    notify_data_t *n_data;

    crm_info("Creating secondary notification for %s", action->uuid);
    n_data = create_notification_boundaries(rsc, RSC_STOP, NULL, stonith_op,
                                            data_set);
    collect_notification_data(rsc, TRUE, FALSE, n_data);
    g_hash_table_insert(n_data->keys, strdup("notify_stop_resource"),
                        strdup(rsc->id));
    g_hash_table_insert(n_data->keys, strdup("notify_stop_uname"),
                        strdup(action->node->details->uname));
    create_notifications(uber_parent(rsc), n_data, data_set);
    free_notification_data(n_data);
}
