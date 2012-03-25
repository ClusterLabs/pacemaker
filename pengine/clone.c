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

#include <crm/msg_xml.h>
#include <allocate.h>
#include <utils.h>
#include <lib/pengine/utils.h>

#define VARIANT_CLONE 1
#include <lib/pengine/variant.h>

gint sort_clone_instance(gconstpointer a, gconstpointer b, gpointer data_set);
static void append_parent_colocation(resource_t * rsc, resource_t * child, gboolean all);

static node_t *
parent_node_instance(const resource_t * rsc, node_t * node)
{
    node_t *ret = NULL;

    if (node != NULL) {
        ret = pe_hash_table_lookup(rsc->parent->allowed_nodes, node->details->id);
    }
    return ret;
}

static gboolean
did_fail(const resource_t * rsc)
{
    GListPtr gIter = rsc->children;

    if (is_set(rsc->flags, pe_rsc_failed)) {
        return TRUE;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        if (did_fail(child_rsc)) {
            return TRUE;
        }
    }
    return FALSE;
}

gint
sort_clone_instance(gconstpointer a, gconstpointer b, gpointer data_set)
{
    int rc = 0;
    node_t *node1 = NULL;
    node_t *node2 = NULL;

    gboolean can1 = TRUE;
    gboolean can2 = TRUE;

    const resource_t *resource1 = (const resource_t *)a;
    const resource_t *resource2 = (const resource_t *)b;

    CRM_ASSERT(resource1 != NULL);
    CRM_ASSERT(resource2 != NULL);

    /* allocation order:
     *  - active instances
     *  - instances running on nodes with the least copies
     *  - active instances on nodes that cant support them or are to be fenced
     *  - failed instances
     *  - inactive instances
     */

    if (resource1->running_on && resource2->running_on) {
        if (g_list_length(resource1->running_on) < g_list_length(resource2->running_on)) {
            crm_trace( "%s < %s: running_on", resource1->id, resource2->id);
            return -1;

        } else if (g_list_length(resource1->running_on) > g_list_length(resource2->running_on)) {
            crm_trace( "%s > %s: running_on", resource1->id, resource2->id);
            return 1;
        }
    }

    if (resource1->running_on) {
        node1 = resource1->running_on->data;
    }
    if (resource2->running_on) {
        node2 = resource2->running_on->data;
    }

    if (node1) {
        node_t *match = pe_hash_table_lookup(resource1->allowed_nodes, node1->details->id);

        if (match == NULL || match->weight < 0) {
            crm_trace( "%s: current location is unavailable", resource1->id);
            node1 = NULL;
            can1 = FALSE;
        }
    }

    if (node2) {
        node_t *match = pe_hash_table_lookup(resource2->allowed_nodes, node2->details->id);

        if (match == NULL || match->weight < 0) {
            crm_trace( "%s: current location is unavailable", resource2->id);
            node2 = NULL;
            can2 = FALSE;
        }
    }

    if (can1 != can2) {
        if (can1) {
            crm_trace( "%s < %s: availability of current location", resource1->id,
                                resource2->id);
            return -1;
        }
        crm_trace( "%s > %s: availability of current location", resource1->id,
                            resource2->id);
        return 1;
    }

    if (resource1->priority < resource2->priority) {
        crm_trace( "%s < %s: priority", resource1->id, resource2->id);
        return 1;

    } else if (resource1->priority > resource2->priority) {
        crm_trace( "%s > %s: priority", resource1->id, resource2->id);
        return -1;
    }

    if (node1 == NULL && node2 == NULL) {
        crm_trace( "%s == %s: not active", resource1->id, resource2->id);
        return 0;
    }

    if (node1 != node2) {
        if (node1 == NULL) {
            crm_trace( "%s > %s: active", resource1->id, resource2->id);
            return 1;
        } else if (node2 == NULL) {
            crm_trace( "%s < %s: active", resource1->id, resource2->id);
            return -1;
        }
    }

    can1 = can_run_resources(node1);
    can2 = can_run_resources(node2);
    if (can1 != can2) {
        if (can1) {
            crm_trace( "%s < %s: can", resource1->id, resource2->id);
            return -1;
        }
        crm_trace( "%s > %s: can", resource1->id, resource2->id);
        return 1;
    }

    node1 = parent_node_instance(resource1, node1);
    node2 = parent_node_instance(resource2, node2);
    if (node1 != NULL && node2 == NULL) {
        crm_trace( "%s < %s: not allowed", resource1->id, resource2->id);
        return -1;
    } else if (node1 == NULL && node2 != NULL) {
        crm_trace( "%s > %s: not allowed", resource1->id, resource2->id);
        return 1;
    }

    if (node1 == NULL || node2 == NULL) {
        crm_trace( "%s == %s: not allowed", resource1->id, resource2->id);
        return 0;
    }

    if (node1->count < node2->count) {
        crm_trace( "%s < %s: count", resource1->id, resource2->id);
        return -1;

    } else if (node1->count > node2->count) {
        crm_trace( "%s > %s: count", resource1->id, resource2->id);
        return 1;
    }

    can1 = did_fail(resource1);
    can2 = did_fail(resource2);
    if (can1 != can2) {
        if (can1) {
            crm_trace( "%s > %s: failed", resource1->id, resource2->id);
            return 1;
        }
        crm_trace( "%s < %s: failed", resource1->id, resource2->id);
        return -1;
    }

    if (node1 && node2) {
        int lpc = 0;
        int max = 0;
        node_t *n = NULL;
        GListPtr gIter = NULL;
        GListPtr list1 = NULL;
        GListPtr list2 = NULL;
        GHashTable *hash1 =
            g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, g_hash_destroy_str);
        GHashTable *hash2 =
            g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, g_hash_destroy_str);

        n = node_copy(resource1->running_on->data);
        g_hash_table_insert(hash1, (gpointer) n->details->id, n);

        n = node_copy(resource2->running_on->data);
        g_hash_table_insert(hash2, (gpointer) n->details->id, n);

        for (gIter = resource1->parent->rsc_cons; gIter; gIter = gIter->next) {
            rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

            crm_trace( "Applying %s to %s", constraint->id, resource1->id);

            hash1 = native_merge_weights(constraint->rsc_rh, resource1->id, hash1,
                                         constraint->node_attribute,
                                         constraint->score / INFINITY, FALSE, FALSE);
        }

        for (gIter = resource1->parent->rsc_cons_lhs; gIter; gIter = gIter->next) {
            rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

            crm_trace( "Applying %s to %s", constraint->id, resource1->id);

            hash1 = native_merge_weights(constraint->rsc_lh, resource1->id, hash1,
                                         constraint->node_attribute,
                                         constraint->score / INFINITY, FALSE, TRUE);
        }

        for (gIter = resource2->parent->rsc_cons; gIter; gIter = gIter->next) {
            rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

            crm_trace( "Applying %s to %s", constraint->id, resource2->id);

            hash2 = native_merge_weights(constraint->rsc_rh, resource2->id, hash2,
                                         constraint->node_attribute,
                                         constraint->score / INFINITY, FALSE, FALSE);
        }

        for (gIter = resource2->parent->rsc_cons_lhs; gIter; gIter = gIter->next) {
            rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

            crm_trace( "Applying %s to %s", constraint->id, resource2->id);

            hash2 = native_merge_weights(constraint->rsc_lh, resource2->id, hash2,
                                         constraint->node_attribute,
                                         constraint->score / INFINITY, FALSE, TRUE);
        }

        /* Current location score */
        node1 = g_list_nth_data(resource1->running_on, 0);
        node1 = g_hash_table_lookup(hash1, node1->details->id);

        node2 = g_list_nth_data(resource2->running_on, 0);
        node2 = g_hash_table_lookup(hash2, node2->details->id);

        if (node1->weight < node2->weight) {
            if (node1->weight < 0) {
                crm_trace( "%s > %s: current score", resource1->id, resource2->id);
                rc = -1;
                goto out;

            } else {
                crm_trace( "%s < %s: current score", resource1->id, resource2->id);
                rc = 1;
                goto out;
            }

        } else if (node1->weight > node2->weight) {
            crm_trace( "%s > %s: current score", resource1->id, resource2->id);
            rc = -1;
            goto out;
        }

        /* All location scores */
        list1 = g_hash_table_get_values(hash1);
        list2 = g_hash_table_get_values(hash2);

        list1 =
            g_list_sort_with_data(list1, sort_node_weight,
                                  g_list_nth_data(resource1->running_on, 0));
        list2 =
            g_list_sort_with_data(list2, sort_node_weight,
                                  g_list_nth_data(resource2->running_on, 0));
        max = g_list_length(list1);
        if (max < g_list_length(list2)) {
            max = g_list_length(list2);
        }

        for (; lpc < max; lpc++) {
            node1 = g_list_nth_data(list1, lpc);
            node2 = g_list_nth_data(list2, lpc);
            if (node1 == NULL) {
                crm_trace( "%s < %s: colocated score NULL", resource1->id,
                                    resource2->id);
                rc = 1;
                break;

            } else if (node2 == NULL) {
                crm_trace( "%s > %s: colocated score NULL", resource1->id,
                                    resource2->id);
                rc = -1;
                break;
            }

            if (node1->weight < node2->weight) {
                crm_trace( "%s < %s: colocated score", resource1->id,
                                    resource2->id);
                rc = 1;
                break;

            } else if (node1->weight > node2->weight) {
                crm_trace( "%s > %s: colocated score", resource1->id,
                                    resource2->id);
                rc = -1;
                break;
            }
        }

        /* Order by reverse uname - same as sort_node_weight() does? */
  out:
        g_hash_table_destroy(hash1);    /* Free mem */
        g_hash_table_destroy(hash2);    /* Free mem */
        g_list_free(list1);
        g_list_free(list2);

        if (rc != 0) {
            return rc;
        }
    }

    rc = strcmp(resource1->id, resource2->id);
    crm_trace( "%s %c %s: default", resource1->id, rc < 0 ? '<' : '>',
                        resource2->id);
    return rc;
}

static node_t *
can_run_instance(resource_t * rsc, node_t * node)
{
    node_t *local_node = NULL;
    clone_variant_data_t *clone_data = NULL;

    if (can_run_resources(node) == FALSE) {
        goto bail;

    } else if (is_set(rsc->flags, pe_rsc_orphan)) {
        goto bail;
    }

    local_node = parent_node_instance(rsc, node);
    get_clone_variant_data(clone_data, rsc->parent);

    if (local_node == NULL) {
        crm_warn("%s cannot run on %s: node not allowed", rsc->id, node->details->uname);
        goto bail;

    } else if (local_node->count < clone_data->clone_node_max) {
        crm_trace("%s can run on %s: %d", rsc->id, node->details->uname, local_node->count);
        return local_node;

    } else {
        crm_trace("%s cannot run on %s: node full (%d >= %d)",
                    rsc->id, node->details->uname, local_node->count, clone_data->clone_node_max);
    }

  bail:
    if (node) {
        common_update_score(rsc, node->details->id, -INFINITY);
    }
    return NULL;
}

static node_t *
color_instance(resource_t * rsc, node_t * prefer, gboolean all_coloc, pe_working_set_t * data_set)
{
    node_t *chosen = NULL;
    node_t *local_node = NULL;

    crm_trace("Processing %s", rsc->id);

    if (is_not_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->fns->location(rsc, NULL, FALSE);

    } else if (is_set(rsc->flags, pe_rsc_allocating)) {
        crm_debug("Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    /* Only include positive colocation preferences of dependant resources
     * if not every node will get a copy of the clone
     */
    append_parent_colocation(rsc->parent, rsc, all_coloc);

    if (prefer) {
        node_t *local_prefer = g_hash_table_lookup(rsc->allowed_nodes, prefer->details->id);

        if (local_prefer == NULL || local_prefer->weight < 0) {
            crm_trace("Not pre-allocating %s to %s - unavailable", rsc->id, prefer->details->uname);
            return NULL;
        }
    }

    if (rsc->allowed_nodes) {
        GHashTableIter iter;
        node_t *try_node = NULL;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&try_node)) {
            can_run_instance(rsc, try_node);
        }
    }

    chosen = rsc->cmds->allocate(rsc, prefer, data_set);
    if (chosen) {
        local_node = pe_hash_table_lookup(rsc->parent->allowed_nodes, chosen->details->id);

        if (prefer && chosen && chosen->details != prefer->details) {
            crm_err("Pre-allocation failed: got %s instead of %s",
                    chosen->details->uname, prefer->details->uname);
            native_deallocate(rsc);
            chosen = NULL;

        } else if (local_node) {
            local_node->count++;

        } else if (is_set(rsc->flags, pe_rsc_managed)) {
            /* what to do? we can't enforce per-node limits in this case */
            crm_config_err("%s not found in %s (list=%d)",
                           chosen->details->id, rsc->parent->id,
                           g_hash_table_size(rsc->parent->allowed_nodes));
        }
    }

    return chosen;
}

static void
append_parent_colocation(resource_t * rsc, resource_t * child, gboolean all)
{

    GListPtr gIter = NULL;

    gIter = rsc->rsc_cons;
    for (; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) gIter->data;

        if (all || cons->score < 0 || cons->score == INFINITY) {
            child->rsc_cons = g_list_prepend(child->rsc_cons, cons);
        }
    }

    gIter = rsc->rsc_cons_lhs;
    for (; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *cons = (rsc_colocation_t *) gIter->data;

        if (all || cons->score < 0) {
            child->rsc_cons_lhs = g_list_prepend(child->rsc_cons_lhs, cons);
        }
    }
}

node_t *
clone_color(resource_t * rsc, node_t * prefer, pe_working_set_t * data_set)
{
    int allocated = 0;
    GHashTableIter iter;
    GListPtr gIter = NULL;
    node_t *node = NULL;
    int available_nodes = 0;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    if (is_not_set(rsc->flags, pe_rsc_provisional)) {
        return NULL;

    } else if (is_set(rsc->flags, pe_rsc_allocating)) {
        crm_debug("Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    set_bit(rsc->flags, pe_rsc_allocating);
    crm_trace("Processing %s", rsc->id);

    /* this information is used by sort_clone_instance() when deciding in which 
     * order to allocate clone instances
     */
    gIter = rsc->rsc_cons;
    for (; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

        crm_trace("%s: Coloring %s first", rsc->id, constraint->rsc_rh->id);
        constraint->rsc_rh->cmds->allocate(constraint->rsc_rh, prefer, data_set);
    }

    gIter = rsc->rsc_cons_lhs;
    for (; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

        rsc->allowed_nodes =
            constraint->rsc_lh->cmds->merge_weights(constraint->rsc_lh, rsc->id, rsc->allowed_nodes,
                                                    constraint->node_attribute,
                                                    constraint->score / INFINITY, TRUE, TRUE);
    }

    gIter = rsc->rsc_tickets;
    for (; gIter != NULL; gIter = gIter->next) {
        rsc_ticket_t *rsc_ticket = (rsc_ticket_t *) gIter->data;

        if (rsc_ticket->ticket->granted == FALSE || rsc_ticket->ticket->standby) {
            rsc_ticket_constraint(rsc, rsc_ticket, data_set);
        }
    }

    dump_node_scores(show_scores ? 0 : scores_log_level, rsc, __FUNCTION__, rsc->allowed_nodes);

    /* count now tracks the number of clones currently allocated */
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        node->count = 0;
        if (can_run_resources(node)) {
            available_nodes++;
        }
    }

    rsc->children = g_list_sort_with_data(rsc->children, sort_clone_instance, data_set);

    /* Pre-allocate as many instances as we can to their current location
     */
    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (available_nodes
           && available_nodes <= clone_data->clone_max
           && g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        int lpc;
        int loop_max = clone_data->clone_max / available_nodes;

        if (loop_max < 1) {
            loop_max = 1;
        }

        if (can_run_resources(node) == FALSE || node->weight < 0) {
            crm_trace("Not Pre-allocatiing %s", node->details->uname);
            continue;
        }

        crm_trace("Pre-allocatiing %s", node->details->uname);
        for (lpc = 0;
             allocated < clone_data->clone_max
             && node->count < clone_data->clone_node_max
             && lpc < clone_data->clone_node_max && lpc < loop_max; lpc++) {
            for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
                resource_t *child = (resource_t *) gIter->data;

                if (child->running_on && is_set(child->flags, pe_rsc_provisional)
                    && is_not_set(child->flags, pe_rsc_failed)) {
                    node_t *child_node = child->running_on->data;

                    if (child_node->details == node->details
                        && color_instance(child, node, clone_data->clone_max < available_nodes,
                                          data_set)) {
                        crm_trace("Pre-allocated %s to %s", child->id, node->details->uname);
                        allocated++;
                        break;
                    }
                }
            }
        }
    }

    crm_trace("Done pre-allocating");

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;

        if (g_list_length(child->running_on) > 0) {
            node_t *child_node = child->running_on->data;
            node_t *local_node = parent_node_instance(child, child->running_on->data);

            if (local_node == NULL) {
                crm_err("%s is running on %s which isn't allowed",
                        child->id, child_node->details->uname);
            }
        }

        if (is_not_set(child->flags, pe_rsc_provisional)) {
        } else if (allocated >= clone_data->clone_max) {
            crm_debug("Child %s not allocated - limit reached", child->id);
            resource_location(child, NULL, -INFINITY, "clone_color:limit_reached", data_set);

        } else if (color_instance(child, NULL, clone_data->clone_max < available_nodes, data_set)) {
            allocated++;
        }
    }

    crm_debug("Allocated %d %s instances of a possible %d",
              allocated, rsc->id, clone_data->clone_max);

    clear_bit(rsc->flags, pe_rsc_provisional);
    clear_bit(rsc->flags, pe_rsc_allocating);

    crm_trace("Done allocating %s", rsc->id);
    return NULL;
}

static void
clone_update_pseudo_status(resource_t * rsc, gboolean * stopping, gboolean * starting,
                           gboolean * active)
{
    GListPtr gIter = NULL;

    if (rsc->children) {

        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            clone_update_pseudo_status(child, stopping, starting, active);
        }

        return;
    }

    CRM_ASSERT(active != NULL);
    CRM_ASSERT(starting != NULL);
    CRM_ASSERT(stopping != NULL);

    if (rsc->running_on) {
        *active = TRUE;
    }

    gIter = rsc->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (*starting && *stopping) {
            return;

        } else if (is_set(action->flags, pe_action_optional)) {
            crm_trace("Skipping optional: %s", action->uuid);
            continue;

        } else if (is_set(action->flags, pe_action_pseudo) == FALSE
                   && is_set(action->flags, pe_action_runnable) == FALSE) {
            crm_trace("Skipping unrunnable: %s", action->uuid);
            continue;

        } else if (safe_str_eq(RSC_STOP, action->task)) {
            crm_trace("Stopping due to: %s", action->uuid);
            *stopping = TRUE;

        } else if (safe_str_eq(RSC_START, action->task)) {
            if (is_set(action->flags, pe_action_runnable) == FALSE) {
                crm_trace("Skipping pseudo-op: %s run=%d, pseudo=%d",
                            action->uuid, is_set(action->flags, pe_action_runnable),
                            is_set(action->flags, pe_action_pseudo));
            } else {
                crm_trace("Starting due to: %s", action->uuid);
                crm_trace("%s run=%d, pseudo=%d",
                            action->uuid, is_set(action->flags, pe_action_runnable),
                            is_set(action->flags, pe_action_pseudo));
                *starting = TRUE;
            }
        }
    }
}

static action_t *
find_rsc_action(resource_t * rsc, const char *key, gboolean active_only, GListPtr * list)
{
    action_t *match = NULL;
    GListPtr possible = NULL;
    GListPtr active = NULL;

    possible = find_actions(rsc->actions, key, NULL);

    if (active_only) {
        GListPtr gIter = possible;

        for (; gIter != NULL; gIter = gIter->next) {
            action_t *op = (action_t *) gIter->data;

            if (is_set(op->flags, pe_action_optional) == FALSE) {
                active = g_list_prepend(active, op);
            }
        }

        if (active && g_list_length(active) == 1) {
            match = g_list_nth_data(active, 0);
        }

        if (list) {
            *list = active;
            active = NULL;
        }

    } else if (possible && g_list_length(possible) == 1) {
        match = g_list_nth_data(possible, 0);

    }
    if (list) {
        *list = possible;
        possible = NULL;
    }

    if (possible) {
        g_list_free(possible);
    }
    if (active) {
        g_list_free(active);
    }

    return match;
}

static void
child_ordering_constraints(resource_t * rsc, pe_working_set_t * data_set)
{
    char *key = NULL;
    action_t *stop = NULL;
    action_t *start = NULL;
    action_t *last_stop = NULL;
    action_t *last_start = NULL;
    GListPtr gIter = rsc->children;
    gboolean active_only = TRUE;        /* change to false to get the old behavior */
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    if (clone_data->ordered == FALSE) {
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;

        key = stop_key(child);
        stop = find_rsc_action(child, key, active_only, NULL);
        crm_free(key);

        key = start_key(child);
        start = find_rsc_action(child, key, active_only, NULL);
        crm_free(key);

        if (stop) {
            if (last_stop) {
                /* child/child relative stop */
                order_actions(stop, last_stop, pe_order_optional);
            }
            last_stop = stop;
        }

        if (start) {
            if (last_start) {
                /* child/child relative start */
                order_actions(last_start, start, pe_order_optional);
            }
            last_start = start;
        }
    }
}

void
clone_create_actions(resource_t * rsc, pe_working_set_t * data_set)
{
    gboolean child_active = FALSE;
    gboolean child_starting = FALSE;
    gboolean child_stopping = FALSE;

    action_t *stop = NULL;
    action_t *stopped = NULL;

    action_t *start = NULL;
    action_t *started = NULL;

    GListPtr gIter = rsc->children;
    resource_t *last_start_rsc = NULL;
    resource_t *last_stop_rsc = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    crm_trace("Creating actions for %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->create_actions(child_rsc, data_set);
        clone_update_pseudo_status(child_rsc, &child_stopping, &child_starting, &child_active);

        if (is_set(child_rsc->flags, pe_rsc_starting)) {
            last_start_rsc = child_rsc;
        }
        if (is_set(child_rsc->flags, pe_rsc_stopping)) {
            last_stop_rsc = child_rsc;
        }
    }

    /* start */
    start = start_action(rsc, NULL, !child_starting);
    started = custom_action(rsc, started_key(rsc),
                            RSC_STARTED, NULL, !child_starting, TRUE, data_set);

    update_action_flags(start, pe_action_pseudo | pe_action_runnable);
    update_action_flags(started, pe_action_pseudo);
    started->priority = INFINITY;

    if (child_active || child_starting) {
        update_action_flags(started, pe_action_runnable);
    }

    child_ordering_constraints(rsc, data_set);
    if (clone_data->start_notify == NULL) {
        clone_data->start_notify =
            create_notification_boundaries(rsc, RSC_START, start, started, data_set);
    }

    /* stop */
    stop = stop_action(rsc, NULL, !child_stopping);
    stopped = custom_action(rsc, stopped_key(rsc),
                            RSC_STOPPED, NULL, !child_stopping, TRUE, data_set);

    stopped->priority = INFINITY;
    update_action_flags(stop, pe_action_pseudo | pe_action_runnable);
    update_action_flags(stopped, pe_action_pseudo | pe_action_runnable);
    if (clone_data->stop_notify == NULL) {
        clone_data->stop_notify =
            create_notification_boundaries(rsc, RSC_STOP, stop, stopped, data_set);

        if (clone_data->stop_notify && clone_data->start_notify) {
            order_actions(clone_data->stop_notify->post_done, clone_data->start_notify->pre,
                          pe_order_optional);
        }
    }
}

void
clone_internal_constraints(resource_t * rsc, pe_working_set_t * data_set)
{
    resource_t *last_rsc = NULL;
    GListPtr gIter = rsc->children;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    crm_trace("Internal constraints for %s", rsc->id);
    new_rsc_order(rsc, RSC_STOPPED, rsc, RSC_START, pe_order_optional, data_set);
    new_rsc_order(rsc, RSC_START, rsc, RSC_STARTED, pe_order_runnable_left, data_set);
    new_rsc_order(rsc, RSC_STOP, rsc, RSC_STOPPED, pe_order_runnable_left, data_set);

    if (rsc->variant == pe_master) {
        new_rsc_order(rsc, RSC_DEMOTED, rsc, RSC_STOP, pe_order_optional, data_set);
        new_rsc_order(rsc, RSC_STARTED, rsc, RSC_PROMOTE, pe_order_runnable_left, data_set);
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->internal_constraints(child_rsc, data_set);

        order_start_start(rsc, child_rsc, pe_order_runnable_left | pe_order_implies_first_printed);
        new_rsc_order(child_rsc, RSC_START, rsc, RSC_STARTED, pe_order_implies_then_printed,
                      data_set);
        if (clone_data->ordered && last_rsc) {
            order_start_start(last_rsc, child_rsc, pe_order_optional);
        }

        order_stop_stop(rsc, child_rsc, pe_order_implies_first_printed);
        new_rsc_order(child_rsc, RSC_STOP, rsc, RSC_STOPPED, pe_order_implies_then_printed,
                      data_set);
        if (clone_data->ordered && last_rsc) {
            order_stop_stop(child_rsc, last_rsc, pe_order_optional);
        }

        last_rsc = child_rsc;
    }
}

static void
assign_node(resource_t * rsc, node_t * node, gboolean force)
{
    if (rsc->children) {

        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            native_assign_node(child_rsc, NULL, node, force);
        }

        return;
    }
    native_assign_node(rsc, NULL, node, force);
}

static resource_t *
find_compatible_child_by_node(resource_t * local_child, node_t * local_node, resource_t * rsc,
                              enum rsc_role_e filter, gboolean current)
{
    node_t *node = NULL;
    GListPtr gIter = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    if (local_node == NULL) {
        crm_err("Can't colocate unrunnable child %s with %s", local_child->id, rsc->id);
        return NULL;
    }

    crm_trace("Looking for compatible child from %s for %s on %s",
              local_child->id, rsc->id, local_node->details->uname);

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;
        enum rsc_role_e next_role = child_rsc->fns->state(child_rsc, current);

        node = child_rsc->fns->location(child_rsc, NULL, current);

        if (filter != RSC_ROLE_UNKNOWN && next_role != filter) {
            crm_trace("Filtered %s", child_rsc->id);
            continue;
        }

        if (node && local_node && node->details == local_node->details) {
            crm_trace("Pairing %s with %s on %s",
                        local_child->id, child_rsc->id, node->details->uname);
            return child_rsc;

        } else if (node) {
            crm_trace("%s - %s vs %s", child_rsc->id, node->details->uname,
                      local_node->details->uname);

        } else {
            crm_trace("%s - not allocated %d", child_rsc->id, current);
        }
    }

    crm_trace("Can't pair %s with %s", local_child->id, rsc->id);
    return NULL;
}

resource_t *
find_compatible_child(resource_t * local_child, resource_t * rsc, enum rsc_role_e filter,
                      gboolean current)
{
    resource_t *pair = NULL;
    GListPtr gIter = NULL;
    GListPtr scratch = NULL;
    node_t *local_node = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    local_node = local_child->fns->location(local_child, NULL, current);
    if (local_node) {
        return find_compatible_child_by_node(local_child, local_node, rsc, filter, current);
    }

    scratch = g_hash_table_get_values(local_child->allowed_nodes);
    scratch = g_list_sort_with_data(scratch, sort_node_weight, NULL);

    gIter = scratch;
    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        pair = find_compatible_child_by_node(local_child, node, rsc, filter, current);
        if (pair) {
            goto done;
        }
    }

    crm_debug("Can't pair %s with %s", local_child->id, rsc->id);
  done:
    g_list_free(scratch);
    return pair;
}

void
clone_rsc_colocation_lh(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    /* -- Never called --
     *
     * Instead we add the colocation constraints to the child and call from there
     */

    GListPtr gIter = rsc_lh->children;

    CRM_CHECK(FALSE, crm_err("This functionality is not thought to be used. Please report a bug."));
    CRM_CHECK(rsc_lh, return);
    CRM_CHECK(rsc_rh, return);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_lh(child_rsc, rsc_rh, constraint);
    }

    return;
}

void
clone_rsc_colocation_rh(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    GListPtr gIter = NULL;
    gboolean do_interleave = FALSE;
    clone_variant_data_t *clone_data = NULL;
    clone_variant_data_t *clone_data_lh = NULL;

    CRM_CHECK(constraint != NULL, return);
    CRM_CHECK(rsc_lh != NULL, pe_err("rsc_lh was NULL for %s", constraint->id); return);
    CRM_CHECK(rsc_rh != NULL, pe_err("rsc_rh was NULL for %s", constraint->id); return);
    CRM_CHECK(rsc_lh->variant == pe_native, return);

    get_clone_variant_data(clone_data, constraint->rsc_rh);
    crm_trace("Processing constraint %s: %s -> %s %d",
                constraint->id, rsc_lh->id, rsc_rh->id, constraint->score);

    if (constraint->rsc_lh->variant >= pe_clone) {

        get_clone_variant_data(clone_data_lh, constraint->rsc_lh);
        if (clone_data_lh->interleave && clone_data->clone_node_max != clone_data_lh->clone_node_max) {
            crm_config_err("Cannot interleave " XML_CIB_TAG_INCARNATION
                           " %s and %s because"
                           " they do not support the same number of"
                           " resources per node", constraint->rsc_lh->id, constraint->rsc_rh->id);

            /* only the LHS side needs to be labeled as interleave */
        } else if (clone_data_lh->interleave) {
            do_interleave = TRUE;
        }
    }

    if (is_set(rsc_rh->flags, pe_rsc_provisional)) {
        crm_trace("%s is still provisional", rsc_rh->id);
        return;

    } else if (do_interleave) {
        resource_t *rh_child = NULL;

        rh_child = find_compatible_child(rsc_lh, rsc_rh, RSC_ROLE_UNKNOWN, FALSE);

        if (rh_child) {
            crm_debug("Pairing %s with %s", rsc_lh->id, rh_child->id);
            rsc_lh->cmds->rsc_colocation_lh(rsc_lh, rh_child, constraint);

        } else if (constraint->score >= INFINITY) {
            crm_notice("Cannot pair %s with instance of %s", rsc_lh->id, rsc_rh->id);
            assign_node(rsc_lh, NULL, TRUE);

        } else {
            crm_debug("Cannot pair %s with instance of %s", rsc_lh->id, rsc_rh->id);
        }

        return;

    } else if (constraint->score >= INFINITY) {
        GListPtr rhs = NULL;

        gIter = rsc_rh->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;
            node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);

            if (chosen != NULL) {
                rhs = g_list_prepend(rhs, chosen);
            }
        }

        node_list_exclude(rsc_lh->allowed_nodes, rhs, FALSE);
        g_list_free(rhs);
        return;
    }

    gIter = rsc_rh->children;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_rh(rsc_lh, child_rsc, constraint);
    }
}

static enum action_tasks
clone_child_action(action_t * action)
{
    enum action_tasks result = no_action;
    resource_t *child = (resource_t *) action->rsc->children->data;

    if (safe_str_eq(action->task, "notify")
        || safe_str_eq(action->task, "notified")) {

        /* Find the action we're notifying about instead */

        int stop = 0;
        char *key = action->uuid;
        int lpc = strlen(key);

        for (; lpc > 0; lpc--) {
            if (key[lpc] == '_' && stop == 0) {
                stop = lpc;

            } else if (key[lpc] == '_') {
                char *task_mutable = NULL;

                lpc++;
                task_mutable = crm_strdup(key + lpc);
                task_mutable[stop - lpc] = 0;

                crm_trace("Extracted action '%s' from '%s'", task_mutable, key);
                result = get_complex_task(child, task_mutable, TRUE);
                crm_free(task_mutable);
                break;
            }
        }

    } else {
        result = get_complex_task(child, action->task, TRUE);
    }
    return result;
}

enum pe_action_flags
clone_action_flags(action_t * action, node_t * node)
{
    GListPtr gIter = NULL;
    gboolean any_runnable = FALSE;
    gboolean check_runnable = TRUE;
    enum action_tasks task = clone_child_action(action);
    enum pe_action_flags flags = (pe_action_optional | pe_action_runnable | pe_action_pseudo);
    const char *task_s = task2text(task);

    gIter = action->rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *child_action = NULL;
        resource_t *child = (resource_t *) gIter->data;

        child_action =
            find_first_action(child->actions, NULL, task_s, child->children ? NULL : node);
        crm_trace("Checking for %s in %s on %s", task_s, child->id,
                  node ? node->details->uname : "none");
        if (child_action) {
            enum pe_action_flags child_flags = child->cmds->action_flags(child_action, node);

            if (is_set(flags, pe_action_optional)
                && is_set(child_flags, pe_action_optional) == FALSE) {
                crm_trace("%s is manditory because of %s", action->uuid, child_action->uuid);
                clear_bit_inplace(flags, pe_action_optional);
                clear_bit_inplace(action->flags, pe_action_optional);
            }
            if (is_set(child_flags, pe_action_runnable)) {
                any_runnable = TRUE;
            }

        } else {

            GListPtr gIter2 = child->actions;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                action_t *op = (action_t *) gIter2->data;

                crm_trace("%s on %s (%s)", op->uuid, op->node ? op->node->details->uname : "none",
                          op->task);
            }
        }
    }

    if (check_runnable && any_runnable == FALSE) {
        crm_trace("%s is not runnable because no children are", action->uuid);
        clear_bit_inplace(flags, pe_action_runnable);
        if (node == NULL) {
            clear_bit_inplace(action->flags, pe_action_runnable);
        }
    }

    return flags;
}

static enum pe_graph_flags
clone_update_actions_interleave(action_t * first, action_t * then, node_t * node,
                                enum pe_action_flags flags, enum pe_action_flags filter,
                                enum pe_ordering type)
{
    gboolean current = FALSE;
    resource_t *first_child = NULL;
    GListPtr gIter = then->rsc->children;
    enum pe_graph_flags changed = pe_graph_none;        /*pe_graph_disable */

    enum action_tasks task = clone_child_action(first);
    const char *first_task = task2text(task);

    /* Fix this - lazy */
    if (strstr(first->uuid, "_stopped_0") || strstr(first->uuid, "_demoted_0")) {
        current = TRUE;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *then_child = (resource_t *) gIter->data;

        CRM_ASSERT(then_child != NULL);
        first_child = find_compatible_child(then_child, first->rsc, RSC_ROLE_UNKNOWN, current);
        if (first_child == NULL && current) {
            crm_trace("Ignore");

        } else if (first_child == NULL) {
            crm_debug("No match found for %s (%d / %s / %s)", then_child->id, current, first->uuid,
                      then->uuid);

            /* Me no like this hack - but what else can we do?
             *
             * If there is no-one active or about to be active
             *   on the same node as then_child, then they must
             *   not be allowed to start
             */
            if (type & (pe_order_runnable_left | pe_order_implies_then) /* Mandatory */ ) {
                crm_info("Inhibiting %s from being active", then_child->id);
                assign_node(then_child, NULL, TRUE);
            }

        } else {
            action_t *first_action = NULL;
            action_t *then_action = NULL;

            crm_debug("Pairing %s with %s", first_child->id, then_child->id);

            first_action = find_first_action(first_child->actions, NULL, first_task, node);
            then_action = find_first_action(then_child->actions, NULL, then->task, node);

            CRM_CHECK(first_action != NULL || is_set(first_child->flags, pe_rsc_orphan),
                      crm_err("No action found for %s in %s (first)", first_task, first_child->id));

            if (then_action == NULL && is_not_set(then_child->flags, pe_rsc_orphan)
                && crm_str_eq(then->task, RSC_STOP, TRUE) == FALSE
                && crm_str_eq(then->task, RSC_DEMOTED, TRUE) == FALSE) {
                crm_err("Internal error: No action found for %s in %s (then)", then->task,
                        then_child->id);
            }

            if (first_action == NULL || then_action == NULL) {
                continue;
            }
            if (order_actions(first_action, then_action, type)) {
                crm_debug("Created constraint for %s -> %s", first_action->uuid, then_action->uuid);
                changed |= (pe_graph_updated_first | pe_graph_updated_then);
            }
            changed |=
                then_child->cmds->update_actions(first_action, then_action, node,
                                                 then_child->cmds->action_flags(then_action, node),
                                                 filter, type);
        }
    }
    return changed;
}

enum pe_graph_flags
clone_update_actions(action_t * first, action_t * then, node_t * node, enum pe_action_flags flags,
                     enum pe_action_flags filter, enum pe_ordering type)
{
    const char *rsc = "none";
    gboolean interleave = FALSE;
    enum pe_graph_flags changed = pe_graph_none;

    if (first->rsc != then->rsc
        && first->rsc && first->rsc->variant >= pe_clone
        && then->rsc && then->rsc->variant >= pe_clone) {
        clone_variant_data_t *clone_data = NULL;

        if (strstr(then->uuid, "_stop_0") || strstr(then->uuid, "_demote_0")) {
            get_clone_variant_data(clone_data, first->rsc);
            rsc = first->rsc->id;
        } else {
            get_clone_variant_data(clone_data, then->rsc);
            rsc = then->rsc->id;
        }
        interleave = clone_data->interleave;
    }

    crm_trace("Interleave %s -> %s: %s (based on %s)",
              first->uuid, then->uuid, interleave ? "yes" : "no", rsc);

    if (interleave) {
        changed = clone_update_actions_interleave(first, then, node, flags, filter, type);

    } else if (then->rsc) {
        GListPtr gIter = then->rsc->children;

        changed |= native_update_actions(first, then, node, flags, filter, type);

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;
            action_t *child_action = find_first_action(child->actions, NULL, then->task, node);

            if (child_action) {
                enum pe_action_flags child_flags = child->cmds->action_flags(child_action, node);

                if (is_set(child_flags, pe_action_runnable)) {
                    changed |=
                        child->cmds->update_actions(first, child_action, node, flags, filter, type);
                }
            }
        }
    }

    return changed;
}

void
clone_rsc_location(resource_t * rsc, rsc_to_node_t * constraint)
{
    GListPtr gIter = rsc->children;

    crm_trace("Processing location constraint %s for %s", constraint->id, rsc->id);

    native_rsc_location(rsc, constraint);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->rsc_location(child_rsc, constraint);
    }
}

void
clone_expand(resource_t * rsc, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    gIter = rsc->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *op = (action_t *) gIter->data;

        rsc->cmds->action_flags(op, NULL);
    }

    if (clone_data->start_notify) {
        collect_notification_data(rsc, TRUE, TRUE, clone_data->start_notify);
        expand_notification_data(clone_data->start_notify);
        create_notifications(rsc, clone_data->start_notify, data_set);
    }

    if (clone_data->stop_notify) {
        collect_notification_data(rsc, TRUE, TRUE, clone_data->stop_notify);
        expand_notification_data(clone_data->stop_notify);
        create_notifications(rsc, clone_data->stop_notify, data_set);
    }

    if (clone_data->promote_notify) {
        collect_notification_data(rsc, TRUE, TRUE, clone_data->promote_notify);
        expand_notification_data(clone_data->promote_notify);
        create_notifications(rsc, clone_data->promote_notify, data_set);
    }

    if (clone_data->demote_notify) {
        collect_notification_data(rsc, TRUE, TRUE, clone_data->demote_notify);
        expand_notification_data(clone_data->demote_notify);
        create_notifications(rsc, clone_data->demote_notify, data_set);
    }

    /* Now that the notifcations have been created we can expand the children */

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->expand(child_rsc, data_set);
    }

    native_expand(rsc, data_set);

    /* The notifications are in the graph now, we can destroy the notify_data */
    free_notification_data(clone_data->demote_notify);
    clone_data->demote_notify = NULL;
    free_notification_data(clone_data->stop_notify);
    clone_data->stop_notify = NULL;
    free_notification_data(clone_data->start_notify);
    clone_data->start_notify = NULL;
    free_notification_data(clone_data->promote_notify);
    clone_data->promote_notify = NULL;
}

static gint
sort_rsc_id(gconstpointer a, gconstpointer b)
{
    const resource_t *resource1 = (const resource_t *)a;
    const resource_t *resource2 = (const resource_t *)b;

    CRM_ASSERT(resource1 != NULL);
    CRM_ASSERT(resource2 != NULL);

    return strcmp(resource1->id, resource2->id);
}

node_t *
rsc_known_on(resource_t * rsc, GListPtr * list)
{
    GListPtr gIter = NULL;
    node_t *one = NULL;
    GListPtr result = NULL;

    if (rsc->children) {

        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            rsc_known_on(child, &result);
        }

    } else if (rsc->known_on) {
        result = g_hash_table_get_values(rsc->known_on);
    }

    if (result && g_list_length(result) == 1) {
        one = g_list_nth_data(result, 0);
    }

    if (list) {
        GListPtr gIter = NULL;

        gIter = result;
        for (; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;

            if (*list == NULL || pe_find_node_id(*list, node->details->id) == NULL) {
                *list = g_list_prepend(*list, node);
            }
        }
    }

    g_list_free(result);
    return one;
}

static resource_t *
find_instance_on(resource_t * rsc, node_t * node)
{
    GListPtr gIter = NULL;

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        GListPtr gIter2 = NULL;
        GListPtr known_list = NULL;
        resource_t *child = (resource_t *) gIter->data;

        rsc_known_on(child, &known_list);

        gIter2 = known_list;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            node_t *known = (node_t *) gIter2->data;

            if (node->details == known->details) {
                g_list_free(known_list);
                return child;
            }
        }
        g_list_free(known_list);
    }

    return NULL;
}

gboolean
clone_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                   gboolean force, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    gboolean any_created = FALSE;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    rsc->children = g_list_sort(rsc->children, sort_rsc_id);
    if (rsc->children == NULL) {
        pe_warn("Clone %s has no children", rsc->id);
        return FALSE;
    }

    if (is_not_set(rsc->flags, pe_rsc_unique)
        && clone_data->clone_node_max == 1) {
        /* only look for one copy */
        resource_t *child = NULL;

        /* Try whoever we probed last time */
        child = find_instance_on(rsc, node);
        if (child) {
            return child->cmds->create_probe(child, node, complete, force, data_set);
        }

        /* Try whoever we plan on starting there */
        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;
            node_t *local_node = child_rsc->fns->location(child_rsc, NULL, FALSE);

            if (local_node == NULL) {
                continue;
            }

            if (local_node->details == node->details) {
                return child_rsc->cmds->create_probe(child_rsc, node, complete, force, data_set);
            }
        }

        /* Fall back to the first clone instance */
        child = rsc->children->data;
        return child->cmds->create_probe(child, node, complete, force, data_set);
    }

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        if (child_rsc->cmds->create_probe(child_rsc, node, complete, force, data_set)) {
            any_created = TRUE;
        }

        if (any_created && is_not_set(rsc->flags, pe_rsc_unique)
            && clone_data->clone_node_max == 1) {
            /* only look for one copy (clone :0) */
            break;
        }
    }

    return any_created;
}

void
clone_append_meta(resource_t * rsc, xmlNode * xml)
{
    char *name = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    name = crm_meta_name(XML_RSC_ATTR_UNIQUE);
    crm_xml_add(xml, name, is_set(rsc->flags, pe_rsc_unique) ? "true" : "false");
    crm_free(name);

    name = crm_meta_name(XML_RSC_ATTR_NOTIFY);
    crm_xml_add(xml, name, is_set(rsc->flags, pe_rsc_notify) ? "true" : "false");
    crm_free(name);

    name = crm_meta_name(XML_RSC_ATTR_INCARNATION_MAX);
    crm_xml_add_int(xml, name, clone_data->clone_max);
    crm_free(name);

    name = crm_meta_name(XML_RSC_ATTR_INCARNATION_NODEMAX);
    crm_xml_add_int(xml, name, clone_data->clone_node_max);
    crm_free(name);
}
