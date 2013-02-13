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

void
pe_free_ordering(GListPtr constraints)
{
    GListPtr iterator = constraints;

    while (iterator != NULL) {
        order_constraint_t *order = iterator->data;

        iterator = iterator->next;

        free(order->lh_action_task);
        free(order->rh_action_task);
        free(order);
    }
    if (constraints != NULL) {
        g_list_free(constraints);
    }
}

void
pe_free_rsc_to_node(GListPtr constraints)
{
    GListPtr iterator = constraints;

    while (iterator != NULL) {
        rsc_to_node_t *cons = iterator->data;

        iterator = iterator->next;

        g_list_free_full(cons->node_list_rh, free);
        free(cons);
    }
    if (constraints != NULL) {
        g_list_free(constraints);
    }
}

rsc_to_node_t *
rsc2node_new(const char *id, resource_t * rsc,
             int node_weight, node_t * foo_node, pe_working_set_t * data_set)
{
    rsc_to_node_t *new_con = NULL;

    if (rsc == NULL || id == NULL) {
        pe_err("Invalid constraint %s for rsc=%p", crm_str(id), rsc);
        return NULL;

    } else if (foo_node == NULL) {
        CRM_CHECK(node_weight == 0, return NULL);
    }

    new_con = calloc(1, sizeof(rsc_to_node_t));
    if (new_con != NULL) {
        new_con->id = id;
        new_con->rsc_lh = rsc;
        new_con->node_list_rh = NULL;
        new_con->role_filter = RSC_ROLE_UNKNOWN;

        if (foo_node != NULL) {
            node_t *copy = node_copy(foo_node);

            copy->weight = merge_weights(node_weight, foo_node->weight);
            new_con->node_list_rh = g_list_prepend(NULL, copy);
        }

        data_set->placement_constraints = g_list_prepend(data_set->placement_constraints, new_con);
        rsc->rsc_location = g_list_prepend(rsc->rsc_location, new_con);
    }

    return new_con;
}

gboolean
can_run_resources(const node_t * node)
{
    if (node == NULL) {
        return FALSE;
    }
#if 0
    if (node->weight < 0) {
        return FALSE;
    }
#endif

    if (node->details->online == FALSE
        || node->details->shutdown || node->details->unclean || node->details->standby) {
        crm_trace("%s: online=%d, unclean=%d, standby=%d",
                  node->details->uname, node->details->online,
                  node->details->unclean, node->details->standby);
        return FALSE;
    }
    return TRUE;
}

struct compare_data {
    const node_t *node1;
    const node_t *node2;
    int result;
};

static void
do_compare_capacity1(gpointer key, gpointer value, gpointer user_data)
{
    int node1_capacity = 0;
    int node2_capacity = 0;
    struct compare_data *data = user_data;

    node1_capacity = crm_parse_int(value, "0");
    node2_capacity =
        crm_parse_int(g_hash_table_lookup(data->node2->details->utilization, key), "0");

    if (node1_capacity > node2_capacity) {
        data->result--;
    } else if (node1_capacity < node2_capacity) {
        data->result++;
    }
}

static void
do_compare_capacity2(gpointer key, gpointer value, gpointer user_data)
{
    int node1_capacity = 0;
    int node2_capacity = 0;
    struct compare_data *data = user_data;

    if (g_hash_table_lookup_extended(data->node1->details->utilization, key, NULL, NULL)) {
        return;
    }

    node1_capacity = 0;
    node2_capacity = crm_parse_int(value, "0");

    if (node1_capacity > node2_capacity) {
        data->result--;
    } else if (node1_capacity < node2_capacity) {
        data->result++;
    }
}

/* rc < 0 if 'node1' has more capacity remaining
 * rc > 0 if 'node1' has less capacity remaining
 */
static int
compare_capacity(const node_t * node1, const node_t * node2)
{
    struct compare_data data;

    data.node1 = node1;
    data.node2 = node2;
    data.result = 0;

    g_hash_table_foreach(node1->details->utilization, do_compare_capacity1, &data);
    g_hash_table_foreach(node2->details->utilization, do_compare_capacity2, &data);

    return data.result;
}

/* return -1 if 'a' is more preferred
 * return  1 if 'b' is more preferred
 */

gint
sort_node_weight(gconstpointer a, gconstpointer b, gpointer data)
{
    const node_t *node1 = (const node_t *)a;
    const node_t *node2 = (const node_t *)b;
    const node_t *active = (node_t *) data;

    int node1_weight = 0;
    int node2_weight = 0;

    int result = 0;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    node1_weight = node1->weight;
    node2_weight = node2->weight;

    if (can_run_resources(node1) == FALSE) {
        node1_weight = -INFINITY;
    }
    if (can_run_resources(node2) == FALSE) {
        node2_weight = -INFINITY;
    }

    if (node1_weight > node2_weight) {
        crm_trace("%s (%d) > %s (%d) : weight",
                  node1->details->uname, node1_weight, node2->details->uname, node2_weight);
        return -1;
    }

    if (node1_weight < node2_weight) {
        crm_trace("%s (%d) < %s (%d) : weight",
                  node1->details->uname, node1_weight, node2->details->uname, node2_weight);
        return 1;
    }

    crm_trace("%s (%d) == %s (%d) : weight",
              node1->details->uname, node1_weight, node2->details->uname, node2_weight);

    if (safe_str_eq(pe_dataset->placement_strategy, "minimal")) {
        goto equal;
    }

    if (safe_str_eq(pe_dataset->placement_strategy, "balanced")) {
        result = compare_capacity(node1, node2);
        if (result != 0) {
            return result;
        }
    }

    /* now try to balance resources across the cluster */
    if (node1->details->num_resources < node2->details->num_resources) {
        crm_trace("%s (%d) < %s (%d) : resources",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return -1;

    } else if (node1->details->num_resources > node2->details->num_resources) {
        crm_trace("%s (%d) > %s (%d) : resources",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return 1;
    }

    if (active && active->details == node1->details) {
        crm_trace("%s (%d) > %s (%d) : active",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return -1;
    } else if (active && active->details == node2->details) {
        crm_trace("%s (%d) > %s (%d) : active",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return 1;
    }
  equal:
    crm_trace("%s = %s", node1->details->uname, node2->details->uname);
    return strcmp(node1->details->uname, node2->details->uname);
}

struct calculate_data {
    node_t *node;
    gboolean allocate;
};

static void
do_calculate_utilization(gpointer key, gpointer value, gpointer user_data)
{
    const char *capacity = NULL;
    char *remain_capacity = NULL;
    struct calculate_data *data = user_data;

    capacity = g_hash_table_lookup(data->node->details->utilization, key);
    if (capacity) {
        if (data->allocate) {
            remain_capacity = crm_itoa(crm_parse_int(capacity, "0") - crm_parse_int(value, "0"));
        } else {
            remain_capacity = crm_itoa(crm_parse_int(capacity, "0") + crm_parse_int(value, "0"));
        }
        g_hash_table_replace(data->node->details->utilization, strdup(key), remain_capacity);
    }
}

/* Specify 'allocate' to TRUE when allocating
 * Otherwise to FALSE when deallocating
 */
static void
calculate_utilization(node_t * node, resource_t * rsc, gboolean allocate)
{
    struct calculate_data data;

    data.node = node;
    data.allocate = allocate;

    g_hash_table_foreach(rsc->utilization, do_calculate_utilization, &data);

    if (allocate) {
        dump_rsc_utilization(show_utilization ? 0 : utilization_log_level, __FUNCTION__, rsc, node);
    }
}

void
native_deallocate(resource_t * rsc)
{
    if (rsc->allocated_to) {
        node_t *old = rsc->allocated_to;

        crm_info("Deallocating %s from %s", rsc->id, old->details->uname);
        set_bit(rsc->flags, pe_rsc_provisional);
        rsc->allocated_to = NULL;

        old->details->allocated_rsc = g_list_remove(old->details->allocated_rsc, rsc);
        old->details->num_resources--;
        /* old->count--; */
        calculate_utilization(old, rsc, FALSE);
        free(old);
    }
}

gboolean
native_assign_node(resource_t * rsc, GListPtr nodes, node_t * chosen, gboolean force)
{
    CRM_ASSERT(rsc->variant == pe_native);

    if (force == FALSE
        && chosen != NULL && (can_run_resources(chosen) == FALSE || chosen->weight < 0)) {
        crm_debug("All nodes for resource %s are unavailable"
                  ", unclean or shutting down (%s: %d, %d)",
                  rsc->id, chosen->details->uname, can_run_resources(chosen), chosen->weight);
        rsc->next_role = RSC_ROLE_STOPPED;
        chosen = NULL;
    }

    /* todo: update the old node for each resource to reflect its
     * new resource count
     */

    native_deallocate(rsc);
    clear_bit(rsc->flags, pe_rsc_provisional);

    if (chosen == NULL) {
        char *key = NULL;
        GListPtr gIter = NULL;
        GListPtr possible_matches = NULL;

        crm_debug("Could not allocate a node for %s", rsc->id);
        rsc->next_role = RSC_ROLE_STOPPED;

        key = generate_op_key(rsc->id, RSC_STOP, 0);
        possible_matches = find_actions(rsc->actions, key, NULL);

        for (gIter = possible_matches; gIter != NULL; gIter = gIter->next) {
            action_t *stop = (action_t *) gIter->data;

            update_action_flags(stop, pe_action_optional | pe_action_clear);
        }

        g_list_free(possible_matches);
        free(key);

        key = generate_op_key(rsc->id, RSC_START, 0);
        possible_matches = find_actions(rsc->actions, key, NULL);

        for (gIter = possible_matches; gIter != NULL; gIter = gIter->next) {
            action_t *start = (action_t *) gIter->data;

            update_action_flags(start, pe_action_runnable | pe_action_clear);
        }

        g_list_free(possible_matches);
        free(key);

        return FALSE;
    }

    crm_debug("Assigning %s to %s", chosen->details->uname, rsc->id);
    rsc->allocated_to = node_copy(chosen);

    chosen->details->allocated_rsc = g_list_prepend(chosen->details->allocated_rsc, rsc);
    chosen->details->num_resources++;
    chosen->count++;
    calculate_utilization(chosen, rsc, TRUE);
    return TRUE;
}

void
log_action(unsigned int log_level, const char *pre_text, action_t * action, gboolean details)
{
    const char *node_uname = NULL;
    const char *node_uuid = NULL;

    if (action == NULL) {
        crm_trace("%s%s: <NULL>", pre_text == NULL ? "" : pre_text, pre_text == NULL ? "" : ": ");
        return;
    }

    if (is_set(action->flags, pe_action_pseudo)) {
        node_uname = NULL;
        node_uuid = NULL;

    } else if (action->node != NULL) {
        node_uname = action->node->details->uname;
        node_uuid = action->node->details->id;
    } else {
        node_uname = "<none>";
        node_uuid = NULL;
    }

    switch (text2task(action->task)) {
        case stonith_node:
        case shutdown_crm:
            crm_trace("%s%s%sAction %d: %s%s%s%s%s%s",
                      pre_text == NULL ? "" : pre_text,
                      pre_text == NULL ? "" : ": ",
                      is_set(action->flags,
                             pe_action_pseudo) ? "Pseduo " : is_set(action->flags,
                                                                    pe_action_optional) ?
                      "Optional " : is_set(action->flags,
                                           pe_action_runnable) ? is_set(action->flags,
                                                                        pe_action_processed)
                      ? "" : "(Provisional) " : "!!Non-Startable!! ", action->id,
                      action->uuid, node_uname ? "\ton " : "",
                      node_uname ? node_uname : "", node_uuid ? "\t\t(" : "",
                      node_uuid ? node_uuid : "", node_uuid ? ")" : "");
            break;
        default:
            crm_trace("%s%s%sAction %d: %s %s%s%s%s%s%s",
                      pre_text == NULL ? "" : pre_text,
                      pre_text == NULL ? "" : ": ",
                      is_set(action->flags,
                             pe_action_optional) ? "Optional " : is_set(action->flags,
                                                                        pe_action_pseudo)
                      ? "Pseduo " : is_set(action->flags,
                                           pe_action_runnable) ? is_set(action->flags,
                                                                        pe_action_processed)
                      ? "" : "(Provisional) " : "!!Non-Startable!! ", action->id,
                      action->uuid, action->rsc ? action->rsc->id : "<none>",
                      node_uname ? "\ton " : "", node_uname ? node_uname : "",
                      node_uuid ? "\t\t(" : "", node_uuid ? node_uuid : "", node_uuid ? ")" : "");

            break;
    }

    if (details) {
        GListPtr gIter = NULL;

        crm_trace("\t\t====== Preceding Actions");

        gIter = action->actions_before;
        for (; gIter != NULL; gIter = gIter->next) {
            action_wrapper_t *other = (action_wrapper_t *) gIter->data;

            log_action(log_level + 1, "\t\t", other->action, FALSE);
        }

        crm_trace("\t\t====== Subsequent Actions");

        gIter = action->actions_after;
        for (; gIter != NULL; gIter = gIter->next) {
            action_wrapper_t *other = (action_wrapper_t *) gIter->data;

            log_action(log_level + 1, "\t\t", other->action, FALSE);
        }

        crm_trace("\t\t====== End");

    } else {
        crm_trace("\t\t(seen=%d, before=%d, after=%d)",
                  action->seen_count,
                  g_list_length(action->actions_before), g_list_length(action->actions_after));
    }
}

gboolean
can_run_any(GHashTable * nodes)
{
    GHashTableIter iter;
    node_t *node = NULL;

    if (nodes == NULL) {
        return FALSE;
    }

    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        if (can_run_resources(node) && node->weight >= 0) {
            return TRUE;
        }
    }

    return FALSE;
}
