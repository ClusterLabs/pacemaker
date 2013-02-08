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

#include <pengine.h>
#include <crm/msg_xml.h>

#include <allocate.h>
#include <utils.h>

#define VARIANT_GROUP 1
#include <lib/pengine/variant.h>

node_t *
group_color(resource_t * rsc, node_t * prefer, pe_working_set_t * data_set)
{
    node_t *node = NULL;
    node_t *group_node = NULL;
    GListPtr gIter = NULL;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    if (is_not_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to;
    }
    pe_rsc_trace(rsc, "Processing %s", rsc->id);
    if (is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    if (group_data->first_child == NULL) {
        /* nothign to allocate */
        clear_bit(rsc->flags, pe_rsc_provisional);
        return NULL;
    }

    set_bit(rsc->flags, pe_rsc_allocating);
    rsc->role = group_data->first_child->role;

    group_data->first_child->rsc_cons =
        g_list_concat(group_data->first_child->rsc_cons, rsc->rsc_cons);
    rsc->rsc_cons = NULL;

    group_data->first_child->rsc_cons_lhs =
        g_list_concat(group_data->first_child->rsc_cons_lhs, rsc->rsc_cons_lhs);
    rsc->rsc_cons_lhs = NULL;

    dump_node_scores(show_scores ? 0 : scores_log_level, rsc, __PRETTY_FUNCTION__,
                     rsc->allowed_nodes);

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        node = child_rsc->cmds->allocate(child_rsc, prefer, data_set);
        if (group_node == NULL) {
            group_node = node;
        }
    }

    rsc->next_role = group_data->first_child->next_role;
    clear_bit(rsc->flags, pe_rsc_allocating);
    clear_bit(rsc->flags, pe_rsc_provisional);

    if (group_data->colocated) {
        return group_node;
    }
    return NULL;
}

void group_update_pseudo_status(resource_t * parent, resource_t * child);

void
group_create_actions(resource_t * rsc, pe_working_set_t * data_set)
{
    action_t *op = NULL;
    const char *value = NULL;
    GListPtr gIter = rsc->children;

    pe_rsc_trace(rsc, "Creating actions for %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->create_actions(child_rsc, data_set);
        group_update_pseudo_status(rsc, child_rsc);
    }

    op = start_action(rsc, NULL, TRUE /* !group_data->child_starting */ );
    set_bit(op->flags, pe_action_pseudo | pe_action_runnable);

    op = custom_action(rsc, started_key(rsc),
                       RSC_STARTED, NULL, TRUE /* !group_data->child_starting */ , TRUE, data_set);
    set_bit(op->flags, pe_action_pseudo | pe_action_runnable);

    op = stop_action(rsc, NULL, TRUE /* !group_data->child_stopping */ );
    set_bit(op->flags, pe_action_pseudo | pe_action_runnable);

    op = custom_action(rsc, stopped_key(rsc),
                       RSC_STOPPED, NULL, TRUE /* !group_data->child_stopping */ , TRUE, data_set);
    set_bit(op->flags, pe_action_pseudo | pe_action_runnable);

    value = g_hash_table_lookup(rsc->meta, "stateful");
    if (crm_is_true(value)) {
        op = custom_action(rsc, demote_key(rsc), RSC_DEMOTE, NULL, TRUE, TRUE, data_set);
        set_bit(op->flags, pe_action_pseudo);
        set_bit(op->flags, pe_action_runnable);
        op = custom_action(rsc, demoted_key(rsc), RSC_DEMOTED, NULL, TRUE, TRUE, data_set);
        set_bit(op->flags, pe_action_pseudo);
        set_bit(op->flags, pe_action_runnable);

        op = custom_action(rsc, promote_key(rsc), RSC_PROMOTE, NULL, TRUE, TRUE, data_set);
        set_bit(op->flags, pe_action_pseudo);
        set_bit(op->flags, pe_action_runnable);
        op = custom_action(rsc, promoted_key(rsc), RSC_PROMOTED, NULL, TRUE, TRUE, data_set);
        set_bit(op->flags, pe_action_pseudo);
        set_bit(op->flags, pe_action_runnable);
    }
}

void
group_update_pseudo_status(resource_t * parent, resource_t * child)
{
    GListPtr gIter = child->actions;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, parent);

    if (group_data->ordered == FALSE) {
        /* If this group is not ordered, then leave the meta-actions as optional */
        return;
    }

    if (group_data->child_stopping && group_data->child_starting) {
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (is_set(action->flags, pe_action_optional)) {
            continue;
        }
        if (safe_str_eq(RSC_STOP, action->task) && is_set(action->flags, pe_action_runnable)) {
            group_data->child_stopping = TRUE;
            pe_rsc_trace(action->rsc, "Based on %s the group is stopping", action->uuid);

        } else if (safe_str_eq(RSC_START, action->task)
                   && is_set(action->flags, pe_action_runnable)) {
            group_data->child_starting = TRUE;
            pe_rsc_trace(action->rsc, "Based on %s the group is starting", action->uuid);
        }
    }
}

void
group_internal_constraints(resource_t * rsc, pe_working_set_t * data_set)
{
    GListPtr gIter = rsc->children;
    resource_t *last_rsc = NULL;
    resource_t *last_active = NULL;
    resource_t *top = uber_parent(rsc);
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    new_rsc_order(rsc, RSC_STOPPED, rsc, RSC_START, pe_order_optional, data_set);
    new_rsc_order(rsc, RSC_START, rsc, RSC_STARTED, pe_order_runnable_left, data_set);
    new_rsc_order(rsc, RSC_STOP, rsc, RSC_STOPPED, pe_order_runnable_left, data_set);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;
        int stop = pe_order_none;
        int stopped = pe_order_implies_then_printed;
        int start = pe_order_implies_then | pe_order_runnable_left;
        int started =
            pe_order_runnable_left | pe_order_implies_then | pe_order_implies_then_printed;

        child_rsc->cmds->internal_constraints(child_rsc, data_set);

        if (last_rsc == NULL) {
            if (group_data->ordered) {
                stop |= pe_order_optional;
                stopped = pe_order_implies_then;
            }

        } else if (group_data->colocated) {
            rsc_colocation_new("group:internal_colocation", NULL, INFINITY,
                               child_rsc, last_rsc, NULL, NULL, data_set);
        }

        if (top->variant == pe_master) {
            new_rsc_order(rsc, RSC_DEMOTE, child_rsc, RSC_DEMOTE,
                          stop | pe_order_implies_first_printed, data_set);

            new_rsc_order(child_rsc, RSC_DEMOTE, rsc, RSC_DEMOTED, stopped, data_set);

            new_rsc_order(child_rsc, RSC_PROMOTE, rsc, RSC_PROMOTED, started, data_set);

            new_rsc_order(rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE,
                          pe_order_implies_first_printed, data_set);

        }

        order_start_start(rsc, child_rsc, pe_order_implies_first_printed);
        order_stop_stop(rsc, child_rsc, stop | pe_order_implies_first_printed);

        new_rsc_order(child_rsc, RSC_STOP, rsc, RSC_STOPPED, stopped, data_set);

        new_rsc_order(child_rsc, RSC_START, rsc, RSC_STARTED, started, data_set);

        if (group_data->ordered == FALSE) {
            order_start_start(rsc, child_rsc, start | pe_order_implies_first_printed);
            if (top->variant == pe_master) {
                new_rsc_order(rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE,
                              start | pe_order_implies_first_printed, data_set);
            }

        } else if (last_rsc != NULL) {
            child_rsc->restart_type = pe_restart_restart;

            order_start_start(last_rsc, child_rsc, start);
            order_stop_stop(child_rsc, last_rsc, pe_order_optional|pe_order_restart);

            if (top->variant == pe_master) {
                new_rsc_order(last_rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE, start, data_set);
                new_rsc_order(child_rsc, RSC_DEMOTE, last_rsc, RSC_DEMOTE, pe_order_optional,
                              data_set);
            }

        } else {
            /* If anyone in the group is starting, then
             *  pe_order_implies_then will cause _everyone_ in the group
             *  to be sent a start action
             * But this is safe since starting something that is already
             *  started is required to be "safe"
             */
            int flags = pe_order_none;

            order_start_start(rsc, child_rsc, flags);
            if (top->variant == pe_master) {
                new_rsc_order(rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE, flags, data_set);
            }

        }

        /* Look for partially active groups
         * Make sure they still shut down in sequence
         */
        if(child_rsc->running_on) {
            if(group_data->ordered
               && last_rsc
               && last_rsc->running_on == NULL
               && last_active
               && last_active->running_on) {
                order_stop_stop(child_rsc, last_active, pe_order_optional);
            }
            last_active = child_rsc;
        }

        last_rsc = child_rsc;
    }

    if (group_data->ordered && last_rsc != NULL) {
        int stop_stop_flags = pe_order_implies_then;
        int stop_stopped_flags = pe_order_optional;

        order_stop_stop(rsc, last_rsc, stop_stop_flags);
        new_rsc_order(last_rsc, RSC_STOP, rsc, RSC_STOPPED, stop_stopped_flags, data_set);

        if (top->variant == pe_master) {
            new_rsc_order(rsc, RSC_DEMOTE, last_rsc, RSC_DEMOTE, stop_stop_flags, data_set);
            new_rsc_order(last_rsc, RSC_DEMOTE, rsc, RSC_DEMOTED, stop_stopped_flags, data_set);
        }
    }
}

void
group_rsc_colocation_lh(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    GListPtr gIter = NULL;
    group_variant_data_t *group_data = NULL;

    if (rsc_lh == NULL) {
        pe_err("rsc_lh was NULL for %s", constraint->id);
        return;

    } else if (rsc_rh == NULL) {
        pe_err("rsc_rh was NULL for %s", constraint->id);
        return;
    }

    gIter = rsc_lh->children;
    pe_rsc_trace(rsc_lh, "Processing constraints from %s", rsc_lh->id);

    get_group_variant_data(group_data, rsc_lh);

    if (group_data->colocated) {
        group_data->first_child->cmds->rsc_colocation_lh(group_data->first_child, rsc_rh,
                                                         constraint);
        return;

    } else if (constraint->score >= INFINITY) {
        crm_config_err("%s: Cannot perform manditory colocation"
                       " between non-colocated group and %s", rsc_lh->id, rsc_rh->id);
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_lh(child_rsc, rsc_rh, constraint);
    }
}

void
group_rsc_colocation_rh(resource_t * rsc_lh, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    GListPtr gIter = rsc_rh->children;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc_rh);
    CRM_CHECK(rsc_lh->variant == pe_native, return);

    pe_rsc_trace(rsc_rh, "Processing RH of constraint %s", constraint->id);
    print_resource(LOG_DEBUG_3, "LHS", rsc_lh, TRUE);

    if (is_set(rsc_rh->flags, pe_rsc_provisional)) {
        return;

    } else if (group_data->colocated && group_data->first_child) {
        if (constraint->score >= INFINITY) {
            /* Ensure RHS is _fully_ up before can start LHS */
            group_data->last_child->cmds->rsc_colocation_rh(rsc_lh, group_data->last_child,
                                                            constraint);
        } else {
            /* A partially active RHS is fine */
            group_data->first_child->cmds->rsc_colocation_rh(rsc_lh, group_data->first_child,
                                                             constraint);
        }

        return;

    } else if (constraint->score >= INFINITY) {
        crm_config_err("%s: Cannot perform manditory colocation with"
                       " non-colocated group: %s", rsc_lh->id, rsc_rh->id);
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_rh(rsc_lh, child_rsc, constraint);
    }
}

enum pe_action_flags
group_action_flags(action_t * action, node_t * node)
{
    GListPtr gIter = NULL;
    enum pe_action_flags flags = (pe_action_optional | pe_action_runnable | pe_action_pseudo);

    for (gIter = action->rsc->children; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;
        enum action_tasks task = get_complex_task(child, action->task, TRUE);
        const char *task_s = task2text(task);
        action_t *child_action = find_first_action(child->actions, NULL, task_s, node);

        if (child_action) {
            enum pe_action_flags child_flags = child->cmds->action_flags(child_action, node);

            if (is_set(flags, pe_action_optional)
                && is_set(child_flags, pe_action_optional) == FALSE) {
                pe_rsc_trace(action->rsc, "%s is manditory because of %s", action->uuid, child_action->uuid);
                clear_bit(flags, pe_action_optional);
                pe_clear_action_bit(action, pe_action_optional);
            }
            if (safe_str_neq(task_s, action->task)
                && is_set(flags, pe_action_runnable)
                && is_set(child_flags, pe_action_runnable) == FALSE) {
                pe_rsc_trace(action->rsc, "%s is not runnable because of %s", action->uuid, child_action->uuid);
                clear_bit(flags, pe_action_runnable);
                pe_clear_action_bit(action, pe_action_runnable);
            }

        } else if (task != stop_rsc) {
            pe_rsc_trace(action->rsc, "%s is not runnable because of %s (not found in %s)", action->uuid, task_s,
                      child->id);
            clear_bit(flags, pe_action_runnable);
        }
    }

    return flags;
}

enum pe_graph_flags
group_update_actions(action_t * first, action_t * then, node_t * node, enum pe_action_flags flags,
                     enum pe_action_flags filter, enum pe_ordering type)
{
    GListPtr gIter = then->rsc->children;
    enum pe_graph_flags changed = pe_graph_none;

    CRM_ASSERT(then->rsc != NULL);
    changed |= native_update_actions(first, then, node, flags, filter, type);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *) gIter->data;
        action_t *child_action = find_first_action(child->actions, NULL, then->task, node);

        if (child_action) {
            changed |= child->cmds->update_actions(first, child_action, node, flags, filter, type);
        }
    }

    return changed;
}

void
group_rsc_location(resource_t * rsc, rsc_to_node_t * constraint)
{
    GListPtr gIter = rsc->children;
    GListPtr saved = constraint->node_list_rh;
    GListPtr zero = node_list_dup(constraint->node_list_rh, TRUE, FALSE);
    gboolean reset_scores = TRUE;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    pe_rsc_debug(rsc, "Processing rsc_location %s for %s", constraint->id, rsc->id);

    native_rsc_location(rsc, constraint);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->rsc_location(child_rsc, constraint);
        if (group_data->colocated && reset_scores) {
            reset_scores = FALSE;
            constraint->node_list_rh = zero;
        }
    }

    constraint->node_list_rh = saved;
    g_list_free_full(zero, free);
}

void
group_expand(resource_t * rsc, pe_working_set_t * data_set)
{
    GListPtr gIter = rsc->children;

    pe_rsc_trace(rsc, "Processing actions from %s", rsc->id);

    CRM_CHECK(rsc != NULL, return);
    native_expand(rsc, data_set);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        child_rsc->cmds->expand(child_rsc, data_set);
    }
}

GHashTable *
group_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes, const char *attr,
                    float factor, enum pe_weights flags)
{
    GListPtr gIter = rsc->rsc_cons_lhs;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    if (is_set(rsc->flags, pe_rsc_merging)) {
        pe_rsc_info(rsc, "Breaking dependency loop with %s at %s", rsc->id, rhs);
        return nodes;
    }

    set_bit(rsc->flags, pe_rsc_merging);

    nodes =
        group_data->first_child->cmds->merge_weights(group_data->first_child, rhs, nodes, attr,
                                                     factor, flags);

    for (; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;

        nodes = native_merge_weights(constraint->rsc_lh, rsc->id, nodes,
                                     constraint->node_attribute,
                                     (float) constraint->score / INFINITY, flags);
    }

    clear_bit(rsc->flags, pe_rsc_merging);
    return nodes;
}

void
group_append_meta(resource_t * rsc, xmlNode * xml)
{
}
