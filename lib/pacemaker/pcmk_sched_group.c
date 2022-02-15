/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/msg_xml.h>

#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

#define VARIANT_GROUP 1
#include <lib/pengine/variant.h>

/*!
 * \internal
 * \brief Expand a group's colocations to its members
 *
 * \param[in,out] rsc  Group resource
 */
static void
expand_group_colocations(pe_resource_t *rsc)
{
    group_variant_data_t *group_data = NULL;
    pe_resource_t *member = NULL;
    bool any_unmanaged = false;

    get_group_variant_data(group_data, rsc);

    // Treat "group with R" colocations as "first member with R"
    member = group_data->first_child;
    member->rsc_cons = g_list_concat(member->rsc_cons, rsc->rsc_cons);


    /* The above works for the whole group because each group member is
     * colocated with the previous one.
     *
     * However, there is a special case when a group has a mandatory colocation
     * with a resource that can't start. In that case,
     * pcmk__block_colocated_starts() will ensure that dependent resources in
     * mandatory colocations (i.e. the first member for groups) can't start
     * either. But if any group member is unmanaged and already started, the
     * internal group colocations are no longer sufficient to make that apply to
     * later members.
     *
     * To handle that case, add mandatory colocations to each member after the
     * first.
     */
    any_unmanaged = !pcmk_is_set(member->flags, pe_rsc_managed);
    for (GList *item = rsc->children->next; item != NULL; item = item->next) {
        member = item->data;
        if (any_unmanaged) {
            for (GList *cons_iter = rsc->rsc_cons; cons_iter != NULL;
                 cons_iter = cons_iter->next) {

                pcmk__colocation_t *constraint = (pcmk__colocation_t *) cons_iter->data;

                if (constraint->score == INFINITY) {
                    member->rsc_cons = g_list_prepend(member->rsc_cons, constraint);
                }
            }
        } else if (!pcmk_is_set(member->flags, pe_rsc_managed)) {
            any_unmanaged = true;
        }
    }

    rsc->rsc_cons = NULL;

    // Treat "R with group" colocations as "R with last member"
    member = group_data->last_child;
    member->rsc_cons_lhs = g_list_concat(member->rsc_cons_lhs,
                                         rsc->rsc_cons_lhs);
    rsc->rsc_cons_lhs = NULL;
}

pe_node_t *
pcmk__group_allocate(pe_resource_t *rsc, pe_node_t *prefer,
                     pe_working_set_t *data_set)
{
    pe_node_t *node = NULL;
    pe_node_t *group_node = NULL;
    GList *gIter = NULL;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to;
    }
    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    if (group_data->first_child == NULL) {
        // Nothing to allocate
        pe__clear_resource_flags(rsc, pe_rsc_provisional);
        return NULL;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    rsc->role = group_data->first_child->role;

    expand_group_colocations(rsc);

    pe__show_node_weights(!pcmk_is_set(data_set->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, data_set);

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        pe_rsc_trace(rsc, "Allocating group %s member %s",
                     rsc->id, child_rsc->id);
        node = child_rsc->cmds->allocate(child_rsc, prefer, data_set);
        if (group_node == NULL) {
            group_node = node;
        }
    }

    pe__set_next_role(rsc, group_data->first_child->next_role,
                      "first group member");
    pe__clear_resource_flags(rsc, pe_rsc_allocating|pe_rsc_provisional);

    if (group_data->colocated) {
        return group_node;
    }
    return NULL;
}

void group_update_pseudo_status(pe_resource_t * parent, pe_resource_t * child);

void
group_create_actions(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_action_t *op = NULL;
    const char *value = NULL;
    GList *gIter = rsc->children;

    pe_rsc_trace(rsc, "Creating actions for %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->create_actions(child_rsc, data_set);
        group_update_pseudo_status(rsc, child_rsc);
    }

    op = start_action(rsc, NULL, TRUE /* !group_data->child_starting */ );
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    op = custom_action(rsc, started_key(rsc),
                       RSC_STARTED, NULL, TRUE /* !group_data->child_starting */ , TRUE, data_set);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    op = stop_action(rsc, NULL, TRUE /* !group_data->child_stopping */ );
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    op = custom_action(rsc, stopped_key(rsc),
                       RSC_STOPPED, NULL, TRUE /* !group_data->child_stopping */ , TRUE, data_set);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_PROMOTABLE);
    if (crm_is_true(value)) {
        op = custom_action(rsc, demote_key(rsc), RSC_DEMOTE, NULL, TRUE, TRUE, data_set);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

        op = custom_action(rsc, demoted_key(rsc), RSC_DEMOTED, NULL, TRUE, TRUE, data_set);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

        op = custom_action(rsc, promote_key(rsc), RSC_PROMOTE, NULL, TRUE, TRUE, data_set);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

        op = custom_action(rsc, promoted_key(rsc), RSC_PROMOTED, NULL, TRUE, TRUE, data_set);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);
    }
}

void
group_update_pseudo_status(pe_resource_t * parent, pe_resource_t * child)
{
    GList *gIter = child->actions;
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
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (pcmk_is_set(action->flags, pe_action_optional)) {
            continue;
        }
        if (pcmk__str_eq(RSC_STOP, action->task, pcmk__str_casei)
            && pcmk_is_set(action->flags, pe_action_runnable)) {

            group_data->child_stopping = TRUE;
            pe_rsc_trace(action->rsc, "Based on %s the group is stopping", action->uuid);

        } else if (pcmk__str_eq(RSC_START, action->task, pcmk__str_casei)
                   && pcmk_is_set(action->flags, pe_action_runnable)) {
            group_data->child_starting = TRUE;
            pe_rsc_trace(action->rsc, "Based on %s the group is starting", action->uuid);
        }
    }
}

void
group_internal_constraints(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GList *gIter = rsc->children;
    pe_resource_t *last_rsc = NULL;
    pe_resource_t *last_active = NULL;
    pe_resource_t *top = uber_parent(rsc);
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional, data_set);
    pcmk__order_resource_actions(rsc, RSC_START, rsc, RSC_STARTED,
                                 pe_order_runnable_left, data_set);
    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_STOPPED,
                                 pe_order_runnable_left, data_set);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
        int stop = pe_order_none;
        int stopped = pe_order_implies_then_printed;
        int start = pe_order_implies_then | pe_order_runnable_left;
        int started =
            pe_order_runnable_left | pe_order_implies_then | pe_order_implies_then_printed;

        child_rsc->cmds->internal_constraints(child_rsc, data_set);

        if (last_rsc == NULL) {
            if (group_data->ordered) {
                pe__set_order_flags(stop, pe_order_optional);
                stopped = pe_order_implies_then;
            }

        } else if (group_data->colocated) {
            pcmk__new_colocation("group:internal_colocation", NULL, INFINITY,
                                 child_rsc, last_rsc, NULL, NULL,
                                 pcmk_is_set(child_rsc->flags, pe_rsc_critical),
                                 data_set);
        }

        if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
            pcmk__order_resource_actions(rsc, RSC_DEMOTE, child_rsc, RSC_DEMOTE,
                                         stop|pe_order_implies_first_printed,
                                         data_set);

            pcmk__order_resource_actions(child_rsc, RSC_DEMOTE, rsc,
                                         RSC_DEMOTED, stopped, data_set);

            pcmk__order_resource_actions(child_rsc, RSC_PROMOTE, rsc,
                                         RSC_PROMOTED, started, data_set);

            pcmk__order_resource_actions(rsc, RSC_PROMOTE, child_rsc,
                                         RSC_PROMOTE,
                                         pe_order_implies_first_printed,
                                         data_set);

        }

        pcmk__order_starts(rsc, child_rsc, pe_order_implies_first_printed,
                           data_set);
        pcmk__order_stops(rsc, child_rsc,
                          stop|pe_order_implies_first_printed, data_set);

        pcmk__order_resource_actions(child_rsc, RSC_STOP, rsc, RSC_STOPPED,
                                     stopped, data_set);
        pcmk__order_resource_actions(child_rsc, RSC_START, rsc, RSC_STARTED,
                                     started, data_set);

        if (group_data->ordered == FALSE) {
            pcmk__order_starts(rsc, child_rsc,
                               start|pe_order_implies_first_printed, data_set);
            if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
                pcmk__order_resource_actions(rsc, RSC_PROMOTE, child_rsc,
                                             RSC_PROMOTE,
                                             start|pe_order_implies_first_printed,
                                             data_set);
            }

        } else if (last_rsc != NULL) {
            pcmk__order_starts(last_rsc, child_rsc, start, data_set);
            pcmk__order_stops(child_rsc, last_rsc,
                              pe_order_optional|pe_order_restart, data_set);

            if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
                pcmk__order_resource_actions(last_rsc, RSC_PROMOTE, child_rsc,
                                             RSC_PROMOTE, start, data_set);
                pcmk__order_resource_actions(child_rsc, RSC_DEMOTE, last_rsc,
                                             RSC_DEMOTE, pe_order_optional,
                                             data_set);
            }

        } else {
            pcmk__order_starts(rsc, child_rsc, pe_order_none, data_set);
            if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
                pcmk__order_resource_actions(rsc, RSC_PROMOTE, child_rsc,
                                             RSC_PROMOTE, pe_order_none,
                                             data_set);
            }
        }

        /* Look for partially active groups
         * Make sure they still shut down in sequence
         */
        if (child_rsc->running_on) {
            if (group_data->ordered
                && last_rsc
                && last_rsc->running_on == NULL && last_active && last_active->running_on) {
                pcmk__order_stops(child_rsc, last_active, pe_order_optional,
                                  data_set);
            }
            last_active = child_rsc;
        }

        last_rsc = child_rsc;
    }

    if (group_data->ordered && last_rsc != NULL) {
        int stop_stop_flags = pe_order_implies_then;
        int stop_stopped_flags = pe_order_optional;

        pcmk__order_stops(rsc, last_rsc, stop_stop_flags, data_set);
        pcmk__order_resource_actions(last_rsc, RSC_STOP, rsc, RSC_STOPPED,
                                     stop_stopped_flags, data_set);

        if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
            pcmk__order_resource_actions(rsc, RSC_DEMOTE, last_rsc, RSC_DEMOTE,
                                         stop_stop_flags, data_set);
            pcmk__order_resource_actions(last_rsc, RSC_DEMOTE, rsc, RSC_DEMOTED,
                                         stop_stopped_flags, data_set);
        }
    }
}

void
group_rsc_colocation_lh(pe_resource_t *dependent, pe_resource_t *primary,
                        pcmk__colocation_t *constraint,
                        pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    group_variant_data_t *group_data = NULL;

    if (dependent == NULL) {
        pe_err("dependent was NULL for %s", constraint->id);
        return;

    } else if (primary == NULL) {
        pe_err("primary was NULL for %s", constraint->id);
        return;
    }

    gIter = dependent->children;
    pe_rsc_trace(dependent, "Processing constraints from %s", dependent->id);

    get_group_variant_data(group_data, dependent);

    if (group_data->colocated) {
        group_data->first_child->cmds->rsc_colocation_lh(group_data->first_child,
                                                         primary, constraint,
                                                         data_set);
        return;

    } else if (constraint->score >= INFINITY) {
        pcmk__config_err("%s: Cannot perform mandatory colocation "
                         "between non-colocated group and %s",
                         dependent->id, primary->id);
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_lh(child_rsc, primary, constraint,
                                           data_set);
    }
}

void
group_rsc_colocation_rh(pe_resource_t *dependent, pe_resource_t *primary,
                        pcmk__colocation_t *constraint,
                        pe_working_set_t *data_set)
{
    GList *gIter = primary->children;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, primary);
    CRM_CHECK(dependent->variant == pe_native, return);

    pe_rsc_trace(primary, "Processing RH %s of constraint %s (LH is %s)",
                 primary->id, constraint->id, dependent->id);

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        return;

    } else if (group_data->colocated && group_data->first_child) {
        if (constraint->score >= INFINITY) {
            /* Ensure RHS is _fully_ up before can start LHS */
            group_data->last_child->cmds->rsc_colocation_rh(dependent,
                                                            group_data->last_child,
                                                            constraint,
                                                            data_set);
        } else {
            /* A partially active RHS is fine */
            group_data->first_child->cmds->rsc_colocation_rh(dependent,
                                                             group_data->first_child,
                                                             constraint,
                                                             data_set);
        }

        return;

    } else if (constraint->score >= INFINITY) {
        pcmk__config_err("%s: Cannot perform mandatory colocation with"
                         " non-colocated group %s", dependent->id, primary->id);
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_rh(dependent, child_rsc, constraint,
                                           data_set);
    }
}

enum pe_action_flags
group_action_flags(pe_action_t * action, pe_node_t * node)
{
    GList *gIter = NULL;
    enum pe_action_flags flags = (pe_action_optional | pe_action_runnable | pe_action_pseudo);

    for (gIter = action->rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;
        enum action_tasks task = get_complex_task(child, action->task, TRUE);
        const char *task_s = task2text(task);
        pe_action_t *child_action = find_first_action(child->actions, NULL, task_s, node);

        if (child_action) {
            enum pe_action_flags child_flags = child->cmds->action_flags(child_action, node);

            if (pcmk_is_set(flags, pe_action_optional)
                && !pcmk_is_set(child_flags, pe_action_optional)) {
                pe_rsc_trace(action->rsc, "%s is mandatory because of %s", action->uuid,
                             child_action->uuid);
                pe__clear_raw_action_flags(flags, "group action",
                                           pe_action_optional);
                pe__clear_action_flags(action, pe_action_optional);
            }
            if (!pcmk__str_eq(task_s, action->task, pcmk__str_casei)
                && pcmk_is_set(flags, pe_action_runnable)
                && !pcmk_is_set(child_flags, pe_action_runnable)) {

                pe_rsc_trace(action->rsc, "%s is not runnable because of %s", action->uuid,
                             child_action->uuid);
                pe__clear_raw_action_flags(flags, "group action",
                                           pe_action_runnable);
                pe__clear_action_flags(action, pe_action_runnable);
            }

        } else if (task != stop_rsc && task != action_demote) {
            pe_rsc_trace(action->rsc, "%s is not runnable because of %s (not found in %s)",
                         action->uuid, task_s, child->id);
            pe__clear_raw_action_flags(flags, "group action",
                                       pe_action_runnable);
        }
    }

    return flags;
}

enum pe_graph_flags
group_update_actions(pe_action_t *first, pe_action_t *then, pe_node_t *node,
                     enum pe_action_flags flags, enum pe_action_flags filter,
                     enum pe_ordering type, pe_working_set_t *data_set)
{
    GList *gIter = then->rsc->children;
    enum pe_graph_flags changed = pe_graph_none;

    CRM_ASSERT(then->rsc != NULL);
    changed |= native_update_actions(first, then, node, flags, filter, type,
                                     data_set);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;
        pe_action_t *child_action = find_first_action(child->actions, NULL, then->task, node);

        if (child_action) {
            changed |= child->cmds->update_actions(first, child_action, node,
                                                   flags, filter, type,
                                                   data_set);
        }
    }

    return changed;
}

void
group_rsc_location(pe_resource_t *rsc, pe__location_t *constraint)
{
    GList *gIter = rsc->children;
    GList *saved = constraint->node_list_rh;
    GList *zero = pcmk__copy_node_list(constraint->node_list_rh, true);
    gboolean reset_scores = TRUE;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    pe_rsc_debug(rsc, "Processing rsc_location %s for %s", constraint->id, rsc->id);

    pcmk__apply_location(constraint, rsc);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

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
group_expand(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    CRM_CHECK(rsc != NULL, return);

    pe_rsc_trace(rsc, "Processing actions from %s", rsc->id);
    native_expand(rsc, data_set);

    for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->expand(child_rsc, data_set);
    }
}

GHashTable *
pcmk__group_merge_weights(pe_resource_t *rsc, const char *primary_id,
                          GHashTable *nodes, const char *attr, float factor,
                          uint32_t flags)
{
    GList *gIter = rsc->rsc_cons_lhs;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    if (pcmk_is_set(rsc->flags, pe_rsc_merging)) {
        pe_rsc_info(rsc, "Breaking dependency loop with %s at %s",
                    rsc->id, primary_id);
        return nodes;
    }

    pe__set_resource_flags(rsc, pe_rsc_merging);

    nodes = group_data->first_child->cmds->merge_weights(group_data->first_child,
                                                         primary_id, nodes,
                                                         attr, factor, flags);

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        nodes = pcmk__native_merge_weights(constraint->dependent, rsc->id,
                                           nodes, constraint->node_attribute,
                                           constraint->score / (float) INFINITY,
                                           flags);
    }

    pe__clear_resource_flags(rsc, pe_rsc_merging);
    return nodes;
}

void
group_append_meta(pe_resource_t * rsc, xmlNode * xml)
{
}

// Group implementation of resource_alloc_functions_t:colocated_resources()
GList *
pcmk__group_colocated_resources(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                                GList *colocated_rscs)
{
    pe_resource_t *child_rsc = NULL;
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);

    if (orig_rsc == NULL) {
        orig_rsc = rsc;
    }

    if (group_data->colocated || pe_rsc_is_clone(rsc->parent)) {
        /* This group has colocated members and/or is cloned -- either way,
         * add every child's colocated resources to the list.
         */
        for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            child_rsc = (pe_resource_t *) gIter->data;
            colocated_rscs = child_rsc->cmds->colocated_resources(child_rsc,
                                                                  orig_rsc,
                                                                  colocated_rscs);
        }

    } else if (group_data->first_child != NULL) {
        /* This group's members are not colocated, and the group is not cloned,
         * so just add the first child's colocations to the list.
         */
        child_rsc = group_data->first_child;
        colocated_rscs = child_rsc->cmds->colocated_resources(child_rsc,
                                                              orig_rsc,
                                                              colocated_rscs);
    }

    // Now consider colocations where the group itself is specified
    colocated_rscs = pcmk__colocated_resources(rsc, orig_rsc, colocated_rscs);

    return colocated_rscs;
}

// Group implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__group_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                            GList *all_rscs, GHashTable *utilization)
{
    group_variant_data_t *group_data = NULL;
    pe_resource_t *child = NULL;

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    pe_rsc_trace(orig_rsc, "%s: Adding group %s as colocated utilization",
                 orig_rsc->id, rsc->id);
    get_group_variant_data(group_data, rsc);
    if (group_data->colocated || pe_rsc_is_clone(rsc->parent)) {
        // Every group member will be on same node, so sum all members
        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            child = (pe_resource_t *) iter->data;

            if (pcmk_is_set(child->flags, pe_rsc_provisional)
                && (g_list_find(all_rscs, child) == NULL)) {
                child->cmds->add_utilization(child, orig_rsc, all_rscs,
                                             utilization);
            }
        }

    } else {
        // Just add first child's utilization
        child = group_data->first_child;
        if ((child != NULL)
            && pcmk_is_set(child->flags, pe_rsc_provisional)
            && (g_list_find(all_rscs, child) == NULL)) {

            child->cmds->add_utilization(child, orig_rsc, all_rscs,
                                         utilization);
        }
    }
}
