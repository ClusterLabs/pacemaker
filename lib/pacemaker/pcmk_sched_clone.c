/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

#define VARIANT_CLONE 1
#include <lib/pengine/variant.h>

static void append_parent_colocation(pe_resource_t * rsc, pe_resource_t * child, gboolean all);

static pe_node_t *
can_run_instance(pe_resource_t * rsc, pe_node_t * node, int limit)
{
    pe_node_t *local_node = NULL;

    if (node == NULL && rsc->allowed_nodes) {
        GHashTableIter iter;
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&local_node)) {
            can_run_instance(rsc, local_node, limit);
        }
        return NULL;
    }

    if (!node) {
        /* make clang analyzer happy */
        goto bail;

    } else if (!pcmk__node_available(node, false)) {
        goto bail;

    } else if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        goto bail;
    }

    local_node = pcmk__top_allowed_node(rsc, node);

    if (local_node == NULL) {
        crm_warn("%s cannot run on %s: node not allowed", rsc->id, node->details->uname);
        goto bail;

    } else if (local_node->weight < 0) {
        common_update_score(rsc, node->details->id, local_node->weight);
        pe_rsc_trace(rsc, "%s cannot run on %s: Parent node weight doesn't allow it.",
                     rsc->id, node->details->uname);

    } else if (local_node->count < limit) {
        pe_rsc_trace(rsc, "%s can run on %s (already running %d)",
                     rsc->id, node->details->uname, local_node->count);
        return local_node;

    } else {
        pe_rsc_trace(rsc, "%s cannot run on %s: node full (%d >= %d)",
                     rsc->id, node->details->uname, local_node->count, limit);
    }

  bail:
    if (node) {
        common_update_score(rsc, node->details->id, -INFINITY);
    }
    return NULL;
}

static pe_node_t *
allocate_instance(pe_resource_t *rsc, pe_node_t *prefer, gboolean all_coloc,
                  int limit, pe_working_set_t *data_set)
{
    pe_node_t *chosen = NULL;
    GHashTable *backup = NULL;

    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "Checking allocation of %s (preferring %s, using %s parent colocations)",
                 rsc->id, (prefer? prefer->details->uname: "none"),
                 (all_coloc? "all" : "some"));

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->fns->location(rsc, NULL, FALSE);

    } else if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    /* Only include positive colocation preferences of dependent resources
     * if not every node will get a copy of the clone
     */
    append_parent_colocation(rsc->parent, rsc, all_coloc);

    if (prefer) {
        pe_node_t *local_prefer = g_hash_table_lookup(rsc->allowed_nodes, prefer->details->id);

        if (local_prefer == NULL || local_prefer->weight < 0) {
            pe_rsc_trace(rsc, "Not pre-allocating %s to %s - unavailable", rsc->id,
                         prefer->details->uname);
            return NULL;
        }
    }

    can_run_instance(rsc, NULL, limit);

    backup = pcmk__copy_node_table(rsc->allowed_nodes);
    pe_rsc_trace(rsc, "Allocating instance %s", rsc->id);
    chosen = rsc->cmds->allocate(rsc, prefer, data_set);
    if (chosen && prefer && (chosen->details != prefer->details)) {
        crm_info("Not pre-allocating %s to %s because %s is better",
                 rsc->id, prefer->details->uname, chosen->details->uname);
        g_hash_table_destroy(rsc->allowed_nodes);
        rsc->allowed_nodes = backup;
        pcmk__unassign_resource(rsc);
        chosen = NULL;
        backup = NULL;
    }
    if (chosen) {
        pe_node_t *local_node = pcmk__top_allowed_node(rsc, chosen);

        if (local_node) {
            local_node->count++;

        } else if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            /* what to do? we can't enforce per-node limits in this case */
            pcmk__config_err("%s not found in %s (list of %d)",
                             chosen->details->id, rsc->parent->id,
                             g_hash_table_size(rsc->parent->allowed_nodes));
        }
    }

    if(backup) {
        g_hash_table_destroy(backup);
    }
    return chosen;
}

static void
append_parent_colocation(pe_resource_t * rsc, pe_resource_t * child, gboolean all)
{

    GList *gIter = NULL;

    gIter = rsc->rsc_cons;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) gIter->data;

        if (all || cons->score < 0 || cons->score == INFINITY) {
            child->rsc_cons = g_list_prepend(child->rsc_cons, cons);
        }
    }

    gIter = rsc->rsc_cons_lhs;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) gIter->data;

        if (!pcmk__colocation_has_influence(cons, child)) {
           continue;
        }
        if (all || cons->score < 0) {
            child->rsc_cons_lhs = g_list_prepend(child->rsc_cons_lhs, cons);
        }
    }
}


void
distribute_children(pe_resource_t *rsc, GList *children, GList *nodes,
                    int max, int per_host_max, pe_working_set_t * data_set);

void
distribute_children(pe_resource_t *rsc, GList *children, GList *nodes,
                    int max, int per_host_max, pe_working_set_t * data_set) 
{
    int loop_max = 0;
    int allocated = 0;
    int available_nodes = 0;
    bool all_coloc = false;

    /* count now tracks the number of clones currently allocated */
    for(GList *nIter = nodes; nIter != NULL; nIter = nIter->next) {
        pe_node_t *node = nIter->data;

        node->count = 0;
        if (pcmk__node_available(node, false)) {
            available_nodes++;
        }
    }

    all_coloc = (max < available_nodes) ? true : false;

    if(available_nodes) {
        loop_max = max / available_nodes;
    }
    if (loop_max < 1) {
        loop_max = 1;
    }

    pe_rsc_debug(rsc, "Allocating up to %d %s instances to a possible %d nodes (at most %d per host, %d optimal)",
                 max, rsc->id, available_nodes, per_host_max, loop_max);

    /* Pre-allocate as many instances as we can to their current location */
    for (GList *gIter = children; gIter != NULL && allocated < max; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;
        pe_node_t *child_node = NULL;
        pe_node_t *local_node = NULL;

        if ((child->running_on == NULL)
            || !pcmk_is_set(child->flags, pe_rsc_provisional)
            || pcmk_is_set(child->flags, pe_rsc_failed)) {

            continue;
        }

        child_node = pe__current_node(child);
        local_node = pcmk__top_allowed_node(child, child_node);

        pe_rsc_trace(rsc,
                     "Checking pre-allocation of %s to %s (%d remaining of %d)",
                     child->id, child_node->details->uname, max - allocated,
                     max);

        if (!pcmk__node_available(child_node, true)) {
            pe_rsc_trace(rsc, "Not pre-allocating because %s can not run %s",
                         child_node->details->uname, child->id);
            continue;
        }

        if ((local_node != NULL) && (local_node->count >= loop_max)) {
            pe_rsc_trace(rsc,
                         "Not pre-allocating because %s already allocated "
                         "optimal instances", child_node->details->uname);
            continue;
        }

        if (allocate_instance(child, child_node, all_coloc, per_host_max,
                              data_set)) {
            pe_rsc_trace(rsc, "Pre-allocated %s to %s", child->id,
                         child_node->details->uname);
            allocated++;
        }
    }

    pe_rsc_trace(rsc, "Done pre-allocating (%d of %d)", allocated, max);

    for (GList *gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        if (child->running_on != NULL) {
            pe_node_t *child_node = pe__current_node(child);
            pe_node_t *local_node = pcmk__top_allowed_node(child, child_node);

            if (local_node == NULL) {
                crm_err("%s is running on %s which isn't allowed",
                        child->id, child_node->details->uname);
            }
        }

        if (!pcmk_is_set(child->flags, pe_rsc_provisional)) {
        } else if (allocated >= max) {
            pe_rsc_debug(rsc, "Child %s not allocated - limit reached %d %d", child->id, allocated, max);
            resource_location(child, NULL, -INFINITY, "clone:limit_reached", data_set);
        } else {
            if (allocate_instance(child, NULL, all_coloc, per_host_max,
                                  data_set)) {
                allocated++;
            }
        }
    }

    pe_rsc_debug(rsc, "Allocated %d %s instances of a possible %d",
                 allocated, rsc->id, max);
}


pe_node_t *
pcmk__clone_allocate(pe_resource_t *rsc, pe_node_t *prefer,
                     pe_working_set_t *data_set)
{
    GList *nodes = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return NULL;

    } else if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__add_promotion_scores(rsc);
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);

    /* This information is used by pcmk__cmp_instance() when deciding the order
     * in which to assign clone instances to nodes.
     */
    for (GList *gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        pe_rsc_trace(rsc, "%s: Allocating %s first",
                     rsc->id, constraint->primary->id);
        constraint->primary->cmds->allocate(constraint->primary, prefer,
                                            data_set);
    }

    for (GList *gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        if (!pcmk__colocation_has_influence(constraint, NULL)) {
            continue;
        }
        rsc->allowed_nodes = constraint->dependent->cmds->merge_weights(
            constraint->dependent, rsc->id, rsc->allowed_nodes,
            constraint->node_attribute, (float)constraint->score / INFINITY,
            (pe_weights_rollback | pe_weights_positive));
    }

    pe__show_node_weights(!pcmk_is_set(data_set->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, data_set);

    nodes = g_hash_table_get_values(rsc->allowed_nodes);
    nodes = pcmk__sort_nodes(nodes, NULL, data_set);
    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance);
    distribute_children(rsc, rsc->children, nodes, clone_data->clone_max, clone_data->clone_node_max, data_set);
    g_list_free(nodes);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__set_instance_roles(rsc, data_set);
    }

    pe__clear_resource_flags(rsc, pe_rsc_provisional|pe_rsc_allocating);
    pe_rsc_trace(rsc, "Done allocating %s", rsc->id);
    return NULL;
}

static void
clone_update_pseudo_status(pe_resource_t * rsc, gboolean * stopping, gboolean * starting,
                           gboolean * active)
{
    GList *gIter = NULL;

    if (rsc->children) {

        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

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
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (*starting && *stopping) {
            return;

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            pe_rsc_trace(rsc, "Skipping optional: %s", action->uuid);
            continue;

        } else if (!pcmk_any_flags_set(action->flags,
                                       pe_action_pseudo|pe_action_runnable)) {
            pe_rsc_trace(rsc, "Skipping unrunnable: %s", action->uuid);
            continue;

        } else if (pcmk__str_eq(RSC_STOP, action->task, pcmk__str_casei)) {
            pe_rsc_trace(rsc, "Stopping due to: %s", action->uuid);
            *stopping = TRUE;

        } else if (pcmk__str_eq(RSC_START, action->task, pcmk__str_casei)) {
            if (!pcmk_is_set(action->flags, pe_action_runnable)) {
                pe_rsc_trace(rsc, "Skipping pseudo-op: %s run=%d, pseudo=%d",
                             action->uuid,
                             pcmk_is_set(action->flags, pe_action_runnable),
                             pcmk_is_set(action->flags, pe_action_pseudo));
            } else {
                pe_rsc_trace(rsc, "Starting due to: %s", action->uuid);
                pe_rsc_trace(rsc, "%s run=%d, pseudo=%d",
                             action->uuid,
                             pcmk_is_set(action->flags, pe_action_runnable),
                             pcmk_is_set(action->flags, pe_action_pseudo));
                *starting = TRUE;
            }
        }
    }
}

static pe_action_t *
find_rsc_action(pe_resource_t *rsc, const char *task)
{
    pe_action_t *match = NULL;
    GList *actions = pe__resource_actions(rsc, NULL, task, FALSE);

    for (GList *item = actions; item != NULL; item = item->next) {
        pe_action_t *op = (pe_action_t *) item->data;

        if (!pcmk_is_set(op->flags, pe_action_optional)) {
            if (match != NULL) {
                // More than one match, don't return any
                match = NULL;
                break;
            }
            match = op;
        }
    }
    g_list_free(actions);
    return match;
}

static void
child_ordering_constraints(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_action_t *stop = NULL;
    pe_action_t *start = NULL;
    pe_action_t *last_stop = NULL;
    pe_action_t *last_start = NULL;
    GList *gIter = NULL;

    if (!pe__clone_is_ordered(rsc)) {
        return;
    }

    /* we have to maintain a consistent sorted child list when building order constraints */
    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);

    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        stop = find_rsc_action(child, RSC_STOP);
        if (stop) {
            if (last_stop) {
                /* child/child relative stop */
                order_actions(stop, last_stop, pe_order_optional);
            }
            last_stop = stop;
        }

        start = find_rsc_action(child, RSC_START);
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
clone_create_actions(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);
    clone_create_pseudo_actions(rsc, rsc->children, &clone_data->start_notify, &clone_data->stop_notify,data_set);
    child_ordering_constraints(rsc, data_set);
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        create_promotable_actions(rsc, data_set);
    }
}

void
clone_create_pseudo_actions(
    pe_resource_t * rsc, GList *children, notify_data_t **start_notify, notify_data_t **stop_notify,  pe_working_set_t * data_set)
{
    gboolean child_active = FALSE;
    gboolean child_starting = FALSE;
    gboolean child_stopping = FALSE;
    gboolean allow_dependent_migrations = TRUE;

    pe_action_t *stop = NULL;
    pe_action_t *stopped = NULL;

    pe_action_t *start = NULL;
    pe_action_t *started = NULL;

    pe_rsc_trace(rsc, "Creating actions for %s", rsc->id);

    for (GList *gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
        gboolean starting = FALSE;
        gboolean stopping = FALSE;

        child_rsc->cmds->create_actions(child_rsc, data_set);
        clone_update_pseudo_status(child_rsc, &stopping, &starting, &child_active);
        if (stopping && starting) {
            allow_dependent_migrations = FALSE;
        }

        child_stopping |= stopping;
        child_starting |= starting;
    }

    /* start */
    start = pcmk__new_rsc_pseudo_action(rsc, RSC_START, !child_starting, true);
    started = pcmk__new_rsc_pseudo_action(rsc, RSC_STARTED, !child_starting,
                                          false);
    started->priority = INFINITY;

    if (child_active || child_starting) {
        pe__set_action_flags(started, pe_action_runnable);
    }

    if (start_notify != NULL && *start_notify == NULL) {
        *start_notify = pcmk__clone_notif_pseudo_ops(rsc, RSC_START, start,
                                                     started);
    }

    /* stop */
    stop = pcmk__new_rsc_pseudo_action(rsc, RSC_STOP, !child_stopping, true);
    stopped = pcmk__new_rsc_pseudo_action(rsc, RSC_STOPPED, !child_stopping,
                                          true);
    stopped->priority = INFINITY;
    if (allow_dependent_migrations) {
        pe__set_action_flags(stop, pe_action_migrate_runnable);
    }

    if (stop_notify != NULL && *stop_notify == NULL) {
        *stop_notify = pcmk__clone_notif_pseudo_ops(rsc, RSC_STOP, stop,
                                                    stopped);

        if (start_notify && *start_notify && *stop_notify) {
            order_actions((*stop_notify)->post_done, (*start_notify)->pre, pe_order_optional);
        }
    }
}

void
clone_internal_constraints(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    pe_resource_t *last_rsc = NULL;
    GList *gIter;
    bool ordered = pe__clone_is_ordered(rsc);

    pe_rsc_trace(rsc, "Internal constraints for %s", rsc->id);
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional, data_set);
    pcmk__order_resource_actions(rsc, RSC_START, rsc, RSC_STARTED,
                                 pe_order_runnable_left, data_set);
    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_STOPPED,
                                 pe_order_runnable_left, data_set);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_STOP,
                                     pe_order_optional, data_set);
        pcmk__order_resource_actions(rsc, RSC_STARTED, rsc, RSC_PROMOTE,
                                     pe_order_runnable_left, data_set);
    }

    if (ordered) {
        /* we have to maintain a consistent sorted child list when building order constraints */
        rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);
    }
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->internal_constraints(child_rsc, data_set);

        pcmk__order_starts(rsc, child_rsc,
                           pe_order_runnable_left|pe_order_implies_first_printed,
                           data_set);
        pcmk__order_resource_actions(child_rsc, RSC_START, rsc, RSC_STARTED,
                                     pe_order_implies_then_printed, data_set);
        if (ordered && (last_rsc != NULL)) {
            pcmk__order_starts(last_rsc, child_rsc, pe_order_optional,
                               data_set);
        }

        pcmk__order_stops(rsc, child_rsc, pe_order_implies_first_printed,
                          data_set);
        pcmk__order_resource_actions(child_rsc, RSC_STOP, rsc, RSC_STOPPED,
                                     pe_order_implies_then_printed, data_set);
        if (ordered && (last_rsc != NULL)) {
            pcmk__order_stops(child_rsc, last_rsc, pe_order_optional, data_set);
        }

        last_rsc = child_rsc;
    }
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        promotable_constraints(rsc, data_set);
    }
}

gboolean
is_child_compatible(pe_resource_t *child_rsc, pe_node_t * local_node, enum rsc_role_e filter, gboolean current) 
{
    pe_node_t *node = NULL;
    enum rsc_role_e next_role = child_rsc->fns->state(child_rsc, current);

    CRM_CHECK(child_rsc && local_node, return FALSE);
    if (is_set_recursive(child_rsc, pe_rsc_block, TRUE) == FALSE) {
        /* We only want instances that haven't failed */
        node = child_rsc->fns->location(child_rsc, NULL, current);
    }

    if (filter != RSC_ROLE_UNKNOWN && next_role != filter) {
        crm_trace("Filtered %s", child_rsc->id);
        return FALSE;
    }

    if (node && (node->details == local_node->details)) {
        return TRUE;

    } else if (node) {
        crm_trace("%s - %s vs %s", child_rsc->id, node->details->uname,
                  local_node->details->uname);

    } else {
        crm_trace("%s - not allocated %d", child_rsc->id, current);
    }
    return FALSE;
}

pe_resource_t *
find_compatible_child(pe_resource_t *local_child, pe_resource_t *rsc,
                      enum rsc_role_e filter, gboolean current,
                      pe_working_set_t *data_set)
{
    pe_resource_t *pair = NULL;
    GList *gIter = NULL;
    GList *scratch = NULL;
    pe_node_t *local_node = NULL;

    local_node = local_child->fns->location(local_child, NULL, current);
    if (local_node) {
        return find_compatible_child_by_node(local_child, local_node, rsc, filter, current);
    }

    scratch = g_hash_table_get_values(local_child->allowed_nodes);
    scratch = pcmk__sort_nodes(scratch, NULL, data_set);

    gIter = scratch;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        pair = find_compatible_child_by_node(local_child, node, rsc, filter, current);
        if (pair) {
            goto done;
        }
    }

    pe_rsc_debug(rsc, "Can't pair %s with %s", local_child->id, rsc->id);
  done:
    g_list_free(scratch);
    return pair;
}

void
clone_rsc_colocation_lh(pe_resource_t *dependent, pe_resource_t *primary,
                        pcmk__colocation_t *constraint,
                        pe_working_set_t *data_set)
{
    /* -- Never called --
     *
     * Instead we add the colocation constraints to the child and call from there
     */
    CRM_ASSERT(FALSE);
}

void
clone_rsc_colocation_rh(pe_resource_t *dependent, pe_resource_t *primary,
                        pcmk__colocation_t *constraint,
                        pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    gboolean do_interleave = FALSE;
    const char *interleave_s = NULL;

    CRM_CHECK(constraint != NULL, return);
    CRM_CHECK(dependent != NULL,
              pe_err("dependent was NULL for %s", constraint->id); return);
    CRM_CHECK(primary != NULL,
              pe_err("primary was NULL for %s", constraint->id); return);
    CRM_CHECK(dependent->variant == pe_native, return);

    pe_rsc_trace(primary, "Processing constraint %s: %s -> %s %d",
                 constraint->id, dependent->id, primary->id, constraint->score);

    if (pcmk_is_set(primary->flags, pe_rsc_promotable)) {
        if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
            pe_rsc_trace(primary, "%s is still provisional", primary->id);
            return;
        } else if (constraint->primary_role == RSC_ROLE_UNKNOWN) {
            pe_rsc_trace(primary, "Handling %s as a clone colocation",
                         constraint->id);
        } else {
            promotable_colocation_rh(dependent, primary, constraint, data_set);
            return;
        }
    }

    /* only the LHS side needs to be labeled as interleave */
    interleave_s = g_hash_table_lookup(constraint->dependent->meta,
                                       XML_RSC_ATTR_INTERLEAVE);
    if (crm_is_true(interleave_s)
        && (constraint->dependent->variant > pe_group)) {
        /* @TODO Do we actually care about multiple primary copies sharing a
         * dependent copy anymore?
         */
        if (copies_per_node(constraint->dependent) != copies_per_node(constraint->primary)) {
            pcmk__config_err("Cannot interleave %s and %s because they do not "
                             "support the same number of instances per node",
                             constraint->dependent->id,
                             constraint->primary->id);

        } else {
            do_interleave = TRUE;
        }
    }

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        pe_rsc_trace(primary, "%s is still provisional", primary->id);
        return;

    } else if (do_interleave) {
        pe_resource_t *primary_instance = NULL;

        primary_instance = find_compatible_child(dependent, primary,
                                                 RSC_ROLE_UNKNOWN, FALSE,
                                                 data_set);
        if (primary_instance != NULL) {
            pe_rsc_debug(primary, "Pairing %s with %s",
                         dependent->id, primary_instance->id);
            dependent->cmds->rsc_colocation_lh(dependent, primary_instance,
                                               constraint, data_set);

        } else if (constraint->score >= INFINITY) {
            crm_notice("Cannot pair %s with instance of %s",
                       dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true);

        } else {
            pe_rsc_debug(primary, "Cannot pair %s with instance of %s",
                         dependent->id, primary->id);
        }

        return;

    } else if (constraint->score >= INFINITY) {
        GList *affected_nodes = NULL;

        gIter = primary->children;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
            pe_node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);

            if (chosen != NULL && is_set_recursive(child_rsc, pe_rsc_block, TRUE) == FALSE) {
                pe_rsc_trace(primary, "Allowing %s: %s %d",
                             constraint->id, chosen->details->uname,
                             chosen->weight);
                affected_nodes = g_list_prepend(affected_nodes, chosen);
            }
        }

        node_list_exclude(dependent->allowed_nodes, affected_nodes, FALSE);
        g_list_free(affected_nodes);
        return;
    }

    gIter = primary->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->rsc_colocation_rh(dependent, child_rsc, constraint,
                                           data_set);
    }
}

enum action_tasks
clone_child_action(pe_action_t * action)
{
    enum action_tasks result = no_action;
    pe_resource_t *child = (pe_resource_t *) action->rsc->children->data;

    if (pcmk__strcase_any_of(action->task, "notify", "notified", NULL)) {

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
                task_mutable = strdup(key + lpc);
                task_mutable[stop - lpc] = 0;

                crm_trace("Extracted action '%s' from '%s'", task_mutable, key);
                result = get_complex_task(child, task_mutable, TRUE);
                free(task_mutable);
                break;
            }
        }

    } else {
        result = get_complex_task(child, action->task, TRUE);
    }
    return result;
}

#define pe__clear_action_summary_flags(flags, action, flag) do {        \
        flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                     "Action summary", action->rsc->id, \
                                     flags, flag, #flag);               \
    } while (0)

enum pe_action_flags
summary_action_flags(pe_action_t * action, GList *children, pe_node_t * node)
{
    GList *gIter = NULL;
    gboolean any_runnable = FALSE;
    gboolean check_runnable = TRUE;
    enum action_tasks task = clone_child_action(action);
    enum pe_action_flags flags = (pe_action_optional | pe_action_runnable | pe_action_pseudo);
    const char *task_s = task2text(task);

    for (gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_action_t *child_action = NULL;
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        child_action = find_first_action(child->actions, NULL, task_s, child->children ? NULL : node);
        pe_rsc_trace(action->rsc, "Checking for %s in %s on %s (%s)", task_s, child->id,
                     node ? node->details->uname : "none", child_action?child_action->uuid:"NA");
        if (child_action) {
            enum pe_action_flags child_flags = child->cmds->action_flags(child_action, node);

            if (pcmk_is_set(flags, pe_action_optional)
                && !pcmk_is_set(child_flags, pe_action_optional)) {
                pe_rsc_trace(child, "%s is mandatory because of %s", action->uuid,
                             child_action->uuid);
                pe__clear_action_summary_flags(flags, action, pe_action_optional);
                pe__clear_action_flags(action, pe_action_optional);
            }
            if (pcmk_is_set(child_flags, pe_action_runnable)) {
                any_runnable = TRUE;
            }
        }
    }

    if (check_runnable && any_runnable == FALSE) {
        pe_rsc_trace(action->rsc, "%s is not runnable because no children are", action->uuid);
        pe__clear_action_summary_flags(flags, action, pe_action_runnable);
        if (node == NULL) {
            pe__clear_action_flags(action, pe_action_runnable);
        }
    }

    return flags;
}

enum pe_action_flags
clone_action_flags(pe_action_t * action, pe_node_t * node)
{
    return summary_action_flags(action, action->rsc->children, node);
}

void
clone_rsc_location(pe_resource_t *rsc, pe__location_t *constraint)
{
    GList *gIter = rsc->children;

    pe_rsc_trace(rsc, "Processing location constraint %s for %s", constraint->id, rsc->id);

    pcmk__apply_location(constraint, rsc);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->rsc_location(child_rsc, constraint);
    }
}

void
clone_expand(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    g_list_foreach(rsc->actions, (GFunc) rsc->cmds->action_flags, NULL);

    pcmk__create_notifications(rsc, clone_data->start_notify);
    pcmk__create_notifications(rsc, clone_data->stop_notify);
    pcmk__create_notifications(rsc, clone_data->promote_notify);
    pcmk__create_notifications(rsc, clone_data->demote_notify);

    /* Now that the notifcations have been created we can expand the children */

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->expand(child_rsc, data_set);
    }

    native_expand(rsc, data_set);

    /* The notifications are in the graph now, we can destroy the notify_data */
    pcmk__free_notification_data(clone_data->demote_notify);
    clone_data->demote_notify = NULL;
    pcmk__free_notification_data(clone_data->stop_notify);
    clone_data->stop_notify = NULL;
    pcmk__free_notification_data(clone_data->start_notify);
    clone_data->start_notify = NULL;
    pcmk__free_notification_data(clone_data->promote_notify);
    clone_data->promote_notify = NULL;
}

// Check whether a resource or any of its children is known on node
static bool
rsc_known_on(const pe_resource_t *rsc, const pe_node_t *node)
{
    if (rsc->children) {
        for (GList *child_iter = rsc->children; child_iter != NULL;
             child_iter = child_iter->next) {

            pe_resource_t *child = (pe_resource_t *) child_iter->data;

            if (rsc_known_on(child, node)) {
                return TRUE;
            }
        }

    } else if (rsc->known_on) {
        GHashTableIter iter;
        pe_node_t *known_node = NULL;

        g_hash_table_iter_init(&iter, rsc->known_on);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &known_node)) {
            if (node->details == known_node->details) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// Look for an instance of clone that is known on node
static pe_resource_t *
find_instance_on(const pe_resource_t *clone, const pe_node_t *node)
{
    for (GList *gIter = clone->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        if (rsc_known_on(child, node)) {
            return child;
        }
    }
    return NULL;
}

// For unique clones, probe each instance separately
static gboolean
probe_unique_clone(pe_resource_t *rsc, pe_node_t *node, pe_action_t *complete,
                   gboolean force, pe_working_set_t *data_set)
{
    gboolean any_created = FALSE;

    for (GList *child_iter = rsc->children; child_iter != NULL;
         child_iter = child_iter->next) {

        pe_resource_t *child = (pe_resource_t *) child_iter->data;

        any_created |= child->cmds->create_probe(child, node, complete, force,
                                                 data_set);
    }
    return any_created;
}

// For anonymous clones, only a single instance needs to be probed
static gboolean
probe_anonymous_clone(pe_resource_t *rsc, pe_node_t *node,
                      pe_action_t *complete, gboolean force,
                      pe_working_set_t *data_set)
{
    // First, check if we probed an instance on this node last time
    pe_resource_t *child = find_instance_on(rsc, node);

    // Otherwise, check if we plan to start an instance on this node
    if (child == NULL) {
        for (GList *child_iter = rsc->children; child_iter && !child;
             child_iter = child_iter->next) {

            pe_node_t *local_node = NULL;
            pe_resource_t *child_rsc = (pe_resource_t *) child_iter->data;

            if (child_rsc) { /* make clang analyzer happy */
                local_node = child_rsc->fns->location(child_rsc, NULL, FALSE);
                if (local_node && (local_node->details == node->details)) {
                    child = child_rsc;
                }
            }
        }
    }

    // Otherwise, use the first clone instance
    if (child == NULL) {
        child = rsc->children->data;
    }
    CRM_ASSERT(child);
    return child->cmds->create_probe(child, node, complete, force, data_set);
}

gboolean
clone_create_probe(pe_resource_t * rsc, pe_node_t * node, pe_action_t * complete,
                   gboolean force, pe_working_set_t * data_set)
{
    gboolean any_created = FALSE;

    CRM_ASSERT(rsc);

    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);
    if (rsc->children == NULL) {
        pe_warn("Clone %s has no children", rsc->id);
        return FALSE;
    }

    if (rsc->exclusive_discover) {
        pe_node_t *allowed = g_hash_table_lookup(rsc->allowed_nodes, node->details->id);
        if (allowed && allowed->rsc_discover_mode != pe_discover_exclusive) {
            /* exclusive discover is enabled and this node is not marked
             * as a node this resource should be discovered on
             *
             * remove the node from allowed_nodes so that the
             * notification contains only nodes that we might ever run
             * on
             */
            g_hash_table_remove(rsc->allowed_nodes, node->details->id);

            /* Bit of a shortcut - might as well take it */
            return FALSE;
        }
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        any_created = probe_unique_clone(rsc, node, complete, force, data_set);
    } else {
        any_created = probe_anonymous_clone(rsc, node, complete, force,
                                            data_set);
    }
    return any_created;
}

void
clone_append_meta(pe_resource_t * rsc, xmlNode * xml)
{
    char *name = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    name = crm_meta_name(XML_RSC_ATTR_UNIQUE);
    crm_xml_add(xml, name, pe__rsc_bool_str(rsc, pe_rsc_unique));
    free(name);

    name = crm_meta_name(XML_RSC_ATTR_NOTIFY);
    crm_xml_add(xml, name, pe__rsc_bool_str(rsc, pe_rsc_notify));
    free(name);

    name = crm_meta_name(XML_RSC_ATTR_INCARNATION_MAX);
    crm_xml_add_int(xml, name, clone_data->clone_max);
    free(name);

    name = crm_meta_name(XML_RSC_ATTR_INCARNATION_NODEMAX);
    crm_xml_add_int(xml, name, clone_data->clone_node_max);
    free(name);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        name = crm_meta_name(XML_RSC_ATTR_PROMOTED_MAX);
        crm_xml_add_int(xml, name, clone_data->promoted_max);
        free(name);

        name = crm_meta_name(XML_RSC_ATTR_PROMOTED_NODEMAX);
        crm_xml_add_int(xml, name, clone_data->promoted_node_max);
        free(name);

        /* @COMPAT Maintain backward compatibility with resource agents that
         * expect the old names (deprecated since 2.0.0).
         */
        name = crm_meta_name(PCMK_XE_PROMOTED_MAX_LEGACY);
        crm_xml_add_int(xml, name, clone_data->promoted_max);
        free(name);

        name = crm_meta_name(PCMK_XE_PROMOTED_NODE_MAX_LEGACY);
        crm_xml_add_int(xml, name, clone_data->promoted_node_max);
        free(name);
    }
}

// Clone implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__clone_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                            GList *all_rscs, GHashTable *utilization)
{
    bool existing = false;
    pe_resource_t *child = NULL;

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    // Look for any child already existing in the list
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        child = (pe_resource_t *) iter->data;
        if (g_list_find(all_rscs, child)) {
            existing = true; // Keep checking remaining children
        } else {
            // If this is a clone of a group, look for group's members
            for (GList *member_iter = child->children; member_iter != NULL;
                 member_iter = member_iter->next) {

                pe_resource_t *member = (pe_resource_t *) member_iter->data;

                if (g_list_find(all_rscs, member) != NULL) {
                    // Add *child's* utilization, not group member's
                    child->cmds->add_utilization(child, orig_rsc, all_rscs,
                                                 utilization);
                    existing = true;
                    break;
                }
            }
        }
    }

    if (!existing && (rsc->children != NULL)) {
        // If nothing was found, still add first child's utilization
        child = (pe_resource_t *) rsc->children->data;

        child->cmds->add_utilization(child, orig_rsc, all_rscs, utilization);
    }
}

// Clone implementation of resource_alloc_functions_t:shutdown_lock()
void
pcmk__clone_shutdown_lock(pe_resource_t *rsc)
{
    return; // Clones currently don't support shutdown locks
}
