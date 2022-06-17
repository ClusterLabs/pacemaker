/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

/*!
 * \internal
 * \brief Expand a group's colocations to its members
 *
 * \param[in,out] rsc  Group resource
 */
static void
expand_group_colocations(pe_resource_t *rsc)
{
    pe_resource_t *member = NULL;
    bool any_unmanaged = false;

    // Treat "group with R" colocations as "first member with R"
    member = (pe_resource_t *) rsc->children->data;
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
    member = pe__last_group_member(rsc);
    member->rsc_cons_lhs = g_list_concat(member->rsc_cons_lhs,
                                         rsc->rsc_cons_lhs);
    rsc->rsc_cons_lhs = NULL;
}

/*!
 * \internal
 * \brief Assign a group resource to a node
 *
 * \param[in,out] rsc     Group resource to assign to a node
 * \param[in]     prefer  Node to prefer, if all else is equal
 *
 * \return Node that \p rsc is assigned to, if assigned entirely to one node
 */
pe_node_t *
pcmk__group_assign(pe_resource_t *rsc, const pe_node_t *prefer)
{
    pe_node_t *first_assigned_node = NULL;
    pe_resource_t *first_member = NULL;

    CRM_ASSERT(rsc != NULL);

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->allocated_to; // Assignment already done
    }
    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Assignment dependency loop detected involving %s",
                     rsc->id);
        return NULL;
    }

    if (rsc->children == NULL) {
        // No members to assign
        pe__clear_resource_flags(rsc, pe_rsc_provisional);
        return NULL;
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    first_member = (pe_resource_t *) rsc->children->data;
    rsc->role = first_member->role;

    expand_group_colocations(rsc);

    pe__show_node_weights(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, rsc->cluster);

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *member = (pe_resource_t *) iter->data;
        pe_node_t *node = NULL;

        pe_rsc_trace(rsc, "Assigning group %s member %s",
                     rsc->id, member->id);
        node = member->cmds->assign(member, prefer);
        if (first_assigned_node == NULL) {
            first_assigned_node = node;
        }
    }

    pe__set_next_role(rsc, first_member->next_role, "first group member");
    pe__clear_resource_flags(rsc, pe_rsc_allocating|pe_rsc_provisional);

    if (!pe__group_flag_is_set(rsc, pe__group_colocated)) {
        return NULL;
    }
    return first_assigned_node;
}

void
group_create_actions(pe_resource_t *rsc)
{
    pe_action_t *op = NULL;
    const char *value = NULL;
    GList *gIter = rsc->children;

    pe_rsc_trace(rsc, "Creating actions for %s", rsc->id);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->create_actions(child_rsc);
    }

    op = start_action(rsc, NULL, TRUE);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    op = custom_action(rsc, started_key(rsc), RSC_STARTED, NULL,
                       TRUE, TRUE, rsc->cluster);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    op = stop_action(rsc, NULL, TRUE);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    op = custom_action(rsc, stopped_key(rsc), RSC_STOPPED, NULL,
                       TRUE, TRUE, rsc->cluster);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

    value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_PROMOTABLE);
    if (crm_is_true(value)) {
        op = custom_action(rsc, demote_key(rsc), RSC_DEMOTE, NULL, TRUE, TRUE,
                           rsc->cluster);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

        op = custom_action(rsc, demoted_key(rsc), RSC_DEMOTED, NULL, TRUE, TRUE,
                           rsc->cluster);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

        op = custom_action(rsc, promote_key(rsc), RSC_PROMOTE, NULL, TRUE, TRUE,
                           rsc->cluster);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);

        op = custom_action(rsc, promoted_key(rsc), RSC_PROMOTED, NULL, TRUE,
                           TRUE, rsc->cluster);
        pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);
    }
}

void
group_internal_constraints(pe_resource_t *rsc)
{
    GList *gIter = rsc->children;
    pe_resource_t *last_rsc = NULL;
    pe_resource_t *last_active = NULL;
    pe_resource_t *top = uber_parent(rsc);
    bool ordered = pe__group_flag_is_set(rsc, pe__group_ordered);
    bool colocated = pe__group_flag_is_set(rsc, pe__group_colocated);

    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_START, rsc, RSC_STARTED,
                                 pe_order_runnable_left);
    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_STOPPED,
                                 pe_order_runnable_left);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
        int stop = pe_order_none;
        int stopped = pe_order_implies_then_printed;
        int start = pe_order_implies_then | pe_order_runnable_left;
        int started =
            pe_order_runnable_left | pe_order_implies_then | pe_order_implies_then_printed;

        child_rsc->cmds->internal_constraints(child_rsc);

        if (last_rsc == NULL) {
            if (ordered) {
                pe__set_order_flags(stop, pe_order_optional);
                stopped = pe_order_implies_then;
            }

        } else if (colocated) {
            pcmk__new_colocation("group:internal_colocation", NULL, INFINITY,
                                 child_rsc, last_rsc, NULL, NULL,
                                 pcmk_is_set(child_rsc->flags, pe_rsc_critical),
                                 rsc->cluster);
        }

        if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
            pcmk__order_resource_actions(rsc, RSC_DEMOTE, child_rsc, RSC_DEMOTE,
                                         stop|pe_order_implies_first_printed);

            pcmk__order_resource_actions(child_rsc, RSC_DEMOTE, rsc,
                                         RSC_DEMOTED, stopped);

            pcmk__order_resource_actions(child_rsc, RSC_PROMOTE, rsc,
                                         RSC_PROMOTED, started);

            pcmk__order_resource_actions(rsc, RSC_PROMOTE, child_rsc,
                                         RSC_PROMOTE,
                                         pe_order_implies_first_printed);

        }

        pcmk__order_starts(rsc, child_rsc, pe_order_implies_first_printed);
        pcmk__order_stops(rsc, child_rsc,
                          stop|pe_order_implies_first_printed);

        pcmk__order_resource_actions(child_rsc, RSC_STOP, rsc, RSC_STOPPED,
                                     stopped);
        pcmk__order_resource_actions(child_rsc, RSC_START, rsc, RSC_STARTED,
                                     started);

        if (!ordered) {
            pcmk__order_starts(rsc, child_rsc,
                               start|pe_order_implies_first_printed);
            if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
                pcmk__order_resource_actions(rsc, RSC_PROMOTE, child_rsc,
                                             RSC_PROMOTE,
                                             start|pe_order_implies_first_printed);
            }

        } else if (last_rsc != NULL) {
            pcmk__order_starts(last_rsc, child_rsc, start);
            pcmk__order_stops(child_rsc, last_rsc,
                              pe_order_optional|pe_order_restart);

            if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
                pcmk__order_resource_actions(last_rsc, RSC_PROMOTE, child_rsc,
                                             RSC_PROMOTE, start);
                pcmk__order_resource_actions(child_rsc, RSC_DEMOTE, last_rsc,
                                             RSC_DEMOTE, pe_order_optional);
            }

        } else {
            pcmk__order_starts(rsc, child_rsc, pe_order_none);
            if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
                pcmk__order_resource_actions(rsc, RSC_PROMOTE, child_rsc,
                                             RSC_PROMOTE, pe_order_none);
            }
        }

        /* Look for partially active groups
         * Make sure they still shut down in sequence
         */
        if (child_rsc->running_on) {
            if (ordered && (last_rsc != NULL)
                && last_rsc->running_on == NULL && last_active && last_active->running_on) {
                pcmk__order_stops(child_rsc, last_active, pe_order_optional);
            }
            last_active = child_rsc;
        }

        last_rsc = child_rsc;
    }

    if (ordered && (last_rsc != NULL)) {
        int stop_stop_flags = pe_order_implies_then;
        int stop_stopped_flags = pe_order_optional;

        pcmk__order_stops(rsc, last_rsc, stop_stop_flags);
        pcmk__order_resource_actions(last_rsc, RSC_STOP, rsc, RSC_STOPPED,
                                     stop_stopped_flags);

        if (pcmk_is_set(top->flags, pe_rsc_promotable)) {
            pcmk__order_resource_actions(rsc, RSC_DEMOTE, last_rsc, RSC_DEMOTE,
                                         stop_stop_flags);
            pcmk__order_resource_actions(last_rsc, RSC_DEMOTE, rsc, RSC_DEMOTED,
                                         stop_stopped_flags);
        }
    }
}

/*!
 * \internal
 * \brief Apply a colocation's score to node weights or resource priority
 *
 * Given a colocation constraint, apply its score to the dependent's
 * allowed node weights (if we are still placing resources) or priority (if
 * we are choosing promotable clone instance roles).
 *
 * \param[in,out] dependent      Dependent resource in colocation
 * \param[in]     primary        Primary resource in colocation
 * \param[in]     colocation     Colocation constraint to apply
 * \param[in]     for_dependent  true if called on behalf of dependent
 */
void
pcmk__group_apply_coloc_score(pe_resource_t *dependent,
                              const pe_resource_t *primary,
                              const pcmk__colocation_t *colocation,
                              bool for_dependent)
{
    GList *gIter = NULL;
    pe_resource_t *member = NULL;

    CRM_CHECK((colocation != NULL) && (dependent != NULL) && (primary != NULL),
              return);

    if (!for_dependent) {
        goto for_primary;
    }

    gIter = dependent->children;
    pe_rsc_trace(dependent, "Processing constraints from %s", dependent->id);

    if (pe__group_flag_is_set(dependent, pe__group_colocated)) {
        member = (pe_resource_t *) dependent->children->data;
        member->cmds->apply_coloc_score(member, primary, colocation, true);
        return;

    } else if (colocation->score >= INFINITY) {
        pcmk__config_err("%s: Cannot perform mandatory colocation "
                         "between non-colocated group and %s",
                         dependent->id, primary->id);
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->apply_coloc_score(child_rsc, primary, colocation,
                                           true);
    }
    return;

for_primary:
    gIter = primary->children;
    CRM_CHECK(dependent->variant == pe_native, return);

    pe_rsc_trace(primary,
                 "Processing colocation %s (%s with group %s) for primary",
                 colocation->id, dependent->id, primary->id);

    member = (pe_resource_t *) primary->children->data;

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        return;

    } else if (pe__group_flag_is_set(primary, pe__group_colocated)
               && (member != NULL)) {
        if (colocation->score >= INFINITY) {
            // Dependent can't start until group is fully up
            member = pe__last_group_member(primary);
        } // else dependent can start as long as group is partially up
        member->cmds->apply_coloc_score(dependent, member, colocation, false);
        return;

    } else if (colocation->score >= INFINITY) {
        pcmk__config_err("%s: Cannot perform mandatory colocation with"
                         " non-colocated group %s", dependent->id, primary->id);
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->apply_coloc_score(dependent, child_rsc, colocation,
                                           false);
    }
}

enum pe_action_flags
group_action_flags(pe_action_t *action, const pe_node_t *node)
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

/*!
 * \internal
 * \brief Update two actions according to an ordering between them
 *
 * Given information about an ordering of two actions, update the actions'
 * flags (and runnable_before members if appropriate) as appropriate for the
 * ordering. In some cases, the ordering could be disabled as well.
 *
 * \param[in] first     'First' action in an ordering
 * \param[in] then      'Then' action in an ordering
 * \param[in] node      If not NULL, limit scope of ordering to this node
 *                      (only used when interleaving instances)
 * \param[in] flags     Action flags for \p first for ordering purposes
 * \param[in] filter    Action flags to limit scope of certain updates (may
 *                      include pe_action_optional to affect only mandatory
 *                      actions, and pe_action_runnable to affect only
 *                      runnable actions)
 * \param[in] type      Group of enum pe_ordering flags to apply
 * \param[in] data_set  Cluster working set
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
uint32_t
group_update_actions(pe_action_t *first, pe_action_t *then, pe_node_t *node,
                     uint32_t flags, uint32_t filter, uint32_t type,
                     pe_working_set_t *data_set)
{
    GList *gIter = then->rsc->children;
    uint32_t changed = pcmk__updated_none;

    CRM_ASSERT(then->rsc != NULL);
    changed |= pcmk__update_ordered_actions(first, then, node, flags, filter,
                                            type, data_set);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;
        pe_action_t *child_action = find_first_action(child->actions, NULL, then->task, node);

        if (child_action) {
            changed |= child->cmds->update_ordered_actions(first, child_action,
                                                           node, flags, filter,
                                                           type, data_set);
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
    gboolean reset_scores = pe__group_flag_is_set(rsc, pe__group_colocated);

    pe_rsc_debug(rsc, "Processing rsc_location %s for %s", constraint->id, rsc->id);

    pcmk__apply_location(rsc, constraint);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->apply_location(child_rsc, constraint);
        if (reset_scores) {
            reset_scores = FALSE;
            constraint->node_list_rh = zero;
        }
    }

    constraint->node_list_rh = saved;
    g_list_free_full(zero, free);
}

/*!
 * \internal
 * \brief Update nodes with scores of colocated resources' nodes
 *
 * Given a table of nodes and a resource, update the nodes' scores with the
 * scores of the best nodes matching the attribute used for each of the
 * resource's relevant colocations.
 *
 * \param[in,out] rsc      Resource to check colocations for
 * \param[in]     log_id   Resource ID to use in log messages
 * \param[in,out] nodes    Nodes to update
 * \param[in]     attr     Colocation attribute (NULL to use default)
 * \param[in]     factor   Incorporate scores multiplied by this factor
 * \param[in]     flags    Bitmask of enum pcmk__coloc_select values
 *
 * \note The caller remains responsible for freeing \p *nodes.
 */
void
pcmk__group_add_colocated_node_scores(pe_resource_t *rsc, const char *log_id,
                                      GHashTable **nodes, const char *attr,
                                      float factor, uint32_t flags)
{
    GList *gIter = rsc->rsc_cons_lhs;
    pe_resource_t *member = NULL;

    CRM_CHECK((rsc != NULL) && (nodes != NULL), return);

    if (log_id == NULL) {
        log_id = rsc->id;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_merging)) {
        pe_rsc_info(rsc, "Breaking dependency loop with %s at %s",
                    rsc->id, log_id);
        return;
    }

    pe__set_resource_flags(rsc, pe_rsc_merging);

    member = (pe_resource_t *) rsc->children->data;
    member->cmds->add_colocated_node_scores(member, log_id, nodes, attr,
                                            factor, flags);

    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        pcmk__add_colocated_node_scores(constraint->dependent, rsc->id, nodes,
                                        constraint->node_attribute,
                                        constraint->score / (float) INFINITY,
                                        flags);
    }

    pe__clear_resource_flags(rsc, pe_rsc_merging);
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

    if (orig_rsc == NULL) {
        orig_rsc = rsc;
    }

    if (pe__group_flag_is_set(rsc, pe__group_colocated)
        || pe_rsc_is_clone(rsc->parent)) {
        /* This group has colocated members and/or is cloned -- either way,
         * add every child's colocated resources to the list.
         */
        for (GList *gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            child_rsc = (pe_resource_t *) gIter->data;
            colocated_rscs = child_rsc->cmds->colocated_resources(child_rsc,
                                                                  orig_rsc,
                                                                  colocated_rscs);
        }

    } else if (rsc->children != NULL) {
        /* This group's members are not colocated, and the group is not cloned,
         * so just add the first child's colocations to the list.
         */
        child_rsc = (pe_resource_t *) rsc->children->data;
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
pcmk__group_add_utilization(const pe_resource_t *rsc,
                            const pe_resource_t *orig_rsc, GList *all_rscs,
                            GHashTable *utilization)
{
    pe_resource_t *child = NULL;

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    pe_rsc_trace(orig_rsc, "%s: Adding group %s as colocated utilization",
                 orig_rsc->id, rsc->id);
    if (pe__group_flag_is_set(rsc, pe__group_colocated)
        || pe_rsc_is_clone(rsc->parent)) {
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
        child = (pe_resource_t *) rsc->children->data;
        if ((child != NULL)
            && pcmk_is_set(child->flags, pe_rsc_provisional)
            && (g_list_find(all_rscs, child) == NULL)) {

            child->cmds->add_utilization(child, orig_rsc, all_rscs,
                                         utilization);
        }
    }
}

// Group implementation of resource_alloc_functions_t:shutdown_lock()
void
pcmk__group_shutdown_lock(pe_resource_t *rsc)
{
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child = (pe_resource_t *) iter->data;

        child->cmds->shutdown_lock(child);
    }
}
