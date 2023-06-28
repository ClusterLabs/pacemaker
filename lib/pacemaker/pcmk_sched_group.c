/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group));

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

    pe__show_node_scores(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
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

/*!
 * \internal
 * \brief Create a pseudo-operation for a group as an ordering point
 *
 * \param[in,out] group   Group resource to create action for
 * \param[in]     action  Action name
 *
 * \return Newly created pseudo-operation
 */
static pe_action_t *
create_group_pseudo_op(pe_resource_t *group, const char *action)
{
    pe_action_t *op = custom_action(group, pcmk__op_key(group->id, action, 0),
                                    action, NULL, TRUE, TRUE, group->cluster);
    pe__set_action_flags(op, pe_action_pseudo|pe_action_runnable);
    return op;
}

/*!
 * \internal
 * \brief Create all actions needed for a given group resource
 *
 * \param[in,out] rsc  Group resource to create actions for
 */
void
pcmk__group_create_actions(pe_resource_t *rsc)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group));

    pe_rsc_trace(rsc, "Creating actions for group %s", rsc->id);

    // Create actions for individual group members
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *member = (pe_resource_t *) iter->data;

        member->cmds->create_actions(member);
    }

    // Create pseudo-actions for group itself to serve as ordering points
    create_group_pseudo_op(rsc, RSC_START);
    create_group_pseudo_op(rsc, RSC_STARTED);
    create_group_pseudo_op(rsc, RSC_STOP);
    create_group_pseudo_op(rsc, RSC_STOPPED);
    if (crm_is_true(g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_PROMOTABLE))) {
        create_group_pseudo_op(rsc, RSC_DEMOTE);
        create_group_pseudo_op(rsc, RSC_DEMOTED);
        create_group_pseudo_op(rsc, RSC_PROMOTE);
        create_group_pseudo_op(rsc, RSC_PROMOTED);
    }
}

// User data for member_internal_constraints()
struct member_data {
    // These could be derived from member but this avoids some function calls
    bool ordered;
    bool colocated;
    bool promotable;

    pe_resource_t *last_active;
    pe_resource_t *previous_member;
};

/*!
 * \internal
 * \brief Create implicit constraints needed for a group member
 *
 * \param[in,out] data       Group member to create implicit constraints for
 * \param[in,out] user_data  Member data (struct member_data *)
 */
static void
member_internal_constraints(gpointer data, gpointer user_data)
{
    pe_resource_t *member = (pe_resource_t *) data;
    struct member_data *member_data = (struct member_data *) user_data;

    // For ordering demote vs demote or stop vs stop
    uint32_t down_flags = pe_order_implies_first_printed;

    // For ordering demote vs demoted or stop vs stopped
    uint32_t post_down_flags = pe_order_implies_then_printed;

    // Create the individual member's implicit constraints
    member->cmds->internal_constraints(member);

    if (member_data->previous_member == NULL) {
        // This is first member
        if (member_data->ordered) {
            pe__set_order_flags(down_flags, pe_order_optional);
            post_down_flags = pe_order_implies_then;
        }

    } else if (member_data->colocated) {
        // Colocate this member with the previous one
        pcmk__new_colocation("group:internal_colocation", NULL, INFINITY,
                             member, member_data->previous_member, NULL, NULL,
                             pcmk_is_set(member->flags, pe_rsc_critical));
    }

    if (member_data->promotable) {
        // Demote group -> demote member -> group is demoted
        pcmk__order_resource_actions(member->parent, RSC_DEMOTE,
                                     member, RSC_DEMOTE, down_flags);
        pcmk__order_resource_actions(member, RSC_DEMOTE,
                                     member->parent, RSC_DEMOTED,
                                     post_down_flags);

        // Promote group -> promote member -> group is promoted
        pcmk__order_resource_actions(member, RSC_PROMOTE,
                                     member->parent, RSC_PROMOTED,
                                     pe_order_runnable_left
                                     |pe_order_implies_then
                                     |pe_order_implies_then_printed);
        pcmk__order_resource_actions(member->parent, RSC_PROMOTE,
                                     member, RSC_PROMOTE,
                                     pe_order_implies_first_printed);
    }

    // Stop group -> stop member -> group is stopped
    pcmk__order_stops(member->parent, member, down_flags);
    pcmk__order_resource_actions(member, RSC_STOP, member->parent, RSC_STOPPED,
                                 post_down_flags);

    // Start group -> start member -> group is started
    pcmk__order_starts(member->parent, member, pe_order_implies_first_printed);
    pcmk__order_resource_actions(member, RSC_START, member->parent, RSC_STARTED,
                                 pe_order_runnable_left
                                 |pe_order_implies_then
                                 |pe_order_implies_then_printed);

    if (!member_data->ordered) {
        pcmk__order_starts(member->parent, member,
                           pe_order_implies_then
                           |pe_order_runnable_left
                           |pe_order_implies_first_printed);
        if (member_data->promotable) {
            pcmk__order_resource_actions(member->parent, RSC_PROMOTE, member,
                                         RSC_PROMOTE,
                                         pe_order_implies_then
                                         |pe_order_runnable_left
                                         |pe_order_implies_first_printed);
        }

    } else if (member_data->previous_member == NULL) {
        pcmk__order_starts(member->parent, member, pe_order_none);
        if (member_data->promotable) {
            pcmk__order_resource_actions(member->parent, RSC_PROMOTE, member,
                                         RSC_PROMOTE, pe_order_none);
        }

    } else {
        // Order this member relative to the previous one

        pcmk__order_starts(member_data->previous_member, member,
                           pe_order_implies_then|pe_order_runnable_left);
        pcmk__order_stops(member, member_data->previous_member,
                          pe_order_optional|pe_order_restart);

        /* In unusual circumstances (such as adding a new member to the middle
         * of a group with unmanaged later members), this member may be active
         * while the previous (new) member is inactive. In this situation, the
         * usual restart orderings will be irrelevant, so we need to order this
         * member's stop before the previous member's start.
         */
        if ((member->running_on != NULL)
            && (member_data->previous_member->running_on == NULL)) {
            pcmk__order_resource_actions(member, RSC_STOP,
                                         member_data->previous_member,
                                         RSC_START,
                                         pe_order_implies_first
                                         |pe_order_runnable_left);
        }

        if (member_data->promotable) {
            pcmk__order_resource_actions(member_data->previous_member,
                                         RSC_PROMOTE, member, RSC_PROMOTE,
                                         pe_order_implies_then
                                         |pe_order_runnable_left);
            pcmk__order_resource_actions(member, RSC_DEMOTE,
                                         member_data->previous_member,
                                         RSC_DEMOTE, pe_order_optional);
        }
    }

    // Make sure partially active groups shut down in sequence
    if (member->running_on != NULL) {
        if (member_data->ordered && (member_data->previous_member != NULL)
            && (member_data->previous_member->running_on == NULL)
            && (member_data->last_active != NULL)
            && (member_data->last_active->running_on != NULL)) {
            pcmk__order_stops(member, member_data->last_active,
                              pe_order_optional);
        }
        member_data->last_active = member;
    }

    member_data->previous_member = member;
}

/*!
 * \internal
 * \brief Create implicit constraints needed for a group resource
 *
 * \param[in,out] rsc  Group resource to create implicit constraints for
 */
void
pcmk__group_internal_constraints(pe_resource_t *rsc)
{
    struct member_data member_data = { false, };
    const pe_resource_t *top = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group));

    /* Order group pseudo-actions relative to each other for restarting:
     * stop group -> group is stopped -> start group -> group is started
     */
    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_STOPPED,
                                 pe_order_runnable_left);
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_START, rsc, RSC_STARTED,
                                 pe_order_runnable_left);

    top = pe__const_top_resource(rsc, false);

    member_data.ordered = pe__group_flag_is_set(rsc, pe__group_ordered);
    member_data.colocated = pe__group_flag_is_set(rsc, pe__group_colocated);
    member_data.promotable = pcmk_is_set(top->flags, pe_rsc_promotable);
    g_list_foreach(rsc->children, member_internal_constraints, &member_data);
}

/*!
 * \internal
 * \brief Apply a colocation's score to node scores or resource priority
 *
 * Given a colocation constraint for a group with some other resource, apply the
 * score to the dependent's allowed node scores (if we are still placing
 * resources) or priority (if we are choosing promotable clone instance roles).
 *
 * \param[in,out] dependent      Dependent group resource in colocation
 * \param[in]     primary        Primary resource in colocation
 * \param[in]     colocation     Colocation constraint to apply
 */
static void
colocate_group_with(pe_resource_t *dependent, const pe_resource_t *primary,
                    const pcmk__colocation_t *colocation)
{
    pe_resource_t *member = NULL;

    if (dependent->children == NULL) {
        return;
    }

    pe_rsc_trace(primary, "Processing %s (group %s with %s) for dependent",
                 colocation->id, dependent->id, primary->id);

    if (pe__group_flag_is_set(dependent, pe__group_colocated)) {
        // Colocate first member (internal colocations will handle the rest)
        member = (pe_resource_t *) dependent->children->data;
        member->cmds->apply_coloc_score(member, primary, colocation, true);
        return;
    }

    if (colocation->score >= INFINITY) {
        pcmk__config_err("%s: Cannot perform mandatory colocation between "
                         "non-colocated group and %s",
                         dependent->id, primary->id);
        return;
    }

    // Colocate each member individually
    for (GList *iter = dependent->children; iter != NULL; iter = iter->next) {
        member = (pe_resource_t *) iter->data;
        member->cmds->apply_coloc_score(member, primary, colocation, true);
    }
}

/*!
 * \internal
 * \brief Apply a colocation's score to node scores or resource priority
 *
 * Given a colocation constraint for some other resource with a group, apply the
 * score to the dependent's allowed node scores (if we are still placing
 * resources) or priority (if we are choosing promotable clone instance roles).
 *
 * \param[in,out] dependent      Dependent resource in colocation
 * \param[in]     primary        Primary group resource in colocation
 * \param[in]     colocation     Colocation constraint to apply
 */
static void
colocate_with_group(pe_resource_t *dependent, const pe_resource_t *primary,
                    const pcmk__colocation_t *colocation)
{
    const pe_resource_t *member = NULL;

    pe_rsc_trace(primary,
                 "Processing colocation %s (%s with group %s) for primary",
                 colocation->id, dependent->id, primary->id);

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        return;
    }

    if (pe__group_flag_is_set(primary, pe__group_colocated)) {

        if (colocation->score >= INFINITY) {
            /* For mandatory colocations, the entire group must be assignable
             * (and in the specified role if any), so apply the colocation based
             * on the last member.
             */
            member = pe__last_group_member(primary);
        } else if (primary->children != NULL) {
            /* For optional colocations, whether the group is partially or fully
             * up doesn't matter, so apply the colocation based on the first
             * member.
             */
            member = (pe_resource_t *) primary->children->data;
        }
        if (member == NULL) {
            return; // Nothing to colocate with
        }

        member->cmds->apply_coloc_score(dependent, member, colocation, false);
        return;
    }

    if (colocation->score >= INFINITY) {
        pcmk__config_err("%s: Cannot perform mandatory colocation with"
                         " non-colocated group %s",
                         dependent->id, primary->id);
        return;
    }

    // Colocate dependent with each member individually
    for (const GList *iter = primary->children; iter != NULL;
         iter = iter->next) {
        member = iter->data;
        member->cmds->apply_coloc_score(dependent, member, colocation, false);
    }
}

/*!
 * \internal
 * \brief Apply a colocation's score to node scores or resource priority
 *
 * Given a colocation constraint, apply its score to the dependent's
 * allowed node scores (if we are still placing resources) or priority (if
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
    CRM_ASSERT((dependent != NULL) && (primary != NULL)
               && (colocation != NULL));

    if (for_dependent) {
        colocate_group_with(dependent, primary, colocation);

    } else {
        // Method should only be called for primitive dependents
        CRM_ASSERT(dependent->variant == pe_native);

        colocate_with_group(dependent, primary, colocation);
    }
}

/*!
 * \internal
 * \brief Return action flags for a given group resource action
 *
 * \param[in,out] action  Group action to get flags for
 * \param[in]     node    If not NULL, limit effects to this node
 *
 * \return Flags appropriate to \p action on \p node
 */
uint32_t
pcmk__group_action_flags(pe_action_t *action, const pe_node_t *node)
{
    // Default flags for a group action
    uint32_t flags = pe_action_optional|pe_action_runnable|pe_action_pseudo;

    CRM_ASSERT(action != NULL);

    // Update flags considering each member's own flags for same action
    for (GList *iter = action->rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *member = (pe_resource_t *) iter->data;

        // Check whether member has the same action
        enum action_tasks task = get_complex_task(member, action->task);
        const char *task_s = task2text(task);
        pe_action_t *member_action = find_first_action(member->actions, NULL,
                                                       task_s, node);

        if (member_action != NULL) {
            uint32_t member_flags = member->cmds->action_flags(member_action,
                                                               node);

            // Group action is mandatory if any member action is
            if (pcmk_is_set(flags, pe_action_optional)
                && !pcmk_is_set(member_flags, pe_action_optional)) {
                pe_rsc_trace(action->rsc, "%s is mandatory because %s is",
                             action->uuid, member_action->uuid);
                pe__clear_raw_action_flags(flags, "group action",
                                           pe_action_optional);
                pe__clear_action_flags(action, pe_action_optional);
            }

            // Group action is unrunnable if any member action is
            if (!pcmk__str_eq(task_s, action->task, pcmk__str_none)
                && pcmk_is_set(flags, pe_action_runnable)
                && !pcmk_is_set(member_flags, pe_action_runnable)) {

                pe_rsc_trace(action->rsc, "%s is unrunnable because %s is",
                             action->uuid, member_action->uuid);
                pe__clear_raw_action_flags(flags, "group action",
                                           pe_action_runnable);
                pe__clear_action_flags(action, pe_action_runnable);
            }

        /* Group (pseudo-)actions other than stop or demote are unrunnable
         * unless every member will do it.
         */
        } else if ((task != stop_rsc) && (task != action_demote)) {
            pe_rsc_trace(action->rsc,
                         "%s is not runnable because %s will not %s",
                         action->uuid, member->id, task_s);
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
 * Given information about an ordering of two actions, update the actions' flags
 * (and runnable_before members if appropriate) as appropriate for the ordering.
 * Effects may cascade to other orderings involving the actions as well.
 *
 * \param[in,out] first     'First' action in an ordering
 * \param[in,out] then      'Then' action in an ordering
 * \param[in]     node      If not NULL, limit scope of ordering to this node
 *                          (only used when interleaving instances)
 * \param[in]     flags     Action flags for \p first for ordering purposes
 * \param[in]     filter    Action flags to limit scope of certain updates (may
 *                          include pe_action_optional to affect only mandatory
 *                          actions, and pe_action_runnable to affect only
 *                          runnable actions)
 * \param[in]     type      Group of enum pe_ordering flags to apply
 * \param[in,out] data_set  Cluster working set
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
uint32_t
pcmk__group_update_ordered_actions(pe_action_t *first, pe_action_t *then,
                                   const pe_node_t *node, uint32_t flags,
                                   uint32_t filter, uint32_t type,
                                   pe_working_set_t *data_set)
{
    uint32_t changed = pcmk__updated_none;

    // Group method can be called only on behalf of "then" action
    CRM_ASSERT((first != NULL) && (then != NULL) && (then->rsc != NULL)
               && (data_set != NULL));

    // Update the actions for the group itself
    changed |= pcmk__update_ordered_actions(first, then, node, flags, filter,
                                            type, data_set);

    // Update the actions for each group member
    for (GList *iter = then->rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *member = (pe_resource_t *) iter->data;

        pe_action_t *member_action = find_first_action(member->actions, NULL,
                                                       then->task, node);

        if (member_action != NULL) {
            changed |= member->cmds->update_ordered_actions(first,
                                                            member_action, node,
                                                            flags, filter, type,
                                                            data_set);
        }
    }
    return changed;
}

/*!
 * \internal
 * \brief Apply a location constraint to a group's allowed node scores
 *
 * \param[in,out] rsc       Group resource to apply constraint to
 * \param[in,out] location  Location constraint to apply
 */
void
pcmk__group_apply_location(pe_resource_t *rsc, pe__location_t *location)
{
    GList *node_list_orig = NULL;
    GList *node_list_copy = NULL;
    bool reset_scores = true;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group)
               && (location != NULL));

    node_list_orig = location->node_list_rh;
    node_list_copy = pcmk__copy_node_list(node_list_orig, true);
    reset_scores = pe__group_flag_is_set(rsc, pe__group_colocated);

    // Apply the constraint for the group itself (updates node scores)
    pcmk__apply_location(rsc, location);

    // Apply the constraint for each member
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *member = (pe_resource_t *) iter->data;

        member->cmds->apply_location(member, location);

        if (reset_scores) {
            /* The first member of colocated groups needs to use the original
             * node scores, but subsequent members should work on a copy, since
             * the first member's scores already incorporate theirs.
             */
            reset_scores = false;
            location->node_list_rh = node_list_copy;
        }
    }

    location->node_list_rh = node_list_orig;
    g_list_free_full(node_list_copy, free);
}

// Group implementation of resource_alloc_functions_t:colocated_resources()
GList *
pcmk__group_colocated_resources(const pe_resource_t *rsc,
                                const pe_resource_t *orig_rsc,
                                GList *colocated_rscs)
{
    const pe_resource_t *member = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group));

    if (orig_rsc == NULL) {
        orig_rsc = rsc;
    }

    if (pe__group_flag_is_set(rsc, pe__group_colocated)
        || pe_rsc_is_clone(rsc->parent)) {
        /* This group has colocated members and/or is cloned -- either way,
         * add every child's colocated resources to the list. The first and last
         * members will include the group's own colocations.
         */
        colocated_rscs = g_list_prepend(colocated_rscs, (gpointer) rsc);
        for (const GList *iter = rsc->children;
             iter != NULL; iter = iter->next) {

            member = (const pe_resource_t *) iter->data;
            colocated_rscs = member->cmds->colocated_resources(member, orig_rsc,
                                                               colocated_rscs);
        }

    } else if (rsc->children != NULL) {
        /* This group's members are not colocated, and the group is not cloned,
         * so just add the group's own colocations to the list.
         */
        colocated_rscs = pcmk__colocated_resources(rsc, orig_rsc,
                                                   colocated_rscs);
    }

    return colocated_rscs;
}

// Group implementation of resource_alloc_functions_t:with_this_colocations()
void
pcmk__with_group_colocations(const pe_resource_t *rsc,
                             const pe_resource_t *orig_rsc, GList **list)

{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group)
               && (orig_rsc != NULL) && (list != NULL));

    // Ignore empty groups
    if (rsc->children == NULL) {
        return;
    }

    /* "With this" colocations are needed only for the group itself and for its
     * last member. Add the group's colocations plus any relevant
     * parent colocations if cloned.
     */
    if ((rsc == orig_rsc) || (orig_rsc == pe__last_group_member(rsc))) {
        crm_trace("Adding 'with %s' colocations to list for %s",
                  rsc->id, orig_rsc->id);
        pcmk__add_with_this_list(list, rsc->rsc_cons_lhs);
        if (rsc->parent != NULL) { // Cloned group
            rsc->parent->cmds->with_this_colocations(rsc->parent, orig_rsc,
                                                     list);
        }
    }
}

// Group implementation of resource_alloc_functions_t:this_with_colocations()
void
pcmk__group_with_colocations(const pe_resource_t *rsc,
                             const pe_resource_t *orig_rsc, GList **list)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group)
               && (orig_rsc != NULL) && (list != NULL));

    // Ignore empty groups
    if (rsc->children == NULL) {
        return;
    }

    /* Colocations for the group itself, or for its first member, consist of the
     * group's colocations plus any relevant parent colocations if cloned.
     */
    if ((rsc == orig_rsc)
        || (orig_rsc == (const pe_resource_t *) rsc->children->data)) {
        crm_trace("Adding '%s with' colocations to list for %s",
                  rsc->id, orig_rsc->id);
        pcmk__add_this_with_list(list, rsc->rsc_cons);
        if (rsc->parent != NULL) { // Cloned group
            rsc->parent->cmds->this_with_colocations(rsc->parent, orig_rsc,
                                                     list);
        }
        return;
    }

    /* Later group members honor the group's colocations indirectly, due to the
     * internal group colocations that chain everything from the first member.
     * However, if an earlier group member is unmanaged, this chaining will not
     * happen, so the group's mandatory colocations must be explicitly added.
     */
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        const pe_resource_t *member = (const pe_resource_t *) iter->data;

        if (orig_rsc == member) {
            break; // We've seen all earlier members, and none are unmanaged
        }

        if (!pcmk_is_set(member->flags, pe_rsc_managed)) {
            crm_trace("Adding mandatory '%s with' colocations to list for "
                      "member %s because earlier member %s is unmanaged",
                      rsc->id, orig_rsc->id, member->id);
            for (const GList *cons_iter = rsc->rsc_cons; cons_iter != NULL;
                 cons_iter = cons_iter->next) {
                const pcmk__colocation_t *colocation = NULL;

                colocation = (const pcmk__colocation_t *) cons_iter->data;
                if (colocation->score == INFINITY) {
                    pcmk__add_this_with(list, colocation);
                }
            }
            // @TODO Add mandatory (or all?) clone constraints if cloned
            break;
        }
    }
}

/*!
 * \internal
 * \brief Update nodes with scores of colocated resources' nodes
 *
 * Given a table of nodes and a resource, update the nodes' scores with the
 * scores of the best nodes matching the attribute used for each of the
 * resource's relevant colocations.
 *
 * \param[in,out] rsc         Group resource to check colocations for
 * \param[in]     log_id      Resource ID for logs (if NULL, use \p rsc ID)
 * \param[in,out] nodes       Nodes to update (set initial contents to NULL
 *                            to copy \p rsc's allowed nodes)
 * \param[in]     colocation  Original colocation constraint (used to get
 *                            configured primary resource's stickiness, and
 *                            to get colocation node attribute; if NULL,
 *                            \p rsc's own matching node scores will not be
 *                            added, and *nodes must be NULL as well)
 * \param[in]     factor      Incorporate scores multiplied by this factor
 * \param[in]     flags       Bitmask of enum pcmk__coloc_select values
 *
 * \note NULL *nodes, NULL colocation, and the pcmk__coloc_select_this_with
 *       flag are used together (and only by cmp_resources()).
 * \note The caller remains responsible for freeing \p *nodes.
 */
void
pcmk__group_add_colocated_node_scores(pe_resource_t *rsc, const char *log_id,
                                      GHashTable **nodes,
                                      pcmk__colocation_t *colocation,
                                      float factor, uint32_t flags)
{
    pe_resource_t *member = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group) && (nodes != NULL)
               && ((colocation != NULL) || (*nodes == NULL)));

    if (log_id == NULL) {
        log_id = rsc->id;
    }

    // Avoid infinite recursion
    if (pcmk_is_set(rsc->flags, pe_rsc_merging)) {
        pe_rsc_info(rsc, "%s: Breaking dependency loop at %s",
                    log_id, rsc->id);
        return;
    }
    pe__set_resource_flags(rsc, pe_rsc_merging);

    // Ignore empty groups (only possible with schema validation disabled)
    if (rsc->children == NULL) {
        return;
    }

    /* Refer the operation to the first or last member as appropriate.
     *
     * cmp_resources() is the only caller that passes a NULL nodes table,
     * and is also the only caller using pcmk__coloc_select_this_with.
     * For "this with" colocations, the last member will recursively incorporate
     * all the other members' "this with" colocations via the internal group
     * colocations (and via the first member, the group's own colocations).
     *
     * For "with this" colocations, the first member works similarly.
     */
    if (*nodes == NULL) {
        member = pe__last_group_member(rsc);
    } else {
        member = rsc->children->data;
    }
    pe_rsc_trace(rsc, "%s: Merging scores from group %s using member %s "
                 "(at %.6f)", log_id, rsc->id, member->id, factor);
    member->cmds->add_colocated_node_scores(member, log_id, nodes, colocation,
                                            factor, flags);
    pe__clear_resource_flags(rsc, pe_rsc_merging);
}

// Group implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__group_add_utilization(const pe_resource_t *rsc,
                            const pe_resource_t *orig_rsc, GList *all_rscs,
                            GHashTable *utilization)
{
    pe_resource_t *member = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group)
               && (orig_rsc != NULL) && (utilization != NULL));

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    pe_rsc_trace(orig_rsc, "%s: Adding group %s as colocated utilization",
                 orig_rsc->id, rsc->id);
    if (pe__group_flag_is_set(rsc, pe__group_colocated)
        || pe_rsc_is_clone(rsc->parent)) {
        // Every group member will be on same node, so sum all members
        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            member = (pe_resource_t *) iter->data;

            if (pcmk_is_set(member->flags, pe_rsc_provisional)
                && (g_list_find(all_rscs, member) == NULL)) {
                member->cmds->add_utilization(member, orig_rsc, all_rscs,
                                              utilization);
            }
        }

    } else if (rsc->children != NULL) {
        // Just add first member's utilization
        member = (pe_resource_t *) rsc->children->data;
        if ((member != NULL)
            && pcmk_is_set(member->flags, pe_rsc_provisional)
            && (g_list_find(all_rscs, member) == NULL)) {

            member->cmds->add_utilization(member, orig_rsc, all_rscs,
                                          utilization);
        }
    }
}

// Group implementation of resource_alloc_functions_t:shutdown_lock()
void
pcmk__group_shutdown_lock(pe_resource_t *rsc)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_group));

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *member = (pe_resource_t *) iter->data;

        member->cmds->shutdown_lock(member);
    }
}
