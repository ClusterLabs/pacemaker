/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/param.h>
#include <glib.h>

#include <crm/lrmd_internal.h>
#include <crm/common/scheduler_internal.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Get the action flags relevant to ordering constraints
 *
 * \param[in,out] action  Action to check
 * \param[in]     node    Node that *other* action in the ordering is on
 *                        (used only for clone resource actions)
 *
 * \return Action flags that should be used for orderings
 */
static uint32_t
action_flags_for_ordering(pcmk_action_t *action, const pcmk_node_t *node)
{
    bool runnable = false;
    uint32_t flags;

    // For non-resource actions, return the action flags
    if (action->rsc == NULL) {
        return action->flags;
    }

    /* For non-clone resources, or a clone action not assigned to a node,
     * return the flags as determined by the resource method without a node
     * specified.
     */
    flags = action->rsc->priv->cmds->action_flags(action, NULL);
    if ((node == NULL) || !pcmk__is_clone(action->rsc)) {
        return flags;
    }

    /* Otherwise (i.e., for clone resource actions on a specific node), first
     * remember whether the non-node-specific action is runnable.
     */
    runnable = pcmk_is_set(flags, pcmk__action_runnable);

    // Then recheck the resource method with the node
    flags = action->rsc->priv->cmds->action_flags(action, node);

    /* For clones in ordering constraints, the node-specific "runnable" doesn't
     * matter, just the non-node-specific setting (i.e., is the action runnable
     * anywhere).
     *
     * This applies only to runnable, and only for ordering constraints. This
     * function shouldn't be used for other types of constraints without
     * changes. Not very satisfying, but it's logical and appears to work well.
     */
    if (runnable && !pcmk_is_set(flags, pcmk__action_runnable)) {
        pcmk__set_raw_action_flags(flags, action->rsc->id,
                                   pcmk__action_runnable);
    }
    return flags;
}

/*!
 * \internal
 * \brief Get action UUID that should be used with a resource ordering
 *
 * When an action is ordered relative to an action for a collective resource
 * (clone, group, or bundle), it actually needs to be ordered after all
 * instances of the collective have completed the relevant action (for example,
 * given "start CLONE then start RSC", RSC must wait until all instances of
 * CLONE have started). Given the UUID and resource of the first action in an
 * ordering, this returns the UUID of the action that should actually be used
 * for ordering (for example, "CLONE_started_0" instead of "CLONE_start_0").
 *
 * \param[in] first_uuid    UUID of first action in ordering
 * \param[in] first_rsc     Resource of first action in ordering
 *
 * \return Newly allocated copy of UUID to use with ordering
 * \note It is the caller's responsibility to free the return value.
 */
static char *
action_uuid_for_ordering(const char *first_uuid,
                         const pcmk_resource_t *first_rsc)
{
    guint interval_ms = 0;
    char *uuid = NULL;
    char *rid = NULL;
    char *first_task_str = NULL;
    enum pcmk__action_type first_task = pcmk__action_unspecified;
    enum pcmk__action_type remapped_task = pcmk__action_unspecified;

    // Only non-notify actions for collective resources need remapping
    if ((strstr(first_uuid, PCMK_ACTION_NOTIFY) != NULL)
        || (first_rsc->priv->variant < pcmk__rsc_variant_group)) {
        goto done;
    }

    // Only non-recurring actions need remapping
    pcmk__assert(parse_op_key(first_uuid, &rid, &first_task_str, &interval_ms));
    if (interval_ms > 0) {
        goto done;
    }

    first_task = pcmk__parse_action(first_task_str);
    switch (first_task) {
        case pcmk__action_stop:
        case pcmk__action_start:
        case pcmk__action_notify:
        case pcmk__action_promote:
        case pcmk__action_demote:
            remapped_task = first_task + 1;
            break;
        case pcmk__action_stopped:
        case pcmk__action_started:
        case pcmk__action_notified:
        case pcmk__action_promoted:
        case pcmk__action_demoted:
            remapped_task = first_task;
            break;
        case pcmk__action_monitor:
        case pcmk__action_shutdown:
        case pcmk__action_fence:
            break;
        default:
            crm_err("Unknown action '%s' in ordering", first_task_str);
            break;
    }

    if (remapped_task != pcmk__action_unspecified) {
        /* If a clone or bundle has notifications enabled, the ordering will be
         * relative to when notifications have been sent for the remapped task.
         */
        if (pcmk_is_set(first_rsc->flags, pcmk__rsc_notify)
            && (pcmk__is_clone(first_rsc) || pcmk__is_bundled(first_rsc))) {
            uuid = pcmk__notify_key(rid, "confirmed-post",
                                    pcmk__action_text(remapped_task));
        } else {
            uuid = pcmk__op_key(rid, pcmk__action_text(remapped_task), 0);
        }
        pcmk__rsc_trace(first_rsc,
                        "Remapped action UUID %s to %s for ordering purposes",
                        first_uuid, uuid);
    }

done:
    free(first_task_str);
    free(rid);
    return (uuid != NULL)? uuid : pcmk__str_copy(first_uuid);
}

/*!
 * \internal
 * \brief Get actual action that should be used with an ordering
 *
 * When an action is ordered relative to an action for a collective resource
 * (clone, group, or bundle), it actually needs to be ordered after all
 * instances of the collective have completed the relevant action (for example,
 * given "start CLONE then start RSC", RSC must wait until all instances of
 * CLONE have started). Given the first action in an ordering, this returns the
 * the action that should actually be used for ordering (for example, the
 * started action instead of the start action).
 *
 * \param[in] action  First action in an ordering
 *
 * \return Actual action that should be used for the ordering
 */
static pcmk_action_t *
action_for_ordering(pcmk_action_t *action)
{
    pcmk_action_t *result = action;
    pcmk_resource_t *rsc = action->rsc;

    if (rsc == NULL) {
        return result;
    }

    if ((rsc->priv->variant >= pcmk__rsc_variant_group)
        && (action->uuid != NULL)) {
        char *uuid = action_uuid_for_ordering(action->uuid, rsc);

        result = find_first_action(rsc->priv->actions, uuid, NULL, NULL);
        if (result == NULL) {
            crm_warn("Not remapping %s to %s because %s does not have "
                     "remapped action", action->uuid, uuid, rsc->id);
            result = action;
        }
        free(uuid);
    }
    return result;
}

/*!
 * \internal
 * \brief Wrapper for update_ordered_actions() method for readability
 *
 * \param[in,out] rsc        Resource to call method for
 * \param[in,out] first      'First' action in an ordering
 * \param[in,out] then       'Then' action in an ordering
 * \param[in]     node       If not NULL, limit scope of ordering to this
 *                           node (only used when interleaving instances)
 * \param[in]     flags      Action flags for \p first for ordering purposes
 * \param[in]     filter     Action flags to limit scope of certain updates
 *                           (may include pcmk__action_optional to affect only
 *                           mandatory actions, and pe_action_runnable to
 *                           affect only runnable actions)
 * \param[in]     type       Group of enum pcmk__action_relation_flags to apply
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
static inline uint32_t
update(pcmk_resource_t *rsc, pcmk_action_t *first, pcmk_action_t *then,
       const pcmk_node_t *node, uint32_t flags, uint32_t filter, uint32_t type,
       pcmk_scheduler_t *scheduler)
{
    return rsc->priv->cmds->update_ordered_actions(first, then, node, flags,
                                                   filter, type, scheduler);
}

/*!
 * \internal
 * \brief Update flags for ordering's actions appropriately for ordering's flags
 *
 * \param[in,out] first        First action in an ordering
 * \param[in,out] then         Then action in an ordering
 * \param[in]     first_flags  Action flags for \p first for ordering purposes
 * \param[in]     then_flags   Action flags for \p then for ordering purposes
 * \param[in,out] order        Action wrapper for \p first in ordering
 * \param[in,out] scheduler    Scheduler data
 *
 * \return Group of enum pcmk__updated flags
 */
static uint32_t
update_action_for_ordering_flags(pcmk_action_t *first, pcmk_action_t *then,
                                 uint32_t first_flags, uint32_t then_flags,
                                 pcmk__related_action_t *order,
                                 pcmk_scheduler_t *scheduler)
{
    uint32_t changed = pcmk__updated_none;

    /* The node will only be used for clones. If interleaved, node will be NULL,
     * otherwise the ordering scope will be limited to the node. Normally, the
     * whole 'then' clone should restart if 'first' is restarted, so then->node
     * is needed.
     */
    pcmk_node_t *node = then->node;

    if (pcmk_is_set(order->flags, pcmk__ar_first_implies_same_node_then)) {
        /* For unfencing, only instances of 'then' on the same node as 'first'
         * (the unfencing operation) should restart, so reset node to
         * first->node, at which point this case is handled like a normal
         * pcmk__ar_first_implies_then.
         */
        pcmk__clear_relation_flags(order->flags,
                                   pcmk__ar_first_implies_same_node_then);
        pcmk__set_relation_flags(order->flags, pcmk__ar_first_implies_then);
        node = first->node;
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: mapped "
                        "pcmk__ar_first_implies_same_node_then to "
                        "pcmk__ar_first_implies_then on %s",
                        first->uuid, then->uuid, pcmk__node_name(node));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_first_implies_then)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node,
                              first_flags & pcmk__action_optional,
                              pcmk__action_optional,
                              pcmk__ar_first_implies_then, scheduler);
        } else if (!pcmk_is_set(first_flags, pcmk__action_optional)
                   && pcmk_is_set(then->flags, pcmk__action_optional)) {
            pcmk__clear_action_flags(then, pcmk__action_optional);
            pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after pcmk__ar_first_implies_then",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_intermediate_stop)
        && (then->rsc != NULL)) {
        enum pcmk__action_flags restart = pcmk__action_optional
                                          |pcmk__action_runnable;

        changed |= update(then->rsc, first, then, node, first_flags, restart,
                          pcmk__ar_intermediate_stop, scheduler);
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after pcmk__ar_intermediate_stop",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_then_implies_first)) {
        if (first->rsc != NULL) {
            changed |= update(first->rsc, first, then, node, first_flags,
                              pcmk__action_optional,
                              pcmk__ar_then_implies_first, scheduler);
        } else if (!pcmk_is_set(first_flags, pcmk__action_optional)
                   && pcmk_is_set(first->flags, pcmk__action_runnable)) {
            pcmk__clear_action_flags(first, pcmk__action_runnable);
            pcmk__set_updated_flags(changed, first, pcmk__updated_first);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after pcmk__ar_then_implies_first",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_promoted_then_implies_first)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node,
                              first_flags & pcmk__action_optional,
                              pcmk__action_optional,
                              pcmk__ar_promoted_then_implies_first, scheduler);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after "
                        "pcmk__ar_promoted_then_implies_first",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_min_runnable)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_runnable, pcmk__ar_min_runnable,
                              scheduler);

        } else if (pcmk_is_set(first_flags, pcmk__action_runnable)) {
            // We have another runnable instance of "first"
            then->runnable_before++;

            /* Mark "then" as runnable if it requires a certain number of
             * "before" instances to be runnable, and they now are.
             */
            if ((then->runnable_before >= then->required_runnable_before)
                && !pcmk_is_set(then->flags, pcmk__action_runnable)) {

                pcmk__set_action_flags(then, pcmk__action_runnable);
                pcmk__set_updated_flags(changed, first, pcmk__updated_then);
            }
        }
        pcmk__rsc_trace(then->rsc, "%s then %s: %s after pcmk__ar_min_runnable",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_nested_remote_probe)
        && (then->rsc != NULL)) {

        if (!pcmk_is_set(first_flags, pcmk__action_runnable)
            && (first->rsc != NULL)
            && (first->rsc->priv->active_nodes != NULL)) {

            pcmk__rsc_trace(then->rsc,
                            "%s then %s: ignoring because first is stopping",
                            first->uuid, then->uuid);
            order->flags = pcmk__ar_none;
        } else {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_runnable,
                              pcmk__ar_unrunnable_first_blocks, scheduler);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after pcmk__ar_nested_remote_probe",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_unrunnable_first_blocks)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_runnable,
                              pcmk__ar_unrunnable_first_blocks, scheduler);

        } else if (!pcmk_is_set(first_flags, pcmk__action_runnable)
                   && pcmk_is_set(then->flags, pcmk__action_runnable)) {

            pcmk__clear_action_flags(then, pcmk__action_runnable);
            pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after pcmk__ar_unrunnable_first_blocks",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_unmigratable_then_blocks)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_optional,
                              pcmk__ar_unmigratable_then_blocks, scheduler);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after "
                        "pcmk__ar_unmigratable_then_blocks",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_first_else_then)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_optional, pcmk__ar_first_else_then,
                              scheduler);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after pcmk__ar_first_else_then",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_ordered)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_runnable, pcmk__ar_ordered,
                              scheduler);
        }
        pcmk__rsc_trace(then->rsc, "%s then %s: %s after pcmk__ar_ordered",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->flags, pcmk__ar_asymmetric)) {
        if (then->rsc != NULL) {
            changed |= update(then->rsc, first, then, node, first_flags,
                              pcmk__action_runnable, pcmk__ar_asymmetric,
                              scheduler);
        }
        pcmk__rsc_trace(then->rsc, "%s then %s: %s after pcmk__ar_asymmetric",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(first->flags, pcmk__action_runnable)
        && pcmk_is_set(order->flags, pcmk__ar_first_implies_then_graphed)
        && !pcmk_is_set(first_flags, pcmk__action_optional)) {

        pcmk__rsc_trace(then->rsc, "%s will be in graph because %s is required",
                        then->uuid, first->uuid);
        pcmk__set_action_flags(then, pcmk__action_always_in_graph);
        // Don't bother marking 'then' as changed just for this
    }

    if (pcmk_is_set(order->flags, pcmk__ar_then_implies_first_graphed)
        && !pcmk_is_set(then_flags, pcmk__action_optional)) {

        pcmk__rsc_trace(then->rsc, "%s will be in graph because %s is required",
                        first->uuid, then->uuid);
        pcmk__set_action_flags(first, pcmk__action_always_in_graph);
        // Don't bother marking 'first' as changed just for this
    }

    if (pcmk_any_flags_set(order->flags, pcmk__ar_first_implies_then
                                         |pcmk__ar_then_implies_first
                                         |pcmk__ar_intermediate_stop)
        && (first->rsc != NULL)
        && !pcmk_is_set(first->rsc->flags, pcmk__rsc_managed)
        && pcmk_is_set(first->rsc->flags, pcmk__rsc_blocked)
        && !pcmk_is_set(first->flags, pcmk__action_runnable)
        && pcmk__str_eq(first->task, PCMK_ACTION_STOP, pcmk__str_none)) {

        /* @TODO This seems odd; why wouldn't an unrunnable "first" already
         * block "then" before this? Note that the unmanaged-stop-{1,2}
         * scheduler regression tests and the test CIB for T209 have tests for
         * "stop then stop" relations that would be good for checking any
         * changes.
         */
        if (pcmk_is_set(then->flags, pcmk__action_runnable)) {
            pcmk__clear_action_flags(then, pcmk__action_runnable);
            pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        }
        pcmk__rsc_trace(then->rsc,
                        "%s then %s: %s after checking whether first "
                        "is blocked, unmanaged, unrunnable stop",
                        first->uuid, then->uuid,
                        (changed? "changed" : "unchanged"));
    }

    return changed;
}

// Convenience macros for logging action properties

#define action_type_str(flags) \
    (pcmk_is_set((flags), pcmk__action_pseudo)? "pseudo-action" : "action")

#define action_optional_str(flags) \
    (pcmk_is_set((flags), pcmk__action_optional)? "optional" : "required")

#define action_runnable_str(flags) \
    (pcmk_is_set((flags), pcmk__action_runnable)? "runnable" : "unrunnable")

#define action_node_str(a) \
    (((a)->node == NULL)? "no node" : (a)->node->priv->name)

/*!
 * \internal
 * \brief Update an action's flags for all orderings where it is "then"
 *
 * \param[in,out] then       Action to update
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__update_action_for_orderings(pcmk_action_t *then,
                                  pcmk_scheduler_t *scheduler)
{
    GList *lpc = NULL;
    uint32_t changed = pcmk__updated_none;
    int last_flags = then->flags;

    pcmk__rsc_trace(then->rsc, "Updating %s %s (%s %s) on %s",
                    action_type_str(then->flags), then->uuid,
                    action_optional_str(then->flags),
                    action_runnable_str(then->flags), action_node_str(then));

    if (then->required_runnable_before > 0) {
        /* Initialize current known "runnable before" actions. As
         * update_action_for_ordering_flags() is called for each of then's
         * before actions, this number will increment as runnable 'first'
         * actions are encountered.
         */
        then->runnable_before = 0;

        /* The pcmk__ar_min_runnable clause of
         * update_action_for_ordering_flags() (called below)
         * will reset runnable if appropriate.
         */
        pcmk__clear_action_flags(then, pcmk__action_runnable);
    }

    for (lpc = then->actions_before; lpc != NULL; lpc = lpc->next) {
        pcmk__related_action_t *other = lpc->data;
        pcmk_action_t *first = other->action;

        pcmk_node_t *then_node = then->node;
        pcmk_node_t *first_node = first->node;

        const uint32_t target = pcmk__rsc_node_assigned;

        if ((first->rsc != NULL)
            && pcmk__is_group(first->rsc)
            && pcmk__str_eq(first->task, PCMK_ACTION_START, pcmk__str_none)) {

            first_node = first->rsc->priv->fns->location(first->rsc, NULL,
                                                         target);
            if (first_node != NULL) {
                pcmk__rsc_trace(first->rsc, "Found %s for 'first' %s",
                                pcmk__node_name(first_node), first->uuid);
            }
        }

        if (pcmk__is_group(then->rsc)
            && pcmk__str_eq(then->task, PCMK_ACTION_START, pcmk__str_none)) {

            then_node = then->rsc->priv->fns->location(then->rsc, NULL, target);
            if (then_node != NULL) {
                pcmk__rsc_trace(then->rsc, "Found %s for 'then' %s",
                                pcmk__node_name(then_node), then->uuid);
            }
        }

        // Disable constraint if it only applies when on same node, but isn't
        if (pcmk_is_set(other->flags, pcmk__ar_if_on_same_node)
            && (first_node != NULL) && (then_node != NULL)
            && !pcmk__same_node(first_node, then_node)) {

            pcmk__rsc_trace(then->rsc,
                            "Disabled ordering %s on %s then %s on %s: "
                            "not same node",
                            other->action->uuid, pcmk__node_name(first_node),
                            then->uuid, pcmk__node_name(then_node));
            other->flags = pcmk__ar_none;
            continue;
        }

        pcmk__clear_updated_flags(changed, then, pcmk__updated_first);

        if ((first->rsc != NULL)
            && pcmk_is_set(other->flags, pcmk__ar_then_cancels_first)
            && !pcmk_is_set(then->flags, pcmk__action_optional)) {

            /* 'then' is required, so we must abandon 'first'
             * (e.g. a required stop cancels any agent reload).
             */
            pcmk__set_action_flags(other->action, pcmk__action_optional);
            if (!strcmp(first->task, PCMK_ACTION_RELOAD_AGENT)) {
                pcmk__clear_rsc_flags(first->rsc, pcmk__rsc_reload);
            }
        }

        if ((first->rsc != NULL) && (then->rsc != NULL)
            && (first->rsc != then->rsc) && !is_parent(then->rsc, first->rsc)) {
            first = action_for_ordering(first);
        }
        if (first != other->action) {
            pcmk__rsc_trace(then->rsc, "Ordering %s after %s instead of %s",
                            then->uuid, first->uuid, other->action->uuid);
        }

        pcmk__rsc_trace(then->rsc,
                        "%s (%#.6x) then %s (%#.6x): type=%#.6x node=%s",
                        first->uuid, first->flags, then->uuid, then->flags,
                        other->flags, action_node_str(first));

        if (first == other->action) {
            /* 'first' was not remapped (e.g. from 'start' to 'running'), which
             * could mean it is a non-resource action, a primitive resource
             * action, or already expanded.
             */
            uint32_t first_flags, then_flags;

            first_flags = action_flags_for_ordering(first, then_node);
            then_flags = action_flags_for_ordering(then, first_node);

            changed |= update_action_for_ordering_flags(first, then,
                                                        first_flags, then_flags,
                                                        other, scheduler);

            /* 'first' was for a complex resource (clone, group, etc),
             * create a new dependency if necessary
             */
        } else if (order_actions(first, then, other->flags)) {
            /* This was the first time 'first' and 'then' were associated,
             * start again to get the new actions_before list
             */
            pcmk__set_updated_flags(changed, then, pcmk__updated_then);
            pcmk__rsc_trace(then->rsc,
                            "Disabled ordering %s then %s in favor of %s "
                            "then %s",
                            other->action->uuid, then->uuid, first->uuid,
                            then->uuid);
            other->flags = pcmk__ar_none;
        }


        if (pcmk_is_set(changed, pcmk__updated_first)) {
            crm_trace("Re-processing %s and its 'after' actions "
                      "because it changed", first->uuid);
            for (GList *lpc2 = first->actions_after; lpc2 != NULL;
                 lpc2 = lpc2->next) {
                pcmk__related_action_t *other = lpc2->data;

                pcmk__update_action_for_orderings(other->action, scheduler);
            }
            pcmk__update_action_for_orderings(first, scheduler);
        }
    }

    if (then->required_runnable_before > 0) {
        if (last_flags == then->flags) {
            pcmk__clear_updated_flags(changed, then, pcmk__updated_then);
        } else {
            pcmk__set_updated_flags(changed, then, pcmk__updated_then);
        }
    }

    if (pcmk_is_set(changed, pcmk__updated_then)) {
        crm_trace("Re-processing %s and its 'after' actions because it changed",
                  then->uuid);
        if (pcmk_is_set(last_flags, pcmk__action_runnable)
            && !pcmk_is_set(then->flags, pcmk__action_runnable)) {
            pcmk__block_colocation_dependents(then);
        }
        pcmk__update_action_for_orderings(then, scheduler);
        for (lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
            pcmk__related_action_t *other = lpc->data;

            pcmk__update_action_for_orderings(other->action, scheduler);
        }
    }
}

static inline bool
is_primitive_action(const pcmk_action_t *action)
{
    return (action != NULL) && pcmk__is_primitive(action->rsc);
}

/*!
 * \internal
 * \brief Clear a single action flag and set reason text
 *
 * \param[in,out] action  Action whose flag should be cleared
 * \param[in]     flag    Action flag that should be cleared
 * \param[in]     reason  Action that is the reason why flag is being cleared
 */
#define clear_action_flag_because(action, flag, reason) do {                \
        if (pcmk_is_set((action)->flags, (flag))) {                         \
            pcmk__clear_action_flags(action, flag);                         \
            if ((action)->rsc != (reason)->rsc) {                           \
                char *reason_text = pe__action2reason((reason), (flag));    \
                pe_action_set_reason((action), reason_text, false);         \
                free(reason_text);                                          \
            }                                                               \
        }                                                                   \
    } while (0)

/*!
 * \internal
 * \brief Update actions in an asymmetric ordering
 *
 * If the "first" action in an asymmetric ordering is unrunnable, make the
 * "second" action unrunnable as well, if appropriate.
 *
 * \param[in]     first  'First' action in an asymmetric ordering
 * \param[in,out] then   'Then' action in an asymmetric ordering
 */
static void
handle_asymmetric_ordering(const pcmk_action_t *first, pcmk_action_t *then)
{
    /* Only resource actions after an unrunnable 'first' action need updates for
     * asymmetric ordering.
     */
    if ((then->rsc == NULL)
        || pcmk_is_set(first->flags, pcmk__action_runnable)) {
        return;
    }

    // Certain optional 'then' actions are unaffected by unrunnable 'first'
    if (pcmk_is_set(then->flags, pcmk__action_optional)) {
        enum rsc_role_e then_rsc_role;

        then_rsc_role = then->rsc->priv->fns->state(then->rsc, TRUE);

        if ((then_rsc_role == pcmk_role_stopped)
            && pcmk__str_eq(then->task, PCMK_ACTION_STOP, pcmk__str_none)) {
            /* If 'then' should stop after 'first' but is already stopped, the
             * ordering is irrelevant.
             */
            return;
        } else if ((then_rsc_role >= pcmk_role_started)
            && pcmk__str_eq(then->task, PCMK_ACTION_START, pcmk__str_none)
            && pe__rsc_running_on_only(then->rsc, then->node)) {
            /* Similarly if 'then' should start after 'first' but is already
             * started on a single node.
             */
            return;
        }
    }

    // 'First' can't run, so 'then' can't either
    clear_action_flag_because(then, pcmk__action_optional, first);
    clear_action_flag_because(then, pcmk__action_runnable, first);
}

/*!
 * \internal
 * \brief Set action bits appropriately when pcmk__ar_intermediate_stop is used
 *
 * \param[in,out] first   'First' action in ordering
 * \param[in,out] then    'Then' action in ordering
 * \param[in]     filter  What action flags to care about
 *
 * \note pcmk__ar_intermediate_stop is set for "stop resource before starting
 *       it" and "stop later group member before stopping earlier group member"
 */
static void
handle_restart_ordering(pcmk_action_t *first, pcmk_action_t *then,
                        uint32_t filter)
{
    const char *reason = NULL;

    pcmk__assert(is_primitive_action(first) && is_primitive_action(then));

    // We need to update the action in two cases:

    // ... if 'then' is required
    if (pcmk_is_set(filter, pcmk__action_optional)
        && !pcmk_is_set(then->flags, pcmk__action_optional)) {
        reason = "restart";
    }

    /* ... if 'then' is unrunnable action on same resource (if a resource
     * should restart but can't start, we still want to stop)
     */
    if (pcmk_is_set(filter, pcmk__action_runnable)
        && !pcmk_is_set(then->flags, pcmk__action_runnable)
        && pcmk_is_set(then->rsc->flags, pcmk__rsc_managed)
        && (first->rsc == then->rsc)) {
        reason = "stop";
    }

    if (reason == NULL) {
        return;
    }

    pcmk__rsc_trace(first->rsc, "Handling %s -> %s for %s",
                    first->uuid, then->uuid, reason);

    // Make 'first' required if it is runnable
    if (pcmk_is_set(first->flags, pcmk__action_runnable)) {
        clear_action_flag_because(first, pcmk__action_optional, then);
    }

    // Make 'first' required if 'then' is required
    if (!pcmk_is_set(then->flags, pcmk__action_optional)) {
        clear_action_flag_because(first, pcmk__action_optional, then);
    }

    // Make 'first' unmigratable if 'then' is unmigratable
    if (!pcmk_is_set(then->flags, pcmk__action_migratable)) {
        clear_action_flag_because(first, pcmk__action_migratable, then);
    }

    // Make 'then' unrunnable if 'first' is required but unrunnable
    if (!pcmk_is_set(first->flags, pcmk__action_optional)
        && !pcmk_is_set(first->flags, pcmk__action_runnable)) {
        clear_action_flag_because(then, pcmk__action_runnable, first);
    }
}

/*!
 * \internal
 * \brief Update two actions according to an ordering between them
 *
 * Given information about an ordering of two actions, update the actions' flags
 * (and runnable_before members if appropriate) as appropriate for the ordering.
 * Effects may cascade to other orderings involving the actions as well.
 *
 * \param[in,out] first      'First' action in an ordering
 * \param[in,out] then       'Then' action in an ordering
 * \param[in]     node       If not NULL, limit scope of ordering to this node
 *                           (ignored)
 * \param[in]     flags      Action flags for \p first for ordering purposes
 * \param[in]     filter     Action flags to limit scope of certain updates (may
 *                           include pcmk__action_optional to affect only
 *                           mandatory actions, and pcmk__action_runnable to
 *                           affect only runnable actions)
 * \param[in]     type       Group of enum pcmk__action_relation_flags to apply
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
uint32_t
pcmk__update_ordered_actions(pcmk_action_t *first, pcmk_action_t *then,
                             const pcmk_node_t *node, uint32_t flags,
                             uint32_t filter, uint32_t type,
                             pcmk_scheduler_t *scheduler)
{
    uint32_t changed = pcmk__updated_none;
    uint32_t then_flags = 0U;
    uint32_t first_flags = 0U;

    pcmk__assert((first != NULL) && (then != NULL) && (scheduler != NULL));

    then_flags = then->flags;
    first_flags = first->flags;
    if (pcmk_is_set(type, pcmk__ar_asymmetric)) {
        handle_asymmetric_ordering(first, then);
    }

    if (pcmk_is_set(type, pcmk__ar_then_implies_first)
        && !pcmk_is_set(then_flags, pcmk__action_optional)) {
        // Then is required, and implies first should be, too

        if (pcmk_is_set(filter, pcmk__action_optional)
            && !pcmk_is_set(flags, pcmk__action_optional)
            && pcmk_is_set(first_flags, pcmk__action_optional)) {
            clear_action_flag_because(first, pcmk__action_optional, then);
        }

        if (pcmk_is_set(flags, pcmk__action_migratable)
            && !pcmk_is_set(then->flags, pcmk__action_migratable)) {
            clear_action_flag_because(first, pcmk__action_migratable, then);
        }
    }

    if (pcmk_is_set(type, pcmk__ar_promoted_then_implies_first)
        && (then->rsc != NULL)
        && (then->rsc->priv->orig_role == pcmk_role_promoted)
        && pcmk_is_set(filter, pcmk__action_optional)
        && !pcmk_is_set(then->flags, pcmk__action_optional)) {

        clear_action_flag_because(first, pcmk__action_optional, then);

        if (pcmk_is_set(first->flags, pcmk__action_migratable)
            && !pcmk_is_set(then->flags, pcmk__action_migratable)) {
            clear_action_flag_because(first, pcmk__action_migratable, then);
        }
    }

    if (pcmk_is_set(type, pcmk__ar_unmigratable_then_blocks)
        && pcmk_is_set(filter, pcmk__action_optional)) {

        if (!pcmk_all_flags_set(then->flags, pcmk__action_migratable
                                             |pcmk__action_runnable)) {
            clear_action_flag_because(first, pcmk__action_runnable, then);
        }

        if (!pcmk_is_set(then->flags, pcmk__action_optional)) {
            clear_action_flag_because(first, pcmk__action_optional, then);
        }
    }

    if (pcmk_is_set(type, pcmk__ar_first_else_then)
        && pcmk_is_set(filter, pcmk__action_optional)
        && !pcmk_is_set(first->flags, pcmk__action_runnable)) {

        clear_action_flag_because(then, pcmk__action_migratable, first);
        pcmk__clear_action_flags(then, pcmk__action_pseudo);
    }

    if (pcmk_is_set(type, pcmk__ar_unrunnable_first_blocks)
        && pcmk_is_set(filter, pcmk__action_runnable)
        && pcmk_is_set(then->flags, pcmk__action_runnable)
        && !pcmk_is_set(flags, pcmk__action_runnable)) {

        clear_action_flag_because(then, pcmk__action_runnable, first);
        clear_action_flag_because(then, pcmk__action_migratable, first);
    }

    if (pcmk_is_set(type, pcmk__ar_first_implies_then)
        && pcmk_is_set(filter, pcmk__action_optional)
        && pcmk_is_set(then->flags, pcmk__action_optional)
        && !pcmk_is_set(flags, pcmk__action_optional)
        && !pcmk_is_set(first->flags, pcmk__action_migratable)) {

        clear_action_flag_because(then, pcmk__action_optional, first);
    }

    if (pcmk_is_set(type, pcmk__ar_intermediate_stop)) {
        handle_restart_ordering(first, then, filter);
    }

    if (then_flags != then->flags) {
        pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        pcmk__rsc_trace(then->rsc,
                        "%s on %s: flags are now %#.6x (was %#.6x) "
                        "because of 'first' %s (%#.6x)",
                        then->uuid, pcmk__node_name(then->node),
                        then->flags, then_flags, first->uuid, first->flags);

        if ((then->rsc != NULL) && (then->rsc->priv->parent != NULL)) {
            // Required to handle "X_stop then X_start" for cloned groups
            pcmk__update_action_for_orderings(then, scheduler);
        }
    }

    if (first_flags != first->flags) {
        pcmk__set_updated_flags(changed, first, pcmk__updated_first);
        pcmk__rsc_trace(first->rsc,
                        "%s on %s: flags are now %#.6x (was %#.6x) "
                        "because of 'then' %s (%#.6x)",
                        first->uuid, pcmk__node_name(first->node),
                        first->flags, first_flags, then->uuid, then->flags);
    }

    return changed;
}

/*!
 * \internal
 * \brief Trace-log an action (optionally with its dependent actions)
 *
 * \param[in] pre_text  If not NULL, prefix the log with this plus ": "
 * \param[in] action    Action to log
 * \param[in] details   If true, recursively log dependent actions
 */
void
pcmk__log_action(const char *pre_text, const pcmk_action_t *action,
                 bool details)
{
    const char *node_uname = NULL;
    const char *node_uuid = NULL;
    const char *desc = NULL;

    CRM_CHECK(action != NULL, return);

    if (!pcmk_is_set(action->flags, pcmk__action_pseudo)) {
        if (action->node != NULL) {
            node_uname = action->node->priv->name;
            node_uuid = action->node->priv->id;
        } else {
            node_uname = "<none>";
        }
    }

    switch (pcmk__parse_action(action->task)) {
        case pcmk__action_fence:
        case pcmk__action_shutdown:
            if (pcmk_is_set(action->flags, pcmk__action_pseudo)) {
                desc = "Pseudo ";
            } else if (pcmk_is_set(action->flags, pcmk__action_optional)) {
                desc = "Optional ";
            } else if (!pcmk_is_set(action->flags, pcmk__action_runnable)) {
                desc = "!!Non-Startable!! ";
            } else {
               desc = "(Provisional) ";
            }
            crm_trace("%s%s%sAction %d: %s%s%s%s%s%s",
                      ((pre_text == NULL)? "" : pre_text),
                      ((pre_text == NULL)? "" : ": "),
                      desc, action->id, action->uuid,
                      (node_uname? "\ton " : ""), (node_uname? node_uname : ""),
                      (node_uuid? "\t\t(" : ""), (node_uuid? node_uuid : ""),
                      (node_uuid? ")" : ""));
            break;
        default:
            if (pcmk_is_set(action->flags, pcmk__action_optional)) {
                desc = "Optional ";
            } else if (pcmk_is_set(action->flags, pcmk__action_pseudo)) {
                desc = "Pseudo ";
            } else if (!pcmk_is_set(action->flags, pcmk__action_runnable)) {
                desc = "!!Non-Startable!! ";
            } else {
               desc = "(Provisional) ";
            }
            crm_trace("%s%s%sAction %d: %s %s%s%s%s%s%s",
                      ((pre_text == NULL)? "" : pre_text),
                      ((pre_text == NULL)? "" : ": "),
                      desc, action->id, action->uuid,
                      (action->rsc? action->rsc->id : "<none>"),
                      (node_uname? "\ton " : ""), (node_uname? node_uname : ""),
                      (node_uuid? "\t\t(" : ""), (node_uuid? node_uuid : ""),
                      (node_uuid? ")" : ""));
            break;
    }

    if (details) {
        const GList *iter = NULL;
        const pcmk__related_action_t *other = NULL;

        crm_trace("\t\t====== Preceding Actions");
        for (iter = action->actions_before; iter != NULL; iter = iter->next) {
            other = (const pcmk__related_action_t *) iter->data;
            pcmk__log_action("\t\t", other->action, false);
        }
        crm_trace("\t\t====== Subsequent Actions");
        for (iter = action->actions_after; iter != NULL; iter = iter->next) {
            other = (const pcmk__related_action_t *) iter->data;
            pcmk__log_action("\t\t", other->action, false);
        }
        crm_trace("\t\t====== End");

    } else {
        crm_trace("\t\t(before=%d, after=%d)",
                  g_list_length(action->actions_before),
                  g_list_length(action->actions_after));
    }
}

/*!
 * \internal
 * \brief Create a new shutdown action for a node
 *
 * \param[in,out] node  Node being shut down
 *
 * \return Newly created shutdown action for \p node
 */
pcmk_action_t *
pcmk__new_shutdown_action(pcmk_node_t *node)
{
    char *shutdown_id = NULL;
    pcmk_action_t *shutdown_op = NULL;

    pcmk__assert(node != NULL);

    shutdown_id = crm_strdup_printf("%s-%s", PCMK_ACTION_DO_SHUTDOWN,
                                    node->priv->name);

    shutdown_op = custom_action(NULL, shutdown_id, PCMK_ACTION_DO_SHUTDOWN,
                                node, FALSE, node->priv->scheduler);

    pcmk__order_stops_before_shutdown(node, shutdown_op);
    pcmk__insert_meta(shutdown_op, PCMK__META_OP_NO_WAIT, PCMK_VALUE_TRUE);
    return shutdown_op;
}

/*!
 * \internal
 * \brief Calculate and add an operation digest to XML
 *
 * Calculate an operation digest, which enables us to later determine when a
 * restart is needed due to the resource's parameters being changed, and add it
 * to given XML.
 *
 * \param[in]     op      Operation result from executor
 * \param[in,out] update  XML to add digest to
 */
static void
add_op_digest_to_xml(const lrmd_event_data_t *op, xmlNode *update)
{
    char *digest = NULL;
    xmlNode *args_xml = NULL;

    if (op->params == NULL) {
        return;
    }
    args_xml = pcmk__xe_create(NULL, PCMK_XE_PARAMETERS);
    g_hash_table_foreach(op->params, hash2field, args_xml);
    pcmk__filter_op_for_digest(args_xml);
    digest = pcmk__digest_operation(args_xml);
    crm_xml_add(update, PCMK__XA_OP_DIGEST, digest);
    pcmk__xml_free(args_xml);
    free(digest);
}

#define FAKE_TE_ID     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

/*!
 * \internal
 * \brief Create XML for resource operation history update
 *
 * \param[in,out] parent          Parent XML node to add to
 * \param[in,out] op              Operation event data
 * \param[in]     caller_version  DC feature set
 * \param[in]     target_rc       Expected result of operation
 * \param[in]     node            Name of node on which operation was performed
 * \param[in]     origin          Arbitrary description of update source
 *
 * \return Newly created XML node for history update
 */
xmlNode *
pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *op,
                         const char *caller_version, int target_rc,
                         const char *node, const char *origin)
{
    char *key = NULL;
    char *magic = NULL;
    char *op_id = NULL;
    char *op_id_additional = NULL;
    char *local_user_data = NULL;
    const char *exit_reason = NULL;

    xmlNode *xml_op = NULL;
    const char *task = NULL;

    CRM_CHECK(op != NULL, return NULL);
    crm_trace("Creating history XML for %s-interval %s action for %s on %s "
              "(DC version: %s, origin: %s)",
              pcmk__readable_interval(op->interval_ms), op->op_type, op->rsc_id,
              ((node == NULL)? "no node" : node), caller_version, origin);

    task = op->op_type;

    /* Record a successful agent reload as a start, and a failed one as a
     * monitor, to make life easier for the scheduler when determining the
     * current state.
     *
     * @COMPAT We should check "reload" here only if the operation was for a
     * pre-OCF-1.1 resource agent, but we don't know that here, and we should
     * only ever get results for actions scheduled by us, so we can reasonably
     * assume any "reload" is actually a pre-1.1 agent reload.
     *
     * @TODO This remapping can make log messages with task confusing for users
     * (for example, an "Initiating reload ..." followed by "... start ...
     * confirmed"). Either do this remapping in the scheduler if possible, or
     * store the original task in a new XML attribute for later logging.
     */
    if (pcmk__str_any_of(task, PCMK_ACTION_RELOAD, PCMK_ACTION_RELOAD_AGENT,
                         NULL)) {
        if (op->op_status == PCMK_EXEC_DONE) {
            task = PCMK_ACTION_START;
        } else {
            task = PCMK_ACTION_MONITOR;
        }
    }

    key = pcmk__op_key(op->rsc_id, task, op->interval_ms);
    if (pcmk__str_eq(task, PCMK_ACTION_NOTIFY, pcmk__str_none)) {
        const char *n_type = crm_meta_value(op->params, "notify_type");
        const char *n_task = crm_meta_value(op->params, "notify_operation");

        CRM_LOG_ASSERT(n_type != NULL);
        CRM_LOG_ASSERT(n_task != NULL);
        op_id = pcmk__notify_key(op->rsc_id, n_type, n_task);

        if (op->op_status != PCMK_EXEC_PENDING) {
            /* Ignore notify errors.
             *
             * @TODO It might be better to keep the correct result here, and
             * ignore it in process_graph_event().
             */
            lrmd__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        }

    /* Migration history is preserved separately, which usually matters for
     * multiple nodes and is important for future cluster transitions.
     */
    } else if (pcmk__str_any_of(op->op_type, PCMK_ACTION_MIGRATE_TO,
                                PCMK_ACTION_MIGRATE_FROM, NULL)) {
        op_id = strdup(key);

    } else if (did_rsc_op_fail(op, target_rc)) {
        op_id = pcmk__op_key(op->rsc_id, "last_failure", 0);
        if (op->interval_ms == 0) {
            /* Ensure 'last' gets updated, in case PCMK_META_RECORD_PENDING is
             * true
             */
            op_id_additional = pcmk__op_key(op->rsc_id, "last", 0);
        }
        exit_reason = op->exit_reason;

    } else if (op->interval_ms > 0) {
        op_id = strdup(key);

    } else {
        op_id = pcmk__op_key(op->rsc_id, "last", 0);
    }

  again:
    xml_op = pcmk__xe_first_child(parent, PCMK__XE_LRM_RSC_OP, PCMK_XA_ID,
                                  op_id);
    if (xml_op == NULL) {
        xml_op = pcmk__xe_create(parent, PCMK__XE_LRM_RSC_OP);
    }

    if (op->user_data == NULL) {
        crm_debug("Generating fake transition key for: " PCMK__OP_FMT
                  " %d from %s", op->rsc_id, op->op_type, op->interval_ms,
                  op->call_id, origin);
        local_user_data = pcmk__transition_key(-1, op->call_id, target_rc,
                                               FAKE_TE_ID);
        op->user_data = local_user_data;
    }

    if (magic == NULL) {
        magic = crm_strdup_printf("%d:%d;%s", op->op_status, op->rc,
                                  (const char *) op->user_data);
    }

    crm_xml_add(xml_op, PCMK_XA_ID, op_id);
    crm_xml_add(xml_op, PCMK__XA_OPERATION_KEY, key);
    crm_xml_add(xml_op, PCMK_XA_OPERATION, task);
    crm_xml_add(xml_op, PCMK_XA_CRM_DEBUG_ORIGIN, origin);
    crm_xml_add(xml_op, PCMK_XA_CRM_FEATURE_SET, caller_version);
    crm_xml_add(xml_op, PCMK__XA_TRANSITION_KEY, op->user_data);
    crm_xml_add(xml_op, PCMK__XA_TRANSITION_MAGIC, magic);
    crm_xml_add(xml_op, PCMK_XA_EXIT_REASON, pcmk__s(exit_reason, ""));
    crm_xml_add(xml_op, PCMK__META_ON_NODE, node); // For context during triage

    crm_xml_add_int(xml_op, PCMK__XA_CALL_ID, op->call_id);
    crm_xml_add_int(xml_op, PCMK__XA_RC_CODE, op->rc);
    crm_xml_add_int(xml_op, PCMK__XA_OP_STATUS, op->op_status);
    crm_xml_add_ms(xml_op, PCMK_META_INTERVAL, op->interval_ms);

    if ((op->t_run > 0) || (op->t_rcchange > 0) || (op->exec_time > 0)
        || (op->queue_time > 0)) {

        crm_trace("Timing data (" PCMK__OP_FMT "): "
                  "last=%lld change=%lld exec=%u queue=%u",
                  op->rsc_id, op->op_type, op->interval_ms,
                  (long long) op->t_run, (long long) op->t_rcchange,
                  op->exec_time, op->queue_time);

        if ((op->interval_ms > 0) && (op->t_rcchange > 0)) {
            // Recurring ops may have changed rc after initial run
            crm_xml_add_ll(xml_op, PCMK_XA_LAST_RC_CHANGE,
                           (long long) op->t_rcchange);
        } else {
            crm_xml_add_ll(xml_op, PCMK_XA_LAST_RC_CHANGE,
                           (long long) op->t_run);
        }

        crm_xml_add_int(xml_op, PCMK_XA_EXEC_TIME, op->exec_time);
        crm_xml_add_int(xml_op, PCMK_XA_QUEUE_TIME, op->queue_time);
    }

    if (pcmk__str_any_of(op->op_type, PCMK_ACTION_MIGRATE_TO,
                         PCMK_ACTION_MIGRATE_FROM, NULL)) {
        /* Record PCMK__META_MIGRATE_SOURCE and PCMK__META_MIGRATE_TARGET always
         * for migrate ops.
         */
        const char *name = PCMK__META_MIGRATE_SOURCE;

        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));

        name = PCMK__META_MIGRATE_TARGET;
        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));
    }

    add_op_digest_to_xml(op, xml_op);

    if (op_id_additional) {
        free(op_id);
        op_id = op_id_additional;
        op_id_additional = NULL;
        goto again;
    }

    if (local_user_data) {
        free(local_user_data);
        op->user_data = NULL;
    }
    free(magic);
    free(op_id);
    free(key);
    return xml_op;
}

/*!
 * \internal
 * \brief Check whether an action shutdown-locks a resource to a node
 *
 * If the PCMK_OPT_SHUTDOWN_LOCK cluster property is set, resources will not be
 * recovered on a different node if cleanly stopped, and may start only on that
 * same node. This function checks whether that applies to a given action, so
 * that the transition graph can be marked appropriately.
 *
 * \param[in] action  Action to check
 *
 * \return true if \p action locks its resource to the action's node,
 *         otherwise false
 */
bool
pcmk__action_locks_rsc_to_node(const pcmk_action_t *action)
{
    // Only resource actions taking place on resource's lock node are locked
    if ((action == NULL) || (action->rsc == NULL)
        || !pcmk__same_node(action->node, action->rsc->priv->lock_node)) {
        return false;
    }

    /* During shutdown, only stops are locked (otherwise, another action such as
     * a demote would cause the controller to clear the lock)
     */
    if (action->node->details->shutdown && (action->task != NULL)
        && (strcmp(action->task, PCMK_ACTION_STOP) != 0)) {
        return false;
    }

    return true;
}

/* lowest to highest */
static gint
sort_action_id(gconstpointer a, gconstpointer b)
{
    const pcmk__related_action_t *action_wrapper2 = a;
    const pcmk__related_action_t *action_wrapper1 = b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }
    if (action_wrapper1->action->id < action_wrapper2->action->id) {
        return 1;
    }
    if (action_wrapper1->action->id > action_wrapper2->action->id) {
        return -1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Remove any duplicate action inputs, merging action flags
 *
 * \param[in,out] action  Action whose inputs should be checked
 */
void
pcmk__deduplicate_action_inputs(pcmk_action_t *action)
{
    GList *item = NULL;
    GList *next = NULL;
    pcmk__related_action_t *last_input = NULL;

    action->actions_before = g_list_sort(action->actions_before,
                                         sort_action_id);
    for (item = action->actions_before; item != NULL; item = next) {
        pcmk__related_action_t *input = item->data;

        next = item->next;
        if ((last_input != NULL)
            && (input->action->id == last_input->action->id)) {
            crm_trace("Input %s (%d) duplicate skipped for action %s (%d)",
                      input->action->uuid, input->action->id,
                      action->uuid, action->id);

            /* For the purposes of scheduling, the ordering flags no longer
             * matter, but crm_simulate looks at certain ones when creating a
             * dot graph. Combining the flags is sufficient for that purpose.
             */
            pcmk__set_relation_flags(last_input->flags, input->flags);
            if (input->graphed) {
                last_input->graphed = true;
            }

            free(item->data);
            action->actions_before = g_list_delete_link(action->actions_before,
                                                        item);
        } else {
            last_input = input;
            input->graphed = false;
        }
    }
}

/*!
 * \internal
 * \brief Output all scheduled actions
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__output_actions(pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = scheduler->priv->out;

    // Output node (non-resource) actions
    for (GList *iter = scheduler->priv->actions;
         iter != NULL; iter = iter->next) {

        char *node_name = NULL;
        char *task = NULL;
        pcmk_action_t *action = (pcmk_action_t *) iter->data;

        if (action->rsc != NULL) {
            continue; // Resource actions will be output later

        } else if (pcmk_is_set(action->flags, pcmk__action_optional)) {
            continue; // This action was not scheduled
        }

        if (pcmk__str_eq(action->task, PCMK_ACTION_DO_SHUTDOWN,
                         pcmk__str_none)) {
            task = strdup("Shutdown");

        } else if (pcmk__str_eq(action->task, PCMK_ACTION_STONITH,
                                pcmk__str_none)) {
            const char *op = g_hash_table_lookup(action->meta,
                                                 PCMK__META_STONITH_ACTION);

            task = crm_strdup_printf("Fence (%s)", op);

        } else {
            continue; // Don't display other node action types
        }

        if (pcmk__is_guest_or_bundle_node(action->node)) {
            const pcmk_resource_t *remote = action->node->priv->remote;

            node_name = crm_strdup_printf("%s (resource: %s)",
                                          pcmk__node_name(action->node),
                                          remote->priv->launcher->id);
        } else if (action->node != NULL) {
            node_name = crm_strdup_printf("%s", pcmk__node_name(action->node));
        }

        out->message(out, "node-action", task, node_name, action->reason);

        free(node_name);
        free(task);
    }

    // Output resource actions
    for (GList *iter = scheduler->priv->resources;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        rsc->priv->cmds->output_actions(rsc);
    }
}

/*!
 * \internal
 * \brief Get action name needed to compare digest for configuration changes
 *
 * \param[in] task         Action name from history
 * \param[in] interval_ms  Action interval (in milliseconds)
 *
 * \return Action name whose digest should be compared
 */
static const char *
task_for_digest(const char *task, guint interval_ms)
{
    /* Certain actions need to be compared against the parameters used to start
     * the resource.
     */
    if ((interval_ms == 0)
        && pcmk__str_any_of(task, PCMK_ACTION_MONITOR, PCMK_ACTION_MIGRATE_FROM,
                            PCMK_ACTION_PROMOTE, NULL)) {
        task = PCMK_ACTION_START;
    }
    return task;
}

/*!
 * \internal
 * \brief Check whether only sanitized parameters to an action changed
 *
 * When collecting CIB files for troubleshooting, crm_report will mask
 * sensitive resource parameters. If simulations were run using that, affected
 * resources would appear to need a restart, which would complicate
 * troubleshooting. To avoid that, we save a "secure digest" of non-sensitive
 * parameters. This function used that digest to check whether only masked
 * parameters are different.
 *
 * \param[in] xml_op       Resource history entry with secure digest
 * \param[in] digest_data  Operation digest information being compared
 * \param[in] scheduler    Scheduler data
 *
 * \return true if only sanitized parameters changed, otherwise false
 */
static bool
only_sanitized_changed(const xmlNode *xml_op,
                       const pcmk__op_digest_t *digest_data,
                       const pcmk_scheduler_t *scheduler)
{
    const char *digest_secure = NULL;

    if (!pcmk_is_set(scheduler->flags, pcmk__sched_sanitized)) {
        // The scheduler is not being run as a simulation
        return false;
    }

    digest_secure = crm_element_value(xml_op, PCMK__XA_OP_SECURE_DIGEST);

    return (digest_data->rc != pcmk__digest_match) && (digest_secure != NULL)
           && (digest_data->digest_secure_calc != NULL)
           && (strcmp(digest_data->digest_secure_calc, digest_secure) == 0);
}

/*!
 * \internal
 * \brief Force a restart due to a configuration change
 *
 * \param[in,out] rsc          Resource that action is for
 * \param[in]     task         Name of action whose configuration changed
 * \param[in]     interval_ms  Action interval (in milliseconds)
 * \param[in,out] node         Node where resource should be restarted
 */
static void
force_restart(pcmk_resource_t *rsc, const char *task, guint interval_ms,
              pcmk_node_t *node)
{
    char *key = pcmk__op_key(rsc->id, task, interval_ms);
    pcmk_action_t *required = custom_action(rsc, key, task, NULL, FALSE,
                                            rsc->priv->scheduler);

    pe_action_set_reason(required, "resource definition change", true);
    trigger_unfencing(rsc, node, "Device parameters changed", NULL,
                      rsc->priv->scheduler);
}

/*!
 * \internal
 * \brief Schedule a reload of a resource on a node
 *
 * \param[in,out] data       Resource to reload
 * \param[in]     user_data  Where resource should be reloaded
 */
static void
schedule_reload(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;
    const pcmk_node_t *node = user_data;

    pcmk_action_t *reload = NULL;

    // For collective resources, just call recursively for children
    if (rsc->priv->variant > pcmk__rsc_variant_primitive) {
        g_list_foreach(rsc->priv->children, schedule_reload, user_data);
        return;
    }

    // Skip the reload in certain situations
    if ((node == NULL)
        || !pcmk_is_set(rsc->flags, pcmk__rsc_managed)
        || pcmk_is_set(rsc->flags, pcmk__rsc_failed)) {
        pcmk__rsc_trace(rsc, "Skip reload of %s:%s%s %s",
                        rsc->id,
                        pcmk_is_set(rsc->flags, pcmk__rsc_managed)? "" : " unmanaged",
                        pcmk_is_set(rsc->flags, pcmk__rsc_failed)? " failed" : "",
                        (node == NULL)? "inactive" : node->priv->name);
        return;
    }

    /* If a resource's configuration changed while a start was pending,
     * force a full restart instead of a reload.
     */
    if (pcmk_is_set(rsc->flags, pcmk__rsc_start_pending)) {
        pcmk__rsc_trace(rsc,
                        "%s: preventing agent reload because start pending",
                        rsc->id);
        custom_action(rsc, stop_key(rsc), PCMK_ACTION_STOP, node, FALSE,
                      rsc->priv->scheduler);
        return;
    }

    // Schedule the reload
    pcmk__set_rsc_flags(rsc, pcmk__rsc_reload);
    reload = custom_action(rsc, reload_key(rsc), PCMK_ACTION_RELOAD_AGENT, node,
                           FALSE, rsc->priv->scheduler);
    pe_action_set_reason(reload, "resource definition change", FALSE);

    // Set orderings so that a required stop or demote cancels the reload
    pcmk__new_ordering(NULL, NULL, reload, rsc, stop_key(rsc), NULL,
                       pcmk__ar_ordered|pcmk__ar_then_cancels_first,
                       rsc->priv->scheduler);
    pcmk__new_ordering(NULL, NULL, reload, rsc, demote_key(rsc), NULL,
                       pcmk__ar_ordered|pcmk__ar_then_cancels_first,
                       rsc->priv->scheduler);
}

/*!
 * \internal
 * \brief Handle any configuration change for an action
 *
 * Given an action from resource history, if the resource's configuration
 * changed since the action was done, schedule any actions needed (restart,
 * reload, unfencing, rescheduling recurring actions, etc.).
 *
 * \param[in,out] rsc     Resource that action is for
 * \param[in,out] node    Node that action was on
 * \param[in]     xml_op  Action XML from resource history
 *
 * \return true if action configuration changed, otherwise false
 */
bool
pcmk__check_action_config(pcmk_resource_t *rsc, pcmk_node_t *node,
                          const xmlNode *xml_op)
{
    guint interval_ms = 0;
    const char *task = NULL;
    const pcmk__op_digest_t *digest_data = NULL;

    CRM_CHECK((rsc != NULL) && (node != NULL) && (xml_op != NULL),
              return false);

    task = crm_element_value(xml_op, PCMK_XA_OPERATION);
    CRM_CHECK(task != NULL, return false);

    crm_element_value_ms(xml_op, PCMK_META_INTERVAL, &interval_ms);

    // If this is a recurring action, check whether it has been orphaned
    if (interval_ms > 0) {
        if (pcmk__find_action_config(rsc, task, interval_ms, false) != NULL) {
            pcmk__rsc_trace(rsc,
                            "%s-interval %s for %s on %s is in configuration",
                            pcmk__readable_interval(interval_ms), task, rsc->id,
                            pcmk__node_name(node));
        } else if (pcmk_is_set(rsc->priv->scheduler->flags,
                               pcmk__sched_cancel_removed_actions)) {
            pcmk__schedule_cancel(rsc,
                                  crm_element_value(xml_op, PCMK__XA_CALL_ID),
                                  task, interval_ms, node, "orphan");
            return true;
        } else {
            pcmk__rsc_debug(rsc, "%s-interval %s for %s on %s is orphaned",
                            pcmk__readable_interval(interval_ms), task, rsc->id,
                            pcmk__node_name(node));
            return true;
        }
    }

    crm_trace("Checking %s-interval %s for %s on %s for configuration changes",
              pcmk__readable_interval(interval_ms), task, rsc->id,
              pcmk__node_name(node));
    task = task_for_digest(task, interval_ms);
    digest_data = rsc_action_digest_cmp(rsc, xml_op, node,
                                        rsc->priv->scheduler);

    if (only_sanitized_changed(xml_op, digest_data, rsc->priv->scheduler)) {
        if (!pcmk__is_daemon && (rsc->priv->scheduler->priv->out != NULL)) {
            pcmk__output_t *out = rsc->priv->scheduler->priv->out;

            out->info(out,
                      "Only 'private' parameters to %s-interval %s for %s "
                      "on %s changed: %s",
                      pcmk__readable_interval(interval_ms), task, rsc->id,
                      pcmk__node_name(node),
                      crm_element_value(xml_op, PCMK__XA_TRANSITION_MAGIC));
        }
        return false;
    }

    switch (digest_data->rc) {
        case pcmk__digest_restart:
            crm_log_xml_debug(digest_data->params_restart, "params:restart");
            force_restart(rsc, task, interval_ms, node);
            return true;

        case pcmk__digest_unknown:
        case pcmk__digest_mismatch:
            // Changes that can potentially be handled by an agent reload

            if (interval_ms > 0) {
                /* Recurring actions aren't reloaded per se, they are just
                 * re-scheduled so the next run uses the new parameters.
                 * The old instance will be cancelled automatically.
                 */
                crm_log_xml_debug(digest_data->params_all, "params:reschedule");
                pcmk__reschedule_recurring(rsc, task, interval_ms, node);

            } else if (crm_element_value(xml_op,
                                         PCMK__XA_OP_RESTART_DIGEST) != NULL) {
                // Agent supports reload, so use it
                trigger_unfencing(rsc, node,
                                  "Device parameters changed (reload)", NULL,
                                  rsc->priv->scheduler);
                crm_log_xml_debug(digest_data->params_all, "params:reload");
                schedule_reload((gpointer) rsc, (gpointer) node);

            } else {
                pcmk__rsc_trace(rsc,
                                "Restarting %s "
                                "because agent doesn't support reload",
                                rsc->id);
                crm_log_xml_debug(digest_data->params_restart,
                                  "params:restart");
                force_restart(rsc, task, interval_ms, node);
            }
            return true;

        default:
            break;
    }
    return false;
}

/*!
 * \internal
 * \brief Create a list of resource's action history entries, sorted by call ID
 *
 * \param[in]  rsc_entry    Resource's \c PCMK__XE_LRM_RSC_OP status XML
 * \param[out] start_index  Where to store index of start-like action, if any
 * \param[out] stop_index   Where to store index of stop action, if any
 */
static GList *
rsc_history_as_list(const xmlNode *rsc_entry, int *start_index, int *stop_index)
{
    GList *ops = NULL;

    for (xmlNode *rsc_op = pcmk__xe_first_child(rsc_entry, PCMK__XE_LRM_RSC_OP,
                                                NULL, NULL);
         rsc_op != NULL; rsc_op = pcmk__xe_next(rsc_op, PCMK__XE_LRM_RSC_OP)) {

        ops = g_list_prepend(ops, rsc_op);
    }
    ops = g_list_sort(ops, sort_op_by_callid);
    calculate_active_ops(ops, start_index, stop_index);
    return ops;
}

/*!
 * \internal
 * \brief Process a resource's action history from the CIB status
 *
 * Given a resource's action history, if the resource's configuration
 * changed since the actions were done, schedule any actions needed (restart,
 * reload, unfencing, rescheduling recurring actions, clean-up, etc.).
 * (This also cancels recurring actions for maintenance mode, which is not
 * entirely related but convenient to do here.)
 *
 * \param[in]     rsc_entry  Resource's \c PCMK__XE_LRM_RSC_OP status XML
 * \param[in,out] rsc        Resource whose history is being processed
 * \param[in,out] node       Node whose history is being processed
 */
static void
process_rsc_history(const xmlNode *rsc_entry, pcmk_resource_t *rsc,
                    pcmk_node_t *node)
{
    int offset = -1;
    int stop_index = 0;
    int start_index = 0;
    GList *sorted_op_list = NULL;

    if (pcmk_is_set(rsc->flags, pcmk__rsc_removed)) {
        if (pcmk__is_anonymous_clone(pe__const_top_resource(rsc, false))) {
            /* @TODO Should this be done for bundled primitives as well? Added
             * by 2ac43ae31
             */
            pcmk__rsc_trace(rsc,
                            "Skipping configuration check "
                            "for orphaned clone instance %s",
                            rsc->id);
        } else {
            pcmk__rsc_trace(rsc,
                            "Skipping configuration check and scheduling "
                            "clean-up for orphaned resource %s", rsc->id);
            pcmk__schedule_cleanup(rsc, node, false);
        }
        return;
    }

    if (pe_find_node_id(rsc->priv->active_nodes,
                        node->priv->id) == NULL) {
        if (pcmk__rsc_agent_changed(rsc, node, rsc_entry, false)) {
            pcmk__schedule_cleanup(rsc, node, false);
        }
        pcmk__rsc_trace(rsc,
                        "Skipping configuration check for %s "
                        "because no longer active on %s",
                        rsc->id, pcmk__node_name(node));
        return;
    }

    pcmk__rsc_trace(rsc, "Checking for configuration changes for %s on %s",
                    rsc->id, pcmk__node_name(node));

    if (pcmk__rsc_agent_changed(rsc, node, rsc_entry, true)) {
        pcmk__schedule_cleanup(rsc, node, false);
    }

    sorted_op_list = rsc_history_as_list(rsc_entry, &start_index, &stop_index);
    if (start_index < stop_index) {
        return; // Resource is stopped
    }

    for (GList *iter = sorted_op_list; iter != NULL; iter = iter->next) {
        xmlNode *rsc_op = (xmlNode *) iter->data;
        const char *task = NULL;
        guint interval_ms = 0;

        if (++offset < start_index) {
            // Skip actions that happened before a start
            continue;
        }

        task = crm_element_value(rsc_op, PCMK_XA_OPERATION);
        crm_element_value_ms(rsc_op, PCMK_META_INTERVAL, &interval_ms);

        if ((interval_ms > 0)
            && (pcmk_is_set(rsc->flags, pcmk__rsc_maintenance)
                || node->details->maintenance)) {
            // Maintenance mode cancels recurring operations
            pcmk__schedule_cancel(rsc,
                                  crm_element_value(rsc_op, PCMK__XA_CALL_ID),
                                  task, interval_ms, node, "maintenance mode");

        } else if ((interval_ms > 0)
                   || pcmk__strcase_any_of(task, PCMK_ACTION_MONITOR,
                                           PCMK_ACTION_START,
                                           PCMK_ACTION_PROMOTE,
                                           PCMK_ACTION_MIGRATE_FROM, NULL)) {
            /* If a resource operation failed, and the operation's definition
             * has changed, clear any fail count so they can be retried fresh.
             */

            if (pe__bundle_needs_remote_name(rsc)) {
                /* We haven't assigned resources to nodes yet, so if the
                 * REMOTE_CONTAINER_HACK is used, we may calculate the digest
                 * based on the literal "#uname" value rather than the properly
                 * substituted value. That would mistakenly make the action
                 * definition appear to have been changed. Defer the check until
                 * later in this case.
                 */
                pcmk__add_param_check(rsc_op, rsc, node, pcmk__check_active);

            } else if (pcmk__check_action_config(rsc, node, rsc_op)
                       && (pe_get_failcount(node, rsc, NULL, pcmk__fc_effective,
                                            NULL) != 0)) {
                pe__clear_failcount(rsc, node, "action definition changed",
                                    rsc->priv->scheduler);
            }
        }
    }
    g_list_free(sorted_op_list);
}

/*!
 * \internal
 * \brief Process a node's action history from the CIB status
 *
 * Given a node's resource history, if the resource's configuration changed
 * since the actions were done, schedule any actions needed (restart,
 * reload, unfencing, rescheduling recurring actions, clean-up, etc.).
 * (This also cancels recurring actions for maintenance mode, which is not
 * entirely related but convenient to do here.)
 *
 * \param[in,out] node      Node whose history is being processed
 * \param[in]     lrm_rscs  Node's \c PCMK__XE_LRM_RESOURCES from CIB status XML
 */
static void
process_node_history(pcmk_node_t *node, const xmlNode *lrm_rscs)
{
    crm_trace("Processing node history for %s", pcmk__node_name(node));
    for (const xmlNode *rsc_entry = pcmk__xe_first_child(lrm_rscs,
                                                         PCMK__XE_LRM_RESOURCE,
                                                         NULL, NULL);
         rsc_entry != NULL;
         rsc_entry = pcmk__xe_next(rsc_entry, PCMK__XE_LRM_RESOURCE)) {

        if (rsc_entry->children != NULL) {
            GList *result = pcmk__rscs_matching_id(pcmk__xe_id(rsc_entry),
                                                   node->priv->scheduler);

            for (GList *iter = result; iter != NULL; iter = iter->next) {
                pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

                if (pcmk__is_primitive(rsc)) {
                    process_rsc_history(rsc_entry, rsc, node);
                }
            }
            g_list_free(result);
        }
    }
}

// XPath to find a node's resource history
#define XPATH_NODE_HISTORY "/" PCMK_XE_CIB "/" PCMK_XE_STATUS   \
                           "/" PCMK__XE_NODE_STATE              \
                           "[@" PCMK_XA_UNAME "='%s']"          \
                           "/" PCMK__XE_LRM "/" PCMK__XE_LRM_RESOURCES

/*!
 * \internal
 * \brief Process any resource configuration changes in the CIB status
 *
 * Go through all nodes' resource history, and if a resource's configuration
 * changed since its actions were done, schedule any actions needed (restart,
 * reload, unfencing, rescheduling recurring actions, clean-up, etc.).
 * (This also cancels recurring actions for maintenance mode, which is not
 * entirely related but convenient to do here.)
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__handle_rsc_config_changes(pcmk_scheduler_t *scheduler)
{
    crm_trace("Check resource and action configuration for changes");

    /* Rather than iterate through the status section, iterate through the nodes
     * and search for the appropriate status subsection for each. This skips
     * orphaned nodes and lets us eliminate some cases before searching the XML.
     */
    for (GList *iter = scheduler->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;

        /* Don't bother checking actions for a node that can't run actions ...
         * unless it's in maintenance mode, in which case we still need to
         * cancel any existing recurring monitors.
         */
        if (node->details->maintenance
            || pcmk__node_available(node, pcmk__node_alive|pcmk__node_usable)) {

            char *xpath = NULL;
            xmlNode *history = NULL;

            xpath = crm_strdup_printf(XPATH_NODE_HISTORY, node->priv->name);
            history = get_xpath_object(xpath, scheduler->input, LOG_NEVER);
            free(xpath);

            process_node_history(node, history);
        }
    }
}
