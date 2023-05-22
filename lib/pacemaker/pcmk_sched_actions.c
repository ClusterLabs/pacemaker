/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
action_flags_for_ordering(pe_action_t *action, const pe_node_t *node)
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
    flags = action->rsc->cmds->action_flags(action, NULL);
    if ((node == NULL) || !pe_rsc_is_clone(action->rsc)) {
        return flags;
    }

    /* Otherwise (i.e., for clone resource actions on a specific node), first
     * remember whether the non-node-specific action is runnable.
     */
    runnable = pcmk_is_set(flags, pe_action_runnable);

    // Then recheck the resource method with the node
    flags = action->rsc->cmds->action_flags(action, node);

    /* For clones in ordering constraints, the node-specific "runnable" doesn't
     * matter, just the non-node-specific setting (i.e., is the action runnable
     * anywhere).
     *
     * This applies only to runnable, and only for ordering constraints. This
     * function shouldn't be used for other types of constraints without
     * changes. Not very satisfying, but it's logical and appears to work well.
     */
    if (runnable && !pcmk_is_set(flags, pe_action_runnable)) {
        pe__set_raw_action_flags(flags, action->rsc->id,
                                 pe_action_runnable);
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
action_uuid_for_ordering(const char *first_uuid, const pe_resource_t *first_rsc)
{
    guint interval_ms = 0;
    char *uuid = NULL;
    char *rid = NULL;
    char *first_task_str = NULL;
    enum action_tasks first_task = no_action;
    enum action_tasks remapped_task = no_action;

    // Only non-notify actions for collective resources need remapping
    if ((strstr(first_uuid, "notify") != NULL)
        || (first_rsc->variant < pe_group)) {
        goto done;
    }

    // Only non-recurring actions need remapping
    CRM_ASSERT(parse_op_key(first_uuid, &rid, &first_task_str, &interval_ms));
    if (interval_ms > 0) {
        goto done;
    }

    first_task = text2task(first_task_str);
    switch (first_task) {
        case stop_rsc:
        case start_rsc:
        case action_notify:
        case action_promote:
        case action_demote:
            remapped_task = first_task + 1;
            break;
        case stopped_rsc:
        case started_rsc:
        case action_notified:
        case action_promoted:
        case action_demoted:
            remapped_task = first_task;
            break;
        case monitor_rsc:
        case shutdown_crm:
        case stonith_node:
            break;
        default:
            crm_err("Unknown action '%s' in ordering", first_task_str);
            break;
    }

    if (remapped_task != no_action) {
        /* If a (clone) resource has notifications enabled, we want to order
         * relative to when all notifications have been sent for the remapped
         * task. Only outermost resources or those in bundles have
         * notifications.
         */
        if (pcmk_is_set(first_rsc->flags, pe_rsc_notify)
            && ((first_rsc->parent == NULL)
                || (pe_rsc_is_clone(first_rsc)
                    && (first_rsc->parent->variant == pe_container)))) {
            uuid = pcmk__notify_key(rid, "confirmed-post",
                                    task2text(remapped_task));
        } else {
            uuid = pcmk__op_key(rid, task2text(remapped_task), 0);
        }
        pe_rsc_trace(first_rsc,
                     "Remapped action UUID %s to %s for ordering purposes",
                     first_uuid, uuid);
    }

done:
    if (uuid == NULL) {
        uuid = strdup(first_uuid);
        CRM_ASSERT(uuid != NULL);
    }
    free(first_task_str);
    free(rid);
    return uuid;
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
static pe_action_t *
action_for_ordering(pe_action_t *action)
{
    pe_action_t *result = action;
    pe_resource_t *rsc = action->rsc;

    if ((rsc != NULL) && (rsc->variant >= pe_group) && (action->uuid != NULL)) {
        char *uuid = action_uuid_for_ordering(action->uuid, rsc);

        result = find_first_action(rsc->actions, uuid, NULL, NULL);
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
 * \brief Update flags for ordering's actions appropriately for ordering's flags
 *
 * \param[in,out] first        First action in an ordering
 * \param[in,out] then         Then action in an ordering
 * \param[in]     first_flags  Action flags for \p first for ordering purposes
 * \param[in]     then_flags   Action flags for \p then for ordering purposes
 * \param[in,out] order        Action wrapper for \p first in ordering
 * \param[in,out] data_set     Cluster working set
 *
 * \return Group of enum pcmk__updated flags
 */
static uint32_t
update_action_for_ordering_flags(pe_action_t *first, pe_action_t *then,
                                 uint32_t first_flags, uint32_t then_flags,
                                 pe_action_wrapper_t *order,
                                 pe_working_set_t *data_set)
{
    uint32_t changed = pcmk__updated_none;

    /* The node will only be used for clones. If interleaved, node will be NULL,
     * otherwise the ordering scope will be limited to the node. Normally, the
     * whole 'then' clone should restart if 'first' is restarted, so then->node
     * is needed.
     */
    pe_node_t *node = then->node;

    if (pcmk_is_set(order->type, pe_order_implies_then_on_node)) {
        /* For unfencing, only instances of 'then' on the same node as 'first'
         * (the unfencing operation) should restart, so reset node to
         * first->node, at which point this case is handled like a normal
         * pe_order_implies_then.
         */
        pe__clear_order_flags(order->type, pe_order_implies_then_on_node);
        pe__set_order_flags(order->type, pe_order_implies_then);
        node = first->node;
        pe_rsc_trace(then->rsc,
                     "%s then %s: mapped pe_order_implies_then_on_node to "
                     "pe_order_implies_then on %s",
                     first->uuid, then->uuid, pe__node_name(node));
    }

    if (pcmk_is_set(order->type, pe_order_implies_then)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags & pe_action_optional,
                                                               pe_action_optional,
                                                               pe_order_implies_then,
                                                               data_set);
        } else if (!pcmk_is_set(first_flags, pe_action_optional)
                   && pcmk_is_set(then->flags, pe_action_optional)) {
            pe__clear_action_flags(then, pe_action_optional);
            pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_implies_then",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_restart) && (then->rsc != NULL)) {
        enum pe_action_flags restart = pe_action_optional|pe_action_runnable;

        changed |= then->rsc->cmds->update_ordered_actions(first, then, node,
                                                           first_flags, restart,
                                                           pe_order_restart,
                                                           data_set);
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_restart",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_implies_first)) {
        if (first->rsc != NULL) {
            changed |= first->rsc->cmds->update_ordered_actions(first, then,
                                                                node,
                                                                first_flags,
                                                                pe_action_optional,
                                                                pe_order_implies_first,
                                                                data_set);
        } else if (!pcmk_is_set(first_flags, pe_action_optional)
                   && pcmk_is_set(first->flags, pe_action_runnable)) {
            pe__clear_action_flags(first, pe_action_runnable);
            pcmk__set_updated_flags(changed, first, pcmk__updated_first);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_implies_first",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_promoted_implies_first)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags & pe_action_optional,
                                                               pe_action_optional,
                                                               pe_order_promoted_implies_first,
                                                               data_set);
        }
        pe_rsc_trace(then->rsc,
                     "%s then %s: %s after pe_order_promoted_implies_first",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_one_or_more)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_runnable,
                                                               pe_order_one_or_more,
                                                               data_set);

        } else if (pcmk_is_set(first_flags, pe_action_runnable)) {
            // We have another runnable instance of "first"
            then->runnable_before++;

            /* Mark "then" as runnable if it requires a certain number of
             * "before" instances to be runnable, and they now are.
             */
            if ((then->runnable_before >= then->required_runnable_before)
                && !pcmk_is_set(then->flags, pe_action_runnable)) {

                pe__set_action_flags(then, pe_action_runnable);
                pcmk__set_updated_flags(changed, first, pcmk__updated_then);
            }
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_one_or_more",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_probe) && (then->rsc != NULL)) {
        if (!pcmk_is_set(first_flags, pe_action_runnable)
            && (first->rsc->running_on != NULL)) {

            pe_rsc_trace(then->rsc,
                         "%s then %s: ignoring because first is stopping",
                         first->uuid, then->uuid);
            order->type = pe_order_none;
        } else {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_runnable,
                                                               pe_order_runnable_left,
                                                               data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_probe",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_runnable_left)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_runnable,
                                                               pe_order_runnable_left,
                                                               data_set);

        } else if (!pcmk_is_set(first_flags, pe_action_runnable)
                   && pcmk_is_set(then->flags, pe_action_runnable)) {

            pe__clear_action_flags(then, pe_action_runnable);
            pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_runnable_left",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_implies_first_migratable)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_optional,
                                                               pe_order_implies_first_migratable,
                                                               data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after "
                     "pe_order_implies_first_migratable",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_pseudo_left)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_optional,
                                                               pe_order_pseudo_left,
                                                               data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_pseudo_left",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_optional)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_runnable,
                                                               pe_order_optional,
                                                               data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_optional",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_asymmetrical)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_ordered_actions(first, then,
                                                               node,
                                                               first_flags,
                                                               pe_action_runnable,
                                                               pe_order_asymmetrical,
                                                               data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_asymmetrical",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(first->flags, pe_action_runnable)
        && pcmk_is_set(order->type, pe_order_implies_then_printed)
        && !pcmk_is_set(first_flags, pe_action_optional)) {

        pe_rsc_trace(then->rsc, "%s will be in graph because %s is required",
                     then->uuid, first->uuid);
        pe__set_action_flags(then, pe_action_print_always);
        // Don't bother marking 'then' as changed just for this
    }

    if (pcmk_is_set(order->type, pe_order_implies_first_printed)
        && !pcmk_is_set(then_flags, pe_action_optional)) {

        pe_rsc_trace(then->rsc, "%s will be in graph because %s is required",
                     first->uuid, then->uuid);
        pe__set_action_flags(first, pe_action_print_always);
        // Don't bother marking 'first' as changed just for this
    }

    if (pcmk_any_flags_set(order->type, pe_order_implies_then
                                        |pe_order_implies_first
                                        |pe_order_restart)
        && (first->rsc != NULL)
        && !pcmk_is_set(first->rsc->flags, pe_rsc_managed)
        && pcmk_is_set(first->rsc->flags, pe_rsc_block)
        && !pcmk_is_set(first->flags, pe_action_runnable)
        && pcmk__str_eq(first->task, RSC_STOP, pcmk__str_none)) {

        if (pcmk_is_set(then->flags, pe_action_runnable)) {
            pe__clear_action_flags(then, pe_action_runnable);
            pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after checking whether first "
                     "is blocked, unmanaged, unrunnable stop",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    return changed;
}

// Convenience macros for logging action properties

#define action_type_str(flags) \
    (pcmk_is_set((flags), pe_action_pseudo)? "pseudo-action" : "action")

#define action_optional_str(flags) \
    (pcmk_is_set((flags), pe_action_optional)? "optional" : "required")

#define action_runnable_str(flags) \
    (pcmk_is_set((flags), pe_action_runnable)? "runnable" : "unrunnable")

#define action_node_str(a) \
    (((a)->node == NULL)? "no node" : (a)->node->details->uname)

/*!
 * \internal
 * \brief Update an action's flags for all orderings where it is "then"
 *
 * \param[in,out] then      Action to update
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__update_action_for_orderings(pe_action_t *then, pe_working_set_t *data_set)
{
    GList *lpc = NULL;
    uint32_t changed = pcmk__updated_none;
    int last_flags = then->flags;

    pe_rsc_trace(then->rsc, "Updating %s %s (%s %s) on %s",
                 action_type_str(then->flags), then->uuid,
                 action_optional_str(then->flags),
                 action_runnable_str(then->flags), action_node_str(then));

    if (pcmk_is_set(then->flags, pe_action_requires_any)) {
        /* Initialize current known "runnable before" actions. As
         * update_action_for_ordering_flags() is called for each of then's
         * before actions, this number will increment as runnable 'first'
         * actions are encountered.
         */
        then->runnable_before = 0;

        if (then->required_runnable_before == 0) {
            /* @COMPAT This ordering constraint uses the deprecated
             * "require-all=false" attribute. Treat it like "clone-min=1".
             */
            then->required_runnable_before = 1;
        }

        /* The pe_order_one_or_more clause of update_action_for_ordering_flags()
         * (called below) will reset runnable if appropriate.
         */
        pe__clear_action_flags(then, pe_action_runnable);
    }

    for (lpc = then->actions_before; lpc != NULL; lpc = lpc->next) {
        pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc->data;
        pe_action_t *first = other->action;

        pe_node_t *then_node = then->node;
        pe_node_t *first_node = first->node;

        if ((first->rsc != NULL)
            && (first->rsc->variant == pe_group)
            && pcmk__str_eq(first->task, RSC_START, pcmk__str_none)) {

            first_node = first->rsc->fns->location(first->rsc, NULL, FALSE);
            if (first_node != NULL) {
                pe_rsc_trace(first->rsc, "Found %s for 'first' %s",
                             pe__node_name(first_node), first->uuid);
            }
        }

        if ((then->rsc != NULL)
            && (then->rsc->variant == pe_group)
            && pcmk__str_eq(then->task, RSC_START, pcmk__str_none)) {

            then_node = then->rsc->fns->location(then->rsc, NULL, FALSE);
            if (then_node != NULL) {
                pe_rsc_trace(then->rsc, "Found %s for 'then' %s",
                             pe__node_name(then_node), then->uuid);
            }
        }

        // Disable constraint if it only applies when on same node, but isn't
        if (pcmk_is_set(other->type, pe_order_same_node)
            && (first_node != NULL) && (then_node != NULL)
            && !pe__same_node(first_node, then_node)) {

            pe_rsc_trace(then->rsc,
                         "Disabled ordering %s on %s then %s on %s: "
                         "not same node",
                         other->action->uuid, pe__node_name(first_node),
                         then->uuid, pe__node_name(then_node));
            other->type = pe_order_none;
            continue;
        }

        pcmk__clear_updated_flags(changed, then, pcmk__updated_first);

        if ((first->rsc != NULL)
            && pcmk_is_set(other->type, pe_order_then_cancels_first)
            && !pcmk_is_set(then->flags, pe_action_optional)) {

            /* 'then' is required, so we must abandon 'first'
             * (e.g. a required stop cancels any agent reload).
             */
            pe__set_action_flags(other->action, pe_action_optional);
            if (!strcmp(first->task, CRMD_ACTION_RELOAD_AGENT)) {
                pe__clear_resource_flags(first->rsc, pe_rsc_reload);
            }
        }

        if ((first->rsc != NULL) && (then->rsc != NULL)
            && (first->rsc != then->rsc) && !is_parent(then->rsc, first->rsc)) {
            first = action_for_ordering(first);
        }
        if (first != other->action) {
            pe_rsc_trace(then->rsc, "Ordering %s after %s instead of %s",
                         then->uuid, first->uuid, other->action->uuid);
        }

        pe_rsc_trace(then->rsc,
                     "%s (%#.6x) then %s (%#.6x): type=%#.6x node=%s",
                     first->uuid, first->flags, then->uuid, then->flags,
                     other->type, action_node_str(first));

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
                                                        other, data_set);

            /* 'first' was for a complex resource (clone, group, etc),
             * create a new dependency if necessary
             */
        } else if (order_actions(first, then, other->type)) {
            /* This was the first time 'first' and 'then' were associated,
             * start again to get the new actions_before list
             */
            pcmk__set_updated_flags(changed, then, pcmk__updated_then);
            pe_rsc_trace(then->rsc,
                         "Disabled ordering %s then %s in favor of %s then %s",
                         other->action->uuid, then->uuid, first->uuid,
                         then->uuid);
            other->type = pe_order_none;
        }


        if (pcmk_is_set(changed, pcmk__updated_first)) {
            crm_trace("Re-processing %s and its 'after' actions "
                      "because it changed", first->uuid);
            for (GList *lpc2 = first->actions_after; lpc2 != NULL;
                 lpc2 = lpc2->next) {
                pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc2->data;

                pcmk__update_action_for_orderings(other->action, data_set);
            }
            pcmk__update_action_for_orderings(first, data_set);
        }
    }

    if (pcmk_is_set(then->flags, pe_action_requires_any)) {
        if (last_flags == then->flags) {
            pcmk__clear_updated_flags(changed, then, pcmk__updated_then);
        } else {
            pcmk__set_updated_flags(changed, then, pcmk__updated_then);
        }
    }

    if (pcmk_is_set(changed, pcmk__updated_then)) {
        crm_trace("Re-processing %s and its 'after' actions because it changed",
                  then->uuid);
        if (pcmk_is_set(last_flags, pe_action_runnable)
            && !pcmk_is_set(then->flags, pe_action_runnable)) {
            pcmk__block_colocation_dependents(then);
        }
        pcmk__update_action_for_orderings(then, data_set);
        for (lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc->data;

            pcmk__update_action_for_orderings(other->action, data_set);
        }
    }
}

static inline bool
is_primitive_action(const pe_action_t *action)
{
    return action && action->rsc && (action->rsc->variant == pe_native);
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
            pe__clear_action_flags(action, flag);                           \
            if ((action)->rsc != (reason)->rsc) {                           \
                char *reason_text = pe__action2reason((reason), (flag));    \
                pe_action_set_reason((action), reason_text,                 \
                                   ((flag) == pe_action_migrate_runnable)); \
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
handle_asymmetric_ordering(const pe_action_t *first, pe_action_t *then)
{
    /* Only resource actions after an unrunnable 'first' action need updates for
     * asymmetric ordering.
     */
    if ((then->rsc == NULL) || pcmk_is_set(first->flags, pe_action_runnable)) {
        return;
    }

    // Certain optional 'then' actions are unaffected by unrunnable 'first'
    if (pcmk_is_set(then->flags, pe_action_optional)) {
        enum rsc_role_e then_rsc_role = then->rsc->fns->state(then->rsc, TRUE);

        if ((then_rsc_role == RSC_ROLE_STOPPED)
            && pcmk__str_eq(then->task, RSC_STOP, pcmk__str_none)) {
            /* If 'then' should stop after 'first' but is already stopped, the
             * ordering is irrelevant.
             */
            return;
        } else if ((then_rsc_role >= RSC_ROLE_STARTED)
            && pcmk__str_eq(then->task, RSC_START, pcmk__str_none)
            && pe__rsc_running_on_only(then->rsc, then->node)) {
            /* Similarly if 'then' should start after 'first' but is already
             * started on a single node.
             */
            return;
        }
    }

    // 'First' can't run, so 'then' can't either
    clear_action_flag_because(then, pe_action_optional, first);
    clear_action_flag_because(then, pe_action_runnable, first);
}

/*!
 * \internal
 * \brief Set action bits appropriately when pe_restart_order is used
 *
 * \param[in,out] first   'First' action in an ordering with pe_restart_order
 * \param[in,out] then    'Then' action in an ordering with pe_restart_order
 * \param[in]     filter  What action flags to care about
 *
 * \note pe_restart_order is set for "stop resource before starting it" and
 *       "stop later group member before stopping earlier group member"
 */
static void
handle_restart_ordering(pe_action_t *first, pe_action_t *then, uint32_t filter)
{
    const char *reason = NULL;

    CRM_ASSERT(is_primitive_action(first));
    CRM_ASSERT(is_primitive_action(then));

    // We need to update the action in two cases:

    // ... if 'then' is required
    if (pcmk_is_set(filter, pe_action_optional)
        && !pcmk_is_set(then->flags, pe_action_optional)) {
        reason = "restart";
    }

    /* ... if 'then' is unrunnable action on same resource (if a resource
     * should restart but can't start, we still want to stop)
     */
    if (pcmk_is_set(filter, pe_action_runnable)
        && !pcmk_is_set(then->flags, pe_action_runnable)
        && pcmk_is_set(then->rsc->flags, pe_rsc_managed)
        && (first->rsc == then->rsc)) {
        reason = "stop";
    }

    if (reason == NULL) {
        return;
    }

    pe_rsc_trace(first->rsc, "Handling %s -> %s for %s",
                 first->uuid, then->uuid, reason);

    // Make 'first' required if it is runnable
    if (pcmk_is_set(first->flags, pe_action_runnable)) {
        clear_action_flag_because(first, pe_action_optional, then);
    }

    // Make 'first' required if 'then' is required
    if (!pcmk_is_set(then->flags, pe_action_optional)) {
        clear_action_flag_because(first, pe_action_optional, then);
    }

    // Make 'first' unmigratable if 'then' is unmigratable
    if (!pcmk_is_set(then->flags, pe_action_migrate_runnable)) {
        clear_action_flag_because(first, pe_action_migrate_runnable, then);
    }

    // Make 'then' unrunnable if 'first' is required but unrunnable
    if (!pcmk_is_set(first->flags, pe_action_optional)
        && !pcmk_is_set(first->flags, pe_action_runnable)) {
        clear_action_flag_because(then, pe_action_runnable, first);
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
 * \param[in,out] first     'First' action in an ordering
 * \param[in,out] then      'Then' action in an ordering
 * \param[in]     node      If not NULL, limit scope of ordering to this node
 *                          (ignored)
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
pcmk__update_ordered_actions(pe_action_t *first, pe_action_t *then,
                             const pe_node_t *node, uint32_t flags,
                             uint32_t filter, uint32_t type,
                             pe_working_set_t *data_set)
{
    uint32_t changed = pcmk__updated_none;
    uint32_t then_flags = 0U;
    uint32_t first_flags = 0U;

    CRM_ASSERT((first != NULL) && (then != NULL) && (data_set != NULL));

    then_flags = then->flags;
    first_flags = first->flags;
    if (pcmk_is_set(type, pe_order_asymmetrical)) {
        handle_asymmetric_ordering(first, then);
    }

    if (pcmk_is_set(type, pe_order_implies_first)
        && !pcmk_is_set(then_flags, pe_action_optional)) {
        // Then is required, and implies first should be, too

        if (pcmk_is_set(filter, pe_action_optional)
            && !pcmk_is_set(flags, pe_action_optional)
            && pcmk_is_set(first_flags, pe_action_optional)) {
            clear_action_flag_because(first, pe_action_optional, then);
        }

        if (pcmk_is_set(flags, pe_action_migrate_runnable)
            && !pcmk_is_set(then->flags, pe_action_migrate_runnable)) {
            clear_action_flag_because(first, pe_action_migrate_runnable, then);
        }
    }

    if (pcmk_is_set(type, pe_order_promoted_implies_first)
        && (then->rsc != NULL) && (then->rsc->role == RSC_ROLE_PROMOTED)
        && pcmk_is_set(filter, pe_action_optional)
        && !pcmk_is_set(then->flags, pe_action_optional)) {

        clear_action_flag_because(first, pe_action_optional, then);

        if (pcmk_is_set(first->flags, pe_action_migrate_runnable)
            && !pcmk_is_set(then->flags, pe_action_migrate_runnable)) {
            clear_action_flag_because(first, pe_action_migrate_runnable,
                                      then);
        }
    }

    if (pcmk_is_set(type, pe_order_implies_first_migratable)
        && pcmk_is_set(filter, pe_action_optional)) {

        if (!pcmk_all_flags_set(then->flags, pe_action_migrate_runnable
                                             |pe_action_runnable)) {
            clear_action_flag_because(first, pe_action_runnable, then);
        }

        if (!pcmk_is_set(then->flags, pe_action_optional)) {
            clear_action_flag_because(first, pe_action_optional, then);
        }
    }

    if (pcmk_is_set(type, pe_order_pseudo_left)
        && pcmk_is_set(filter, pe_action_optional)
        && !pcmk_is_set(first->flags, pe_action_runnable)) {

        clear_action_flag_because(then, pe_action_migrate_runnable, first);
        pe__clear_action_flags(then, pe_action_pseudo);
    }

    if (pcmk_is_set(type, pe_order_runnable_left)
        && pcmk_is_set(filter, pe_action_runnable)
        && pcmk_is_set(then->flags, pe_action_runnable)
        && !pcmk_is_set(flags, pe_action_runnable)) {

        clear_action_flag_because(then, pe_action_runnable, first);
        clear_action_flag_because(then, pe_action_migrate_runnable, first);
    }

    if (pcmk_is_set(type, pe_order_implies_then)
        && pcmk_is_set(filter, pe_action_optional)
        && pcmk_is_set(then->flags, pe_action_optional)
        && !pcmk_is_set(flags, pe_action_optional)
        && !pcmk_is_set(first->flags, pe_action_migrate_runnable)) {

        clear_action_flag_because(then, pe_action_optional, first);
    }

    if (pcmk_is_set(type, pe_order_restart)) {
        handle_restart_ordering(first, then, filter);
    }

    if (then_flags != then->flags) {
        pcmk__set_updated_flags(changed, first, pcmk__updated_then);
        pe_rsc_trace(then->rsc,
                     "%s on %s: flags are now %#.6x (was %#.6x) "
                     "because of 'first' %s (%#.6x)",
                     then->uuid, pe__node_name(then->node),
                     then->flags, then_flags, first->uuid, first->flags);

        if ((then->rsc != NULL) && (then->rsc->parent != NULL)) {
            // Required to handle "X_stop then X_start" for cloned groups
            pcmk__update_action_for_orderings(then, data_set);
        }
    }

    if (first_flags != first->flags) {
        pcmk__set_updated_flags(changed, first, pcmk__updated_first);
        pe_rsc_trace(first->rsc,
                     "%s on %s: flags are now %#.6x (was %#.6x) "
                     "because of 'then' %s (%#.6x)",
                     first->uuid, pe__node_name(first->node),
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
pcmk__log_action(const char *pre_text, const pe_action_t *action, bool details)
{
    const char *node_uname = NULL;
    const char *node_uuid = NULL;
    const char *desc = NULL;

    CRM_CHECK(action != NULL, return);

    if (!pcmk_is_set(action->flags, pe_action_pseudo)) {
        if (action->node != NULL) {
            node_uname = action->node->details->uname;
            node_uuid = action->node->details->id;
        } else {
            node_uname = "<none>";
        }
    }

    switch (text2task(action->task)) {
        case stonith_node:
        case shutdown_crm:
            if (pcmk_is_set(action->flags, pe_action_pseudo)) {
                desc = "Pseudo ";
            } else if (pcmk_is_set(action->flags, pe_action_optional)) {
                desc = "Optional ";
            } else if (!pcmk_is_set(action->flags, pe_action_runnable)) {
                desc = "!!Non-Startable!! ";
            } else if (pcmk_is_set(action->flags, pe_action_processed)) {
               desc = "";
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
            if (pcmk_is_set(action->flags, pe_action_optional)) {
                desc = "Optional ";
            } else if (pcmk_is_set(action->flags, pe_action_pseudo)) {
                desc = "Pseudo ";
            } else if (!pcmk_is_set(action->flags, pe_action_runnable)) {
                desc = "!!Non-Startable!! ";
            } else if (pcmk_is_set(action->flags, pe_action_processed)) {
               desc = "";
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
        const pe_action_wrapper_t *other = NULL;

        crm_trace("\t\t====== Preceding Actions");
        for (iter = action->actions_before; iter != NULL; iter = iter->next) {
            other = (const pe_action_wrapper_t *) iter->data;
            pcmk__log_action("\t\t", other->action, false);
        }
        crm_trace("\t\t====== Subsequent Actions");
        for (iter = action->actions_after; iter != NULL; iter = iter->next) {
            other = (const pe_action_wrapper_t *) iter->data;
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
pe_action_t *
pcmk__new_shutdown_action(pe_node_t *node)
{
    char *shutdown_id = NULL;
    pe_action_t *shutdown_op = NULL;

    CRM_ASSERT(node != NULL);

    shutdown_id = crm_strdup_printf("%s-%s", CRM_OP_SHUTDOWN,
                                    node->details->uname);

    shutdown_op = custom_action(NULL, shutdown_id, CRM_OP_SHUTDOWN, node, FALSE,
                                TRUE, node->details->data_set);

    pcmk__order_stops_before_shutdown(node, shutdown_op);
    add_hash_param(shutdown_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
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
    args_xml = create_xml_node(NULL, XML_TAG_PARAMS);
    g_hash_table_foreach(op->params, hash2field, args_xml);
    pcmk__filter_op_for_digest(args_xml);
    digest = calculate_operation_digest(args_xml, NULL);
    crm_xml_add(update, XML_LRM_ATTR_OP_DIGEST, digest);
    free_xml(args_xml);
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
     */
    if (pcmk__str_any_of(task, CRMD_ACTION_RELOAD, CRMD_ACTION_RELOAD_AGENT,
                         NULL)) {
        if (op->op_status == PCMK_EXEC_DONE) {
            task = CRMD_ACTION_START;
        } else {
            task = CRMD_ACTION_STATUS;
        }
    }

    key = pcmk__op_key(op->rsc_id, task, op->interval_ms);
    if (pcmk__str_eq(task, CRMD_ACTION_NOTIFY, pcmk__str_none)) {
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
    } else if (pcmk__str_any_of(op->op_type, CRMD_ACTION_MIGRATE,
                                CRMD_ACTION_MIGRATED, NULL)) {
        op_id = strdup(key);

    } else if (did_rsc_op_fail(op, target_rc)) {
        op_id = pcmk__op_key(op->rsc_id, "last_failure", 0);
        if (op->interval_ms == 0) {
            // Ensure 'last' gets updated, in case record-pending is true
            op_id_additional = pcmk__op_key(op->rsc_id, "last", 0);
        }
        exit_reason = op->exit_reason;

    } else if (op->interval_ms > 0) {
        op_id = strdup(key);

    } else {
        op_id = pcmk__op_key(op->rsc_id, "last", 0);
    }

  again:
    xml_op = pcmk__xe_match(parent, XML_LRM_TAG_RSC_OP, XML_ATTR_ID, op_id);
    if (xml_op == NULL) {
        xml_op = create_xml_node(parent, XML_LRM_TAG_RSC_OP);
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

    crm_xml_add(xml_op, XML_ATTR_ID, op_id);
    crm_xml_add(xml_op, XML_LRM_ATTR_TASK_KEY, key);
    crm_xml_add(xml_op, XML_LRM_ATTR_TASK, task);
    crm_xml_add(xml_op, XML_ATTR_ORIGIN, origin);
    crm_xml_add(xml_op, XML_ATTR_CRM_VERSION, caller_version);
    crm_xml_add(xml_op, XML_ATTR_TRANSITION_KEY, op->user_data);
    crm_xml_add(xml_op, XML_ATTR_TRANSITION_MAGIC, magic);
    crm_xml_add(xml_op, XML_LRM_ATTR_EXIT_REASON, pcmk__s(exit_reason, ""));
    crm_xml_add(xml_op, XML_LRM_ATTR_TARGET, node); // For context during triage

    crm_xml_add_int(xml_op, XML_LRM_ATTR_CALLID, op->call_id);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_RC, op->rc);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_OPSTATUS, op->op_status);
    crm_xml_add_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, op->interval_ms);

    if (compare_version("2.1", caller_version) <= 0) {
        if (op->t_run || op->t_rcchange || op->exec_time || op->queue_time) {
            crm_trace("Timing data (" PCMK__OP_FMT
                      "): last=%u change=%u exec=%u queue=%u",
                      op->rsc_id, op->op_type, op->interval_ms,
                      op->t_run, op->t_rcchange, op->exec_time, op->queue_time);

            if ((op->interval_ms != 0) && (op->t_rcchange != 0)) {
                // Recurring ops may have changed rc after initial run
                crm_xml_add_ll(xml_op, XML_RSC_OP_LAST_CHANGE,
                               (long long) op->t_rcchange);
            } else {
                crm_xml_add_ll(xml_op, XML_RSC_OP_LAST_CHANGE,
                               (long long) op->t_run);
            }

            crm_xml_add_int(xml_op, XML_RSC_OP_T_EXEC, op->exec_time);
            crm_xml_add_int(xml_op, XML_RSC_OP_T_QUEUE, op->queue_time);
        }
    }

    if (pcmk__str_any_of(op->op_type, CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED,
                         NULL)) {
        /*
         * Record migrate_source and migrate_target always for migrate ops.
         */
        const char *name = XML_LRM_ATTR_MIGRATE_SOURCE;

        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));

        name = XML_LRM_ATTR_MIGRATE_TARGET;
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
 * If the shutdown-lock cluster property is set, resources will not be recovered
 * on a different node if cleanly stopped, and may start only on that same node.
 * This function checks whether that applies to a given action, so that the
 * transition graph can be marked appropriately.
 *
 * \param[in] action  Action to check
 *
 * \return true if \p action locks its resource to the action's node,
 *         otherwise false
 */
bool
pcmk__action_locks_rsc_to_node(const pe_action_t *action)
{
    // Only resource actions taking place on resource's lock node are locked
    if ((action == NULL) || (action->rsc == NULL)
        || !pe__same_node(action->node, action->rsc->lock_node)) {
        return false;
    }

    /* During shutdown, only stops are locked (otherwise, another action such as
     * a demote would cause the controller to clear the lock)
     */
    if (action->node->details->shutdown && (action->task != NULL)
        && (strcmp(action->task, RSC_STOP) != 0)) {
        return false;
    }

    return true;
}

/* lowest to highest */
static gint
sort_action_id(gconstpointer a, gconstpointer b)
{
    const pe_action_wrapper_t *action_wrapper2 = (const pe_action_wrapper_t *)a;
    const pe_action_wrapper_t *action_wrapper1 = (const pe_action_wrapper_t *)b;

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
pcmk__deduplicate_action_inputs(pe_action_t *action)
{
    GList *item = NULL;
    GList *next = NULL;
    pe_action_wrapper_t *last_input = NULL;

    action->actions_before = g_list_sort(action->actions_before,
                                         sort_action_id);
    for (item = action->actions_before; item != NULL; item = next) {
        pe_action_wrapper_t *input = (pe_action_wrapper_t *) item->data;

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
            last_input->type |= input->type;
            if (input->state == pe_link_dumped) {
                last_input->state = pe_link_dumped;
            }

            free(item->data);
            action->actions_before = g_list_delete_link(action->actions_before,
                                                        item);
        } else {
            last_input = input;
            input->state = pe_link_not_dumped;
        }
    }
}

/*!
 * \internal
 * \brief Output all scheduled actions
 *
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__output_actions(pe_working_set_t *data_set)
{
    pcmk__output_t *out = data_set->priv;

    // Output node (non-resource) actions
    for (GList *iter = data_set->actions; iter != NULL; iter = iter->next) {
        char *node_name = NULL;
        char *task = NULL;
        pe_action_t *action = (pe_action_t *) iter->data;

        if (action->rsc != NULL) {
            continue; // Resource actions will be output later

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            continue; // This action was not scheduled
        }

        if (pcmk__str_eq(action->task, CRM_OP_SHUTDOWN, pcmk__str_none)) {
            task = strdup("Shutdown");

        } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_none)) {
            const char *op = g_hash_table_lookup(action->meta,
                                                 "stonith_action");

            task = crm_strdup_printf("Fence (%s)", op);

        } else {
            continue; // Don't display other node action types
        }

        if (pe__is_guest_node(action->node)) {
            node_name = crm_strdup_printf("%s (resource: %s)",
                                          pe__node_name(action->node),
                                          action->node->details->remote_rsc->container->id);
        } else if (action->node != NULL) {
            node_name = crm_strdup_printf("%s", pe__node_name(action->node));
        }

        out->message(out, "node-action", task, node_name, action->reason);

        free(node_name);
        free(task);
    }

    // Output resource actions
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        rsc->cmds->output_actions(rsc);
    }
}

/*!
 * \internal
 * \brief Check whether action from resource history is still in configuration
 *
 * \param[in] rsc          Resource that action is for
 * \param[in] task         Action's name
 * \param[in] interval_ms  Action's interval (in milliseconds)
 *
 * \return true if action is still in resource configuration, otherwise false
 */
static bool
action_in_config(const pe_resource_t *rsc, const char *task, guint interval_ms)
{
    char *key = pcmk__op_key(rsc->id, task, interval_ms);
    bool config = (find_rsc_op_entry(rsc, key) != NULL);

    free(key);
    return config;
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
    if ((interval_ms == 0) && pcmk__str_any_of(task, RSC_STATUS, RSC_MIGRATED,
                                               RSC_PROMOTE, NULL)) {
        task = RSC_START;
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
 * \param[in] data_set     Cluster working set
 *
 * \return true if only sanitized parameters changed, otherwise false
 */
static bool
only_sanitized_changed(const xmlNode *xml_op,
                       const op_digest_cache_t *digest_data,
                       const pe_working_set_t *data_set)
{
    const char *digest_secure = NULL;

    if (!pcmk_is_set(data_set->flags, pe_flag_sanitized)) {
        // The scheduler is not being run as a simulation
        return false;
    }

    digest_secure = crm_element_value(xml_op, XML_LRM_ATTR_SECURE_DIGEST);

    return (digest_data->rc != RSC_DIGEST_MATCH) && (digest_secure != NULL)
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
force_restart(pe_resource_t *rsc, const char *task, guint interval_ms,
              pe_node_t *node)
{
    char *key = pcmk__op_key(rsc->id, task, interval_ms);
    pe_action_t *required = custom_action(rsc, key, task, NULL, FALSE, TRUE,
                                          rsc->cluster);

    pe_action_set_reason(required, "resource definition change", true);
    trigger_unfencing(rsc, node, "Device parameters changed", NULL,
                      rsc->cluster);
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
    pe_resource_t *rsc = data;
    const pe_node_t *node = user_data;
    pe_action_t *reload = NULL;

    // For collective resources, just call recursively for children
    if (rsc->variant > pe_native) {
        g_list_foreach(rsc->children, schedule_reload, user_data);
        return;
    }

    // Skip the reload in certain situations
    if ((node == NULL)
        || !pcmk_is_set(rsc->flags, pe_rsc_managed)
        || pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        pe_rsc_trace(rsc, "Skip reload of %s:%s%s %s",
                     rsc->id,
                     pcmk_is_set(rsc->flags, pe_rsc_managed)? "" : " unmanaged",
                     pcmk_is_set(rsc->flags, pe_rsc_failed)? " failed" : "",
                     (node == NULL)? "inactive" : node->details->uname);
        return;
    }

    /* If a resource's configuration changed while a start was pending,
     * force a full restart instead of a reload.
     */
    if (pcmk_is_set(rsc->flags, pe_rsc_start_pending)) {
        pe_rsc_trace(rsc, "%s: preventing agent reload because start pending",
                     rsc->id);
        custom_action(rsc, stop_key(rsc), CRMD_ACTION_STOP, node, FALSE, TRUE,
                      rsc->cluster);
        return;
    }

    // Schedule the reload
    pe__set_resource_flags(rsc, pe_rsc_reload);
    reload = custom_action(rsc, reload_key(rsc), CRMD_ACTION_RELOAD_AGENT, node,
                           FALSE, TRUE, rsc->cluster);
    pe_action_set_reason(reload, "resource definition change", FALSE);

    // Set orderings so that a required stop or demote cancels the reload
    pcmk__new_ordering(NULL, NULL, reload, rsc, stop_key(rsc), NULL,
                       pe_order_optional|pe_order_then_cancels_first,
                       rsc->cluster);
    pcmk__new_ordering(NULL, NULL, reload, rsc, demote_key(rsc), NULL,
                       pe_order_optional|pe_order_then_cancels_first,
                       rsc->cluster);
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
pcmk__check_action_config(pe_resource_t *rsc, pe_node_t *node,
                          const xmlNode *xml_op)
{
    guint interval_ms = 0;
    const char *task = NULL;
    const op_digest_cache_t *digest_data = NULL;

    CRM_CHECK((rsc != NULL) && (node != NULL) && (xml_op != NULL),
              return false);

    task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    CRM_CHECK(task != NULL, return false);

    crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

    // If this is a recurring action, check whether it has been orphaned
    if (interval_ms > 0) {
        if (action_in_config(rsc, task, interval_ms)) {
            pe_rsc_trace(rsc, "%s-interval %s for %s on %s is in configuration",
                         pcmk__readable_interval(interval_ms), task, rsc->id,
                         pe__node_name(node));
        } else if (pcmk_is_set(rsc->cluster->flags,
                               pe_flag_stop_action_orphans)) {
            pcmk__schedule_cancel(rsc,
                                  crm_element_value(xml_op,
                                                    XML_LRM_ATTR_CALLID),
                                  task, interval_ms, node, "orphan");
            return true;
        } else {
            pe_rsc_debug(rsc, "%s-interval %s for %s on %s is orphaned",
                         pcmk__readable_interval(interval_ms), task, rsc->id,
                         pe__node_name(node));
            return true;
        }
    }

    crm_trace("Checking %s-interval %s for %s on %s for configuration changes",
              pcmk__readable_interval(interval_ms), task, rsc->id,
              pe__node_name(node));
    task = task_for_digest(task, interval_ms);
    digest_data = rsc_action_digest_cmp(rsc, xml_op, node, rsc->cluster);

    if (only_sanitized_changed(xml_op, digest_data, rsc->cluster)) {
        if (!pcmk__is_daemon && (rsc->cluster->priv != NULL)) {
            pcmk__output_t *out = rsc->cluster->priv;

            out->info(out,
                      "Only 'private' parameters to %s-interval %s for %s "
                      "on %s changed: %s",
                      pcmk__readable_interval(interval_ms), task, rsc->id,
                      pe__node_name(node),
                      crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        }
        return false;
    }

    switch (digest_data->rc) {
        case RSC_DIGEST_RESTART:
            crm_log_xml_debug(digest_data->params_restart, "params:restart");
            force_restart(rsc, task, interval_ms, node);
            return true;

        case RSC_DIGEST_ALL:
        case RSC_DIGEST_UNKNOWN:
            // Changes that can potentially be handled by an agent reload

            if (interval_ms > 0) {
                /* Recurring actions aren't reloaded per se, they are just
                 * re-scheduled so the next run uses the new parameters.
                 * The old instance will be cancelled automatically.
                 */
                crm_log_xml_debug(digest_data->params_all, "params:reschedule");
                pcmk__reschedule_recurring(rsc, task, interval_ms, node);

            } else if (crm_element_value(xml_op,
                                         XML_LRM_ATTR_RESTART_DIGEST) != NULL) {
                // Agent supports reload, so use it
                trigger_unfencing(rsc, node,
                                  "Device parameters changed (reload)", NULL,
                                  rsc->cluster);
                crm_log_xml_debug(digest_data->params_all, "params:reload");
                schedule_reload((gpointer) rsc, (gpointer) node);

            } else {
                pe_rsc_trace(rsc,
                             "Restarting %s "
                             "because agent doesn't support reload", rsc->id);
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
 * \param[in]  rsc_entry    Resource's <lrm_rsc_op> status XML
 * \param[out] start_index  Where to store index of start-like action, if any
 * \param[out] stop_index   Where to store index of stop action, if any
 */
static GList *
rsc_history_as_list(const xmlNode *rsc_entry, int *start_index, int *stop_index)
{
    GList *ops = NULL;

    for (xmlNode *rsc_op = first_named_child(rsc_entry, XML_LRM_TAG_RSC_OP);
         rsc_op != NULL; rsc_op = crm_next_same_xml(rsc_op)) {
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
 * \param[in]     rsc_entry  Resource's <lrm_rsc_op> status XML
 * \param[in,out] rsc        Resource whose history is being processed
 * \param[in,out] node       Node whose history is being processed
 */
static void
process_rsc_history(const xmlNode *rsc_entry, pe_resource_t *rsc,
                    pe_node_t *node)
{
    int offset = -1;
    int stop_index = 0;
    int start_index = 0;
    GList *sorted_op_list = NULL;

    if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        if (pe_rsc_is_anon_clone(pe__const_top_resource(rsc, false))) {
            pe_rsc_trace(rsc,
                         "Skipping configuration check "
                         "for orphaned clone instance %s",
                         rsc->id);
        } else {
            pe_rsc_trace(rsc,
                         "Skipping configuration check and scheduling clean-up "
                         "for orphaned resource %s", rsc->id);
            pcmk__schedule_cleanup(rsc, node, false);
        }
        return;
    }

    if (pe_find_node_id(rsc->running_on, node->details->id) == NULL) {
        if (pcmk__rsc_agent_changed(rsc, node, rsc_entry, false)) {
            pcmk__schedule_cleanup(rsc, node, false);
        }
        pe_rsc_trace(rsc,
                     "Skipping configuration check for %s "
                     "because no longer active on %s",
                     rsc->id, pe__node_name(node));
        return;
    }

    pe_rsc_trace(rsc, "Checking for configuration changes for %s on %s",
                 rsc->id, pe__node_name(node));

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

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        crm_element_value_ms(rsc_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

        if ((interval_ms > 0)
            && (pcmk_is_set(rsc->flags, pe_rsc_maintenance)
                || node->details->maintenance)) {
            // Maintenance mode cancels recurring operations
            pcmk__schedule_cancel(rsc,
                                  crm_element_value(rsc_op,
                                                    XML_LRM_ATTR_CALLID),
                                  task, interval_ms, node, "maintenance mode");

        } else if ((interval_ms > 0)
                   || pcmk__strcase_any_of(task, RSC_STATUS, RSC_START,
                                           RSC_PROMOTE, RSC_MIGRATED, NULL)) {
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
                pe__add_param_check(rsc_op, rsc, node, pe_check_active,
                                    rsc->cluster);

            } else if (pcmk__check_action_config(rsc, node, rsc_op)
                       && (pe_get_failcount(node, rsc, NULL, pe_fc_effective,
                                            NULL) != 0)) {
                pe__clear_failcount(rsc, node, "action definition changed",
                                    rsc->cluster);
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
 * \param[in]     lrm_rscs  Node's <lrm_resources> from CIB status XML
 */
static void
process_node_history(pe_node_t *node, const xmlNode *lrm_rscs)
{
    crm_trace("Processing node history for %s", pe__node_name(node));
    for (const xmlNode *rsc_entry = first_named_child(lrm_rscs,
                                                      XML_LRM_TAG_RESOURCE);
         rsc_entry != NULL; rsc_entry = crm_next_same_xml(rsc_entry)) {

        if (xml_has_children(rsc_entry)) {
            GList *result = pcmk__rscs_matching_id(ID(rsc_entry),
                                                   node->details->data_set);

            for (GList *iter = result; iter != NULL; iter = iter->next) {
                pe_resource_t *rsc = (pe_resource_t *) iter->data;

                if (rsc->variant == pe_native) {
                    process_rsc_history(rsc_entry, rsc, node);
                }
            }
            g_list_free(result);
        }
    }
}

// XPath to find a node's resource history
#define XPATH_NODE_HISTORY "/" XML_TAG_CIB "/" XML_CIB_TAG_STATUS             \
                           "/" XML_CIB_TAG_STATE "[@" XML_ATTR_UNAME "='%s']" \
                           "/" XML_CIB_TAG_LRM "/" XML_LRM_TAG_RESOURCES

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
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__handle_rsc_config_changes(pe_working_set_t *data_set)
{
    crm_trace("Check resource and action configuration for changes");

    /* Rather than iterate through the status section, iterate through the nodes
     * and search for the appropriate status subsection for each. This skips
     * orphaned nodes and lets us eliminate some cases before searching the XML.
     */
    for (GList *iter = data_set->nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;

        /* Don't bother checking actions for a node that can't run actions ...
         * unless it's in maintenance mode, in which case we still need to
         * cancel any existing recurring monitors.
         */
        if (node->details->maintenance
            || pcmk__node_available(node, false, false)) {

            char *xpath = NULL;
            xmlNode *history = NULL;

            xpath = crm_strdup_printf(XPATH_NODE_HISTORY, node->details->uname);
            history = get_xpath_object(xpath, data_set->input, LOG_NEVER);
            free(xpath);

            process_node_history(node, history);
        }
    }
}
