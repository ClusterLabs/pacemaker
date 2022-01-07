/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

extern void ReloadRsc(pe_resource_t *rsc, pe_node_t *node,
                      pe_working_set_t *data_set);
extern gboolean DeleteRsc(pe_resource_t *rsc, pe_node_t *node,
                          gboolean optional, pe_working_set_t *data_set);

/*!
 * \internal
 * \brief Get the action flags relevant to ordering constraints
 *
 * \param[in] action  Action to check
 * \param[in] node    Node that *other* action in the ordering is on
 *                    (used only for clone resource actions)
 *
 * \return Action flags that should be used for orderings
 */
static enum pe_action_flags
action_flags_for_ordering(pe_action_t *action, pe_node_t *node)
{
    bool runnable = false;
    enum pe_action_flags flags;

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
action_uuid_for_ordering(const char *first_uuid, pe_resource_t *first_rsc)
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
 * \param[in] first        First action in an ordering
 * \param[in] then         Then action in an ordering
 * \param[in] first_flags  Action flags for \p first for ordering purposes
 * \param[in] then_flags   Action flags for \p then for ordering purposes
 * \param[in] order        Action wrapper for \p first in ordering
 * \param[in] data_set     Cluster working set
 *
 * \return Mask of pe_graph_updated_first and/or pe_graph_updated_then
 */
static enum pe_graph_flags
update_action_for_ordering_flags(pe_action_t *first, pe_action_t *then,
                                 enum pe_action_flags first_flags,
                                 enum pe_action_flags then_flags,
                                 pe_action_wrapper_t *order,
                                 pe_working_set_t *data_set)
{
    enum pe_graph_flags changed = pe_graph_none;

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
                     first->uuid, then->uuid, node->details->uname);
    }

    if (pcmk_is_set(order->type, pe_order_implies_then)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                                                       first_flags & pe_action_optional,
                                                       pe_action_optional,
                                                       pe_order_implies_then,
                                                       data_set);
        } else if (!pcmk_is_set(first_flags, pe_action_optional)
                   && pcmk_is_set(then->flags, pe_action_optional)) {
            pe__clear_action_flags(then, pe_action_optional);
            pe__set_graph_flags(changed, first, pe_graph_updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_implies_then",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_restart) && (then->rsc != NULL)) {
        enum pe_action_flags restart = pe_action_optional|pe_action_runnable;

        changed |= then->rsc->cmds->update_actions(first, then, node,
                                                   first_flags, restart,
                                                   pe_order_restart, data_set);
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_restart",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_implies_first)) {
        if (first->rsc != NULL) {
            changed |= first->rsc->cmds->update_actions(first, then, node,
                                                        first_flags,
                                                        pe_action_optional,
                                                        pe_order_implies_first,
                                                        data_set);
        } else if (!pcmk_is_set(first_flags, pe_action_optional)
                   && pcmk_is_set(first->flags, pe_action_runnable)) {
            pe__clear_action_flags(first, pe_action_runnable);
            pe__set_graph_flags(changed, first, pe_graph_updated_first);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_implies_first",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_promoted_implies_first)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
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
            changed |= then->rsc->cmds->update_actions(first, then, node,
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
                pe__set_graph_flags(changed, first, pe_graph_updated_then);
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
            changed |= then->rsc->cmds->update_actions(first, then, node,
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
            changed |= then->rsc->cmds->update_actions(first, then, node,
                                                       first_flags,
                                                       pe_action_runnable,
                                                       pe_order_runnable_left,
                                                       data_set);

        } else if (!pcmk_is_set(first_flags, pe_action_runnable)
                   && pcmk_is_set(then->flags, pe_action_runnable)) {

            pe__clear_action_flags(then, pe_action_runnable);
            pe__set_graph_flags(changed, first, pe_graph_updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_runnable_left",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_implies_first_migratable)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional,
                pe_order_implies_first_migratable, data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after "
                     "pe_order_implies_first_migratable",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (pcmk_is_set(order->type, pe_order_pseudo_left)) {
        if (then->rsc != NULL) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
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
            changed |= then->rsc->cmds->update_actions(first, then, node,
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
            changed |= then->rsc->cmds->update_actions(first, then, node,
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
        && pcmk__str_eq(first->task, RSC_STOP, pcmk__str_casei)) {

        if (pcmk_is_set(then->flags, pe_action_runnable)) {
            pe__clear_action_flags(then, pe_action_runnable);
            pe__set_graph_flags(changed, first, pe_graph_updated_then);
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
 * \param[in] then      Action to update
 * \param[in] data_set  Cluster working set
 */
void
pcmk__update_action_for_orderings(pe_action_t *then, pe_working_set_t *data_set)
{
    GList *lpc = NULL;
    enum pe_graph_flags changed = pe_graph_none;
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
            && pcmk__str_eq(first->task, RSC_START, pcmk__str_casei)) {

            first_node = first->rsc->fns->location(first->rsc, NULL, FALSE);
            if (first_node != NULL) {
                pe_rsc_trace(first->rsc, "Found node %s for 'first' %s",
                             first_node->details->uname, first->uuid);
            }
        }

        if ((then->rsc != NULL)
            && (then->rsc->variant == pe_group)
            && pcmk__str_eq(then->task, RSC_START, pcmk__str_casei)) {

            then_node = then->rsc->fns->location(then->rsc, NULL, FALSE);
            if (then_node != NULL) {
                pe_rsc_trace(then->rsc, "Found node %s for 'then' %s",
                             then_node->details->uname, then->uuid);
            }
        }

        // Disable constraint if it only applies when on same node, but isn't
        if (pcmk_is_set(other->type, pe_order_same_node)
            && (first_node != NULL) && (then_node != NULL)
            && (first_node->details != then_node->details)) {

            pe_rsc_trace(then->rsc,
                         "Disabled ordering %s on %s then %s on %s: not same node",
                         other->action->uuid, first_node->details->uname,
                         then->uuid, then_node->details->uname);
            other->type = pe_order_none;
            continue;
        }

        pe__clear_graph_flags(changed, then, pe_graph_updated_first);

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
            enum pe_action_flags first_flags, then_flags;

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
            pe__set_graph_flags(changed, then,
                                pe_graph_updated_then|pe_graph_disable);
        }

        if (pcmk_is_set(changed, pe_graph_disable)) {
            pe_rsc_trace(then->rsc,
                         "Disabled ordering %s then %s in favor of %s then %s",
                         other->action->uuid, then->uuid, first->uuid,
                         then->uuid);
            pe__clear_graph_flags(changed, then, pe_graph_disable);
            other->type = pe_order_none;
        }

        if (pcmk_is_set(changed, pe_graph_updated_first)) {
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
            pe__clear_graph_flags(changed, then, pe_graph_updated_then);
        } else {
            pe__set_graph_flags(changed, then, pe_graph_updated_then);
        }
    }

    if (pcmk_is_set(changed, pe_graph_updated_then)) {
        crm_trace("Re-processing %s and its 'after' actions because it changed",
                  then->uuid);
        if (pcmk_is_set(last_flags, pe_action_runnable)
            && !pcmk_is_set(then->flags, pe_action_runnable)) {
            pcmk__block_colocated_starts(then, data_set);
        }
        pcmk__update_action_for_orderings(then, data_set);
        for (lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc->data;

            pcmk__update_action_for_orderings(other->action, data_set);
        }
    }
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
pcmk__log_action(const char *pre_text, pe_action_t *action, bool details)
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
        GList *iter = NULL;

        crm_trace("\t\t====== Preceding Actions");
        for (iter = action->actions_before; iter != NULL; iter = iter->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) iter->data;

            pcmk__log_action("\t\t", other->action, false);
        }
        crm_trace("\t\t====== Subsequent Actions");
        for (iter = action->actions_after; iter != NULL; iter = iter->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) iter->data;

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
 * \brief Create a new pseudo-action for a resource
 *
 * \param[in] rsc   Resource to create action for
 * \param[in] task  Action name
 * \param[in] optional  Whether action should be considered optional
 * \param[in] runnable  Whethe action should be considered runnable
 *
 * \return New action object corresponding to arguments
 */
pe_action_t *
pcmk__new_rsc_pseudo_action(pe_resource_t *rsc, const char *task,
                            bool optional, bool runnable)
{
    pe_action_t *action = NULL;

    CRM_ASSERT((rsc != NULL) && (task != NULL));

    action = custom_action(rsc, pcmk__op_key(rsc->id, task, 0), task, NULL,
                           optional, TRUE, rsc->cluster);
    pe__set_action_flags(action, pe_action_pseudo);
    if (runnable) {
        pe__set_action_flags(action, pe_action_runnable);
    }
    return action;
}

/*!
 * \internal
 * \brief Create an executor cancel action
 *
 * \param[in] rsc          Resource of action to cancel
 * \param[in] task         Name of action to cancel
 * \param[in] interval_ms  Interval of action to cancel
 * \param[in] node         Node of action to cancel
 * \param[in] data_set     Working set of cluster
 *
 * \return Created op
 */
pe_action_t *
pcmk__new_cancel_action(pe_resource_t *rsc, const char *task, guint interval_ms,
                        pe_node_t *node)
{
    pe_action_t *cancel_op = NULL;
    char *key = NULL;
    char *interval_ms_s = NULL;

    CRM_ASSERT((rsc != NULL) && (task != NULL) && (node != NULL));

    // @TODO dangerous if possible to schedule another action with this key
    key = pcmk__op_key(rsc->id, task, interval_ms);

    cancel_op = custom_action(rsc, key, RSC_CANCEL, node, FALSE, TRUE,
                              rsc->cluster);

    free(cancel_op->task);
    cancel_op->task = strdup(RSC_CANCEL);

    free(cancel_op->cancel_task);
    cancel_op->cancel_task = strdup(task);

    interval_ms_s = crm_strdup_printf("%u", interval_ms);
    add_hash_param(cancel_op->meta, XML_LRM_ATTR_TASK, task);
    add_hash_param(cancel_op->meta, XML_LRM_ATTR_INTERVAL_MS, interval_ms_s);
    free(interval_ms_s);

    return cancel_op;
}

/*!
 * \internal
 * \brief Create a new shutdown action for a node
 *
 * \param[in] node         Node being shut down
 * \param[in] data_set     Working set of cluster
 *
 * \return Newly created shutdown action for \p node
 */
pe_action_t *
pcmk__new_shutdown_action(pe_node_t *node, pe_working_set_t *data_set)
{
    char *shutdown_id = NULL;
    pe_action_t *shutdown_op = NULL;

    CRM_ASSERT((node != NULL) && (data_set != NULL));

    shutdown_id = crm_strdup_printf("%s-%s", CRM_OP_SHUTDOWN,
                                    node->details->uname);

    shutdown_op = custom_action(NULL, shutdown_id, CRM_OP_SHUTDOWN, node, FALSE,
                                TRUE, data_set);

    pcmk__order_stops_before_shutdown(node, shutdown_op, data_set);
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
 * \param[in] op       Operation result from executor
 * \param[in] update   XML to add digest to
 */
static void
add_op_digest_to_xml(lrmd_event_data_t *op, xmlNode *update)
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
    crm_xml_add(xml_op, XML_LRM_ATTR_EXIT_REASON, exit_reason == NULL ? "" : exit_reason);
    crm_xml_add(xml_op, XML_LRM_ATTR_TARGET, node); /* For context during triage */

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

    if (pcmk__str_any_of(op->op_type, CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED, NULL)) {
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
        || (action->rsc->lock_node == NULL) || (action->node == NULL)
        || (action->node->details != action->rsc->lock_node->details)) {
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
 * \param[in] action  Action whose inputs should be checked
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
 * \param[in] data_set  Cluster working set
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

        if (pcmk__str_eq(action->task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
            task = strdup("Shutdown");

        } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {
            const char *op = g_hash_table_lookup(action->meta, "stonith_action");

            task = crm_strdup_printf("Fence (%s)", op);

        } else {
            continue; // Don't display other node action types
        }

        if (pe__is_guest_node(action->node)) {
            node_name = crm_strdup_printf("%s (resource: %s)",
                                          action->node->details->uname,
                                          action->node->details->remote_rsc->container->id);
        } else if (action->node != NULL) {
            node_name = crm_strdup_printf("%s", action->node->details->uname);
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
 * \brief Schedule cancellation of a recurring action
 *
 * \param[in] rsc          Resource that action is for
 * \param[in] call_id      Action's call ID from history
 * \param[in] task         Action name
 * \param[in] interval_ms  Action interval
 * \param[in] node         Node that history entry is for
 * \param[in] reason       Short description of why action is being cancelled
 */
static void
schedule_cancel(pe_resource_t *rsc, const char *call_id, const char *task,
                guint interval_ms, pe_node_t *node, const char *reason)
{
    pe_action_t *cancel = NULL;

    CRM_CHECK((rsc != NULL) && (task != NULL)
              && (node != NULL) && (reason != NULL),
              return);

    crm_info("Recurring %s-interval %s for %s will be stopped on %s: %s",
             pcmk__readable_interval(interval_ms), task, rsc->id,
             crm_str(node->details->uname), reason);
    cancel = pcmk__new_cancel_action(rsc, task, interval_ms, node);
    add_hash_param(cancel->meta, XML_LRM_ATTR_CALLID, call_id);

    // Cancellations happen after stops
    pcmk__new_ordering(rsc, stop_key(rsc), NULL, rsc, NULL, cancel,
                       pe_order_optional, rsc->cluster);
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
action_in_config(pe_resource_t *rsc, const char *task, guint interval_ms)
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
    if ((interval_ms == 0)
        && pcmk__str_any_of(task, RSC_STATUS, RSC_MIGRATED, RSC_PROMOTE, NULL)) {
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
only_sanitized_changed(xmlNode *xml_op, const op_digest_cache_t *digest_data,
                       pe_working_set_t *data_set)
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
 * \param[in] rsc          Resource that action is for
 * \param[in] task         Name of action whose configuration changed
 * \param[in] interval_ms  Action interval (in milliseconds)
 * \param[in] node         Node where resource should be restarted
 * \param[in] digest_data  Operation digest information being compared
 */
static void
force_restart(pe_resource_t *rsc, const char *task, guint interval_ms,
              pe_node_t *node, const op_digest_cache_t *digest_data)
{
    char *key = pcmk__op_key(rsc->id, task, interval_ms);
    pe_action_t *required = custom_action(rsc, key, task, NULL, FALSE, TRUE,
                                          rsc->cluster);

    crm_log_xml_debug(digest_data->params_restart, "params:restart");
    pe_action_set_reason(required, "resource definition change", true);
    trigger_unfencing(rsc, node, "Device parameters changed", NULL,
                      rsc->cluster);
}

/*!
 * \internal
 * \brief Reschedule a recurring action
 *
 * \param[in] rsc          Resource that action is for
 * \param[in] task         Name of action being rescheduled
 * \param[in] interval_ms  Action interval (in milliseconds)
 * \param[in] node         Node where action should be rescheduled
 */
static void
reschedule_recurring(pe_resource_t *rsc, const char *task, guint interval_ms,
                     pe_node_t *node)
{
    pe_action_t *op = NULL;

    trigger_unfencing(rsc, node, "Device parameters changed (reschedule)",
                      NULL, rsc->cluster);
    op = custom_action(rsc, pcmk__op_key(rsc->id, task, interval_ms),
                       task, node, TRUE, TRUE, rsc->cluster);
    pe__set_action_flags(op, pe_action_reschedule);
}

/*!
 * \internal
 * \brief Handle any configuration change for an action
 *
 * Given an action from resource history, if the resource's configuration
 * changed since the action was done, schedule any actions needed (restart,
 * reload, unfencing, rescheduling recurring actions, etc.).
 *
 * \param[in] rsc     Resource that action is for
 * \param[in] node    Node that action was on
 * \param[in] xml_op  Action XML from resource history
 *
 * \return true if action configuration changed, otherwise false
 */
bool
pcmk__check_action_config(pe_resource_t *rsc, pe_node_t *node, xmlNode *xml_op)
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
                         node->details->uname);
        } else if (pcmk_is_set(rsc->cluster->flags,
                               pe_flag_stop_action_orphans)) {
            schedule_cancel(rsc,
                            crm_element_value(xml_op, XML_LRM_ATTR_CALLID),
                            task, interval_ms, node, "orphan");
            return true;
        } else {
            pe_rsc_debug(rsc, "%s-interval %s for %s on %s is orphaned",
                         pcmk__readable_interval(interval_ms), task, rsc->id,
                         node->details->uname);
            return true;
        }
    }

    crm_trace("Checking %s-interval %s for %s on %s for configuration changes",
              pcmk__readable_interval(interval_ms), task, rsc->id,
              node->details->uname);
    task = task_for_digest(task, interval_ms);
    digest_data = rsc_action_digest_cmp(rsc, xml_op, node, rsc->cluster);

    if (only_sanitized_changed(xml_op, digest_data, rsc->cluster)) {
        if (!pcmk__is_daemon && (rsc->cluster->priv != NULL)) {
            pcmk__output_t *out = rsc->cluster->priv;

            out->info(out,
                      "Only 'private' parameters to %s-interval %s for %s "
                      "on %s changed: %s",
                      pcmk__readable_interval(interval_ms), task, rsc->id,
                      node->details->uname,
                      crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        }
        return false;
    }

    switch (digest_data->rc) {
        case RSC_DIGEST_RESTART:
            force_restart(rsc, task, interval_ms, node, digest_data);
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
                reschedule_recurring(rsc, task, interval_ms, node);

            } else if (crm_element_value(xml_op,
                                         XML_LRM_ATTR_RESTART_DIGEST) != NULL) {
                // Agent supports reload, so use it
                trigger_unfencing(rsc, node,
                                  "Device parameters changed (reload)", NULL,
                                  rsc->cluster);
                crm_log_xml_debug(digest_data->params_all, "params:reload");
                ReloadRsc(rsc, node, rsc->cluster);

            } else {
                pe_rsc_trace(rsc,
                             "Restarting %s because agent doesn't support reload",
                             rsc->id);
                force_restart(rsc, task, interval_ms, node, digest_data);
            }
            return true;

        default:
            break;
    }
    return false;
}

static void
check_actions_for(xmlNode * rsc_entry, pe_resource_t * rsc, pe_node_t * node, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    int offset = -1;
    int stop_index = 0;
    int start_index = 0;

    const char *task = NULL;

    xmlNode *rsc_op = NULL;
    GList *op_list = NULL;
    GList *sorted_op_list = NULL;

    CRM_CHECK(node != NULL, return);

    if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        pe_resource_t *parent = uber_parent(rsc);
        if(parent == NULL
           || pe_rsc_is_clone(parent) == FALSE
           || pcmk_is_set(parent->flags, pe_rsc_unique)) {
            pe_rsc_trace(rsc, "Skipping param check for %s and deleting: orphan", rsc->id);
            DeleteRsc(rsc, node, FALSE, data_set);
        } else {
            pe_rsc_trace(rsc, "Skipping param check for %s (orphan clone)", rsc->id);
        }
        return;

    } else if (pe_find_node_id(rsc->running_on, node->details->id) == NULL) {
        if (pcmk__rsc_agent_changed(rsc, node, rsc_entry, false)) {
            DeleteRsc(rsc, node, FALSE, data_set);
        }
        pe_rsc_trace(rsc, "Skipping param check for %s: no longer active on %s",
                     rsc->id, node->details->uname);
        return;
    }

    pe_rsc_trace(rsc, "Processing %s on %s", rsc->id, node->details->uname);

    if (pcmk__rsc_agent_changed(rsc, node, rsc_entry, true)) {
        DeleteRsc(rsc, node, FALSE, data_set);
    }

    for (rsc_op = pcmk__xe_first_child(rsc_entry); rsc_op != NULL;
         rsc_op = pcmk__xe_next(rsc_op)) {

        if (pcmk__str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, pcmk__str_none)) {
            op_list = g_list_prepend(op_list, rsc_op);
        }
    }

    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;
        guint interval_ms = 0;

        offset++;

        if (start_index < stop_index) {
            /* stopped */
            continue;
        } else if (offset < start_index) {
            /* action occurred prior to a start */
            continue;
        }

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        crm_element_value_ms(rsc_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

        if ((interval_ms > 0) &&
            (pcmk_is_set(rsc->flags, pe_rsc_maintenance) || node->details->maintenance)) {
            // Maintenance mode cancels recurring operations
            schedule_cancel(rsc,
                            crm_element_value(rsc_op, XML_LRM_ATTR_CALLID),
                            task, interval_ms, node, "maintenance mode");

        } else if ((interval_ms > 0) || pcmk__strcase_any_of(task, RSC_STATUS, RSC_START,
                                                             RSC_PROMOTE, RSC_MIGRATED, NULL)) {
            /* If a resource operation failed, and the operation's definition
             * has changed, clear any fail count so they can be retried fresh.
             */

            if (pe__bundle_needs_remote_name(rsc, data_set)) {
                /* We haven't allocated resources to nodes yet, so if the
                 * REMOTE_CONTAINER_HACK is used, we may calculate the digest
                 * based on the literal "#uname" value rather than the properly
                 * substituted value. That would mistakenly make the action
                 * definition appear to have been changed. Defer the check until
                 * later in this case.
                 */
                pe__add_param_check(rsc_op, rsc, node, pe_check_active,
                                    data_set);

            } else if (pcmk__check_action_config(rsc, node, rsc_op)
                && pe_get_failcount(node, rsc, NULL, pe_fc_effective, NULL,
                                    data_set)) {
                pe__clear_failcount(rsc, node, "action definition changed",
                                    data_set);
            }
        }
    }
    g_list_free(sorted_op_list);
}

static void
check_actions(pe_working_set_t * data_set)
{
    const char *id = NULL;
    pe_node_t *node = NULL;
    xmlNode *lrm_rscs = NULL;
    xmlNode *status = pcmk_find_cib_element(data_set->input,
                                            XML_CIB_TAG_STATUS);
    xmlNode *node_state = NULL;

    for (node_state = pcmk__xe_first_child(status); node_state != NULL;
         node_state = pcmk__xe_next(node_state)) {

        if (pcmk__str_eq((const char *)node_state->name, XML_CIB_TAG_STATE,
                         pcmk__str_none)) {
            id = crm_element_value(node_state, XML_ATTR_ID);
            lrm_rscs = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
            lrm_rscs = find_xml_node(lrm_rscs, XML_LRM_TAG_RESOURCES, FALSE);

            node = pe_find_node_id(data_set->nodes, id);

            if (node == NULL) {
                continue;

            /* Still need to check actions for a maintenance node to cancel existing monitor operations */
            } else if (!pcmk__node_available(node) && !node->details->maintenance) {
                crm_trace("Skipping param check for %s: can't run resources",
                          node->details->uname);
                continue;
            }

            crm_trace("Processing node %s", node->details->uname);
            if (node->details->online
                || pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
                xmlNode *rsc_entry = NULL;

                for (rsc_entry = pcmk__xe_first_child(lrm_rscs);
                     rsc_entry != NULL;
                     rsc_entry = pcmk__xe_next(rsc_entry)) {

                    if (pcmk__str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, pcmk__str_none)) {

                        if (xml_has_children(rsc_entry)) {
                            GList *gIter = NULL;
                            GList *result = NULL;

                            result = pcmk__rscs_matching_id(ID(rsc_entry),
                                                            data_set);
                            for (gIter = result; gIter != NULL; gIter = gIter->next) {
                                pe_resource_t *rsc = (pe_resource_t *) gIter->data;

                                if (rsc->variant != pe_native) {
                                    continue;
                                }
                                check_actions_for(rsc_entry, rsc, node, data_set);
                            }
                            g_list_free(result);
                        }
                    }
                }
            }
        }
    }
}

/*
 * Check for orphaned or redefined actions
 */
gboolean
stage4(pe_working_set_t * data_set)
{
    check_actions(data_set);
    return TRUE;
}
