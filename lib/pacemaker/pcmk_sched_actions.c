/*
 * Copyright 2004-2021 the Pacemaker project contributors
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

#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

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
                     "%s (0x%.6x) then %s (0x%.6x): type=0x%.6x node=%s",
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
