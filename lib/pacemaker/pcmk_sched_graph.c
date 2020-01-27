/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <pacemaker-internal.h>

void update_colo_start_chain(pe_action_t *action, pe_working_set_t *data_set);
gboolean rsc_update_action(action_t * first, action_t * then, enum pe_ordering type);

static enum pe_action_flags
get_action_flags(action_t * action, node_t * node)
{
    enum pe_action_flags flags = action->flags;

    if (action->rsc) {
        flags = action->rsc->cmds->action_flags(action, NULL);

        if (pe_rsc_is_clone(action->rsc) && node) {

            /* We only care about activity on $node */
            enum pe_action_flags clone_flags = action->rsc->cmds->action_flags(action, node);

            /* Go to great lengths to ensure the correct value for pe_action_runnable...
             *
             * If we are a clone, then for _ordering_ constraints, it's only relevant
             * if we are runnable _anywhere_.
             *
             * This only applies to _runnable_ though, and only for ordering constraints.
             * If this function is ever used during colocation, then we'll need additional logic
             *
             * Not very satisfying, but it's logical and appears to work well.
             */
            if (is_not_set(clone_flags, pe_action_runnable)
                && is_set(flags, pe_action_runnable)) {
                pe_rsc_trace(action->rsc, "Fixing up runnable flag for %s", action->uuid);
                set_bit(clone_flags, pe_action_runnable);
            }
            flags = clone_flags;
        }
    }
    return flags;
}

static char *
convert_non_atomic_uuid(char *old_uuid, resource_t * rsc, gboolean allow_notify,
                        gboolean free_original)
{
    guint interval_ms = 0;
    char *uuid = NULL;
    char *rid = NULL;
    char *raw_task = NULL;
    int task = no_action;

    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "Processing %s", old_uuid);
    if (old_uuid == NULL) {
        return NULL;

    } else if (strstr(old_uuid, "notify") != NULL) {
        goto done;              /* no conversion */

    } else if (rsc->variant < pe_group) {
        goto done;              /* no conversion */
    }

    CRM_ASSERT(parse_op_key(old_uuid, &rid, &raw_task, &interval_ms));
    if (interval_ms > 0) {
        goto done;              /* no conversion */
    }

    task = text2task(raw_task);
    switch (task) {
        case stop_rsc:
        case start_rsc:
        case action_notify:
        case action_promote:
        case action_demote:
            break;
        case stopped_rsc:
        case started_rsc:
        case action_notified:
        case action_promoted:
        case action_demoted:
            task--;
            break;
        case monitor_rsc:
        case shutdown_crm:
        case stonith_node:
            task = no_action;
            break;
        default:
            crm_err("Unknown action: %s", raw_task);
            task = no_action;
            break;
    }

    if (task != no_action) {
        if (is_set(rsc->flags, pe_rsc_notify) && allow_notify) {
            uuid = generate_notify_key(rid, "confirmed-post", task2text(task + 1));

        } else {
            uuid = pcmk__op_key(rid, task2text(task + 1), 0);
        }
        pe_rsc_trace(rsc, "Converted %s -> %s", old_uuid, uuid);
    }

  done:
    if (uuid == NULL) {
        uuid = strdup(old_uuid);
    }

    if (free_original) {
        free(old_uuid);
    }

    free(raw_task);
    free(rid);
    return uuid;
}

static action_t *
rsc_expand_action(action_t * action)
{
    gboolean notify = FALSE;
    action_t *result = action;
    resource_t *rsc = action->rsc;

    if (rsc == NULL) {
        return action;
    }

    if ((rsc->parent == NULL)
        || (pe_rsc_is_clone(rsc) && (rsc->parent->variant == pe_container))) {
        /* Only outermost resources have notification actions.
         * The exception is those in bundles.
         */
        notify = is_set(rsc->flags, pe_rsc_notify);
    }

    if (rsc->variant >= pe_group) {
        /* Expand 'start' -> 'started' */
        char *uuid = NULL;

        uuid = convert_non_atomic_uuid(action->uuid, rsc, notify, FALSE);
        if (uuid) {
            pe_rsc_trace(rsc, "Converting %s to %s %d", action->uuid, uuid,
                         is_set(rsc->flags, pe_rsc_notify));
            result = find_first_action(rsc->actions, uuid, NULL, NULL);
            if (result == NULL) {
                crm_err("Couldn't expand %s to %s in %s", action->uuid, uuid, rsc->id);
                result = action;
            }
            free(uuid);
        }
    }
    return result;
}

static enum pe_graph_flags
graph_update_action(action_t * first, action_t * then, node_t * node,
                    enum pe_action_flags first_flags, enum pe_action_flags then_flags,
                    action_wrapper_t *order, pe_working_set_t *data_set)
{
    enum pe_graph_flags changed = pe_graph_none;
    enum pe_ordering type = order->type;
    gboolean processed = FALSE;

    /* TODO: Do as many of these in parallel as possible */

    if(is_set(type, pe_order_implies_then_on_node)) {
        /* Normally we want the _whole_ 'then' clone to
         * restart if 'first' is restarted, so then->node is
         * needed.
         *
         * However for unfencing, we want to limit this to
         * instances on the same node as 'first' (the
         * unfencing operation), so first->node is supplied.
         *
         * Swap the node, from then on we can can treat it
         * like any other 'pe_order_implies_then'
         */

        clear_bit(type, pe_order_implies_then_on_node);
        set_bit(type, pe_order_implies_then);
        node = first->node;
    }

    clear_bit(first_flags, pe_action_pseudo);

    if (type & pe_order_implies_then) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags & pe_action_optional, pe_action_optional,
                pe_order_implies_then, data_set);

        } else if (is_set(first_flags, pe_action_optional) == FALSE) {
            if (update_action_flags(then, pe_action_optional | pe_action_clear, __FUNCTION__, __LINE__)) {
                changed |= pe_graph_updated_then;
            }
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "implies right: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("implies right: %s then %s %p", first->uuid, then->uuid, then->rsc);
        }
    }

    if ((type & pe_order_restart) && then->rsc) {
        enum pe_action_flags restart = (pe_action_optional | pe_action_runnable);

        processed = TRUE;
        changed |= then->rsc->cmds->update_actions(first, then, node,
                                                   first_flags, restart,
                                                   pe_order_restart, data_set);
        if (changed) {
            pe_rsc_trace(then->rsc, "restart: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("restart: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_implies_first) {
        processed = TRUE;
        if (first->rsc) {
            changed |= first->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional, pe_order_implies_first,
                data_set);

        } else if (is_set(first_flags, pe_action_optional) == FALSE) {
            pe_rsc_trace(first->rsc, "first unrunnable: %s (%d) then %s (%d)",
                         first->uuid, is_set(first_flags, pe_action_optional),
                         then->uuid, is_set(then_flags, pe_action_optional));
            if (update_action_flags(first, pe_action_runnable | pe_action_clear, __FUNCTION__, __LINE__)) {
                changed |= pe_graph_updated_first;
            }
        }

        if (changed) {
            pe_rsc_trace(then->rsc, "implies left: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("implies left: %s (%d) then %s (%d)",
                      first->uuid, is_set(first_flags, pe_action_optional),
                      then->uuid, is_set(then_flags, pe_action_optional));
        }
    }

    if (type & pe_order_implies_first_master) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags & pe_action_optional, pe_action_optional,
                pe_order_implies_first_master, data_set);
        }

        if (changed) {
            pe_rsc_trace(then->rsc,
                         "implies left when right rsc is Master role: %s then %s: changed",
                         first->uuid, then->uuid);
        } else {
            crm_trace("implies left when right rsc is Master role: %s then %s", first->uuid,
                      then->uuid);
        }
    }

    if (type & pe_order_one_or_more) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_one_or_more,
                data_set);

        } else if (is_set(first_flags, pe_action_runnable)) {
            /* alright. a "first" action is considered runnable, incremente
             * the 'runnable_before' counter */
            then->runnable_before++;

            /* if the runnable before count for then exceeds the required number
             * of "before" runnable actions... mark then as runnable */
            if (then->runnable_before >= then->required_runnable_before) {
                if (update_action_flags(then, pe_action_runnable, __FUNCTION__, __LINE__)) {
                    changed |= pe_graph_updated_then;
                }
            }
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "runnable_one_or_more: %s then %s: changed", first->uuid,
                         then->uuid);
        } else {
            crm_trace("runnable_one_or_more: %s then %s", first->uuid, then->uuid);
        }
    }

    if (then->rsc && is_set(type, pe_order_probe)) {
        processed = TRUE;

        if (is_not_set(first_flags, pe_action_runnable) && first->rsc->running_on != NULL) {
            pe_rsc_trace(then->rsc, "Ignoring %s then %s - %s is about to be stopped",
                         first->uuid, then->uuid, first->rsc->id);
            type = pe_order_none;
            order->type = pe_order_none;

        } else {
            pe_rsc_trace(then->rsc, "Enforcing %s then %s", first->uuid, then->uuid);
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_runnable_left,
                data_set);
        }

        if (changed) {
            pe_rsc_trace(then->rsc, "runnable: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("runnable: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_runnable_left) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_runnable_left,
                data_set);

        } else if (is_set(first_flags, pe_action_runnable) == FALSE) {
            pe_rsc_trace(then->rsc, "then unrunnable: %s then %s", first->uuid, then->uuid);
            if (update_action_flags(then, pe_action_runnable | pe_action_clear, __FUNCTION__, __LINE__)) {
                 changed |= pe_graph_updated_then;
            }
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "runnable: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("runnable: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_implies_first_migratable) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional,
                pe_order_implies_first_migratable, data_set);
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "optional: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("optional: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_pseudo_left) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional, pe_order_pseudo_left,
                data_set);
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "optional: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("optional: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_optional) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_optional, data_set);
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "optional: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("optional: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_asymmetrical) {
        processed = TRUE;
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_asymmetrical,
                data_set);
        }

        if (changed) {
            pe_rsc_trace(then->rsc, "asymmetrical: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("asymmetrical: %s then %s", first->uuid, then->uuid);
        }

    }

    if ((first->flags & pe_action_runnable) && (type & pe_order_implies_then_printed)
        && (first_flags & pe_action_optional) == 0) {
        processed = TRUE;
        crm_trace("%s implies %s printed", first->uuid, then->uuid);
        update_action_flags(then, pe_action_print_always, __FUNCTION__, __LINE__);  /* don't care about changed */
    }

    if (is_set(type, pe_order_implies_first_printed) && is_set(then_flags, pe_action_optional) == FALSE) {
        processed = TRUE;
        crm_trace("%s implies %s printed", then->uuid, first->uuid);
        update_action_flags(first, pe_action_print_always, __FUNCTION__, __LINE__); /* don't care about changed */
    }

    if ((type & pe_order_implies_then
         || type & pe_order_implies_first
         || type & pe_order_restart)
        && first->rsc
        && safe_str_eq(first->task, RSC_STOP)
        && is_not_set(first->rsc->flags, pe_rsc_managed)
        && is_set(first->rsc->flags, pe_rsc_block)
        && is_not_set(first->flags, pe_action_runnable)) {

        if (update_action_flags(then, pe_action_runnable | pe_action_clear, __FUNCTION__, __LINE__)) {
            changed |= pe_graph_updated_then;
        }

        if (changed) {
            pe_rsc_trace(then->rsc, "unmanaged left: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("unmanaged left: %s then %s", first->uuid, then->uuid);
        }
    }

    if (processed == FALSE) {
        crm_trace("Constraint 0x%.6x not applicable", type);
    }

    return changed;
}

static void
mark_start_blocked(pe_resource_t *rsc, pe_resource_t *reason,
                   pe_working_set_t *data_set)
{
    GListPtr gIter = rsc->actions;
    char *reason_text = crm_strdup_printf("colocation with %s", reason->id);

    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (safe_str_neq(action->task, RSC_START)) {
            continue;
        }
        if (is_set(action->flags, pe_action_runnable)) {
            pe_action_set_flag_reason(__FUNCTION__, __LINE__, action, NULL, reason_text, pe_action_runnable, FALSE);
            update_colo_start_chain(action, data_set);
            update_action(action, data_set);
        }
    }
    free(reason_text);
}

void
update_colo_start_chain(pe_action_t *action, pe_working_set_t *data_set)
{
    GListPtr gIter = NULL;
    resource_t *rsc = NULL;

    if (is_not_set(action->flags, pe_action_runnable) && safe_str_eq(action->task, RSC_START)) {
        rsc = uber_parent(action->rsc);
        if (rsc->parent) {
            /* For bundles, uber_parent() returns the clone/master, not the
             * bundle, so the existence of rsc->parent implies this is a bundle.
             * In this case, we need the bundle resource, so that we can check
             * if all containers are stopped/stopping.
             */
            rsc = rsc->parent;
        }
    }

    if (rsc == NULL || rsc->rsc_cons_lhs == NULL) {
        return;
    }

    /* if rsc has children, all the children need to have start set to
     * unrunnable before we follow the colo chain for the parent. */
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        resource_t *child = (resource_t *)gIter->data;
        action_t *start = find_first_action(child->actions, NULL, RSC_START, NULL);
        if (start == NULL || is_set(start->flags, pe_action_runnable)) {
            return;
        }
    }

    for (gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *colocate_with = (rsc_colocation_t *)gIter->data;
        if (colocate_with->score == INFINITY) {
            mark_start_blocked(colocate_with->rsc_lh, action->rsc, data_set);
        }
    }
}

gboolean
update_action(pe_action_t *then, pe_working_set_t *data_set)
{
    GListPtr lpc = NULL;
    enum pe_graph_flags changed = pe_graph_none;
    int last_flags = then->flags;

    crm_trace("Processing %s (%s %s %s)",
              then->uuid,
              is_set(then->flags, pe_action_optional) ? "optional" : "required",
              is_set(then->flags, pe_action_runnable) ? "runnable" : "unrunnable",
              is_set(then->flags,
                     pe_action_pseudo) ? "pseudo" : then->node ? then->node->details->uname : "");

    if (is_set(then->flags, pe_action_requires_any)) {
        /* initialize current known runnable before actions to 0
         * from here as graph_update_action is called for each of
         * then's before actions, this number will increment as
         * runnable 'first' actions are encountered */
        then->runnable_before = 0;

        /* for backwards compatibility with previous options that use
         * the 'requires_any' flag, initialize required to 1 if it is
         * not set. */ 
        if (then->required_runnable_before == 0) {
            then->required_runnable_before = 1;
        }
        pe_clear_action_bit(then, pe_action_runnable);
        /* We are relying on the pe_order_one_or_more clause of
         * graph_update_action(), called as part of the:
         *
         *    'if (first == other->action)'
         *
         * block below, to set this back if appropriate
         */
    }

    for (lpc = then->actions_before; lpc != NULL; lpc = lpc->next) {
        action_wrapper_t *other = (action_wrapper_t *) lpc->data;
        action_t *first = other->action;

        node_t *then_node = then->node;
        node_t *first_node = first->node;

        enum pe_action_flags then_flags = 0;
        enum pe_action_flags first_flags = 0;

        if (first->rsc && first->rsc->variant == pe_group && safe_str_eq(first->task, RSC_START)) {
            first_node = first->rsc->fns->location(first->rsc, NULL, FALSE);
            if (first_node) {
                crm_trace("First: Found node %s for %s", first_node->details->uname, first->uuid);
            }
        }

        if (then->rsc && then->rsc->variant == pe_group && safe_str_eq(then->task, RSC_START)) {
            then_node = then->rsc->fns->location(then->rsc, NULL, FALSE);
            if (then_node) {
                crm_trace("Then: Found node %s for %s", then_node->details->uname, then->uuid);
            }
        }
        /* Disable constraint if it only applies when on same node, but isn't */
        if (is_set(other->type, pe_order_same_node) && first_node && then_node
            && (first_node->details != then_node->details)) {

            crm_trace("Disabled constraint %s on %s -> %s on %s",
                       other->action->uuid, first_node->details->uname,
                       then->uuid, then_node->details->uname);
            other->type = pe_order_none;
            continue;
        }

        clear_bit(changed, pe_graph_updated_first);

        if (first->rsc && is_set(other->type, pe_order_then_cancels_first)
            && is_not_set(then->flags, pe_action_optional)) {

            /* 'then' is required, so we must abandon 'first'
             * (e.g. a required stop cancels any reload).
             */
            set_bit(other->action->flags, pe_action_optional);
            if (!strcmp(first->task, CRMD_ACTION_RELOAD)) {
                clear_bit(first->rsc->flags, pe_rsc_reload);
            }
        }

        if (first->rsc && then->rsc && (first->rsc != then->rsc)
            && (is_parent(then->rsc, first->rsc) == FALSE)) {
            first = rsc_expand_action(first);
        }
        if (first != other->action) {
            crm_trace("Ordering %s after %s instead of %s", then->uuid, first->uuid,
                      other->action->uuid);
        }

        first_flags = get_action_flags(first, then_node);
        then_flags = get_action_flags(then, first_node);

        crm_trace("Checking %s (%s %s %s) against %s (%s %s %s) filter=0x%.6x type=0x%.6x",
                  then->uuid,
                  is_set(then_flags, pe_action_optional) ? "optional" : "required",
                  is_set(then_flags, pe_action_runnable) ? "runnable" : "unrunnable",
                  is_set(then_flags,
                         pe_action_pseudo) ? "pseudo" : then->node ? then->node->details->
                  uname : "", first->uuid, is_set(first_flags,
                                                  pe_action_optional) ? "optional" : "required",
                  is_set(first_flags, pe_action_runnable) ? "runnable" : "unrunnable",
                  is_set(first_flags,
                         pe_action_pseudo) ? "pseudo" : first->node ? first->node->details->
                  uname : "", first_flags, other->type);

        if (first == other->action) {
            /*
             * 'first' was not expanded (e.g. from 'start' to 'running'), which could mean it:
             * - has no associated resource,
             * - was a primitive,
             * - was pre-expanded (e.g. 'running' instead of 'start')
             *
             * The third argument here to graph_update_action() is a node which is used under two conditions:
             * - Interleaving, in which case first->node and
             *   then->node are equal (and NULL)
             * - If 'then' is a clone, to limit the scope of the
             *   constraint to instances on the supplied node
             *
             */
            node_t *node = then->node;
            changed |= graph_update_action(first, then, node, first_flags,
                                           then_flags, other, data_set);

            /* 'first' was for a complex resource (clone, group, etc),
             * create a new dependency if necessary
             */
        } else if (order_actions(first, then, other->type)) {
            /* This was the first time 'first' and 'then' were associated,
             * start again to get the new actions_before list
             */
            changed |= (pe_graph_updated_then | pe_graph_disable);
        }

        if (changed & pe_graph_disable) {
            crm_trace("Disabled constraint %s -> %s in favor of %s -> %s",
                      other->action->uuid, then->uuid, first->uuid, then->uuid);
            clear_bit(changed, pe_graph_disable);
            other->type = pe_order_none;
        }

        if (changed & pe_graph_updated_first) {
            GListPtr lpc2 = NULL;

            crm_trace("Updated %s (first %s %s %s), processing dependents ",
                      first->uuid,
                      is_set(first->flags, pe_action_optional) ? "optional" : "required",
                      is_set(first->flags, pe_action_runnable) ? "runnable" : "unrunnable",
                      is_set(first->flags,
                             pe_action_pseudo) ? "pseudo" : first->node ? first->node->details->
                      uname : "");
            for (lpc2 = first->actions_after; lpc2 != NULL; lpc2 = lpc2->next) {
                action_wrapper_t *other = (action_wrapper_t *) lpc2->data;

                update_action(other->action, data_set);
            }
            update_action(first, data_set);
        }
    }

    if (is_set(then->flags, pe_action_requires_any)) {
        if (last_flags != then->flags) {
            changed |= pe_graph_updated_then;
        } else {
            clear_bit(changed, pe_graph_updated_then);
        }
    }

    if (changed & pe_graph_updated_then) {
        crm_trace("Updated %s (then %s %s %s), processing dependents ",
                  then->uuid,
                  is_set(then->flags, pe_action_optional) ? "optional" : "required",
                  is_set(then->flags, pe_action_runnable) ? "runnable" : "unrunnable",
                  is_set(then->flags,
                         pe_action_pseudo) ? "pseudo" : then->node ? then->node->details->
                  uname : "");

        if (is_set(last_flags, pe_action_runnable) && is_not_set(then->flags, pe_action_runnable)) {
            update_colo_start_chain(then, data_set);
        }
        update_action(then, data_set);
        for (lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
            action_wrapper_t *other = (action_wrapper_t *) lpc->data;

            update_action(other->action, data_set);
        }
    }

    return FALSE;
}

gboolean
shutdown_constraints(node_t * node, action_t * shutdown_op, pe_working_set_t * data_set)
{
    /* add the stop to the before lists so it counts as a pre-req
     * for the shutdown
     */
    GListPtr lpc = NULL;

    for (lpc = data_set->actions; lpc != NULL; lpc = lpc->next) {
        action_t *action = (action_t *) lpc->data;

        if (action->rsc == NULL || action->node == NULL) {
            continue;
        } else if (action->node->details != node->details) {
            continue;
        } else if (is_set(action->rsc->flags, pe_rsc_maintenance)) {
            pe_rsc_trace(action->rsc, "Skipping %s: maintenance mode", action->uuid);
            continue;
        } else if (node->details->maintenance) {
            pe_rsc_trace(action->rsc, "Skipping %s: node %s is in maintenance mode",
                         action->uuid, node->details->uname);
            continue;
        } else if (safe_str_neq(action->task, RSC_STOP)) {
            continue;
        } else if (is_not_set(action->rsc->flags, pe_rsc_managed)
                   && is_not_set(action->rsc->flags, pe_rsc_block)) {
            /*
             * If another action depends on this one, we may still end up blocking
             */
            pe_rsc_trace(action->rsc, "Skipping %s: unmanaged", action->uuid);
            continue;
        }

        pe_rsc_trace(action->rsc, "Ordering %s before shutdown on %s", action->uuid,
                     node->details->uname);
        pe_clear_action_bit(action, pe_action_optional);
        custom_action_order(action->rsc, NULL, action,
                            NULL, strdup(CRM_OP_SHUTDOWN), shutdown_op,
                            pe_order_optional | pe_order_runnable_left, data_set);
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Order all actions appropriately relative to a fencing operation
 *
 * Ensure start operations of affected resources are ordered after fencing,
 * imply stop and demote operations of affected resources by marking them as
 * pseudo-actions, etc.
 *
 * \param[in]     stonith_op  Fencing operation
 * \param[in,out] data_set    Working set of cluster
 */
void
pcmk__order_vs_fence(pe_action_t *stonith_op, pe_working_set_t *data_set)
{
    CRM_CHECK(stonith_op && data_set, return);
    for (GList *r = data_set->resources; r != NULL; r = r->next) {
        rsc_stonith_ordering((pe_resource_t *) r->data, stonith_op, data_set);
    }
}

static node_t *
get_router_node(action_t *action)
{
    node_t *began_on = NULL;
    node_t *ended_on = NULL;
    node_t *router_node = NULL;
    bool partial_migration = FALSE;
    const char *task = action->task;

    if (safe_str_eq(task, CRM_OP_FENCE)
        || !pe__is_guest_or_remote_node(action->node)) {
        return NULL;
    }

    CRM_ASSERT(action->node->details->remote_rsc != NULL);

    began_on = pe__current_node(action->node->details->remote_rsc);
    ended_on = action->node->details->remote_rsc->allocated_to;
    if (action->node->details->remote_rsc
        && (action->node->details->remote_rsc->container == NULL)
        && action->node->details->remote_rsc->partial_migration_target) {
        partial_migration = TRUE;
    }

    /* if there is only one location to choose from,
     * this is easy. Check for those conditions first */
    if (!began_on || !ended_on) {
        /* remote rsc is either shutting down or starting up */
        return began_on ? began_on : ended_on;
    } else if (began_on->details == ended_on->details) {
        /* remote rsc didn't move nodes. */
        return began_on;
    }

    /* If we have get here, we know the remote resource
     * began on one node and is moving to another node.
     *
     * This means some actions will get routed through the cluster
     * node the connection rsc began on, and others are routed through
     * the cluster node the connection rsc ends up on.
     *
     * 1. stop, demote, migrate actions of resources living in the remote
     *    node _MUST_ occur _BEFORE_ the connection can move (these actions
     *    are all required before the remote rsc stop action can occur.) In
     *    this case, we know these actions have to be routed through the initial
     *    cluster node the connection resource lived on before the move takes place.
     *    The exception is a partial migration of a (non-guest) remote
     *    connection resource; in that case, all actions (even these) will be
     *    ordered after the connection's pseudo-start on the migration target,
     *    so the target is the router node.
     *
     * 2. Everything else (start, promote, monitor, probe, refresh, clear failcount
     *    delete ....) must occur after the resource starts on the node it is
     *    moving to.
     */

    if (safe_str_eq(task, "notify")) {
        task = g_hash_table_lookup(action->meta, "notify_operation");
    }

    /* 1. before connection rsc moves. */
    if ((safe_str_eq(task, "stop") ||
        safe_str_eq(task, "demote") ||
        safe_str_eq(task, "migrate_from") ||
        safe_str_eq(task, "migrate_to")) && !partial_migration) {

        router_node = began_on;

    /* 2. after connection rsc moves. */
    } else {
        router_node = ended_on;
    }
    return router_node;
}

/*!
 * \internal
 * \brief Add an XML node tag for a specified ID
 *
 * \param[in]     id      Node UUID to add
 * \param[in,out] xml     Parent XML tag to add to
 */
static xmlNode*
add_node_to_xml_by_id(const char *id, xmlNode *xml)
{
    xmlNode *node_xml;

    node_xml = create_xml_node(xml, XML_CIB_TAG_NODE);
    crm_xml_add(node_xml, XML_ATTR_UUID, id);

    return node_xml;
}

/*!
 * \internal
 * \brief Add an XML node tag for a specified node
 *
 * \param[in]     node  Node to add
 * \param[in,out] xml   XML to add node to
 */
static void
add_node_to_xml(const node_t *node, void *xml)
{
    add_node_to_xml_by_id(node->details->id, (xmlNode *) xml);
}

/*!
 * \internal
 * \brief Add XML with nodes that need an update of their maintenance state
 *
 * \param[in,out] xml       Parent XML tag to add to
 * \param[in]     data_set  Working set for cluster
 */
static int
add_maintenance_nodes(xmlNode *xml, const pe_working_set_t *data_set)
{
    GListPtr gIter = NULL;
    xmlNode *maintenance =
        xml?create_xml_node(xml, XML_GRAPH_TAG_MAINTENANCE):NULL;
    int count = 0;

    for (gIter = data_set->nodes; gIter != NULL;
         gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        struct pe_node_shared_s *details = node->details;

        if (!pe__is_guest_or_remote_node(node)) {
            continue; /* just remote nodes need to know atm */
        }

        if (details->maintenance != details->remote_maintenance) {
            if (maintenance) {
                crm_xml_add(
                    add_node_to_xml_by_id(node->details->id, maintenance),
                    XML_NODE_IS_MAINTENANCE, details->maintenance?"1":"0");
            }
            count++;
        }
    }
    crm_trace("%s %d nodes to adjust maintenance-mode "
              "to transition", maintenance?"Added":"Counted", count);
    return count;
}

/*!
 * \internal
 * \brief Add pseudo action with nodes needing maintenance state update
 *
 * \param[in,out] data_set  Working set for cluster
 */
void
add_maintenance_update(pe_working_set_t *data_set)
{
    action_t *action = NULL;

    if (add_maintenance_nodes(NULL, data_set)) {
        crm_trace("adding maintenance state update pseudo action");
        action = get_pseudo_op(CRM_OP_MAINTENANCE_NODES, data_set);
        set_bit(action->flags, pe_action_print_always);
    }
}

/*!
 * \internal
 * \brief Add XML with nodes that an action is expected to bring down
 *
 * If a specified action is expected to bring any nodes down, add an XML block
 * with their UUIDs. When a node is lost, this allows the controller to
 * determine whether it was expected.
 *
 * \param[in,out] xml       Parent XML tag to add to
 * \param[in]     action    Action to check for downed nodes
 * \param[in]     data_set  Working set for cluster
 */
static void
add_downed_nodes(xmlNode *xml, const action_t *action,
                 const pe_working_set_t *data_set)
{
    CRM_CHECK(xml && action && action->node && data_set, return);

    if (safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {

        /* Shutdown makes the action's node down */
        xmlNode *downed = create_xml_node(xml, XML_GRAPH_TAG_DOWNED);
        add_node_to_xml_by_id(action->node->details->id, downed);

    } else if (safe_str_eq(action->task, CRM_OP_FENCE)) {

        /* Fencing makes the action's node and any hosted guest nodes down */
        const char *fence = g_hash_table_lookup(action->meta, "stonith_action");

        if (safe_str_eq(fence, "off") || safe_str_eq(fence, "reboot")) {
            xmlNode *downed = create_xml_node(xml, XML_GRAPH_TAG_DOWNED);
            add_node_to_xml_by_id(action->node->details->id, downed);
            pe_foreach_guest_node(data_set, action->node, add_node_to_xml, downed);
        }

    } else if (action->rsc && action->rsc->is_remote_node
               && safe_str_eq(action->task, CRMD_ACTION_STOP)) {

        /* Stopping a remote connection resource makes connected node down,
         * unless it's part of a migration
         */
        GListPtr iter;
        action_t *input;
        gboolean migrating = FALSE;

        for (iter = action->actions_before; iter != NULL; iter = iter->next) {
            input = ((action_wrapper_t *) iter->data)->action;
            if (input->rsc && safe_str_eq(action->rsc->id, input->rsc->id)
               && safe_str_eq(input->task, CRMD_ACTION_MIGRATED)) {
                migrating = TRUE;
                break;
            }
        }
        if (!migrating) {
            xmlNode *downed = create_xml_node(xml, XML_GRAPH_TAG_DOWNED);
            add_node_to_xml_by_id(action->rsc->id, downed);
        }
    }
}

static bool
should_lock_action(pe_action_t *action)
{
    // Only actions taking place on resource's lock node are locked
    if ((action->rsc->lock_node == NULL) || (action->node == NULL)
        || (action->node->details != action->rsc->lock_node->details)) {
        return false;
    }

    /* During shutdown, only stops are locked (otherwise, another action such as
     * a demote would cause the controller to clear the lock)
     */
    if (action->node->details->shutdown && action->task
        && strcmp(action->task, RSC_STOP)) {
        return false;
    }

    return true;
}

static xmlNode *
action2xml(action_t * action, gboolean as_input, pe_working_set_t *data_set)
{
    gboolean needs_node_info = TRUE;
    gboolean needs_maintenance_info = FALSE;
    xmlNode *action_xml = NULL;
    xmlNode *args_xml = NULL;
#if ENABLE_VERSIONED_ATTRS
    pe_rsc_action_details_t *rsc_details = NULL;
#endif

    if (action == NULL) {
        return NULL;
    }

    if (safe_str_eq(action->task, CRM_OP_FENCE)) {
        /* All fences need node info; guest node fences are pseudo-events */
        action_xml = create_xml_node(NULL,
                                     is_set(action->flags, pe_action_pseudo)?
                                     XML_GRAPH_TAG_PSEUDO_EVENT :
                                     XML_GRAPH_TAG_CRM_EVENT);

    } else if (safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (safe_str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (safe_str_eq(action->task, CRM_OP_LRM_REFRESH)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (safe_str_eq(action->task, CRM_OP_LRM_DELETE)) {
        // CIB-only clean-up for shutdown locks
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);
        crm_xml_add(action_xml, PCMK__XA_MODE, XML_TAG_CIB);

/* 	} else if(safe_str_eq(action->task, RSC_PROBED)) { */
/* 		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT); */

    } else if (is_set(action->flags, pe_action_pseudo)) {
        if (safe_str_eq(action->task, CRM_OP_MAINTENANCE_NODES)) {
            needs_maintenance_info = TRUE;
        }
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_PSEUDO_EVENT);
        needs_node_info = FALSE;

    } else {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);

#if ENABLE_VERSIONED_ATTRS
        rsc_details = pe_rsc_action_details(action);
#endif
    }

    crm_xml_add_int(action_xml, XML_ATTR_ID, action->id);
    crm_xml_add(action_xml, XML_LRM_ATTR_TASK, action->task);
    if (action->rsc != NULL && action->rsc->clone_name != NULL) {
        char *clone_key = NULL;
        const char *interval_ms_s = g_hash_table_lookup(action->meta,
                                                        XML_LRM_ATTR_INTERVAL_MS);
        guint interval_ms = crm_parse_ms(interval_ms_s);

        if (safe_str_eq(action->task, RSC_NOTIFY)) {
            const char *n_type = g_hash_table_lookup(action->meta, "notify_type");
            const char *n_task = g_hash_table_lookup(action->meta, "notify_operation");

            CRM_CHECK(n_type != NULL, crm_err("No notify type value found for %s", action->uuid));
            CRM_CHECK(n_task != NULL,
                      crm_err("No notify operation value found for %s", action->uuid));
            clone_key = generate_notify_key(action->rsc->clone_name, n_type, n_task);

        } else if(action->cancel_task) {
            clone_key = pcmk__op_key(action->rsc->clone_name,
                                     action->cancel_task, interval_ms);
        } else {
            clone_key = pcmk__op_key(action->rsc->clone_name,
                                     action->task, interval_ms);
        }

        CRM_CHECK(clone_key != NULL, crm_err("Could not generate a key for %s", action->uuid));
        crm_xml_add(action_xml, XML_LRM_ATTR_TASK_KEY, clone_key);
        crm_xml_add(action_xml, "internal_" XML_LRM_ATTR_TASK_KEY, action->uuid);
        free(clone_key);

    } else {
        crm_xml_add(action_xml, XML_LRM_ATTR_TASK_KEY, action->uuid);
    }

    if (needs_node_info && action->node != NULL) {
        node_t *router_node = get_router_node(action);

        crm_xml_add(action_xml, XML_LRM_ATTR_TARGET, action->node->details->uname);
        crm_xml_add(action_xml, XML_LRM_ATTR_TARGET_UUID, action->node->details->id);
        if (router_node) {
            crm_xml_add(action_xml, XML_LRM_ATTR_ROUTER_NODE, router_node->details->uname);
        }

        g_hash_table_insert(action->meta, strdup(XML_LRM_ATTR_TARGET), strdup(action->node->details->uname));
        g_hash_table_insert(action->meta, strdup(XML_LRM_ATTR_TARGET_UUID), strdup(action->node->details->id));
    }

    /* No details if this action is only being listed in the inputs section */
    if (as_input) {
        return action_xml;
    }

    if (action->rsc && is_not_set(action->flags, pe_action_pseudo)) {
        int lpc = 0;
        xmlNode *rsc_xml = NULL;
        const char *attr_list[] = {
            XML_AGENT_ATTR_CLASS,
            XML_AGENT_ATTR_PROVIDER,
            XML_ATTR_TYPE
        };

        /* If a resource is locked to a node via shutdown-lock, mark its actions
         * so the controller can preserve the lock when the action completes.
         */
        if (should_lock_action(action)) {
            crm_xml_add_ll(action_xml, XML_CONFIG_ATTR_SHUTDOWN_LOCK,
                           (long long) action->rsc->lock_time);
        }

        // List affected resource

        rsc_xml = create_xml_node(action_xml,
                                  crm_element_name(action->rsc->xml));
        if (is_set(action->rsc->flags, pe_rsc_orphan)
            && action->rsc->clone_name) {
            /* Do not use the 'instance free' name here as that
             * might interfere with the instance we plan to keep.
             * Ie. if there are more than two named /anonymous/
             * instances on a given node, we need to make sure the
             * command goes to the right one.
             *
             * Keep this block, even when everyone is using
             * 'instance free' anonymous clone names - it means
             * we'll do the right thing if anyone toggles the
             * unique flag to 'off'
             */
            crm_debug("Using orphan clone name %s instead of %s", action->rsc->id,
                      action->rsc->clone_name);
            crm_xml_add(rsc_xml, XML_ATTR_ID, action->rsc->clone_name);
            crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->id);

        } else if (is_not_set(action->rsc->flags, pe_rsc_unique)) {
            const char *xml_id = ID(action->rsc->xml);

            crm_debug("Using anonymous clone name %s for %s (aka. %s)", xml_id, action->rsc->id,
                      action->rsc->clone_name);

            /* ID is what we'd like client to use
             * ID_LONG is what they might know it as instead
             *
             * ID_LONG is only strictly needed /here/ during the
             * transition period until all nodes in the cluster
             * are running the new software /and/ have rebooted
             * once (meaning that they've only ever spoken to a DC
             * supporting this feature).
             *
             * If anyone toggles the unique flag to 'on', the
             * 'instance free' name will correspond to an orphan
             * and fall into the clause above instead
             */
            crm_xml_add(rsc_xml, XML_ATTR_ID, xml_id);
            if (action->rsc->clone_name && safe_str_neq(xml_id, action->rsc->clone_name)) {
                crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->clone_name);
            } else {
                crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->id);
            }

        } else {
            CRM_ASSERT(action->rsc->clone_name == NULL);
            crm_xml_add(rsc_xml, XML_ATTR_ID, action->rsc->id);
        }

        for (lpc = 0; lpc < DIMOF(attr_list); lpc++) {
            crm_xml_add(rsc_xml, attr_list[lpc],
                        g_hash_table_lookup(action->rsc->meta, attr_list[lpc]));
        }
    }

    /* List any attributes in effect */
    args_xml = create_xml_node(NULL, XML_TAG_ATTRS);
    crm_xml_add(args_xml, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    g_hash_table_foreach(action->extra, hash2field, args_xml);
    if (action->rsc != NULL && action->node) {
        GHashTable *p = crm_str_table_new();

        get_rsc_attributes(p, action->rsc, action->node, data_set);
        g_hash_table_foreach(p, hash2smartfield, args_xml);
        g_hash_table_destroy(p);

#if ENABLE_VERSIONED_ATTRS
        {
            xmlNode *versioned_parameters = create_xml_node(NULL, XML_TAG_RSC_VER_ATTRS);

            pe_get_versioned_attributes(versioned_parameters, action->rsc,
                                        action->node, data_set);
            if (xml_has_children(versioned_parameters)) {
                add_node_copy(action_xml, versioned_parameters);
            }
            free_xml(versioned_parameters);
        }
#endif

    } else if(action->rsc && action->rsc->variant <= pe_native) {
        g_hash_table_foreach(action->rsc->parameters, hash2smartfield, args_xml);

#if ENABLE_VERSIONED_ATTRS
        if (xml_has_children(action->rsc->versioned_parameters)) {
            add_node_copy(action_xml, action->rsc->versioned_parameters);
        }
#endif
    }

#if ENABLE_VERSIONED_ATTRS
    if (rsc_details) {
        if (xml_has_children(rsc_details->versioned_parameters)) {
            add_node_copy(action_xml, rsc_details->versioned_parameters);
        }

        if (xml_has_children(rsc_details->versioned_meta)) {
            add_node_copy(action_xml, rsc_details->versioned_meta);
        }
    }
#endif

    g_hash_table_foreach(action->meta, hash2metafield, args_xml);
    if (action->rsc != NULL) {
        const char *value = g_hash_table_lookup(action->rsc->meta, "external-ip");
        resource_t *parent = action->rsc;

        while (parent != NULL) {
            parent->cmds->append_meta(parent, args_xml);
            parent = parent->parent;
        }

        if(value) {
            hash2smartfield((gpointer)"pcmk_external_ip", (gpointer)value, (gpointer)args_xml);
        }

        if (pe__is_guest_node(action->node)) {
            pe_node_t *host = NULL;
            enum action_tasks task = text2task(action->task);

            if(task == action_notify || task == action_notified) {
                const char *n_task = g_hash_table_lookup(action->meta, "notify_operation");
                task = text2task(n_task);
            }

            // Differentiate between up and down actions
            switch (task) {
                case stop_rsc:
                case stopped_rsc:
                case action_demote:
                case action_demoted:
                    host = pe__current_node(action->node->details->remote_rsc->container);
                    break;
                case start_rsc:
                case started_rsc:
                case monitor_rsc:
                case action_promote:
                case action_promoted:
                    host = action->node->details->remote_rsc->container->allocated_to;
                    break;
                default:
                    break;
            }

            if(host) {
                hash2metafield((gpointer)XML_RSC_ATTR_TARGET,
                               (gpointer)g_hash_table_lookup(action->rsc->meta, XML_RSC_ATTR_TARGET), (gpointer)args_xml);
                hash2metafield((gpointer)PCMK_ENV_PHYSICAL_HOST, (gpointer)host->details->uname, (gpointer)args_xml);
            }
        }

    } else if (safe_str_eq(action->task, CRM_OP_FENCE) && action->node) {
        /* Pass the node's attributes as meta-attributes.
         *
         * @TODO: Determine whether it is still necessary to do this. It was
         * added in 33d99707, probably for the libfence-based implementation in
         * c9a90bd, which is no longer used.
         */
        g_hash_table_foreach(action->node->details->attrs, hash2metafield, args_xml);
    }

    sorted_xml(args_xml, action_xml, FALSE);
    free_xml(args_xml);

    /* List any nodes this action is expected to make down */
    if (needs_node_info && (action->node != NULL)) {
        add_downed_nodes(action_xml, action, data_set);
    }

    if (needs_maintenance_info) {
        add_maintenance_nodes(action_xml, data_set);
    }

    crm_log_xml_trace(action_xml, "dumped action");
    return action_xml;
}

static bool
should_dump_action(pe_action_t *action)
{
    CRM_CHECK(action != NULL, return false);

    if (is_set(action->flags, pe_action_dumped)) {
        crm_trace("Action %s (%d) already dumped", action->uuid, action->id);
        return false;

    } else if (is_set(action->flags, pe_action_pseudo)
               && safe_str_eq(action->task, CRM_OP_PROBED)) {
        GListPtr lpc = NULL;

        /* This is a horrible but convenient hack
         *
         * It mimimizes the number of actions with unsatisfied inputs
         * (i.e. not included in the graph)
         *
         * This in turn, means we can be more concise when printing
         * aborted/incomplete graphs.
         *
         * It also makes it obvious which node is preventing
         * probe_complete from running (presumably because it is only
         * partially up)
         *
         * For these reasons we tolerate such perversions
         */

        for (lpc = action->actions_after; lpc != NULL; lpc = lpc->next) {
            pe_action_wrapper_t *wrapper = (pe_action_wrapper_t *) lpc->data;

            if (is_not_set(wrapper->action->flags, pe_action_runnable)) {
                /* Only interested in runnable operations */
            } else if (safe_str_neq(wrapper->action->task, RSC_START)) {
                /* Only interested in start operations */
            } else if (is_set(wrapper->action->flags, pe_action_dumped)
                       || should_dump_action(wrapper->action)) {
                crm_trace("Action %s (%d) should be dumped: "
                          "dependency of %s (%d)",
                          action->uuid, action->id,
                          wrapper->action->uuid, wrapper->action->id);
                return true;
            }
        }
    }

    if (is_not_set(action->flags, pe_action_runnable)) {
        crm_trace("Ignoring action %s (%d): unrunnable",
                  action->uuid, action->id);
        return false;

    } else if (is_set(action->flags, pe_action_optional)
               && is_not_set(action->flags, pe_action_print_always)) {
        crm_trace("Ignoring action %s (%d): optional",
                  action->uuid, action->id);
        return false;

    // Monitors should be dumped even for unmanaged resources
    } else if (action->rsc && is_not_set(action->rsc->flags, pe_rsc_managed)
               && safe_str_neq(action->task, RSC_STATUS)) {

        const char *interval_ms_s = g_hash_table_lookup(action->meta,
                                                        XML_LRM_ATTR_INTERVAL_MS);

        // Cancellation of recurring monitors should still be dumped
        if ((interval_ms_s == NULL) || !strcmp(interval_ms_s, "0")) {
            crm_trace("Ignoring action %s (%d): for unmanaged resource (%s)",
                      action->uuid, action->id, action->rsc->id);
            return false;
        }
    }

    if (is_set(action->flags, pe_action_pseudo)
        || safe_str_eq(action->task, CRM_OP_FENCE)
        || safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {
        /* skip the next checks */
        return true;
    }

    if (action->node == NULL) {
        pe_err("Skipping action %s (%d) "
               "because it was not allocated to a node (bug?)",
               action->uuid, action->id);
        log_action(LOG_DEBUG, "Unallocated action", action, false);
        return false;

    } else if (is_set(action->flags, pe_action_dc)) {
        crm_trace("Action %s (%d) should be dumped: "
                  "can run on DC instead of %s",
                  action->uuid, action->id, action->node->details->uname);

    } else if (pe__is_guest_node(action->node)
               && !action->node->details->remote_requires_reset) {
        crm_trace("Action %s (%d) should be dumped: "
                  "assuming will be runnable on guest node %s",
                  action->uuid, action->id, action->node->details->uname);

    } else if (action->node->details->online == false) {
        pe_err("Skipping action %s (%d) "
               "because it was scheduled for offline node (bug?)",
               action->uuid, action->id);
        log_action(LOG_DEBUG, "Action for offline node", action, FALSE);
        return false;
#if 0
        /* but this would also affect resources that can be safely
         *  migrated before a fencing op
         */
    } else if (action->node->details->unclean == false) {
        pe_err("Skipping action %s (%d) "
               "because it was scheduled for unclean node (bug?)",
               action->uuid, action->id);
        log_action(LOG_DEBUG, "Action for unclean node", action, false);
        return false;
#endif
    }
    return true;
}

/* lowest to highest */
static gint
sort_action_id(gconstpointer a, gconstpointer b)
{
    const action_wrapper_t *action_wrapper2 = (const action_wrapper_t *)a;
    const action_wrapper_t *action_wrapper1 = (const action_wrapper_t *)b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (action_wrapper1->action->id > action_wrapper2->action->id) {
        return -1;
    }

    if (action_wrapper1->action->id < action_wrapper2->action->id) {
        return 1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Check whether an action input should be in the transition graph
 *
 * \param[in]     action  Action to check
 * \param[in,out] input   Action input to check
 *
 * \return true if input should be in graph, false otherwise
 * \note This function may not only check an input, but disable it under certian
 *       circumstances (load or anti-colocation orderings that are not needed).
 */
static bool
check_dump_input(pe_action_t *action, pe_action_wrapper_t *input)
{
    int type = input->type;

    if (input->state == pe_link_dumped) {
        return true;
    }

    type &= ~pe_order_implies_first_printed;
    type &= ~pe_order_implies_then_printed;
    type &= ~pe_order_optional;

    if (input->type == pe_order_none) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "ordering disabled",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (is_not_set(input->action->flags, pe_action_runnable)
               && (type == pe_order_none)
               && safe_str_neq(input->action->uuid, CRM_OP_PROBED)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "optional and input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (is_not_set(input->action->flags, pe_action_runnable)
               && is_set(input->type, pe_order_one_or_more)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "one-or-more and input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (is_set(action->flags, pe_action_pseudo)
               && is_set(input->type, pe_order_stonith_stop)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "stonith stop but action is pseudo",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (is_set(input->type, pe_order_implies_first_migratable)
               && is_not_set(input->action->flags, pe_action_runnable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "implies input migratable but input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (is_set(input->type, pe_order_apply_first_non_migratable)
               && is_set(input->action->flags, pe_action_migrate_runnable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "only if input unmigratable but input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if ((input->type == pe_order_optional)
               && is_set(input->action->flags, pe_action_migrate_runnable)
               && crm_ends_with(input->action->uuid, "_stop_0")) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "optional but stop in migration",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (input->type == pe_order_load) {
        pe_node_t *input_node = input->action->node;

        // load orderings are relevant only if actions are for same node

        if (action->rsc && safe_str_eq(action->task, RSC_MIGRATE)) {
            pe_node_t *allocated = action->rsc->allocated_to;

            /* For load_stopped -> migrate_to orderings, we care about where it
             * has been allocated to, not where it will be executed.
             */
            if ((input_node == NULL) || (allocated == NULL)
                || (input_node->details != allocated->details)) {
                crm_trace("Ignoring %s (%d) input %s (%d): "
                          "load ordering node mismatch %s vs %s",
                          action->uuid, action->id,
                          input->action->uuid, input->action->id,
                          (allocated? allocated->details->uname : "<none>"),
                          (input_node? input_node->details->uname : "<none>"));
                input->type = pe_order_none;
                return false;
            }

        } else if ((input_node == NULL) || (action->node == NULL)
                   || (input_node->details != action->node->details)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "load ordering node mismatch %s vs %s",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id,
                      (action->node? action->node->details->uname : "<none>"),
                      (input_node? input_node->details->uname : "<none>"));
            input->type = pe_order_none;
            return false;

        } else if (is_set(input->action->flags, pe_action_optional)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "load ordering input optional",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id);
            input->type = pe_order_none;
            return false;
        }

    } else if (input->type == pe_order_anti_colocation) {
        if (input->action->node && action->node
            && (input->action->node->details != action->node->details)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "anti-colocation node mismatch %s vs %s",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id,
                      action->node->details->uname,
                      input->action->node->details->uname);
            input->type = pe_order_none;
            return false;

        } else if (is_set(input->action->flags, pe_action_optional)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "anti-colocation input optional",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id);
            input->type = pe_order_none;
            return false;
        }

    } else if (input->action->rsc
               && input->action->rsc != action->rsc
               && is_set(input->action->rsc->flags, pe_rsc_failed)
               && is_not_set(input->action->rsc->flags, pe_rsc_managed)
               && crm_ends_with(input->action->uuid, "_stop_0")
               && action->rsc && pe_rsc_is_clone(action->rsc)) {
        crm_warn("Ignoring requirement that %s complete before %s:"
                 " unmanaged failed resources cannot prevent clone shutdown",
                 input->action->uuid, action->uuid);
        return false;

    } else if (is_set(input->action->flags, pe_action_optional)
               && is_not_set(input->action->flags, pe_action_print_always)
               && is_not_set(input->action->flags, pe_action_dumped)
               && !should_dump_action(input->action)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "input optional",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;
    }

    crm_trace("%s (%d) input %s (%d) @ %s should be dumped: %s, %s, %s, 0x%.6x",
              action->uuid, action->id,
              input->action->uuid, input->action->id,
              input->action->node? input->action->node->details->uname : "no node",
              is_set(input->action->flags, pe_action_pseudo)? "pseudo" : "real",
              is_set(input->action->flags, pe_action_runnable)? "runnable" : "unrunnable",
              is_set(input->action->flags, pe_action_optional)? "optional" : "required",
              input->type);
    return true;
}

static bool
graph_has_loop(pe_action_t *init_action, pe_action_t *action,
               pe_action_wrapper_t *input)
{
    bool has_loop = false;

    if (is_set(input->action->flags, pe_action_tracking)) {
        crm_trace("Breaking tracking loop: %s@%s -> %s@%s (0x%.6x)",
                  input->action->uuid,
                  input->action->node? input->action->node->details->uname : "",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  input->type);
        return false;
    }

    // Don't need to check inputs that won't be used
    if (!check_dump_input(action, input)) {
        return false;
    }

    if (input->action == init_action) {
        crm_debug("Input loop found in %s@%s ->...-> %s@%s",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  init_action->uuid,
                  init_action->node? init_action->node->details->uname : "");
        return true;
    }

    set_bit(input->action->flags, pe_action_tracking);

    crm_trace("Checking inputs of action %s@%s input %s@%s (0x%.6x)"
              "for graph loop with %s@%s ",
              action->uuid,
              action->node? action->node->details->uname : "",
              input->action->uuid,
              input->action->node? input->action->node->details->uname : "",
              input->type,
              init_action->uuid,
              init_action->node? init_action->node->details->uname : "");

    // Recursively check input itself for loops
    for (GList *iter = input->action->actions_before;
         iter != NULL; iter = iter->next) {

        if (graph_has_loop(init_action, input->action,
                           (pe_action_wrapper_t *) iter->data)) {
            // Recursive call already logged a debug message
            has_loop = true;
            goto done;
        }
    }

done:
    pe_clear_action_bit(input->action, pe_action_tracking);

    if (!has_loop) {
        crm_trace("No input loop found in %s@%s -> %s@%s (0x%.6x)",
                  input->action->uuid,
                  input->action->node? input->action->node->details->uname : "",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  input->type);
    }
    return has_loop;
}

bool
pcmk__ordering_is_invalid(pe_action_t *action, pe_action_wrapper_t *input)
{
    /* Prevent user-defined ordering constraints between resources
     * running in a guest node and the resource that defines that node.
     */
    if (is_not_set(input->type, pe_order_preserve)
        && action->rsc && action->rsc->fillers
        && input->action->rsc && input->action->node
        && input->action->node->details->remote_rsc
        && (input->action->node->details->remote_rsc->container == action->rsc)) {
        crm_warn("Invalid ordering constraint between %s and %s",
                 input->action->rsc->id, action->rsc->id);
        return true;
    }

    /* If there's an order like
     * "rscB_stop node2"-> "load_stopped_node2" -> "rscA_migrate_to node1"
     *
     * then rscA is being migrated from node1 to node2, while rscB is being
     * migrated from node2 to node1. If there would be a graph loop,
     * break the order "load_stopped_node2" -> "rscA_migrate_to node1".
     */
    if ((input->type == pe_order_load) && action->rsc
        && safe_str_eq(action->task, RSC_MIGRATE)
        && graph_has_loop(action, action, input)) {
        return true;
    }

    return false;
}

// Remove duplicate inputs (regardless of flags)
static void
deduplicate_inputs(pe_action_t *action)
{
    GList *item = NULL;
    GList *next = NULL;
    pe_action_wrapper_t *last_input = NULL;

    action->actions_before = g_list_sort(action->actions_before,
                                         sort_action_id);
    for (item = action->actions_before; item != NULL; item = next) {
        pe_action_wrapper_t *input = (pe_action_wrapper_t *) item->data;

        next = item->next;
        if (last_input && (input->action->id == last_input->action->id)) {
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
 * \brief Add an action to the transition graph XML if appropriate
 *
 * \param[in] action    Action to possibly add
 * \param[in] data_set  Cluster working set
 *
 * \note This will de-duplicate the action inputs, meaning that the
 *       pe_action_wrapper_t:type flags can no longer be relied on to retain
 *       their original settings. That means this MUST be called after stage7()
 *       is complete, and nothing after this should rely on those type flags.
 *       (For example, some code looks for type equal to some flag rather than
 *       whether the flag is set, and some code looks for particular
 *       combinations of flags -- such code must be done before stage8().)
 */
void
graph_element_from_action(pe_action_t *action, pe_working_set_t *data_set)
{
    GList *lpc = NULL;
    int synapse_priority = 0;
    xmlNode *syn = NULL;
    xmlNode *set = NULL;
    xmlNode *in = NULL;
    xmlNode *xml_action = NULL;
    pe_action_wrapper_t *input = NULL;

    /* If we haven't already, de-duplicate inputs -- even if we won't be dumping
     * the action, so that crm_simulate dot graphs don't have duplicates.
     */
    if (is_not_set(action->flags, pe_action_dedup)) {
        deduplicate_inputs(action);
        set_bit(action->flags, pe_action_dedup);
    }

    if (should_dump_action(action) == FALSE) {
        return;
    }

    set_bit(action->flags, pe_action_dumped);

    syn = create_xml_node(data_set->graph, "synapse");
    set = create_xml_node(syn, "action_set");
    in = create_xml_node(syn, "inputs");

    crm_xml_add_int(syn, XML_ATTR_ID, data_set->num_synapse);
    data_set->num_synapse++;

    if (action->rsc != NULL) {
        synapse_priority = action->rsc->priority;
    }
    if (action->priority > synapse_priority) {
        synapse_priority = action->priority;
    }
    if (synapse_priority > 0) {
        crm_xml_add_int(syn, XML_CIB_ATTR_PRIORITY, synapse_priority);
    }

    xml_action = action2xml(action, FALSE, data_set);
    add_node_nocopy(set, crm_element_name(xml_action), xml_action);

    for (lpc = action->actions_before; lpc != NULL; lpc = lpc->next) {
        input = (pe_action_wrapper_t *) lpc->data;
        if (check_dump_input(action, input)) {
            xmlNode *input_xml = create_xml_node(in, "trigger");

            input->state = pe_link_dumped;
            xml_action = action2xml(input->action, TRUE, data_set);
            add_node_nocopy(input_xml, crm_element_name(xml_action), xml_action);
        }
    }
}
