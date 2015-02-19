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

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <allocate.h>
#include <utils.h>

gboolean update_action(action_t * action);
void update_colo_start_chain(action_t * action);
gboolean rsc_update_action(action_t * first, action_t * then, enum pe_ordering type);

static enum pe_action_flags
get_action_flags(action_t * action, node_t * node)
{
    enum pe_action_flags flags = action->flags;

    if (action->rsc) {
        flags = action->rsc->cmds->action_flags(action, NULL);

        if (action->rsc->variant >= pe_clone && node) {

            /* We only care about activity on $node */
            enum pe_action_flags clone_flags = action->rsc->cmds->action_flags(action, node);

            /* Go to great lengths to ensure the correct value for pe_action_runnable...
             *
             * If we are a clone, then for _ordering_ constraints, its only relevant
             * if we are runnable _anywhere_.
             *
             * This only applies to _runnable_ though, and only for ordering constraints.
             * If this function is ever used during colocation, then we'll need additional logic
             *
             * Not very satisfying, but its logical and appears to work well.
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
    int interval = 0;
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

    CRM_ASSERT(parse_op_key(old_uuid, &rid, &raw_task, &interval));
    if (interval > 0) {
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
            uuid = generate_op_key(rid, task2text(task + 1), 0);
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
    action_t *result = action;

    if (action->rsc && action->rsc->variant >= pe_group) {
        /* Expand 'start' -> 'started' */
        char *uuid = NULL;
        gboolean notify = FALSE;

        if (action->rsc->parent == NULL) {
            /* Only outter-most resources have notification actions */
            notify = is_set(action->rsc->flags, pe_rsc_notify);
        }

        uuid = convert_non_atomic_uuid(action->uuid, action->rsc, notify, FALSE);
        if (uuid) {
            pe_rsc_trace(action->rsc, "Converting %s to %s %d", action->uuid, uuid,
                         is_set(action->rsc->flags, pe_rsc_notify));
            result = find_first_action(action->rsc->actions, uuid, NULL, NULL);
            if (result == NULL) {
                crm_err("Couldn't expand %s", action->uuid);
                result = action;
            }
            free(uuid);
        }
    }
    return result;
}

static enum pe_graph_flags
graph_update_action(action_t * first, action_t * then, node_t * node, enum pe_action_flags flags,
                    enum pe_ordering type)
{
    enum pe_graph_flags changed = pe_graph_none;
    gboolean processed = FALSE;

    /* TODO: Do as many of these in parallel as possible */

    if (type & pe_order_implies_then) {
        processed = TRUE;
        if (then->rsc) {
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags & pe_action_optional,
                                                pe_action_optional, pe_order_implies_then);

        } else if (is_set(flags, pe_action_optional) == FALSE) {
            if (update_action_flags(then, pe_action_optional | pe_action_clear)) {
                changed |= pe_graph_updated_then;
            }
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "implies right: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("implies right: %s then %s", first->uuid, then->uuid);
        }
    }

    if ((type & pe_order_restart) && then->rsc) {
        enum pe_action_flags restart = (pe_action_optional | pe_action_runnable);

        processed = TRUE;
        changed |=
            then->rsc->cmds->update_actions(first, then, node, flags, restart, pe_order_restart);
        if (changed) {
            pe_rsc_trace(then->rsc, "restart: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("restart: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_implies_first) {
        processed = TRUE;
        if (first->rsc) {
            changed |=
                first->rsc->cmds->update_actions(first, then, node, flags,
                                                 pe_action_optional, pe_order_implies_first);

        } else if (is_set(flags, pe_action_optional) == FALSE) {
            if (update_action_flags(first, pe_action_runnable | pe_action_clear)) {
                changed |= pe_graph_updated_first;
            }
        }

        if (changed) {
            pe_rsc_trace(then->rsc, "implies left: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("implies left: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_implies_first_master) {
        processed = TRUE;
        if (then->rsc) {
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags & pe_action_optional,
                                                pe_action_optional, pe_order_implies_first_master);
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
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags,
                                                pe_action_runnable, pe_order_one_or_more);

        } else if (is_set(flags, pe_action_runnable)) {
            if (update_action_flags(then, pe_action_runnable)) {
                changed |= pe_graph_updated_then;
            }
        }
        if (changed) {
            pe_rsc_trace(then->rsc, "runnable_one_or_more: %s then %s: changed", first->uuid,
                         then->uuid);
        } else {
            crm_trace("runnable_one_or_more: %s then %s", first->uuid, then->uuid);
        }
    }

    if (type & pe_order_runnable_left) {
        processed = TRUE;
        if (then->rsc) {
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags,
                                                pe_action_runnable, pe_order_runnable_left);

        } else if (is_set(flags, pe_action_runnable) == FALSE) {
            if (update_action_flags(then, pe_action_runnable | pe_action_clear)) {
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
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags,
                                                pe_action_optional, pe_order_implies_first_migratable);
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
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags,
                                                pe_action_optional, pe_order_pseudo_left);
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
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags,
                                                pe_action_runnable, pe_order_optional);
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
            changed |=
                then->rsc->cmds->update_actions(first, then, node, flags,
                                                pe_action_runnable, pe_order_asymmetrical);
        }

        if (changed) {
            pe_rsc_trace(then->rsc, "asymmetrical: %s then %s: changed", first->uuid, then->uuid);
        } else {
            crm_trace("asymmetrical: %s then %s", first->uuid, then->uuid);
        }

    }

    if ((first->flags & pe_action_runnable) && (type & pe_order_implies_then_printed)
        && (flags & pe_action_optional) == 0) {
        processed = TRUE;
        crm_trace("%s implies %s printed", first->uuid, then->uuid);
        update_action_flags(then, pe_action_print_always);      /* dont care about changed */
    }

    if ((type & pe_order_implies_first_printed) && (flags & pe_action_optional) == 0) {
        processed = TRUE;
        crm_trace("%s implies %s printed", then->uuid, first->uuid);
        update_action_flags(first, pe_action_print_always);     /* dont care about changed */
    }

    if ((type & pe_order_implies_then
         || type & pe_order_implies_first
         || type & pe_order_restart)
        && first->rsc
        && safe_str_eq(first->task, RSC_STOP)
        && is_not_set(first->rsc->flags, pe_rsc_managed)
        && is_set(first->rsc->flags, pe_rsc_block)
        && is_not_set(first->flags, pe_action_runnable)) {

        if (update_action_flags(then, pe_action_runnable | pe_action_clear)) {
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
mark_start_blocked(resource_t *rsc)
{
    GListPtr gIter = rsc->actions;

    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (safe_str_neq(action->task, RSC_START)) {
            continue;
        }
        if (is_set(action->flags, pe_action_runnable)) {
            clear_bit(action->flags, pe_action_runnable);
            update_colo_start_chain(action);
            update_action(action);
        }
    }
}

void
update_colo_start_chain(action_t *action)
{
    GListPtr gIter = NULL;
    resource_t *rsc = NULL;

    if (is_not_set(action->flags, pe_action_runnable) && safe_str_eq(action->task, RSC_START)) {
        rsc = uber_parent(action->rsc);
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
            mark_start_blocked(colocate_with->rsc_lh);
        }
    }
}

gboolean
update_action(action_t * then)
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
        clear_bit(then->flags, pe_action_runnable);
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

        clear_bit(changed, pe_graph_updated_first);

        if (first->rsc != then->rsc
            && first->rsc != NULL && then->rsc != NULL && first->rsc != then->rsc->parent) {
            first = rsc_expand_action(first);
        }
        if (first != other->action) {
            crm_trace("Ordering %s afer %s instead of %s", then->uuid, first->uuid,
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
             * 'first' was not expanded (ie. from 'start' to 'running'), which could mean it:
             * - has no associated resource,
             * - was a primitive,
             * - was pre-expanded (ie. 'running' instead of 'start')
             *
             * The third argument here to graph_update_action() is a node which is used under two conditions:
             * - Interleaving, in which case first->node and
             *   then->node are equal (and NULL)
             * - If 'then' is a clone, to limit the scope of the
             *   constraint to instances on the supplied node
             *
             */
            int otype = other->type;
            node_t *node = then->node;

            if(is_set(otype, pe_order_implies_then_on_node)) {
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

                clear_bit(otype, pe_order_implies_then_on_node);
                set_bit(otype, pe_order_implies_then);
                node = first->node;
            }
            clear_bit(first_flags, pe_action_pseudo);
            changed |= graph_update_action(first, then, node, first_flags, otype);

            /* 'first' was for a complex resource (clone, group, etc),
             * create a new dependancy if necessary
             */
        } else if (order_actions(first, then, other->type)) {
            /* This was the first time 'first' and 'then' were associated,
             * start again to get the new actions_before list
             */
            changed |= (pe_graph_updated_then | pe_graph_disable);
        }

        if (changed & pe_graph_disable) {
            crm_trace("Disabled constraint %s -> %s", other->action->uuid, then->uuid);
            clear_bit(changed, pe_graph_disable);
            other->type = pe_order_none;
        }

        if (changed & pe_graph_updated_first) {
            GListPtr lpc2 = NULL;

            crm_trace("Updated %s (first %s %s %s), processing dependants ",
                      first->uuid,
                      is_set(first->flags, pe_action_optional) ? "optional" : "required",
                      is_set(first->flags, pe_action_runnable) ? "runnable" : "unrunnable",
                      is_set(first->flags,
                             pe_action_pseudo) ? "pseudo" : first->node ? first->node->details->
                      uname : "");
            for (lpc2 = first->actions_after; lpc2 != NULL; lpc2 = lpc2->next) {
                action_wrapper_t *other = (action_wrapper_t *) lpc2->data;

                update_action(other->action);
            }
            update_action(first);
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
        crm_trace("Updated %s (then %s %s %s), processing dependants ",
                  then->uuid,
                  is_set(then->flags, pe_action_optional) ? "optional" : "required",
                  is_set(then->flags, pe_action_runnable) ? "runnable" : "unrunnable",
                  is_set(then->flags,
                         pe_action_pseudo) ? "pseudo" : then->node ? then->node->details->
                  uname : "");

        if (is_set(last_flags, pe_action_runnable) && is_not_set(then->flags, pe_action_runnable)) {
            update_colo_start_chain(then);
        }
        update_action(then);
        for (lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
            action_wrapper_t *other = (action_wrapper_t *) lpc->data;

            update_action(other->action);
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
            pe_rsc_trace(action->rsc, "Skipping %s: maintainence mode", action->uuid);
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

gboolean
stonith_constraints(node_t * node, action_t * stonith_op, pe_working_set_t * data_set)
{
    CRM_CHECK(stonith_op != NULL, return FALSE);

    /*
     * Make sure the stonith OP occurs before we start any shared resources
     */
    if (stonith_op != NULL) {
        GListPtr lpc = NULL;

        for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
            resource_t *rsc = (resource_t *) lpc->data;

            rsc_stonith_ordering(rsc, stonith_op, data_set);
        }
    }

    /* add the stonith OP as a stop pre-req and the mark the stop
     * as a pseudo op - since its now redundant
     */

    return TRUE;
}

static node_t *
get_router_node(action_t *action)
{
    node_t *began_on = NULL;
    node_t *ended_on = NULL;
    node_t *router_node = NULL;

    if (is_remote_node(action->node) == FALSE) {
        return NULL;
    }

    CRM_ASSERT(action->node->details->remote_rsc != NULL);

    if (action->node->details->remote_rsc->running_on) {
        began_on = action->node->details->remote_rsc->running_on->data;
    }
    ended_on = action->node->details->remote_rsc->allocated_to;

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
     *
     * 2. Everything else (start, promote, monitor, probe, refresh, clear failcount
     *    delete ....) must occur after the resource starts on the node it is
     *    moving to.
     */

    /* 1. before connection rsc moves. */
    if (safe_str_eq(action->task, "stop") ||
        safe_str_eq(action->task, "demote") ||
        safe_str_eq(action->task, "migrate_from") ||
        safe_str_eq(action->task, "migrate_to")) {

        router_node = began_on;

    /* 2. after connection rsc moves. */
    } else {
        router_node = ended_on;
    }
    return router_node;
}

static xmlNode *
action2xml(action_t * action, gboolean as_input, pe_working_set_t *data_set)
{
    gboolean needs_node_info = TRUE;
    xmlNode *action_xml = NULL;
    xmlNode *args_xml = NULL;
    char *action_id_s = NULL;

    if (action == NULL) {
        return NULL;
    }

    if (safe_str_eq(action->task, CRM_OP_FENCE)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);
/* 		needs_node_info = FALSE; */

    } else if (safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (safe_str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (safe_str_eq(action->task, CRM_OP_LRM_REFRESH)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

/* 	} else if(safe_str_eq(action->task, RSC_PROBED)) { */
/* 		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT); */

    } else if (is_set(action->flags, pe_action_pseudo)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_PSEUDO_EVENT);
        needs_node_info = FALSE;

    } else {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
    }

    action_id_s = crm_itoa(action->id);
    crm_xml_add(action_xml, XML_ATTR_ID, action_id_s);
    free(action_id_s);

    crm_xml_add(action_xml, XML_LRM_ATTR_TASK, action->task);
    if (action->rsc != NULL && action->rsc->clone_name != NULL) {
        char *clone_key = NULL;
        const char *interval_s = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL);
        int interval = crm_parse_int(interval_s, "0");

        if (safe_str_eq(action->task, RSC_NOTIFY)) {
            const char *n_type = g_hash_table_lookup(action->meta, "notify_type");
            const char *n_task = g_hash_table_lookup(action->meta, "notify_operation");

            CRM_CHECK(n_type != NULL, crm_err("No notify type value found for %s", action->uuid));
            CRM_CHECK(n_task != NULL,
                      crm_err("No notify operation value found for %s", action->uuid));
            clone_key = generate_notify_key(action->rsc->clone_name, n_type, n_task);

        } else if(action->cancel_task) {
            clone_key = generate_op_key(action->rsc->clone_name, action->cancel_task, interval);
        } else {
            clone_key = generate_op_key(action->rsc->clone_name, action->task, interval);
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
    }

    if (is_set(action->flags, pe_action_failure_is_fatal) == FALSE) {
        add_hash_param(action->meta, XML_ATTR_TE_ALLOWFAIL, XML_BOOLEAN_TRUE);
    }

    if (as_input) {
        return action_xml;
    }

    if (action->rsc) {
        if (is_set(action->flags, pe_action_pseudo) == FALSE) {
            int lpc = 0;

            xmlNode *rsc_xml = create_xml_node(action_xml, crm_element_name(action->rsc->xml));

            const char *attr_list[] = {
                XML_AGENT_ATTR_CLASS,
                XML_AGENT_ATTR_PROVIDER,
                XML_ATTR_TYPE
            };

            if (is_set(action->rsc->flags, pe_rsc_orphan) && action->rsc->clone_name) {
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
                 * and fall into the claus above instead
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
    }

    args_xml = create_xml_node(NULL, XML_TAG_ATTRS);
    crm_xml_add(args_xml, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    g_hash_table_foreach(action->extra, hash2field, args_xml);
    if (action->rsc != NULL && action->node) {
        GHashTable *p = g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

        get_rsc_attributes(p, action->rsc, action->node, data_set);
        g_hash_table_foreach(p, hash2smartfield, args_xml);

        g_hash_table_destroy(p);
    } else if(action->rsc) {
        g_hash_table_foreach(action->rsc->parameters, hash2smartfield, args_xml);
    }

    g_hash_table_foreach(action->meta, hash2metafield, args_xml);
    if (action->rsc != NULL) {
        resource_t *parent = action->rsc;

        while (parent != NULL) {
            parent->cmds->append_meta(parent, args_xml);
            parent = parent->parent;
        }

    } else if (safe_str_eq(action->task, CRM_OP_FENCE) && action->node) {
        g_hash_table_foreach(action->node->details->attrs, hash2metafield, args_xml);
    }

    sorted_xml(args_xml, action_xml, FALSE);
    crm_log_xml_trace(action_xml, "dumped action");
    free_xml(args_xml);

    return action_xml;
}

static gboolean
should_dump_action(action_t * action)
{
    CRM_CHECK(action != NULL, return FALSE);

    if (is_set(action->flags, pe_action_dumped)) {
        crm_trace("action %d (%s) was already dumped", action->id, action->uuid);
        return FALSE;

    } else if (is_set(action->flags, pe_action_pseudo) && safe_str_eq(action->task, CRM_OP_PROBED)) {
        GListPtr lpc = NULL;

        /* This is a horrible but convenient hack
         *
         * It mimimizes the number of actions with unsatisfied inputs
         * (ie. not included in the graph)
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
            action_wrapper_t *wrapper = (action_wrapper_t *) lpc->data;

            if (is_not_set(wrapper->action->flags, pe_action_runnable)) {
                /* Only interested in runnable operations */
            } else if (safe_str_neq(wrapper->action->task, RSC_START)) {
                /* Only interested in start operations */
            } else if (is_set(wrapper->action->flags, pe_action_dumped)) {
                crm_trace("action %d (%s) dependancy of %s",
                          action->id, action->uuid, wrapper->action->uuid);
                return TRUE;

            } else if (should_dump_action(wrapper->action)) {
                crm_trace("action %d (%s) dependancy of %s",
                          action->id, action->uuid, wrapper->action->uuid);
                return TRUE;
            }
        }
    }

    if (is_set(action->flags, pe_action_runnable) == FALSE) {
        crm_trace("action %d (%s) was not runnable", action->id, action->uuid);
        return FALSE;

    } else if (is_set(action->flags, pe_action_optional)
               && is_set(action->flags, pe_action_print_always) == FALSE) {
        crm_trace("action %d (%s) was optional", action->id, action->uuid);
        return FALSE;

    } else if (action->rsc != NULL && is_not_set(action->rsc->flags, pe_rsc_managed)) {
        const char *interval = NULL;

        interval = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL);

        /* make sure probes and recurring monitors go through */
        if (safe_str_neq(action->task, RSC_STATUS) && interval == NULL) {
            crm_trace("action %d (%s) was for an unmanaged resource (%s)",
                      action->id, action->uuid, action->rsc->id);
            return FALSE;
        }
    }

    if (is_set(action->flags, pe_action_pseudo)
        || safe_str_eq(action->task, CRM_OP_FENCE)
        || safe_str_eq(action->task, CRM_OP_SHUTDOWN)) {
        /* skip the next checks */
        return TRUE;
    }

    if (action->node == NULL) {
        pe_err("action %d (%s) was not allocated", action->id, action->uuid);
        log_action(LOG_DEBUG, "Unallocated action", action, FALSE);
        return FALSE;

    } else if (action->node->details->online == FALSE) {
        pe_err("action %d was (%s) scheduled for offline node", action->id, action->uuid);
        log_action(LOG_DEBUG, "Action for offline node", action, FALSE);
        return FALSE;
#if 0
        /* but this would also affect resources that can be safely
         *  migrated before a fencing op
         */
    } else if (action->node->details->unclean == FALSE) {
        pe_err("action %d was (%s) scheduled for unclean node", action->id, action->uuid);
        log_action(LOG_DEBUG, "Action for unclean node", action, FALSE);
        return FALSE;
#endif
    }
    return TRUE;
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

static gboolean
should_dump_input(int last_action, action_t * action, action_wrapper_t * wrapper)
{
    int type = wrapper->type;

    type &= ~pe_order_implies_first_printed;
    type &= ~pe_order_implies_then_printed;
    type &= ~pe_order_optional;

    if (wrapper->action->node
        && action->rsc && action->rsc->fillers
        && is_not_set(type, pe_order_preserve)
        && wrapper->action->node->details->remote_rsc
        && uber_parent(action->rsc) != uber_parent(wrapper->action->rsc)
        ) {
        /* This prevents user-defined ordering constraints between
         * resources in remote nodes and the resources that
         * define/represent a remote node.
         *
         * There is no known valid reason to allow this sort of thing
         * but if one arises, we'd need to change the
         * action->rsc->fillers clause to be more specific, possibly
         * to check that it contained wrapper->action->rsc
         */
        crm_warn("Invalid ordering constraint between %s and %s",
                 wrapper->action->rsc->id, action->rsc->id);
        wrapper->type = pe_order_none;
        return FALSE;
    }

    wrapper->state = pe_link_not_dumped;
    if (last_action == wrapper->action->id) {
        crm_trace("Input (%d) %s duplicated for %s",
                  wrapper->action->id, wrapper->action->uuid, action->uuid);
        wrapper->state = pe_link_dup;
        return FALSE;

    } else if (wrapper->type == pe_order_none) {
        crm_trace("Input (%d) %s suppressed for %s",
                  wrapper->action->id, wrapper->action->uuid, action->uuid);
        return FALSE;

    } else if (is_set(wrapper->action->flags, pe_action_runnable) == FALSE
               && type == pe_order_none && safe_str_neq(wrapper->action->uuid, CRM_OP_PROBED)) {
        crm_trace("Input (%d) %s optional (ordering) for %s",
                  wrapper->action->id, wrapper->action->uuid, action->uuid);
        return FALSE;

    } else if (is_set(action->flags, pe_action_pseudo)
               && (wrapper->type & pe_order_stonith_stop)) {
        crm_trace("Input (%d) %s suppressed for %s",
                  wrapper->action->id, wrapper->action->uuid, action->uuid);
        return FALSE;

    } else if ((wrapper->type & pe_order_implies_first_migratable) && (is_set(wrapper->action->flags, pe_action_runnable) == FALSE)) {
        return FALSE;

    } else if ((wrapper->type & pe_order_apply_first_non_migratable)
                && (is_set(wrapper->action->flags, pe_action_migrate_runnable))) {
        return FALSE;

    } else if ((wrapper->type == pe_order_optional)
               && strstr(wrapper->action->uuid, "_stop_0")
               && is_set(wrapper->action->flags, pe_action_migrate_runnable)) {

        /* for optional only ordering, ordering is not preserved for
         * a stop action that is actually involved with a migration. */
        return FALSE;
    } else if (wrapper->type == pe_order_load) {
        crm_trace("check load filter %s.%s -> %s.%s",
                  wrapper->action->uuid,
                  wrapper->action->node ? wrapper->action->node->details->uname : "", action->uuid,
                  action->node ? action->node->details->uname : "");

        if (action->rsc && safe_str_eq(action->task, RSC_MIGRATE)) {
            /* Remove the orders like the following if not needed or introducing transition loop:
             *     "load_stopped_node2" -> "rscA_migrate_to node1"
             * which were created also from: pengine/native.c: MigrateRsc()
             *     order_actions(other, then, other_w->type);
             */

            /* For migrate_to ops, we care about where it has been
             * allocated to, not where the action will be executed
             */
            if (wrapper->action->node == NULL || action->rsc->allocated_to == NULL
                || wrapper->action->node->details != action->rsc->allocated_to->details) {
                /* Check if the actions are for the same node, ignore otherwise */
                crm_trace("load filter - migrate");
                wrapper->type = pe_order_none;
                return FALSE;

            } else {
                GListPtr lpc = NULL;

                for (lpc = wrapper->action->actions_before; lpc != NULL; lpc = lpc->next) {
                    action_wrapper_t *wrapper_before = (action_wrapper_t *) lpc->data;

                    /* If there's any order like:
                     * "rscB_stop node2"-> "load_stopped_node2" -> "rscA_migrate_to node1"
                     * rscA is being migrated from node1 to node2,
                     * while rscB is being migrated from node2 to node1.
                     * There will be potential transition loop.
                     * Break the order "load_stopped_node2" -> "rscA_migrate_to node1".
                     */

                    if (wrapper_before->type != pe_order_load
                        || is_set(wrapper_before->action->flags, pe_action_optional)
                        || is_not_set(wrapper_before->action->flags, pe_action_migrate_runnable)
                        || wrapper_before->action->node == NULL
                        || wrapper->action->node == NULL
                        || wrapper_before->action->node->details != wrapper->action->node->details) {
                        continue;
                    }

                    if (wrapper_before->action->rsc
                        && wrapper_before->action->rsc->allocated_to
                        && action->node
                        && wrapper_before->action->rsc->allocated_to->details == action->node->details) {

                        crm_trace("load filter - migrate loop");
                        wrapper->type = pe_order_none;
                        return FALSE;
                    }
                }
            }

        } else if (wrapper->action->node == NULL || action->node == NULL
                   || wrapper->action->node->details != action->node->details) {
            /* Check if the actions are for the same node, ignore otherwise */
            crm_trace("load filter - node");
            wrapper->type = pe_order_none;
            return FALSE;

        } else if (is_set(wrapper->action->flags, pe_action_optional)) {
            /* Check if the pre-req is optional, ignore if so */
            crm_trace("load filter - optional");
            wrapper->type = pe_order_none;
            return FALSE;
        }

    } else if (wrapper->type == pe_order_anti_colocation) {
        crm_trace("check anti-colocation filter %s.%s -> %s.%s",
                  wrapper->action->uuid,
                  wrapper->action->node ? wrapper->action->node->details->uname : "",
                  action->uuid,
                  action->node ? action->node->details->uname : "");

        if (wrapper->action->node && action->node
            && wrapper->action->node->details != action->node->details) {
            /* Check if the actions are for the same node, ignore otherwise */
            crm_trace("anti-colocation filter - node");
            wrapper->type = pe_order_none;
            return FALSE;

        } else if (is_set(wrapper->action->flags, pe_action_optional)) {
            /* Check if the pre-req is optional, ignore if so */
            crm_trace("anti-colocation filter - optional");
            wrapper->type = pe_order_none;
            return FALSE;
        }

    } else if (wrapper->action->rsc
               && wrapper->action->rsc != action->rsc
               && is_set(wrapper->action->rsc->flags, pe_rsc_failed)
               && is_not_set(wrapper->action->rsc->flags, pe_rsc_managed)
               && strstr(wrapper->action->uuid, "_stop_0")
               && action->rsc && action->rsc->variant >= pe_clone) {
        crm_warn("Ignoring requirement that %s complete before %s:"
                 " unmanaged failed resources cannot prevent clone shutdown",
                 wrapper->action->uuid, action->uuid);
        return FALSE;

    } else if (is_set(wrapper->action->flags, pe_action_dumped)
               || should_dump_action(wrapper->action)) {
        crm_trace("Input (%d) %s should be dumped for %s", wrapper->action->id,
                  wrapper->action->uuid, action->uuid);
        goto dump;

#if 0
    } else if (is_set(wrapper->action->flags, pe_action_runnable)
               && is_set(wrapper->action->flags, pe_action_pseudo)
               && wrapper->action->rsc->variant != pe_native) {
        crm_crit("Input (%d) %s should be dumped for %s",
                 wrapper->action->id, wrapper->action->uuid, action->uuid);
        goto dump;
#endif
    } else if (is_set(wrapper->action->flags, pe_action_optional) == TRUE
               && is_set(wrapper->action->flags, pe_action_print_always) == FALSE) {
        crm_trace("Input (%d) %s optional for %s", wrapper->action->id,
                  wrapper->action->uuid, action->uuid);
        crm_trace("Input (%d) %s n=%p p=%d r=%d o=%d a=%d f=0x%.6x",
                  wrapper->action->id, wrapper->action->uuid, wrapper->action->node,
                  is_set(wrapper->action->flags, pe_action_pseudo),
                  is_set(wrapper->action->flags, pe_action_runnable),
                  is_set(wrapper->action->flags, pe_action_optional),
                  is_set(wrapper->action->flags, pe_action_print_always), wrapper->type);
        return FALSE;

    }

  dump:
    crm_trace("Input (%d) %s n=%p p=%d r=%d o=%d a=%d f=0x%.6x dumped for %s",
              wrapper->action->id,
              wrapper->action->uuid,
              wrapper->action->node,
              is_set(wrapper->action->flags, pe_action_pseudo),
              is_set(wrapper->action->flags, pe_action_runnable),
              is_set(wrapper->action->flags, pe_action_optional),
              is_set(wrapper->action->flags, pe_action_print_always), wrapper->type, action->uuid);
    return TRUE;
}

void
graph_element_from_action(action_t * action, pe_working_set_t * data_set)
{
    GListPtr lpc = NULL;
    int last_action = -1;
    int synapse_priority = 0;
    xmlNode *syn = NULL;
    xmlNode *set = NULL;
    xmlNode *in = NULL;
    xmlNode *input = NULL;
    xmlNode *xml_action = NULL;

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

    action->actions_before = g_list_sort(action->actions_before, sort_action_id);

    for (lpc = action->actions_before; lpc != NULL; lpc = lpc->next) {
        action_wrapper_t *wrapper = (action_wrapper_t *) lpc->data;

        if (should_dump_input(last_action, action, wrapper) == FALSE) {
            continue;
        }

        wrapper->state = pe_link_dumped;
        CRM_CHECK(last_action < wrapper->action->id,;
            );
        last_action = wrapper->action->id;
        input = create_xml_node(in, "trigger");

        xml_action = action2xml(wrapper->action, TRUE, data_set);
        add_node_nocopy(input, crm_element_name(xml_action), xml_action);
    }
}
