/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Check whether a probe should be ordered before another action
 *
 * \param[in] probe  Probe action to check
 * \param[in] then   Other action to check
 *
 * \return true if \p probe should be ordered before \p then, otherwise false
 */
static bool
probe_needed_before_action(pe_action_t *probe, pe_action_t *then)
{
    // Probes on a node are performed after unfencing it, not before
    if (pcmk__str_eq(then->task, CRM_OP_FENCE, pcmk__str_casei)
         && (probe->node != NULL) && (then->node != NULL)
         && (probe->node->details == then->node->details)) {
        const char *op = g_hash_table_lookup(then->meta, "stonith_action");

        if (pcmk__str_eq(op, "on", pcmk__str_casei)) {
            return false;
        }
    }

    // Probes should be done on a node before shutting it down
    if (pcmk__str_eq(then->task, CRM_OP_SHUTDOWN, pcmk__str_none)
        && (probe->node != NULL) && (then->node != NULL)
        && (probe->node->details != then->node->details)) {
        return false;
    }

    // Otherwise probes should always be done before any other action
    return true;
}

/*!
 * \internal
 * \brief Add implicit "probe then X" orderings for "stop then X" orderings
 *
 * If the state of a resource is not known yet, a probe will be scheduled,
 * expecting a "not running" result. If the probe fails, a stop will not be
 * scheduled until the next transition. Thus, if there are ordering constraints
 * like "stop this resource then do something else that's not for the same
 * resource", add implicit "probe this resource then do something" equivalents
 * so the relation is upheld until we know whether a stop is needed.
 *
 * \param[in] data_set  Cluster working set
 */
static void
add_probe_orderings_for_stops(pe_working_set_t *data_set)
{
    for (GList *iter = data_set->ordering_constraints; iter != NULL;
         iter = iter->next) {

        pe__ordering_t *order = iter->data;
        enum pe_ordering order_type = pe_order_optional;
        GList *probes = NULL;
        GList *then_actions = NULL;

        // Skip disabled orderings
        if (order->type == pe_order_none) {
            continue;
        }

        // Skip non-resource orderings, and orderings for the same resource
        if ((order->lh_rsc == NULL) || (order->lh_rsc == order->rh_rsc)) {
            continue;
        }

        // Skip invalid orderings (shouldn't be possible)
        if (((order->lh_action == NULL) && (order->lh_action_task == NULL)) ||
            ((order->rh_action == NULL) && (order->rh_action_task == NULL))) {
            continue;
        }

        // Skip orderings for first actions other than stop
        if ((order->lh_action != NULL)
            && !pcmk__str_eq(order->lh_action->task, RSC_STOP, pcmk__str_none)) {
            continue;
        } else if ((order->lh_action == NULL)
                   && !pcmk__ends_with(order->lh_action_task, "_" RSC_STOP "_0")) {
            continue;
        }

        /* Do not imply a probe ordering for a resource inside of a stopping
         * container. Otherwise, it might introduce a transition loop, since a
         * probe could be scheduled after the container starts again.
         */
        if ((order->rh_rsc != NULL)
            && (order->lh_rsc->container == order->rh_rsc)) {

            if ((order->rh_action != NULL)
                && pcmk__str_eq(order->rh_action->task, RSC_STOP,
                                pcmk__str_none)) {
                continue;
            } else if ((order->rh_action == NULL)
                       && pcmk__ends_with(order->rh_action_task,
                                          "_" RSC_STOP "_0")) {
                continue;
            }
        }

        // Preserve certain order options for future filtering
        if (pcmk_is_set(order->type, pe_order_apply_first_non_migratable)) {
            pe__set_order_flags(order_type,
                                pe_order_apply_first_non_migratable);
        }
        if (pcmk_is_set(order->type, pe_order_same_node)) {
            pe__set_order_flags(order_type, pe_order_same_node);
        }

        // Preserve certain order types for future filtering
        if ((order->type == pe_order_anti_colocation)
            || (order->type == pe_order_load)) {
            order_type = order->type;
        }

        // List all scheduled probes for the first resource
        probes = pe__resource_actions(order->lh_rsc, NULL, RSC_STATUS, FALSE);
        if (probes == NULL) { // There aren't any
            continue;
        }

        // List all relevant "then" actions
        if (order->rh_action != NULL) {
            then_actions = g_list_prepend(NULL, order->rh_action);

        } else if (order->rh_rsc != NULL) {
            then_actions = find_actions(order->rh_rsc->actions,
                                        order->rh_action_task, NULL);
            if (then_actions == NULL) { // There aren't any
                g_list_free(probes);
                continue;
            }
        }

        crm_trace("Implying 'probe then' orderings for '%s then %s' "
                  "(id=%d, type=%.6x)",
                  order->lh_action? order->lh_action->uuid : order->lh_action_task,
                  order->rh_action? order->rh_action->uuid : order->rh_action_task,
                  order->id, order->type);

        for (GList *probe_iter = probes; probe_iter != NULL;
             probe_iter = probe_iter->next) {

            pe_action_t *probe = (pe_action_t *) probe_iter->data;

            for (GList *then_iter = then_actions; then_iter != NULL;
                 then_iter = then_iter->next) {

                pe_action_t *then = (pe_action_t *) then_iter->data;

                if (probe_needed_before_action(probe, then)) {
                    order_actions(probe, then, order_type);
                }
            }
        }

        g_list_free(then_actions);
        g_list_free(probes);
    }
}

static void
order_first_probe_then_restart_repromote(pe_action_t * probe,
                                         pe_action_t * after,
                                         pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    bool interleave = FALSE;
    pe_resource_t *compatible_rsc = NULL;

    if (probe == NULL
        || probe->rsc == NULL
        || probe->rsc->variant != pe_native) {
        return;
    }

    if (after == NULL
        // Avoid running into any possible loop
        || pcmk_is_set(after->flags, pe_action_tracking)) {
        return;
    }

    if (!pcmk__str_eq(probe->task, RSC_STATUS, pcmk__str_casei)) {
        return;
    }

    pe__set_action_flags(after, pe_action_tracking);

    crm_trace("Processing based on %s %s -> %s %s",
              probe->uuid,
              probe->node ? probe->node->details->uname: "",
              after->uuid,
              after->node ? after->node->details->uname : "");

    if (after->rsc
        /* Better not build a dependency directly with a clone/group.
         * We are going to proceed through the ordering chain and build
         * dependencies with its children.
         */
        && after->rsc->variant == pe_native
        && probe->rsc != after->rsc) {

            GList *then_actions = NULL;
            enum pe_ordering probe_order_type = pe_order_optional;

            if (pcmk__str_eq(after->task, RSC_START, pcmk__str_casei)) {
                then_actions = pe__resource_actions(after->rsc, NULL, RSC_STOP, FALSE);

            } else if (pcmk__str_eq(after->task, RSC_PROMOTE, pcmk__str_casei)) {
                then_actions = pe__resource_actions(after->rsc, NULL, RSC_DEMOTE, FALSE);
            }

            for (gIter = then_actions; gIter != NULL; gIter = gIter->next) {
                pe_action_t *then = (pe_action_t *) gIter->data;

                // Skip any pseudo action which for example is implied by fencing
                if (pcmk_is_set(then->flags, pe_action_pseudo)) {
                    continue;
                }

                order_actions(probe, then, probe_order_type);
            }
            g_list_free(then_actions);
    }

    if (after->rsc
        && after->rsc->variant > pe_group) {
        const char *interleave_s = g_hash_table_lookup(after->rsc->meta,
                                                       XML_RSC_ATTR_INTERLEAVE);

        interleave = crm_is_true(interleave_s);

        if (interleave) {
            /* For an interleaved clone, we should build a dependency only
             * with the relevant clone child.
             */
            compatible_rsc = find_compatible_child(probe->rsc,
                                                   after->rsc,
                                                   RSC_ROLE_UNKNOWN,
                                                   FALSE, data_set);
        }
    }

    for (gIter = after->actions_after; gIter != NULL; gIter = gIter->next) {
        pe_action_wrapper_t *after_wrapper = (pe_action_wrapper_t *) gIter->data;
        /* pe_order_implies_then is the reason why a required A.start
         * implies/enforces B.start to be required too, which is the cause of
         * B.restart/re-promote.
         *
         * Not sure about pe_order_implies_then_on_node though. It's now only
         * used for unfencing case, which tends to introduce transition
         * loops...
         */

        if (!pcmk_is_set(after_wrapper->type, pe_order_implies_then)) {
            /* The order type between a group/clone and its child such as
             * B.start-> B_child.start is:
             * pe_order_implies_first_printed | pe_order_runnable_left
             *
             * Proceed through the ordering chain and build dependencies with
             * its children.
             */
            if (after->rsc == NULL
                || after->rsc->variant < pe_group
                || probe->rsc->parent == after->rsc
                || after_wrapper->action->rsc == NULL
                || after_wrapper->action->rsc->variant > pe_group
                || after->rsc != after_wrapper->action->rsc->parent) {
                continue;
            }

            /* Proceed to the children of a group or a non-interleaved clone.
             * For an interleaved clone, proceed only to the relevant child.
             */
            if (after->rsc->variant > pe_group
                && interleave == TRUE
                && (compatible_rsc == NULL
                    || compatible_rsc != after_wrapper->action->rsc)) {
                continue;
            }
        }

        crm_trace("Proceeding through %s %s -> %s %s (type=%#.6x)",
                  after->uuid,
                  after->node ? after->node->details->uname: "",
                  after_wrapper->action->uuid,
                  after_wrapper->action->node ? after_wrapper->action->node->details->uname : "",
                  after_wrapper->type);

        order_first_probe_then_restart_repromote(probe, after_wrapper->action, data_set);
    }
}

static void clear_actions_tracking_flag(pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (pcmk_is_set(action->flags, pe_action_tracking)) {
            pe__clear_action_flags(action, pe_action_tracking);
        }
    }
}

static void
order_first_rsc_probes(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    GList *probes = NULL;

    g_list_foreach(rsc->children, (GFunc) order_first_rsc_probes, data_set);

    if (rsc->variant != pe_native) {
        return;
    }

    probes = pe__resource_actions(rsc, NULL, RSC_STATUS, FALSE);

    for (gIter = probes; gIter != NULL; gIter= gIter->next) {
        pe_action_t *probe = (pe_action_t *) gIter->data;
        GList *aIter = NULL;

        for (aIter = probe->actions_after; aIter != NULL; aIter = aIter->next) {
            pe_action_wrapper_t *after_wrapper = (pe_action_wrapper_t *) aIter->data;

            order_first_probe_then_restart_repromote(probe, after_wrapper->action, data_set);
            clear_actions_tracking_flag(data_set);
        }
    }

    g_list_free(probes);
}

static void
order_first_probes(pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        order_first_rsc_probes(rsc, data_set);
    }

    add_probe_orderings_for_stops(data_set);
}

static void
order_then_probes(pe_working_set_t * data_set)
{
#if 0
    GList *gIter = NULL;

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        /* Given "A then B", we would prefer to wait for A to be
         * started before probing B.
         *
         * If A was a filesystem on which the binaries and data for B
         * lived, it would have been useful if the author of B's agent
         * could assume that A is running before B.monitor will be
         * called.
         *
         * However we can't _only_ probe once A is running, otherwise
         * we'd not detect the state of B if A could not be started
         * for some reason.
         *
         * In practice however, we cannot even do an opportunistic
         * version of this because B may be moving:
         *
         *   B.probe -> B.start
         *   B.probe -> B.stop
         *   B.stop -> B.start
         *   A.stop -> A.start
         *   A.start -> B.probe
         *
         * So far so good, but if we add the result of this code:
         *
         *   B.stop -> A.stop
         *
         * Then we get a loop:
         *
         *   B.probe -> B.stop -> A.stop -> A.start -> B.probe
         *
         * We could kill the 'B.probe -> B.stop' dependency, but that
         * could mean stopping B "too" soon, because B.start must wait
         * for the probes to complete.
         *
         * Another option is to allow it only if A is a non-unique
         * clone with clone-max == node-max (since we'll never be
         * moving it).  However, we could still be stopping one
         * instance at the same time as starting another.

         * The complexity of checking for allowed conditions combined
         * with the ever narrowing usecase suggests that this code
         * should remain disabled until someone gets smarter.
         */
        pe_action_t *start = NULL;
        GList *actions = NULL;
        GList *probes = NULL;

        actions = pe__resource_actions(rsc, NULL, RSC_START, FALSE);

        if (actions) {
            start = actions->data;
            g_list_free(actions);
        }

        if(start == NULL) {
            crm_err("No start action for %s", rsc->id);
            continue;
        }

        probes = pe__resource_actions(rsc, NULL, RSC_STATUS, FALSE);

        for (actions = start->actions_before; actions != NULL; actions = actions->next) {
            pe_action_wrapper_t *before = (pe_action_wrapper_t *) actions->data;

            GList *pIter = NULL;
            pe_action_t *first = before->action;
            pe_resource_t *first_rsc = first->rsc;

            if(first->required_runnable_before) {
                GList *clone_actions = NULL;
                for (clone_actions = first->actions_before; clone_actions != NULL; clone_actions = clone_actions->next) {
                    before = (pe_action_wrapper_t *) clone_actions->data;

                    crm_trace("Testing %s -> %s (%p) for %s", first->uuid, before->action->uuid, before->action->rsc, start->uuid);

                    CRM_ASSERT(before->action->rsc);
                    first_rsc = before->action->rsc;
                    break;
                }

            } else if(!pcmk__str_eq(first->task, RSC_START, pcmk__str_casei)) {
                crm_trace("Not a start op %s for %s", first->uuid, start->uuid);
            }

            if(first_rsc == NULL) {
                continue;

            } else if(uber_parent(first_rsc) == uber_parent(start->rsc)) {
                crm_trace("Same parent %s for %s", first_rsc->id, start->uuid);
                continue;

            } else if(FALSE && pe_rsc_is_clone(uber_parent(first_rsc)) == FALSE) {
                crm_trace("Not a clone %s for %s", first_rsc->id, start->uuid);
                continue;
            }

            crm_err("Applying %s before %s %d", first->uuid, start->uuid, uber_parent(first_rsc)->variant);

            for (pIter = probes; pIter != NULL; pIter = pIter->next) {
                pe_action_t *probe = (pe_action_t *) pIter->data;

                crm_err("Ordering %s before %s", first->uuid, probe->uuid);
                order_actions(first, probe, pe_order_optional);
            }
        }
    }
#endif
}

void
pcmk__order_probes(pe_working_set_t *data_set)
{
    order_first_probes(data_set);
    order_then_probes(data_set);
}
