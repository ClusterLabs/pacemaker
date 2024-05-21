/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
 * \brief Add the expected result to a newly created probe
 *
 * \param[in,out] probe  Probe action to add expected result to
 * \param[in]     rsc    Resource that probe is for
 * \param[in]     node   Node that probe will run on
 */
static void
add_expected_result(pcmk_action_t *probe, const pcmk_resource_t *rsc,
                    const pcmk_node_t *node)
{
    // Check whether resource is currently active on node
    pcmk_node_t *running = pe_find_node_id(rsc->private->active_nodes,
                                           node->details->id);

    // The expected result is what we think the resource's current state is
    if (running == NULL) {
        pe__add_action_expected_result(probe, CRM_EX_NOT_RUNNING);

    } else if (rsc->private->orig_role == pcmk_role_promoted) {
        pe__add_action_expected_result(probe, CRM_EX_PROMOTED);
    }
}

/*!
 * \internal
 * \brief Create any needed robes on a node for a list of resources
 *
 * \param[in,out] rscs  List of resources to create probes for
 * \param[in,out] node  Node to create probes on
 *
 * \return true if any probe was created, otherwise false
 */
bool
pcmk__probe_resource_list(GList *rscs, pcmk_node_t *node)
{
    bool any_created = false;

    for (GList *iter = rscs; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (rsc->private->cmds->create_probe(rsc, node)) {
            any_created = true;
        }
    }
    return any_created;
}

/*!
 * \internal
 * \brief Order one resource's start after another's start-up probe
 *
 * \param[in,out] rsc1  Resource that might get start-up probe
 * \param[in]     rsc2  Resource that might be started
 */
static void
probe_then_start(pcmk_resource_t *rsc1, pcmk_resource_t *rsc2)
{
    const pcmk_node_t *rsc1_node = rsc1->private->assigned_node;

    if ((rsc1_node != NULL)
        && (g_hash_table_lookup(rsc1->private->probed_nodes,
                                rsc1_node->details->id) == NULL)) {

        pcmk__new_ordering(rsc1,
                           pcmk__op_key(rsc1->id, PCMK_ACTION_MONITOR, 0),
                           NULL,
                           rsc2, pcmk__op_key(rsc2->id, PCMK_ACTION_START, 0),
                           NULL,
                           pcmk__ar_ordered, rsc1->private->scheduler);
    }
}

/*!
 * \internal
 * \brief Check whether a guest resource will stop
 *
 * \param[in] node  Guest node to check
 *
 * \return true if guest resource will likely stop, otherwise false
 */
static bool
guest_resource_will_stop(const pcmk_node_t *node)
{
    const pcmk_resource_t *guest_rsc = node->details->remote_rsc->container;
    const pcmk_node_t *guest_node = guest_rsc->private->assigned_node;

    /* Ideally, we'd check whether the guest has a required stop, but that
     * information doesn't exist yet, so approximate it ...
     */
    return node->details->remote_requires_reset
           || node->details->unclean
           || pcmk_is_set(guest_rsc->flags, pcmk__rsc_failed)
           || (guest_rsc->private->next_role == pcmk_role_stopped)

           // Guest is moving
           || ((guest_rsc->private->orig_role > pcmk_role_stopped)
               && (guest_node != NULL)
               && pcmk__find_node_in_list(guest_rsc->private->active_nodes,
                                          guest_node->details->uname) == NULL);
}

/*!
 * \internal
 * \brief Create a probe action for a resource on a node
 *
 * \param[in,out] rsc   Resource to create probe for
 * \param[in,out] node  Node to create probe on
 *
 * \return Newly created probe action
 */
static pcmk_action_t *
probe_action(pcmk_resource_t *rsc, pcmk_node_t *node)
{
    pcmk_action_t *probe = NULL;
    char *key = pcmk__op_key(rsc->id, PCMK_ACTION_MONITOR, 0);

    crm_debug("Scheduling probe of %s %s on %s",
              pcmk_role_text(rsc->private->orig_role), rsc->id,
              pcmk__node_name(node));

    probe = custom_action(rsc, key, PCMK_ACTION_MONITOR, node, FALSE,
                          rsc->private->scheduler);
    pcmk__clear_action_flags(probe, pcmk_action_optional);

    pcmk__order_vs_unfence(rsc, node, probe, pcmk__ar_ordered);
    add_expected_result(probe, rsc, node);
    return probe;
}

/*!
 * \internal
 * \brief Create probes for a resource on a node, if needed
 *
 * \brief Schedule any probes needed for a resource on a node
 *
 * \param[in,out] rsc   Resource to create probe for
 * \param[in,out] node  Node to create probe on
 *
 * \return true if any probe was created, otherwise false
 */
bool
pcmk__probe_rsc_on_node(pcmk_resource_t *rsc, pcmk_node_t *node)
{
    uint32_t flags = pcmk__ar_ordered;
    pcmk_action_t *probe = NULL;
    pcmk_node_t *allowed = NULL;
    pcmk_resource_t *top = uber_parent(rsc);
    const char *reason = NULL;

    CRM_ASSERT((rsc != NULL) && (node != NULL));

    if (!pcmk_is_set(rsc->private->scheduler->flags,
                     pcmk_sched_probe_resources)) {
        reason = "start-up probes are disabled";
        goto no_probe;
    }

    if (pcmk__is_pacemaker_remote_node(node)) {
        const char *class = crm_element_value(rsc->private->xml, PCMK_XA_CLASS);

        if (pcmk__str_eq(class, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_none)) {
            reason = "Pacemaker Remote nodes cannot run stonith agents";
            goto no_probe;

        } else if (pcmk__is_guest_or_bundle_node(node)
                   && pe__resource_contains_guest_node(rsc->private->scheduler,
                                                       rsc)) {
            reason = "guest nodes cannot run resources containing guest nodes";
            goto no_probe;

        } else if (pcmk_is_set(rsc->flags, pcmk__rsc_is_remote_connection)) {
            reason = "Pacemaker Remote nodes cannot host remote connections";
            goto no_probe;
        }
    }

    // If this is a collective resource, probes are created for its children
    if (rsc->children != NULL) {
        return pcmk__probe_resource_list(rsc->children, node);
    }

    if ((rsc->container != NULL)
        && !pcmk_is_set(rsc->flags, pcmk__rsc_is_remote_connection)) {
        reason = "resource is inside a container";
        goto no_probe;

    } else if (pcmk_is_set(rsc->flags, pcmk__rsc_removed)) {
        reason = "resource is orphaned";
        goto no_probe;

    } else if (g_hash_table_lookup(rsc->private->probed_nodes,
                                   node->details->id) != NULL) {
        reason = "resource state is already known";
        goto no_probe;
    }

    allowed = g_hash_table_lookup(rsc->private->allowed_nodes,
                                  node->details->id);

    if (pcmk_is_set(rsc->flags, pcmk__rsc_exclusive_probes)
        || pcmk_is_set(top->flags, pcmk__rsc_exclusive_probes)) {
        // Exclusive discovery is enabled ...

        if (allowed == NULL) {
            // ... but this node is not allowed to run the resource
            reason = "resource has exclusive discovery but is not allowed "
                     "on node";
            goto no_probe;

        } else if (allowed->rsc_discover_mode != pcmk_probe_exclusive) {
            // ... but no constraint marks this node for discovery of resource
            reason = "resource has exclusive discovery but is not enabled "
                     "on node";
            goto no_probe;
        }
    }

    if (allowed == NULL) {
        allowed = node;
    }
    if (allowed->rsc_discover_mode == pcmk_probe_never) {
        reason = "node has discovery disabled";
        goto no_probe;
    }

    if (pcmk__is_guest_or_bundle_node(node)) {
        pcmk_resource_t *guest = node->details->remote_rsc->container;

        if (guest->private->orig_role == pcmk_role_stopped) {
            // The guest is stopped, so we know no resource is active there
            reason = "node's guest is stopped";
            probe_then_start(guest, top);
            goto no_probe;

        } else if (guest_resource_will_stop(node)) {
            reason = "node's guest will stop";

            // Order resource start after guest stop (in case it's restarting)
            pcmk__new_ordering(guest,
                               pcmk__op_key(guest->id, PCMK_ACTION_STOP, 0),
                               NULL, top,
                               pcmk__op_key(top->id, PCMK_ACTION_START, 0),
                               NULL, pcmk__ar_ordered, rsc->private->scheduler);
            goto no_probe;
        }
    }

    // We've eliminated all cases where a probe is not needed, so now it is
    probe = probe_action(rsc, node);

    /* Below, we will order the probe relative to start or reload. If this is a
     * clone instance, the start or reload is for the entire clone rather than
     * just the instance. Otherwise, the start or reload is for the resource
     * itself.
     */
    if (!pcmk__is_clone(top)) {
        top = rsc;
    }

    /* Prevent a start if the resource can't be probed, but don't cause the
     * resource or entire clone to stop if already active.
     */
    if (!pcmk_is_set(probe->flags, pcmk_action_runnable)
        && (top->private->active_nodes == NULL)) {
        pcmk__set_relation_flags(flags, pcmk__ar_unrunnable_first_blocks);
    }

    // Start or reload after probing the resource
    pcmk__new_ordering(rsc, NULL, probe,
                       top, pcmk__op_key(top->id, PCMK_ACTION_START, 0), NULL,
                       flags, rsc->private->scheduler);
    pcmk__new_ordering(rsc, NULL, probe, top, reload_key(rsc), NULL,
                       pcmk__ar_ordered, rsc->private->scheduler);

    return true;

no_probe:
    pcmk__rsc_trace(rsc,
                    "Skipping probe for %s on %s because %s",
                    rsc->id, node->details->id, reason);
    return false;
}

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
probe_needed_before_action(const pcmk_action_t *probe,
                           const pcmk_action_t *then)
{
    // Probes on a node are performed after unfencing it, not before
    if (pcmk__str_eq(then->task, PCMK_ACTION_STONITH, pcmk__str_none)
        && pcmk__same_node(probe->node, then->node)) {
        const char *op = g_hash_table_lookup(then->meta,
                                             PCMK__META_STONITH_ACTION);

        if (pcmk__str_eq(op, PCMK_ACTION_ON, pcmk__str_casei)) {
            return false;
        }
    }

    // Probes should be done on a node before shutting it down
    if (pcmk__str_eq(then->task, PCMK_ACTION_DO_SHUTDOWN, pcmk__str_none)
        && (probe->node != NULL) && (then->node != NULL)
        && !pcmk__same_node(probe->node, then->node)) {
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
 * \param[in,out] scheduler  Scheduler data
 */
static void
add_probe_orderings_for_stops(pcmk_scheduler_t *scheduler)
{
    for (GList *iter = scheduler->ordering_constraints; iter != NULL;
         iter = iter->next) {

        pcmk__action_relation_t *order = iter->data;
        uint32_t order_flags = pcmk__ar_ordered;
        GList *probes = NULL;
        GList *then_actions = NULL;
        pcmk_action_t *first = NULL;
        pcmk_action_t *then = NULL;

        // Skip disabled orderings
        if (order->flags == pcmk__ar_none) {
            continue;
        }

        // Skip non-resource orderings, and orderings for the same resource
        if ((order->rsc1 == NULL) || (order->rsc1 == order->rsc2)) {
            continue;
        }

        // Skip invalid orderings (shouldn't be possible)
        first = order->action1;
        then = order->action2;
        if (((first == NULL) && (order->task1 == NULL))
            || ((then == NULL) && (order->task2 == NULL))) {
            continue;
        }

        // Skip orderings for first actions other than stop
        if ((first != NULL) && !pcmk__str_eq(first->task, PCMK_ACTION_STOP,
                                             pcmk__str_none)) {
            continue;
        } else if ((first == NULL)
                   && !pcmk__ends_with(order->task1,
                                       "_" PCMK_ACTION_STOP "_0")) {
            continue;
        }

        /* Do not imply a probe ordering for a resource inside of a stopping
         * container. Otherwise, it might introduce a transition loop, since a
         * probe could be scheduled after the container starts again.
         */
        if ((order->rsc2 != NULL) && (order->rsc1->container == order->rsc2)) {

            if ((then != NULL) && pcmk__str_eq(then->task, PCMK_ACTION_STOP,
                                               pcmk__str_none)) {
                continue;
            } else if ((then == NULL)
                       && pcmk__ends_with(order->task2,
                                          "_" PCMK_ACTION_STOP "_0")) {
                continue;
            }
        }

        // Preserve certain order options for future filtering
        if (pcmk_is_set(order->flags, pcmk__ar_if_first_unmigratable)) {
            pcmk__set_relation_flags(order_flags,
                                     pcmk__ar_if_first_unmigratable);
        }
        if (pcmk_is_set(order->flags, pcmk__ar_if_on_same_node)) {
            pcmk__set_relation_flags(order_flags, pcmk__ar_if_on_same_node);
        }

        // Preserve certain order types for future filtering
        if ((order->flags == pcmk__ar_if_required_on_same_node)
            || (order->flags == pcmk__ar_if_on_same_node_or_target)) {
            order_flags = order->flags;
        }

        // List all scheduled probes for the first resource
        probes = pe__resource_actions(order->rsc1, NULL, PCMK_ACTION_MONITOR,
                                      FALSE);
        if (probes == NULL) { // There aren't any
            continue;
        }

        // List all relevant "then" actions
        if (then != NULL) {
            then_actions = g_list_prepend(NULL, then);

        } else if (order->rsc2 != NULL) {
            then_actions = find_actions(order->rsc2->private->actions,
                                        order->task2, NULL);
            if (then_actions == NULL) { // There aren't any
                g_list_free(probes);
                continue;
            }
        }

        crm_trace("Implying 'probe then' orderings for '%s then %s' "
                  "(id=%d, type=%.6x)",
                  ((first == NULL)? order->task1 : first->uuid),
                  ((then == NULL)? order->task2 : then->uuid),
                  order->id, order->flags);

        for (GList *probe_iter = probes; probe_iter != NULL;
             probe_iter = probe_iter->next) {

            pcmk_action_t *probe = (pcmk_action_t *) probe_iter->data;

            for (GList *then_iter = then_actions; then_iter != NULL;
                 then_iter = then_iter->next) {

                pcmk_action_t *then = (pcmk_action_t *) then_iter->data;

                if (probe_needed_before_action(probe, then)) {
                    order_actions(probe, then, order_flags);
                }
            }
        }

        g_list_free(then_actions);
        g_list_free(probes);
    }
}

/*!
 * \internal
 * \brief Add necessary orderings between probe and starts of clone instances
 *
 * , in additon to the ordering with the parent resource added upon creating
 * the probe.
 *
 * \param[in,out] probe     Probe as 'first' action in an ordering
 * \param[in,out] after     'then' action wrapper in the ordering
 */
static void
add_start_orderings_for_probe(pcmk_action_t *probe,
                              pcmk__related_action_t *after)
{
    uint32_t flags = pcmk__ar_ordered|pcmk__ar_unrunnable_first_blocks;

    /* Although the ordering between the probe of the clone instance and the
     * start of its parent has been added in pcmk__probe_rsc_on_node(), we
     * avoided enforcing `pcmk__ar_unrunnable_first_blocks` order type for that
     * as long as any of the clone instances are running to prevent them from
     * being unexpectedly stopped.
     *
     * On the other hand, we still need to prevent any inactive instances from
     * starting unless the probe is runnable so that we don't risk starting too
     * many instances before we know the state on all nodes.
     */
    if ((after->action->rsc->private->variant <= pcmk__rsc_variant_group)
        || pcmk_is_set(probe->flags, pcmk_action_runnable)
        // The order type is already enforced for its parent.
        || pcmk_is_set(after->type, pcmk__ar_unrunnable_first_blocks)
        || (pe__const_top_resource(probe->rsc, false) != after->action->rsc)
        || !pcmk__str_eq(after->action->task, PCMK_ACTION_START,
                         pcmk__str_none)) {
        return;
    }

    crm_trace("Adding probe start orderings for 'unrunnable %s@%s "
              "then instances of %s@%s'",
              probe->uuid, pcmk__node_name(probe->node),
              after->action->uuid, pcmk__node_name(after->action->node));

    for (GList *then_iter = after->action->actions_after; then_iter != NULL;
         then_iter = then_iter->next) {

        pcmk__related_action_t *then = then_iter->data;

        if ((then->action->rsc->private->active_nodes != NULL)
            || (pe__const_top_resource(then->action->rsc, false)
                != after->action->rsc)
            || !pcmk__str_eq(then->action->task, PCMK_ACTION_START,
                             pcmk__str_none)) {
            continue;
        }

        crm_trace("Adding probe start ordering for 'unrunnable %s@%s "
                  "then %s@%s' (type=%#.6x)",
                  probe->uuid, pcmk__node_name(probe->node),
                  then->action->uuid, pcmk__node_name(then->action->node),
                  flags);

        /* Prevent the instance from starting if the instance can't, but don't
         * cause any other intances to stop if already active.
         */
        order_actions(probe, then->action, flags);
    }

    return;
}

/*!
 * \internal
 * \brief Order probes before restarts and re-promotes
 *
 * If a given ordering is a "probe then start" or "probe then promote" ordering,
 * add an implicit "probe then stop/demote" ordering in case the action is part
 * of a restart/re-promote, and do the same recursively for all actions ordered
 * after the "then" action.
 *
 * \param[in,out] probe     Probe as 'first' action in an ordering
 * \param[in,out] after     'then' action in the ordering
 */
static void
add_restart_orderings_for_probe(pcmk_action_t *probe, pcmk_action_t *after)
{
    GList *iter = NULL;
    bool interleave = false;
    pcmk_resource_t *compatible_rsc = NULL;

    // Validate that this is a resource probe followed by some action
    if ((after == NULL) || (probe == NULL) || !pcmk__is_primitive(probe->rsc)
        || !pcmk__str_eq(probe->task, PCMK_ACTION_MONITOR, pcmk__str_none)) {
        return;
    }

    // Avoid running into any possible loop
    if (pcmk_is_set(after->flags, pcmk_action_detect_loop)) {
        return;
    }
    pcmk__set_action_flags(after, pcmk_action_detect_loop);

    crm_trace("Adding probe restart orderings for '%s@%s then %s@%s'",
              probe->uuid, pcmk__node_name(probe->node),
              after->uuid, pcmk__node_name(after->node));

    /* Add restart orderings if "then" is for a different primitive.
     * Orderings for collective resources will be added later.
     */
    if (pcmk__is_primitive(after->rsc) && (probe->rsc != after->rsc)) {

            GList *then_actions = NULL;

            if (pcmk__str_eq(after->task, PCMK_ACTION_START, pcmk__str_none)) {
                then_actions = pe__resource_actions(after->rsc, NULL,
                                                    PCMK_ACTION_STOP, FALSE);

            } else if (pcmk__str_eq(after->task, PCMK_ACTION_PROMOTE,
                                    pcmk__str_none)) {
                then_actions = pe__resource_actions(after->rsc, NULL,
                                                    PCMK_ACTION_DEMOTE, FALSE);
            }

            for (iter = then_actions; iter != NULL; iter = iter->next) {
                pcmk_action_t *then = (pcmk_action_t *) iter->data;

                // Skip pseudo-actions (for example, those implied by fencing)
                if (!pcmk_is_set(then->flags, pcmk_action_pseudo)) {
                    order_actions(probe, then, pcmk__ar_ordered);
                }
            }
            g_list_free(then_actions);
    }

    /* Detect whether "then" is an interleaved clone action. For these, we want
     * to add orderings only for the relevant instance.
     */
    if ((after->rsc != NULL)
        && (after->rsc->private->variant > pcmk__rsc_variant_group)) {
        const char *interleave_s = g_hash_table_lookup(after->rsc->meta,
                                                       PCMK_META_INTERLEAVE);

        interleave = crm_is_true(interleave_s);
        if (interleave) {
            compatible_rsc = pcmk__find_compatible_instance(probe->rsc,
                                                            after->rsc,
                                                            pcmk_role_unknown,
                                                            false);
        }
    }

    /* Now recursively do the same for all actions ordered after "then". This
     * also handles collective resources since the collective action will be
     * ordered before its individual instances' actions.
     */
    for (iter = after->actions_after; iter != NULL; iter = iter->next) {
        pcmk__related_action_t *after_wrapper = iter->data;
        const pcmk_resource_t *chained_rsc = NULL;

        /* pcmk__ar_first_implies_then is the reason why a required A.start
         * implies/enforces B.start to be required too, which is the cause of
         * B.restart/re-promote.
         *
         * Not sure about pcmk__ar_first_implies_same_node_then though. It's now
         * only used for unfencing case, which tends to introduce transition
         * loops...
         */
        if (!pcmk_is_set(after_wrapper->type, pcmk__ar_first_implies_then)) {
            /* The order type between a group/clone and its child such as
             * B.start-> B_child.start is:
             * pcmk__ar_then_implies_first_graphed
             * |pcmk__ar_unrunnable_first_blocks
             *
             * Proceed through the ordering chain and build dependencies with
             * its children.
             */
            if ((after->rsc == NULL)
                || (after->rsc->private->variant < pcmk__rsc_variant_group)
                || (probe->rsc->private->parent == after->rsc)
                || (after_wrapper->action->rsc == NULL)) {
                continue;
            }
            chained_rsc = after_wrapper->action->rsc;

            if ((chained_rsc->private->variant > pcmk__rsc_variant_group)
                || (after->rsc != chained_rsc->private->parent)) {
                continue;
            }

            /* Proceed to the children of a group or a non-interleaved clone.
             * For an interleaved clone, proceed only to the relevant child.
             */
            if ((after->rsc->private->variant > pcmk__rsc_variant_group)
                && interleave
                && ((compatible_rsc == NULL)
                    || (compatible_rsc != chained_rsc))) {
                continue;
            }
        }

        crm_trace("Recursively adding probe restart orderings for "
                  "'%s@%s then %s@%s' (type=%#.6x)",
                  after->uuid, pcmk__node_name(after->node),
                  after_wrapper->action->uuid,
                  pcmk__node_name(after_wrapper->action->node),
                  after_wrapper->type);

        add_restart_orderings_for_probe(probe, after_wrapper->action);
    }
}

/*!
 * \internal
 * \brief Clear the tracking flag on all scheduled actions
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
clear_actions_tracking_flag(pcmk_scheduler_t *scheduler)
{
    for (GList *iter = scheduler->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *action = iter->data;

        pcmk__clear_action_flags(action, pcmk_action_detect_loop);
    }
}

/*!
 * \internal
 * \brief Add start and restart orderings for probes scheduled for a resource
 *
 * \param[in,out] data       Resource whose probes should be ordered
 * \param[in]     user_data  Unused
 */
static void
add_start_restart_orderings_for_rsc(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;
    GList *probes = NULL;

    // For collective resources, order each instance recursively
    if (!pcmk__is_primitive(rsc)) {
        g_list_foreach(rsc->children, add_start_restart_orderings_for_rsc,
                       NULL);
        return;
    }

    // Find all probes for given resource
    probes = pe__resource_actions(rsc, NULL, PCMK_ACTION_MONITOR, FALSE);

    // Add probe restart orderings for each probe found
    for (GList *iter = probes; iter != NULL; iter = iter->next) {
        pcmk_action_t *probe = (pcmk_action_t *) iter->data;

        for (GList *then_iter = probe->actions_after; then_iter != NULL;
             then_iter = then_iter->next) {

            pcmk__related_action_t *then = then_iter->data;

            add_start_orderings_for_probe(probe, then);
            add_restart_orderings_for_probe(probe, then->action);
            clear_actions_tracking_flag(rsc->private->scheduler);
        }
    }

    g_list_free(probes);
}

/*!
 * \internal
 * \brief Add "A then probe B" orderings for "A then B" orderings
 *
 * \param[in,out] scheduler  Scheduler data
 *
 * \note This function is currently disabled (see next comment).
 */
static void
order_then_probes(pcmk_scheduler_t *scheduler)
{
#if 0
    /* Given an ordering "A then B", we would prefer to wait for A to be started
     * before probing B.
     *
     * For example, if A is a filesystem which B can't even run without, it
     * would be helpful if the author of B's agent could assume that A is
     * running before B.monitor will be called.
     *
     * However, we can't _only_ probe after A is running, otherwise we wouldn't
     * detect the state of B if A could not be started. We can't even do an
     * opportunistic version of this, because B may be moving:
     *
     *   A.stop -> A.start -> B.probe -> B.stop -> B.start
     *
     * and if we add B.stop -> A.stop here, we get a loop:
     *
     *   A.stop -> A.start -> B.probe -> B.stop -> A.stop
     *
     * We could kill the "B.probe -> B.stop" dependency, but that could mean
     * stopping B "too" soon, because B.start must wait for the probe, and
     * we don't want to stop B if we can't start it.
     *
     * We could add the ordering only if A is an anonymous clone with
     * clone-max == node-max (since we'll never be moving it). However, we could
     * still be stopping one instance at the same time as starting another.
     *
     * The complexity of checking for allowed conditions combined with the ever
     * narrowing use case suggests that this code should remain disabled until
     * someone gets smarter.
     */
    for (GList *iter = scheduler->resources; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        pcmk_action_t *start = NULL;
        GList *actions = NULL;
        GList *probes = NULL;

        actions = pe__resource_actions(rsc, NULL, PCMK_ACTION_START, FALSE);

        if (actions) {
            start = actions->data;
            g_list_free(actions);
        }

        if (start == NULL) {
            crm_debug("No start action for %s", rsc->id);
            continue;
        }

        probes = pe__resource_actions(rsc, NULL, PCMK_ACTION_MONITOR, FALSE);

        for (actions = start->actions_before; actions != NULL;
             actions = actions->next) {

            pcmk__related_action_t *before = actions->data;

            pcmk_action_t *first = before->action;
            pcmk_resource_t *first_rsc = first->rsc;

            if (first->required_runnable_before) {
                for (GList *clone_actions = first->actions_before;
                     clone_actions != NULL;
                     clone_actions = clone_actions->next) {

                    before = clone_actions->data;

                    crm_trace("Testing '%s then %s' for %s",
                              first->uuid, before->action->uuid, start->uuid);

                    CRM_ASSERT(before->action->rsc != NULL);
                    first_rsc = before->action->rsc;
                    break;
                }

            } else if (!pcmk__str_eq(first->task, PCMK_ACTION_START,
                                     pcmk__str_none)) {
                crm_trace("Not a start op %s for %s", first->uuid, start->uuid);
            }

            if (first_rsc == NULL) {
                continue;

            } else if (pe__const_top_resource(first_rsc, false)
                       == pe__const_top_resource(start->rsc, false)) {
                crm_trace("Same parent %s for %s", first_rsc->id, start->uuid);
                continue;

            } else if (!pcmk__is_clone(pe__const_top_resource(first_rsc,
                                                              false))) {
                crm_trace("Not a clone %s for %s", first_rsc->id, start->uuid);
                continue;
            }

            crm_debug("Applying %s before %s", first->uuid, start->uuid);

            for (GList *probe_iter = probes; probe_iter != NULL;
                 probe_iter = probe_iter->next) {

                pcmk_action_t *probe = (pcmk_action_t *) probe_iter->data;

                crm_debug("Ordering %s before %s", first->uuid, probe->uuid);
                order_actions(first, probe, pcmk__ar_ordered);
            }
        }
    }
#endif
}

void
pcmk__order_probes(pcmk_scheduler_t *scheduler)
{
    // Add orderings for "probe then X"
    g_list_foreach(scheduler->resources, add_start_restart_orderings_for_rsc,
                   NULL);
    add_probe_orderings_for_stops(scheduler);

    order_then_probes(scheduler);
}

/*!
 * \internal
 * \brief Schedule any probes needed
 *
 * \param[in,out] scheduler  Scheduler data
 *
 * \note This may also schedule fencing of failed remote nodes.
 */
void
pcmk__schedule_probes(pcmk_scheduler_t *scheduler)
{
    // Schedule probes on each node in the cluster as needed
    for (GList *iter = scheduler->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;
        const char *probed = NULL;

        if (!node->details->online) { // Don't probe offline nodes
            if (pcmk__is_failed_remote_node(node)) {
                pe_fence_node(scheduler, node,
                              "the connection is unrecoverable", FALSE);
            }
            continue;

        } else if (node->details->unclean) { // ... or nodes that need fencing
            continue;

        } else if (!node->details->rsc_discovery_enabled) {
            // The user requested that probes not be done on this node
            continue;
        }

        /* This is no longer needed for live clusters, since the probe_complete
         * node attribute will never be in the CIB. However this is still useful
         * for processing old saved CIBs (< 1.1.14), including the
         * reprobe-target_rc regression test.
         */
        probed = pcmk__node_attr(node, CRM_OP_PROBED, NULL,
                                 pcmk__rsc_node_current);
        if (probed != NULL && crm_is_true(probed) == FALSE) {
            pcmk_action_t *probe_op = NULL;

            probe_op = custom_action(NULL,
                                     crm_strdup_printf("%s-%s", CRM_OP_REPROBE,
                                                       node->details->uname),
                                     CRM_OP_REPROBE, node, FALSE, scheduler);
            pcmk__insert_meta(probe_op, PCMK__META_OP_NO_WAIT, PCMK_VALUE_TRUE);
            continue;
        }

        // Probe each resource in the cluster on this node, as needed
        pcmk__probe_resource_list(scheduler->resources, node);
    }
}
