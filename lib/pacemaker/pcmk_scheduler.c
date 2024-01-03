/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/common/scheduler_internal.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

CRM_TRACE_INIT_DATA(pacemaker);

/*!
 * \internal
 * \brief Do deferred action checks after assignment
 *
 * When unpacking the resource history, the scheduler checks for resource
 * configurations that have changed since an action was run. However, at that
 * time, bundles using the REMOTE_CONTAINER_HACK don't have their final
 * parameter information, so instead they add a deferred check to a list. This
 * function processes one entry in that list.
 *
 * \param[in,out] rsc     Resource that action history is for
 * \param[in,out] node    Node that action history is for
 * \param[in]     rsc_op  Action history entry
 * \param[in]     check   Type of deferred check to do
 */
static void
check_params(pcmk_resource_t *rsc, pcmk_node_t *node, const xmlNode *rsc_op,
             enum pcmk__check_parameters check)
{
    const char *reason = NULL;
    pcmk__op_digest_t *digest_data = NULL;

    switch (check) {
        case pcmk__check_active:
            if (pcmk__check_action_config(rsc, node, rsc_op)
                && pe_get_failcount(node, rsc, NULL, pcmk__fc_effective,
                                    NULL)) {
                reason = "action definition changed";
            }
            break;

        case pcmk__check_last_failure:
            digest_data = rsc_action_digest_cmp(rsc, rsc_op, node,
                                                rsc->cluster);
            switch (digest_data->rc) {
                case pcmk__digest_unknown:
                    crm_trace("Resource %s history entry %s on %s has "
                              "no digest to compare",
                              rsc->id, ID(rsc_op), node->details->id);
                    break;
                case pcmk__digest_match:
                    break;
                default:
                    reason = "resource parameters have changed";
                    break;
            }
            break;
    }
    if (reason != NULL) {
        pe__clear_failcount(rsc, node, reason, rsc->cluster);
    }
}

/*!
 * \internal
 * \brief Check whether a resource has failcount clearing scheduled on a node
 *
 * \param[in] node  Node to check
 * \param[in] rsc   Resource to check
 *
 * \return true if \p rsc has failcount clearing scheduled on \p node,
 *         otherwise false
 */
static bool
failcount_clear_action_exists(const pcmk_node_t *node,
                              const pcmk_resource_t *rsc)
{
    GList *list = pe__resource_actions(rsc, node, PCMK_ACTION_CLEAR_FAILCOUNT,
                                       TRUE);

    if (list != NULL) {
        g_list_free(list);
        return true;
    }
    return false;
}

/*!
 * \internal
 * \brief Ban a resource from a node if it reached its failure threshold there
 *
 * \param[in,out] data       Resource to check failure threshold for
 * \param[in]     user_data  Node to check resource on
 */
static void
check_failure_threshold(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;
    const pcmk_node_t *node = user_data;

    // If this is a collective resource, apply recursively to children instead
    if (rsc->children != NULL) {
        g_list_foreach(rsc->children, check_failure_threshold, user_data);
        return;
    }

    if (!failcount_clear_action_exists(node, rsc)) {
        /* Don't force the resource away from this node due to a failcount
         * that's going to be cleared.
         *
         * @TODO Failcount clearing can be scheduled in
         * pcmk__handle_rsc_config_changes() via process_rsc_history(), or in
         * schedule_resource_actions() via check_params(). This runs well before
         * then, so it cannot detect those, meaning we might check the migration
         * threshold when we shouldn't. Worst case, we stop or move the
         * resource, then move it back in the next transition.
         */
        pcmk_resource_t *failed = NULL;

        if (pcmk__threshold_reached(rsc, node, &failed)) {
            resource_location(failed, node, -INFINITY, "__fail_limit__",
                              rsc->cluster);
        }
    }
}

/*!
 * \internal
 * \brief If resource has exclusive discovery, ban node if not allowed
 *
 * Location constraints have a resource-discovery option that allows users to
 * specify where probes are done for the affected resource. If this is set to
 * exclusive, probes will only be done on nodes listed in exclusive constraints.
 * This function bans the resource from the node if the node is not listed.
 *
 * \param[in,out] data       Resource to check
 * \param[in]     user_data  Node to check resource on
 */
static void
apply_exclusive_discovery(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;
    const pcmk_node_t *node = user_data;

    if (rsc->exclusive_discover
        || pe__const_top_resource(rsc, false)->exclusive_discover) {
        pcmk_node_t *match = NULL;

        // If this is a collective resource, apply recursively to children
        g_list_foreach(rsc->children, apply_exclusive_discovery, user_data);

        match = g_hash_table_lookup(rsc->allowed_nodes, node->details->id);
        if ((match != NULL)
            && (match->rsc_discover_mode != pcmk_probe_exclusive)) {
            match->weight = -INFINITY;
        }
    }
}

/*!
 * \internal
 * \brief Apply stickiness to a resource if appropriate
 *
 * \param[in,out] data       Resource to check for stickiness
 * \param[in]     user_data  Ignored
 */
static void
apply_stickiness(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;
    pcmk_node_t *node = NULL;

    // If this is a collective resource, apply recursively to children instead
    if (rsc->children != NULL) {
        g_list_foreach(rsc->children, apply_stickiness, NULL);
        return;
    }

    /* A resource is sticky if it is managed, has stickiness configured, and is
     * active on a single node.
     */
    if (!pcmk_is_set(rsc->flags, pcmk_rsc_managed)
        || (rsc->stickiness < 1) || !pcmk__list_of_1(rsc->running_on)) {
        return;
    }

    node = rsc->running_on->data;

    /* In a symmetric cluster, stickiness can always be used. In an
     * asymmetric cluster, we have to check whether the resource is still
     * allowed on the node, so we don't keep the resource somewhere it is no
     * longer explicitly enabled.
     */
    if (!pcmk_is_set(rsc->cluster->flags, pcmk_sched_symmetric_cluster)
        && (g_hash_table_lookup(rsc->allowed_nodes,
                                node->details->id) == NULL)) {
        pcmk__rsc_debug(rsc,
                        "Ignoring %s stickiness because the cluster is "
                        "asymmetric and %s is not explicitly allowed",
                        rsc->id, pe__node_name(node));
        return;
    }

    pcmk__rsc_debug(rsc, "Resource %s has %d stickiness on %s",
                    rsc->id, rsc->stickiness, pe__node_name(node));
    resource_location(rsc, node, rsc->stickiness, "stickiness", rsc->cluster);
}

/*!
 * \internal
 * \brief Apply shutdown locks for all resources as appropriate
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
apply_shutdown_locks(pcmk_scheduler_t *scheduler)
{
    if (!pcmk_is_set(scheduler->flags, pcmk_sched_shutdown_lock)) {
        return;
    }
    for (GList *iter = scheduler->resources; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        rsc->cmds->shutdown_lock(rsc);
    }
}

/*!
 * \internal
 * \brief Calculate the number of available nodes in the cluster
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
count_available_nodes(pcmk_scheduler_t *scheduler)
{
    if (pcmk_is_set(scheduler->flags, pcmk_sched_no_compat)) {
        return;
    }

    // @COMPAT for API backward compatibility only (cluster does not use value)
    for (GList *iter = scheduler->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;

        if ((node != NULL) && (node->weight >= 0) && node->details->online
            && (node->details->type != node_ping)) {
            scheduler->max_valid_nodes++;
        }
    }
    crm_trace("Online node count: %d", scheduler->max_valid_nodes);
}

/*
 * \internal
 * \brief Apply node-specific scheduling criteria
 *
 * After the CIB has been unpacked, process node-specific scheduling criteria
 * including shutdown locks, location constraints, resource stickiness,
 * migration thresholds, and exclusive resource discovery.
 */
static void
apply_node_criteria(pcmk_scheduler_t *scheduler)
{
    crm_trace("Applying node-specific scheduling criteria");
    apply_shutdown_locks(scheduler);
    count_available_nodes(scheduler);
    pcmk__apply_locations(scheduler);
    g_list_foreach(scheduler->resources, apply_stickiness, NULL);

    for (GList *node_iter = scheduler->nodes; node_iter != NULL;
         node_iter = node_iter->next) {
        for (GList *rsc_iter = scheduler->resources; rsc_iter != NULL;
             rsc_iter = rsc_iter->next) {
            check_failure_threshold(rsc_iter->data, node_iter->data);
            apply_exclusive_discovery(rsc_iter->data, node_iter->data);
        }
    }
}

/*!
 * \internal
 * \brief Assign resources to nodes
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
assign_resources(pcmk_scheduler_t *scheduler)
{
    GList *iter = NULL;

    crm_trace("Assigning resources to nodes");

    if (!pcmk__str_eq(scheduler->placement_strategy, "default",
                      pcmk__str_casei)) {
        pcmk__sort_resources(scheduler);
    }
    pcmk__show_node_capacities("Original", scheduler);

    if (pcmk_is_set(scheduler->flags, pcmk_sched_have_remote_nodes)) {
        /* Assign remote connection resources first (which will also assign any
         * colocation dependencies). If the connection is migrating, always
         * prefer the partial migration target.
         */
        for (iter = scheduler->resources; iter != NULL; iter = iter->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

            if (rsc->is_remote_node) {
                pcmk__rsc_trace(rsc, "Assigning remote connection resource '%s'",
                                rsc->id);
                rsc->cmds->assign(rsc, rsc->partial_migration_target, true);
            }
        }
    }

    /* now do the rest of the resources */
    for (iter = scheduler->resources; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        if (!rsc->is_remote_node) {
            pcmk__rsc_trace(rsc, "Assigning %s resource '%s'",
                            rsc->xml->name, rsc->id);
            rsc->cmds->assign(rsc, NULL, true);
        }
    }

    pcmk__show_node_capacities("Remaining", scheduler);
}

/*!
 * \internal
 * \brief Schedule fail count clearing on online nodes if resource is orphaned
 *
 * \param[in,out] data       Resource to check
 * \param[in]     user_data  Ignored
 */
static void
clear_failcounts_if_orphaned(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;

    if (!pcmk_is_set(rsc->flags, pcmk_rsc_removed)) {
        return;
    }
    crm_trace("Clear fail counts for orphaned resource %s", rsc->id);

    /* There's no need to recurse into rsc->children because those
     * should just be unassigned clone instances.
     */

    for (GList *iter = rsc->cluster->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;
        pcmk_action_t *clear_op = NULL;

        if (!node->details->online) {
            continue;
        }
        if (pe_get_failcount(node, rsc, NULL, pcmk__fc_effective, NULL) == 0) {
            continue;
        }

        clear_op = pe__clear_failcount(rsc, node, "it is orphaned",
                                       rsc->cluster);

        /* We can't use order_action_then_stop() here because its
         * pcmk__ar_guest_allowed breaks things
         */
        pcmk__new_ordering(clear_op->rsc, NULL, clear_op, rsc, stop_key(rsc),
                           NULL, pcmk__ar_ordered, rsc->cluster);
    }
}

/*!
 * \internal
 * \brief Schedule any resource actions needed
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
schedule_resource_actions(pcmk_scheduler_t *scheduler)
{
    // Process deferred action checks
    pe__foreach_param_check(scheduler, check_params);
    pe__free_param_checks(scheduler);

    if (pcmk_is_set(scheduler->flags, pcmk_sched_probe_resources)) {
        crm_trace("Scheduling probes");
        pcmk__schedule_probes(scheduler);
    }

    if (pcmk_is_set(scheduler->flags, pcmk_sched_stop_removed_resources)) {
        g_list_foreach(scheduler->resources, clear_failcounts_if_orphaned,
                       NULL);
    }

    crm_trace("Scheduling resource actions");
    for (GList *iter = scheduler->resources; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        rsc->cmds->create_actions(rsc);
    }
}

/*!
 * \internal
 * \brief Check whether a resource or any of its descendants are managed
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource or any descendant is managed, otherwise false
 */
static bool
is_managed(const pcmk_resource_t *rsc)
{
    if (pcmk_is_set(rsc->flags, pcmk_rsc_managed)) {
        return true;
    }
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        if (is_managed((pcmk_resource_t *) iter->data)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether any resources in the cluster are managed
 *
 * \param[in] scheduler  Scheduler data
 *
 * \return true if any resource is managed, otherwise false
 */
static bool
any_managed_resources(const pcmk_scheduler_t *scheduler)
{
    for (const GList *iter = scheduler->resources;
         iter != NULL; iter = iter->next) {
        if (is_managed((const pcmk_resource_t *) iter->data)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether a node requires fencing
 *
 * \param[in] node          Node to check
 * \param[in] have_managed  Whether any resource in cluster is managed
 *
 * \return true if \p node should be fenced, otherwise false
 */
static bool
needs_fencing(const pcmk_node_t *node, bool have_managed)
{
    return have_managed && node->details->unclean
           && pe_can_fence(node->details->data_set, node);
}

/*!
 * \internal
 * \brief Check whether a node requires shutdown
 *
 * \param[in] node          Node to check
 *
 * \return true if \p node should be shut down, otherwise false
 */
static bool
needs_shutdown(const pcmk_node_t *node)
{
    if (pe__is_guest_or_remote_node(node)) {
       /* Do not send shutdown actions for Pacemaker Remote nodes.
        * @TODO We might come up with a good use for this in the future.
        */
        return false;
    }
    return node->details->online && node->details->shutdown;
}

/*!
 * \internal
 * \brief Track and order non-DC fencing
 *
 * \param[in,out] list       List of existing non-DC fencing actions
 * \param[in,out] action     Fencing action to prepend to \p list
 * \param[in]     scheduler  Scheduler data
 *
 * \return (Possibly new) head of \p list
 */
static GList *
add_nondc_fencing(GList *list, pcmk_action_t *action,
                  const pcmk_scheduler_t *scheduler)
{
    if (!pcmk_is_set(scheduler->flags, pcmk_sched_concurrent_fencing)
        && (list != NULL)) {
        /* Concurrent fencing is disabled, so order each non-DC
         * fencing in a chain. If there is any DC fencing or
         * shutdown, it will be ordered after the last action in the
         * chain later.
         */
        order_actions((pcmk_action_t *) list->data, action, pcmk__ar_ordered);
    }
    return g_list_prepend(list, action);
}

/*!
 * \internal
 * \brief Schedule a node for fencing
 *
 * \param[in,out] node      Node that requires fencing
 */
static pcmk_action_t *
schedule_fencing(pcmk_node_t *node)
{
    pcmk_action_t *fencing = pe_fence_op(node, NULL, FALSE, "node is unclean",
                                       FALSE, node->details->data_set);

    pcmk__sched_warn("Scheduling node %s for fencing", pe__node_name(node));
    pcmk__order_vs_fence(fencing, node->details->data_set);
    return fencing;
}

/*!
 * \internal
 * \brief Create and order node fencing and shutdown actions
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
schedule_fencing_and_shutdowns(pcmk_scheduler_t *scheduler)
{
    pcmk_action_t *dc_down = NULL;
    bool integrity_lost = false;
    bool have_managed = any_managed_resources(scheduler);
    GList *fencing_ops = NULL;
    GList *shutdown_ops = NULL;

    crm_trace("Scheduling fencing and shutdowns as needed");
    if (!have_managed) {
        crm_notice("No fencing will be done until there are resources "
                   "to manage");
    }

    // Check each node for whether it needs fencing or shutdown
    for (GList *iter = scheduler->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;
        pcmk_action_t *fencing = NULL;

        /* Guest nodes are "fenced" by recovering their container resource,
         * so handle them separately.
         */
        if (pe__is_guest_node(node)) {
            if (node->details->remote_requires_reset && have_managed
                && pe_can_fence(scheduler, node)) {
                pcmk__fence_guest(node);
            }
            continue;
        }

        if (needs_fencing(node, have_managed)) {
            fencing = schedule_fencing(node);

            // Track DC and non-DC fence actions separately
            if (node->details->is_dc) {
                dc_down = fencing;
            } else {
                fencing_ops = add_nondc_fencing(fencing_ops, fencing,
                                                scheduler);
            }

        } else if (needs_shutdown(node)) {
            pcmk_action_t *down_op = pcmk__new_shutdown_action(node);

            // Track DC and non-DC shutdown actions separately
            if (node->details->is_dc) {
                dc_down = down_op;
            } else {
                shutdown_ops = g_list_prepend(shutdown_ops, down_op);
            }
        }

        if ((fencing == NULL) && node->details->unclean) {
            integrity_lost = true;
            pcmk__config_warn("Node %s is unclean but cannot be fenced",
                              pe__node_name(node));
        }
    }

    if (integrity_lost) {
        if (!pcmk_is_set(scheduler->flags, pcmk_sched_fencing_enabled)) {
            pcmk__config_warn("Resource functionality and data integrity "
                              "cannot be guaranteed (configure, enable, "
                              "and test fencing to correct this)");

        } else if (!pcmk_is_set(scheduler->flags, pcmk_sched_quorate)) {
            crm_notice("Unclean nodes will not be fenced until quorum is "
                       "attained or " PCMK_OPT_NO_QUORUM_POLICY " is set to "
                       "ignore");
        }
    }

    if (dc_down != NULL) {
        /* Order any non-DC shutdowns before any DC shutdown, to avoid repeated
         * DC elections. However, we don't want to order non-DC shutdowns before
         * a DC *fencing*, because even though we don't want a node that's
         * shutting down to become DC, the DC fencing could be ordered before a
         * clone stop that's also ordered before the shutdowns, thus leading to
         * a graph loop.
         */
        if (pcmk__str_eq(dc_down->task, PCMK_ACTION_DO_SHUTDOWN,
                         pcmk__str_none)) {
            pcmk__order_after_each(dc_down, shutdown_ops);
        }

        // Order any non-DC fencing before any DC fencing or shutdown

        if (pcmk_is_set(scheduler->flags, pcmk_sched_concurrent_fencing)) {
            /* With concurrent fencing, order each non-DC fencing action
             * separately before any DC fencing or shutdown.
             */
            pcmk__order_after_each(dc_down, fencing_ops);
        } else if (fencing_ops != NULL) {
            /* Without concurrent fencing, the non-DC fencing actions are
             * already ordered relative to each other, so we just need to order
             * the DC fencing after the last action in the chain (which is the
             * first item in the list).
             */
            order_actions((pcmk_action_t *) fencing_ops->data, dc_down,
                          pcmk__ar_ordered);
        }
    }
    g_list_free(fencing_ops);
    g_list_free(shutdown_ops);
}

static void
log_resource_details(pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = scheduler->priv;
    GList *all = NULL;

    /* Due to the `crm_mon --node=` feature, out->message() for all the
     * resource-related messages expects a list of nodes that we are allowed to
     * output information for. Here, we create a wildcard to match all nodes.
     */
    all = g_list_prepend(all, (gpointer) "*");

    for (GList *item = scheduler->resources; item != NULL; item = item->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) item->data;

        // Log all resources except inactive orphans
        if (!pcmk_is_set(rsc->flags, pcmk_rsc_removed)
            || (rsc->role != pcmk_role_stopped)) {
            out->message(out, crm_map_element_name(rsc->xml), 0, rsc, all, all);
        }
    }

    g_list_free(all);
}

static void
log_all_actions(pcmk_scheduler_t *scheduler)
{
    /* This only ever outputs to the log, so ignore whatever output object was
     * previously set and just log instead.
     */
    pcmk__output_t *prev_out = scheduler->priv;
    pcmk__output_t *out = NULL;

    if (pcmk__log_output_new(&out) != pcmk_rc_ok) {
        return;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);
    pcmk__output_set_log_level(out, LOG_NOTICE);
    scheduler->priv = out;

    out->begin_list(out, NULL, NULL, "Actions");
    pcmk__output_actions(scheduler);
    out->end_list(out);
    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);

    scheduler->priv = prev_out;
}

/*!
 * \internal
 * \brief Log all required but unrunnable actions at trace level
 *
 * \param[in] scheduler  Scheduler data
 */
static void
log_unrunnable_actions(const pcmk_scheduler_t *scheduler)
{
    const uint64_t flags = pcmk_action_optional
                           |pcmk_action_runnable
                           |pcmk_action_pseudo;

    crm_trace("Required but unrunnable actions:");
    for (const GList *iter = scheduler->actions;
         iter != NULL; iter = iter->next) {

        const pcmk_action_t *action = (const pcmk_action_t *) iter->data;

        if (!pcmk_any_flags_set(action->flags, flags)) {
            pcmk__log_action("\t", action, true);
        }
    }
}

/*!
 * \internal
 * \brief Unpack the CIB for scheduling
 *
 * \param[in,out] cib        CIB XML to unpack (may be NULL if already unpacked)
 * \param[in]     flags      Scheduler flags to set in addition to defaults
 * \param[in,out] scheduler  Scheduler data
 */
static void
unpack_cib(xmlNode *cib, unsigned long long flags, pcmk_scheduler_t *scheduler)
{
    const char* localhost_save = NULL;

    if (pcmk_is_set(scheduler->flags, pcmk_sched_have_status)) {
        crm_trace("Reusing previously calculated cluster status");
        pe__set_working_set_flags(scheduler, flags);
        return;
    }

    if (scheduler->localhost) {
        localhost_save = scheduler->localhost;
    }

    CRM_ASSERT(cib != NULL);
    crm_trace("Calculating cluster status");

    /* This will zero the entire struct without freeing anything first, so
     * callers should never call pcmk__schedule_actions() with a populated data
     * set unless pcmk_sched_have_status is set (i.e. cluster_status() was
     * previously called, whether directly or via pcmk__schedule_actions()).
     */
    set_working_set_defaults(scheduler);

    if (localhost_save) {
        scheduler->localhost = localhost_save;
    }

    pe__set_working_set_flags(scheduler, flags);
    scheduler->input = cib;
    cluster_status(scheduler); // Sets pcmk_sched_have_status
}

/*!
 * \internal
 * \brief Run the scheduler for a given CIB
 *
 * \param[in,out] cib        CIB XML to use as scheduler input
 * \param[in]     flags      Scheduler flags to set in addition to defaults
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__schedule_actions(xmlNode *cib, unsigned long long flags,
                       pcmk_scheduler_t *scheduler)
{
    unpack_cib(cib, flags, scheduler);
    pcmk__set_assignment_methods(scheduler);
    pcmk__apply_node_health(scheduler);
    pcmk__unpack_constraints(scheduler);
    if (pcmk_is_set(scheduler->flags, pcmk_sched_validate_only)) {
        return;
    }

    if (!pcmk_is_set(scheduler->flags, pcmk_sched_location_only)
        && pcmk__is_daemon) {
        log_resource_details(scheduler);
    }

    apply_node_criteria(scheduler);

    if (pcmk_is_set(scheduler->flags, pcmk_sched_location_only)) {
        return;
    }

    pcmk__create_internal_constraints(scheduler);
    pcmk__handle_rsc_config_changes(scheduler);
    assign_resources(scheduler);
    schedule_resource_actions(scheduler);

    /* Remote ordering constraints need to happen prior to calculating fencing
     * because it is one more place we can mark nodes as needing fencing.
     */
    pcmk__order_remote_connection_actions(scheduler);

    schedule_fencing_and_shutdowns(scheduler);
    pcmk__apply_orderings(scheduler);
    log_all_actions(scheduler);
    pcmk__create_graph(scheduler);

    if (get_crm_log_level() == LOG_TRACE) {
        log_unrunnable_actions(scheduler);
    }
}
