/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

#include <glib.h>

#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

CRM_TRACE_INIT_DATA(pacemaker);

/*!
 * \internal
 * \brief Do deferred action checks after allocation
 *
 * When unpacking the resource history, the scheduler checks for resource
 * configurations that have changed since an action was run. However, at that
 * time, bundles using the REMOTE_CONTAINER_HACK don't have their final
 * parameter information, so instead they add a deferred check to a list. This
 * function processes one entry in that list.
 *
 * \param[in] rsc       Resource that action history is for
 * \param[in] node      Node that action history is for
 * \param[in] rsc_op    Action history entry
 * \param[in] check     Type of deferred check to do
 * \param[in] data_set  Working set for cluster
 */
static void
check_params(pe_resource_t *rsc, pe_node_t *node, xmlNode *rsc_op,
             enum pe_check_parameters check, pe_working_set_t *data_set)
{
    const char *reason = NULL;
    op_digest_cache_t *digest_data = NULL;

    switch (check) {
        case pe_check_active:
            if (pcmk__check_action_config(rsc, node, rsc_op)
                && pe_get_failcount(node, rsc, NULL, pe_fc_effective, NULL,
                                    data_set)) {
                reason = "action definition changed";
            }
            break;

        case pe_check_last_failure:
            digest_data = rsc_action_digest_cmp(rsc, rsc_op, node, data_set);
            switch (digest_data->rc) {
                case RSC_DIGEST_UNKNOWN:
                    crm_trace("Resource %s history entry %s on %s has "
                              "no digest to compare",
                              rsc->id, ID(rsc_op), node->details->id);
                    break;
                case RSC_DIGEST_MATCH:
                    break;
                default:
                    reason = "resource parameters have changed";
                    break;
            }
            break;
    }
    if (reason != NULL) {
        pe__clear_failcount(rsc, node, reason, data_set);
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
failcount_clear_action_exists(pe_node_t *node, pe_resource_t *rsc)
{
    GList *list = pe__resource_actions(rsc, node, CRM_OP_CLEAR_FAILCOUNT, TRUE);

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
 * \param[in] rsc       Resource to check failure threshold for
 * \param[in] node      Node to check \p rsc on
 */
static void
check_failure_threshold(pe_resource_t *rsc, pe_node_t *node)
{
    // If this is a collective resource, apply recursively to children instead
    if (rsc->children != NULL) {
        g_list_foreach(rsc->children, (GFunc) check_failure_threshold,
                       node);
        return;

    } else if (failcount_clear_action_exists(node, rsc)) {
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
        return;

    } else {
        pe_resource_t *failed = NULL;

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
 * \param[in] rsc   Resource to check
 * \param[in] node  Node to check \p rsc on
 */
static void
apply_exclusive_discovery(pe_resource_t *rsc, pe_node_t *node)
{
    if (rsc->exclusive_discover || uber_parent(rsc)->exclusive_discover) {
        pe_node_t *match = NULL;

        // If this is a collective resource, apply recursively to children
        g_list_foreach(rsc->children, (GFunc) apply_exclusive_discovery, node);

        match = g_hash_table_lookup(rsc->allowed_nodes, node->details->id);
        if ((match != NULL)
            && (match->rsc_discover_mode != pe_discover_exclusive)) {
            match->weight = -INFINITY;
        }
    }
}

/*!
 * \internal
 * \brief Apply stickiness to a resource if appropriate
 *
 * \param[in] rsc       Resource to check for stickiness
 * \param[in] data_set  Cluster working set
 */
static void
apply_stickiness(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    pe_node_t *node = NULL;

    // If this is a collective resource, apply recursively to children instead
    if (rsc->children != NULL) {
        g_list_foreach(rsc->children, (GFunc) apply_stickiness, data_set);
        return;
    }

    /* A resource is sticky if it is managed, has stickiness configured, and is
     * active on a single node.
     */
    if (!pcmk_is_set(rsc->flags, pe_rsc_managed)
        || (rsc->stickiness < 1) || !pcmk__list_of_1(rsc->running_on)) {
        return;
    }

    node = rsc->running_on->data;

    /* In a symmetric cluster, stickiness can always be used. In an
     * asymmetric cluster, we have to check whether the resource is still
     * allowed on the node, so we don't keep the resource somewhere it is no
     * longer explicitly enabled.
     */
    if (!pcmk_is_set(rsc->cluster->flags, pe_flag_symmetric_cluster)
        && (pe_hash_table_lookup(rsc->allowed_nodes,
                                 node->details->id) == NULL)) {
        pe_rsc_debug(rsc,
                     "Ignoring %s stickiness because the cluster is "
                     "asymmetric and node %s is not explicitly allowed",
                     rsc->id, node->details->uname);
        return;
    }

    pe_rsc_debug(rsc, "Resource %s has %d stickiness on node %s",
                 rsc->id, rsc->stickiness, node->details->uname);
    resource_location(rsc, node, rsc->stickiness, "stickiness",
                      rsc->cluster);
}

/*!
 * \internal
 * \brief Apply shutdown locks for all resources as appropriate
 *
 * \param[in] data_set  Cluster working set
 */
static void
apply_shutdown_locks(pe_working_set_t *data_set)
{
    if (!pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)) {
        return;
    }
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        rsc->cmds->shutdown_lock(rsc);
    }
}

/*!
 * \internal
 * \brief Calculate the number of available nodes in the cluster
 *
 * \param[in] data_set  Cluster working set
 */
static void
count_available_nodes(pe_working_set_t *data_set)
{
    if (pcmk_is_set(data_set->flags, pe_flag_no_compat)) {
        return;
    }

    // @COMPAT for API backward compatibility only (cluster does not use value)
    for (GList *iter = data_set->nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;

        if ((node != NULL) && (node->weight >= 0) && node->details->online
            && (node->details->type != node_ping)) {
            data_set->max_valid_nodes++;
        }
    }
    crm_trace("Online node count: %d", data_set->max_valid_nodes);
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
apply_node_criteria(pe_working_set_t *data_set)
{
    crm_trace("Applying node-specific scheduling criteria");
    apply_shutdown_locks(data_set);
    count_available_nodes(data_set);
    pcmk__apply_locations(data_set);
    g_list_foreach(data_set->resources, (GFunc) apply_stickiness, data_set);

    for (GList *node_iter = data_set->nodes; node_iter != NULL;
         node_iter = node_iter->next) {
        for (GList *rsc_iter = data_set->resources; rsc_iter != NULL;
             rsc_iter = rsc_iter->next) {
            pe_node_t *node = (pe_node_t *) node_iter->data;
            pe_resource_t *rsc = (pe_resource_t *) rsc_iter->data;

            check_failure_threshold(rsc, node);
            apply_exclusive_discovery(rsc, node);
        }
    }
}

/*!
 * \internal
 * \brief Allocate resources to nodes
 *
 * \param[in] data_set  Cluster working set
 */
static void
allocate_resources(pe_working_set_t *data_set)
{
    GList *iter = NULL;

    crm_trace("Allocating resources to nodes");

    if (!pcmk__str_eq(data_set->placement_strategy, "default", pcmk__str_casei)) {
        pcmk__sort_resources(data_set);
    }
    pcmk__show_node_capacities("Original", data_set);

    if (pcmk_is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        /* Allocate remote connection resources first (which will also allocate
         * any colocation dependencies). If the connection is migrating, always
         * prefer the partial migration target.
         */
        for (iter = data_set->resources; iter != NULL; iter = iter->next) {
            pe_resource_t *rsc = (pe_resource_t *) iter->data;

            if (rsc->is_remote_node) {
                pe_rsc_trace(rsc, "Allocating remote connection resource '%s'",
                             rsc->id);
                rsc->cmds->allocate(rsc, rsc->partial_migration_target,
                                    data_set);
            }
        }
    }

    /* now do the rest of the resources */
    for (iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        if (!rsc->is_remote_node) {
            pe_rsc_trace(rsc, "Allocating %s resource '%s'",
                         crm_element_name(rsc->xml), rsc->id);
            rsc->cmds->allocate(rsc, NULL, data_set);
        }
    }

    pcmk__show_node_capacities("Remaining", data_set);
}

/*!
 * \internal
 * \brief Schedule fail count clearing on online nodes if resource is orphaned
 *
 * \param[in] rsc       Resource to check
 * \param[in] data_set  Cluster working set
 */
static void
clear_failcounts_if_orphaned(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        return;
    }
    crm_trace("Clear fail counts for orphaned resource %s", rsc->id);

    /* There's no need to recurse into rsc->children because those
     * should just be unallocated clone instances.
     */

    for (GList *iter = data_set->nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;
        pe_action_t *clear_op = NULL;

        if (!node->details->online) {
            continue;
        }
        if (pe_get_failcount(node, rsc, NULL, pe_fc_effective, NULL,
                             data_set) == 0) {
            continue;
        }

        clear_op = pe__clear_failcount(rsc, node, "it is orphaned", data_set);

        /* We can't use order_action_then_stop() here because its
         * pe_order_preserve breaks things
         */
        pcmk__new_ordering(clear_op->rsc, NULL, clear_op, rsc, stop_key(rsc),
                           NULL, pe_order_optional, data_set);
    }
}

/*!
 * \internal
 * \brief Schedule any resource actions needed
 *
 * \param[in] data_set  Cluster working set
 */
static void
schedule_resource_actions(pe_working_set_t *data_set)
{
    // Process deferred action checks
    pe__foreach_param_check(data_set, check_params);
    pe__free_param_checks(data_set);

    if (pcmk_is_set(data_set->flags, pe_flag_startup_probes)) {
        crm_trace("Scheduling probes");
        pcmk__schedule_probes(data_set);
    }

    if (pcmk_is_set(data_set->flags, pe_flag_stop_rsc_orphans)) {
        g_list_foreach(data_set->resources,
                       (GFunc) clear_failcounts_if_orphaned, data_set);
    }

    crm_trace("Scheduling resource actions");
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        rsc->cmds->create_actions(rsc, data_set);
    }
}

/*!
 * \internal
 * \brief Check whether a resource or any of its descendants are managed
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if resource or any descendent is managed, otherwise false
 */
static bool
is_managed(const pe_resource_t *rsc)
{
    if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        return true;
    }
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        if (is_managed((pe_resource_t *) iter->data)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether any resources in the cluster are managed
 *
 * \param[in] data_set  Cluster working set
 *
 * \return true if any resource is managed, otherwise false
 */
static bool
any_managed_resources(pe_working_set_t *data_set)
{
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        if (is_managed((pe_resource_t *) iter->data)) {
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
 * \param[in] data_set      Cluster working set
 *
 * \return true if \p node should be fenced, otherwise false
 */
static bool
needs_fencing(pe_node_t *node, bool have_managed, pe_working_set_t *data_set)
{
    return have_managed && node->details->unclean
           && pe_can_fence(data_set, node);
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
needs_shutdown(pe_node_t *node)
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
 * \param[in] list    List of existing non-DC fencing actions
 * \param[in] action  Fencing action to prepend to \p list
 *
 * \return (Possibly new) head of \p list
 */
static GList *
add_nondc_fencing(GList *list, pe_action_t *action, pe_working_set_t *data_set)
{
    if (!pcmk_is_set(data_set->flags, pe_flag_concurrent_fencing)
        && (list != NULL)) {
        /* Concurrent fencing is disabled, so order each non-DC
         * fencing in a chain. If there is any DC fencing or
         * shutdown, it will be ordered after the last action in the
         * chain later.
         */
        order_actions((pe_action_t *) list->data, action, pe_order_optional);
    }
    return g_list_prepend(list, action);
}

/*!
 * \internal
 * \brief Schedule a node for fencing
 *
 * \param[in] node      Node that requires fencing
 * \param[in] data_set  Cluster working set
 */
static pe_action_t *
schedule_fencing(pe_node_t *node, pe_working_set_t *data_set)
{
    pe_action_t *fencing = pe_fence_op(node, NULL, FALSE, "node is unclean",
                                       FALSE, data_set);

    pe_warn("Scheduling Node %s for STONITH", node->details->uname);
    pcmk__order_vs_fence(fencing, data_set);
    return fencing;
}

/*!
 * \internal
 * \brief Create and order node fencing and shutdown actions
 *
 * \param[in] data_set  Cluster working set
 */
static void
schedule_fencing_and_shutdowns(pe_working_set_t *data_set)
{
    pe_action_t *dc_down = NULL;
    bool integrity_lost = false;
    bool have_managed = any_managed_resources(data_set);
    GList *fencing_ops = NULL;
    GList *shutdown_ops = NULL;

    crm_trace("Scheduling fencing and shutdowns as needed");
    if (!have_managed) {
        crm_notice("Delaying fencing operations until there are resources to manage");
    }

    // Check each node for whether it needs fencing or shutdown
    for (GList *iter = data_set->nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;
        pe_action_t *fencing = NULL;

        /* Guest nodes are "fenced" by recovering their container resource,
         * so handle them separately.
         */
        if (pe__is_guest_node(node)) {
            if (node->details->remote_requires_reset && have_managed
                && pe_can_fence(data_set, node)) {
                pcmk__fence_guest(node, data_set);
            }
            continue;
        }

        if (needs_fencing(node, have_managed, data_set)) {
            fencing = schedule_fencing(node, data_set);

            // Track DC and non-DC fence actions separately
            if (node->details->is_dc) {
                dc_down = fencing;
            } else {
                fencing_ops = add_nondc_fencing(fencing_ops, fencing, data_set);
            }

        } else if (needs_shutdown(node)) {
            pe_action_t *down_op = pcmk__new_shutdown_action(node, data_set);

            // Track DC and non-DC shutdown actions separately
            if (node->details->is_dc) {
                dc_down = down_op;
            } else {
                shutdown_ops = g_list_prepend(shutdown_ops, down_op);
            }
        }

        if ((fencing == NULL) && node->details->unclean) {
            integrity_lost = true;
            pe_warn("Node %s is unclean!", node->details->uname);
        }
    }

    if (integrity_lost) {
        if (!pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            pe_warn("YOUR RESOURCES ARE NOW LIKELY COMPROMISED");
            pe_err("ENABLE STONITH TO KEEP YOUR RESOURCES SAFE");

        } else if (!pcmk_is_set(data_set->flags, pe_flag_have_quorum)) {
            crm_notice("Cannot fence unclean nodes until quorum is"
                       " attained (or no-quorum-policy is set to ignore)");
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
        if (pcmk__str_eq(dc_down->task, CRM_OP_SHUTDOWN, pcmk__str_none)) {
            pcmk__order_after_all(dc_down, shutdown_ops);
        }

        // Order any non-DC fencing before any DC fencing or shutdown

        if (pcmk_is_set(data_set->flags, pe_flag_concurrent_fencing)) {
            /* With concurrent fencing, order each non-DC fencing action
             * separately before any DC fencing or shutdown.
             */
            pcmk__order_after_all(dc_down, fencing_ops);
        } else if (fencing_ops != NULL) {
            /* Without concurrent fencing, the non-DC fencing actions are
             * already ordered relative to each other, so we just need to order
             * the DC fencing after the last action in the chain (which is the
             * first item in the list).
             */
            order_actions((pe_action_t *) fencing_ops->data, dc_down,
                          pe_order_optional);
        }
    }
    g_list_free(fencing_ops);
    g_list_free(shutdown_ops);
}

static void
log_resource_details(pe_working_set_t *data_set)
{
    pcmk__output_t *out = data_set->priv;
    GList *all = NULL;

    /* We need a list of nodes that we are allowed to output information for.
     * This is necessary because out->message for all the resource-related
     * messages expects such a list, due to the `crm_mon --node=` feature.  Here,
     * we just make it a list of all the nodes.
     */
    all = g_list_prepend(all, (gpointer) "*");

    for (GList *item = data_set->resources; item != NULL; item = item->next) {
        pe_resource_t *rsc = (pe_resource_t *) item->data;

        // Log all resources except inactive orphans
        if (!pcmk_is_set(rsc->flags, pe_rsc_orphan)
            || (rsc->role != RSC_ROLE_STOPPED)) {
            out->message(out, crm_map_element_name(rsc->xml), 0, rsc, all, all);
        }
    }

    g_list_free(all);
}

static void
log_all_actions(pe_working_set_t *data_set)
{
    /* This only ever outputs to the log, so ignore whatever output object was
     * previously set and just log instead.
     */
    pcmk__output_t *prev_out = data_set->priv;
    pcmk__output_t *out = pcmk__new_logger();

    if (out == NULL) {
        return;
    }

    pcmk__output_set_log_level(out, LOG_NOTICE);
    data_set->priv = out;

    out->begin_list(out, NULL, NULL, "Actions");
    pcmk__output_actions(data_set);
    out->end_list(out);
    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);

    data_set->priv = prev_out;
}

/*!
 * \internal
 * \brief Log all required but unrunnable actions at trace level
 *
 * \param[in] data_set  Cluster working set
 */
static void
log_unrunnable_actions(pe_working_set_t *data_set)
{
    const uint64_t flags = pe_action_optional|pe_action_runnable|pe_action_pseudo;

    crm_trace("Required but unrunnable actions:");
    for (GList *iter = data_set->actions; iter != NULL; iter = iter->next) {
        pe_action_t *action = (pe_action_t *) iter->data;

        if (!pcmk_any_flags_set(action->flags, flags)) {
            pcmk__log_action("\t", action, true);
        }
    }
}

/*!
 * \internal
 * \brief Unpack the CIB for scheduling
 *
 * \param[in] cib       CIB XML to unpack (may be NULL if previously unpacked)
 * \param[in] flags     Working set flags to set in addition to defaults
 * \param[in] data_set  Cluster working set
 */
static void
unpack_cib(xmlNode *cib, unsigned long long flags, pe_working_set_t *data_set)
{
    if (pcmk_is_set(data_set->flags, pe_flag_have_status)) {
        crm_trace("Reusing previously calculated cluster status");
        pe__set_working_set_flags(data_set, flags);
        return;
    }

    CRM_ASSERT(cib != NULL);
    crm_trace("Calculating cluster status");

    /* This will zero the entire struct without freeing anything first, so
     * callers should never call pcmk__schedule_actions() with a populated data
     * set unless pe_flag_have_status is set (i.e. cluster_status() was
     * previously called, whether directly or via pcmk__schedule_actions()).
     */
    set_working_set_defaults(data_set);

    pe__set_working_set_flags(data_set, flags);
    data_set->input = cib;
    cluster_status(data_set); // Sets pe_flag_have_status
}

/*!
 * \internal
 * \brief Run the scheduler for a given CIB
 *
 * \param[in]     cib       CIB XML to use as scheduler input
 * \param[in]     flags     Working set flags to set in addition to defaults
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__schedule_actions(xmlNode *cib, unsigned long long flags,
                       pe_working_set_t *data_set)
{
    unpack_cib(cib, flags, data_set);
    pcmk__set_allocation_methods(data_set);
    pcmk__apply_node_health(data_set);
    pcmk__unpack_constraints(data_set);
    if (pcmk_is_set(data_set->flags, pe_flag_check_config)) {
        return;
    }

    if (!pcmk_is_set(data_set->flags, pe_flag_quick_location) &&
         pcmk__is_daemon) {
        log_resource_details(data_set);
    }

    apply_node_criteria(data_set);

    if (pcmk_is_set(data_set->flags, pe_flag_quick_location)) {
        return;
    }

    pcmk__create_internal_constraints(data_set);
    pcmk__handle_rsc_config_changes(data_set);

    allocate_resources(data_set);
    schedule_resource_actions(data_set);

    /* Remote ordering constraints need to happen prior to calculating fencing
     * because it is one more place we can mark nodes as needing fencing.
     */
    pcmk__order_remote_connection_actions(data_set);

    schedule_fencing_and_shutdowns(data_set);

    pcmk__apply_orderings(data_set);
    log_all_actions(data_set);

    crm_trace("Create transition graph");
    pcmk__create_graph(data_set);
    if (get_crm_log_level() == LOG_TRACE) {
        log_unrunnable_actions(data_set);
    }
}
