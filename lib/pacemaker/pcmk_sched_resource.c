/*
 * Copyright 2014-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>
#include <string.h>
#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

// Resource allocation methods that vary by resource variant
static resource_alloc_functions_t allocation_methods[] = {
    {
        pcmk__primitive_assign,
        pcmk__primitive_create_actions,
        pcmk__probe_rsc_on_node,
        pcmk__primitive_internal_constraints,
        pcmk__primitive_apply_coloc_score,
        pcmk__colocated_resources,
        pcmk__with_primitive_colocations,
        pcmk__primitive_with_colocations,
        pcmk__add_colocated_node_scores,
        pcmk__apply_location,
        pcmk__primitive_action_flags,
        pcmk__update_ordered_actions,
        pcmk__output_resource_actions,
        pcmk__add_rsc_actions_to_graph,
        pcmk__primitive_add_graph_meta,
        pcmk__primitive_add_utilization,
        pcmk__primitive_shutdown_lock,
    },
    {
        pcmk__group_assign,
        pcmk__group_create_actions,
        pcmk__probe_rsc_on_node,
        pcmk__group_internal_constraints,
        pcmk__group_apply_coloc_score,
        pcmk__group_colocated_resources,
        pcmk__with_group_colocations,
        pcmk__group_with_colocations,
        pcmk__group_add_colocated_node_scores,
        pcmk__group_apply_location,
        pcmk__group_action_flags,
        pcmk__group_update_ordered_actions,
        pcmk__output_resource_actions,
        pcmk__add_rsc_actions_to_graph,
        pcmk__noop_add_graph_meta,
        pcmk__group_add_utilization,
        pcmk__group_shutdown_lock,
    },
    {
        pcmk__clone_assign,
        pcmk__clone_create_actions,
        clone_create_probe,
        clone_internal_constraints,
        pcmk__clone_apply_coloc_score,
        pcmk__colocated_resources,
        pcmk__with_clone_colocations,
        pcmk__clone_with_colocations,
        pcmk__add_colocated_node_scores,
        clone_rsc_location,
        clone_action_flags,
        pcmk__instance_update_ordered_actions,
        pcmk__output_resource_actions,
        clone_expand,
        clone_append_meta,
        pcmk__clone_add_utilization,
        pcmk__clone_shutdown_lock,
    },
    {
        pcmk__bundle_allocate,
        pcmk__bundle_create_actions,
        pcmk__bundle_create_probe,
        pcmk__bundle_internal_constraints,
        pcmk__bundle_apply_coloc_score,
        pcmk__colocated_resources,
        pcmk__with_bundle_colocations,
        pcmk__bundle_with_colocations,
        pcmk__add_colocated_node_scores,
        pcmk__bundle_rsc_location,
        pcmk__bundle_action_flags,
        pcmk__instance_update_ordered_actions,
        pcmk__output_bundle_actions,
        pcmk__bundle_expand,
        pcmk__noop_add_graph_meta,
        pcmk__bundle_add_utilization,
        pcmk__bundle_shutdown_lock,
    }
};

/*!
 * \internal
 * \brief Check whether a resource's agent standard, provider, or type changed
 *
 * \param[in,out] rsc             Resource to check
 * \param[in,out] node            Node needing unfencing if agent changed
 * \param[in]     rsc_entry       XML with previously known agent information
 * \param[in]     active_on_node  Whether \p rsc is active on \p node
 *
 * \return true if agent for \p rsc changed, otherwise false
 */
bool
pcmk__rsc_agent_changed(pe_resource_t *rsc, pe_node_t *node,
                        const xmlNode *rsc_entry, bool active_on_node)
{
    bool changed = false;
    const char *attr_list[] = {
        XML_ATTR_TYPE,
        XML_AGENT_ATTR_CLASS,
        XML_AGENT_ATTR_PROVIDER
    };

    for (int i = 0; i < PCMK__NELEM(attr_list); i++) {
        const char *value = crm_element_value(rsc->xml, attr_list[i]);
        const char *old_value = crm_element_value(rsc_entry, attr_list[i]);

        if (!pcmk__str_eq(value, old_value, pcmk__str_none)) {
            changed = true;
            trigger_unfencing(rsc, node, "Device definition changed", NULL,
                              rsc->cluster);
            if (active_on_node) {
                crm_notice("Forcing restart of %s on %s "
                           "because %s changed from '%s' to '%s'",
                           rsc->id, pe__node_name(node), attr_list[i],
                           pcmk__s(old_value, ""), pcmk__s(value, ""));
            }
        }
    }
    if (changed && active_on_node) {
        // Make sure the resource is restarted
        custom_action(rsc, stop_key(rsc), CRMD_ACTION_STOP, node, FALSE, TRUE,
                      rsc->cluster);
        pe__set_resource_flags(rsc, pe_rsc_start_pending);
    }
    return changed;
}

/*!
 * \internal
 * \brief Add resource (and any matching children) to list if it matches ID
 *
 * \param[in] result  List to add resource to
 * \param[in] rsc     Resource to check
 * \param[in] id      ID to match
 *
 * \return (Possibly new) head of list
 */
static GList *
add_rsc_if_matching(GList *result, pe_resource_t *rsc, const char *id)
{
    if ((strcmp(rsc->id, id) == 0)
        || ((rsc->clone_name != NULL) && (strcmp(rsc->clone_name, id) == 0))) {
        result = g_list_prepend(result, rsc);
    }
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child = (pe_resource_t *) iter->data;

        result = add_rsc_if_matching(result, child, id);
    }
    return result;
}

/*!
 * \internal
 * \brief Find all resources matching a given ID by either ID or clone name
 *
 * \param[in] id        Resource ID to check
 * \param[in] data_set  Cluster working set
 *
 * \return List of all resources that match \p id
 * \note The caller is responsible for freeing the return value with
 *       g_list_free().
 */
GList *
pcmk__rscs_matching_id(const char *id, const pe_working_set_t *data_set)
{
    GList *result = NULL;

    CRM_CHECK((id != NULL) && (data_set != NULL), return NULL);
    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        result = add_rsc_if_matching(result, (pe_resource_t *) iter->data, id);
    }
    return result;
}

/*!
 * \internal
 * \brief Set the variant-appropriate allocation methods for a resource
 *
 * \param[in,out] rsc      Resource to set allocation methods for
 * \param[in]     ignored  Here so function can be used with g_list_foreach()
 */
static void
set_allocation_methods_for_rsc(pe_resource_t *rsc, void *ignored)
{
    rsc->cmds = &allocation_methods[rsc->variant];
    g_list_foreach(rsc->children, (GFunc) set_allocation_methods_for_rsc, NULL);
}

/*!
 * \internal
 * \brief Set the variant-appropriate allocation methods for all resources
 *
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__set_allocation_methods(pe_working_set_t *data_set)
{
    g_list_foreach(data_set->resources, (GFunc) set_allocation_methods_for_rsc,
                   NULL);
}

// Shared implementation of resource_alloc_functions_t:colocated_resources()
GList *
pcmk__colocated_resources(const pe_resource_t *rsc, const pe_resource_t *orig_rsc,
                          GList *colocated_rscs)
{
    const GList *iter = NULL;
    GList *colocations = NULL;

    if (orig_rsc == NULL) {
        orig_rsc = rsc;
    }

    if ((rsc == NULL) || (g_list_find(colocated_rscs, rsc) != NULL)) {
        return colocated_rscs;
    }

    pe_rsc_trace(orig_rsc, "%s is in colocation chain with %s",
                 rsc->id, orig_rsc->id);
    colocated_rscs = g_list_prepend(colocated_rscs, (gpointer) rsc);

    // Follow colocations where this resource is the dependent resource
    colocations = pcmk__this_with_colocations(rsc);
    for (iter = colocations; iter != NULL; iter = iter->next) {
        const pcmk__colocation_t *constraint = iter->data;
        const pe_resource_t *primary = constraint->primary;

        if (primary == orig_rsc) {
            continue; // Break colocation loop
        }

        if ((constraint->score == INFINITY) &&
            (pcmk__colocation_affects(rsc, primary, constraint,
                                      true) == pcmk__coloc_affects_location)) {

            colocated_rscs = primary->cmds->colocated_resources(primary,
                                                                orig_rsc,
                                                                colocated_rscs);
        }
    }
    g_list_free(colocations);

    // Follow colocations where this resource is the primary resource
    colocations = pcmk__with_this_colocations(rsc);
    for (iter = colocations; iter != NULL; iter = iter->next) {
        const pcmk__colocation_t *constraint = iter->data;
        const pe_resource_t *dependent = constraint->dependent;

        if (dependent == orig_rsc) {
            continue; // Break colocation loop
        }

        if (pe_rsc_is_clone(rsc) && !pe_rsc_is_clone(dependent)) {
            continue; // We can't be sure whether dependent will be colocated
        }

        if ((constraint->score == INFINITY) &&
            (pcmk__colocation_affects(dependent, rsc, constraint,
                                      true) == pcmk__coloc_affects_location)) {

            colocated_rscs = dependent->cmds->colocated_resources(dependent,
                                                                  orig_rsc,
                                                                  colocated_rscs);
        }
    }
    g_list_free(colocations);

    return colocated_rscs;
}

// No-op function for variants that don't need to implement add_graph_meta()
void
pcmk__noop_add_graph_meta(const pe_resource_t *rsc, xmlNode *xml)
{
}

void
pcmk__output_resource_actions(pe_resource_t *rsc)
{
    pcmk__output_t *out = rsc->cluster->priv;

    pe_node_t *next = NULL;
    pe_node_t *current = NULL;

    if (rsc->children != NULL) {
        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *) iter->data;

            child->cmds->output_actions(child);
        }
        return;
    }

    next = rsc->allocated_to;
    if (rsc->running_on) {
        current = pe__current_node(rsc);
        if (rsc->role == RSC_ROLE_STOPPED) {
            /* This can occur when resources are being recovered because
             * the current role can change in pcmk__primitive_create_actions()
             */
            rsc->role = RSC_ROLE_STARTED;
        }
    }

    if ((current == NULL) && pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        /* Don't log stopped orphans */
        return;
    }

    out->message(out, "rsc-action", rsc, current, next);
}

/*!
 * \internal
 * \brief Assign a specified primitive resource to a node
 *
 * Assign a specified primitive resource to a specified node, if the node can
 * run the resource (or unconditionally, if \p force is true). Mark the resource
 * as no longer provisional. If the primitive can't be assigned (or \p chosen is
 * NULL), unassign any previous assignment for it, set its next role to stopped,
 * and update any existing actions scheduled for it. This is not done
 * recursively for children, so it should be called only for primitives.
 *
 * \param[in,out] rsc     Resource to assign
 * \param[in,out] chosen  Node to assign \p rsc to
 * \param[in]     force   If true, assign to \p chosen even if unavailable
 *
 * \return true if \p rsc could be assigned, otherwise false
 *
 * \note Assigning a resource to the NULL node using this function is different
 *       from calling pcmk__unassign_resource(), in that it will also update any
 *       actions created for the resource.
 */
bool
pcmk__finalize_assignment(pe_resource_t *rsc, pe_node_t *chosen, bool force)
{
    pcmk__output_t *out = rsc->cluster->priv;

    CRM_ASSERT(rsc->variant == pe_native);

    if (!force && (chosen != NULL)) {
        if ((chosen->weight < 0)
            // Allow the graph to assume that guest node connections will come up
            || (!pcmk__node_available(chosen, true, false)
                && !pe__is_guest_node(chosen))) {

            crm_debug("All nodes for resource %s are unavailable, unclean or "
                      "shutting down (%s can%s run resources, with weight %d)",
                      rsc->id, pe__node_name(chosen),
                      (pcmk__node_available(chosen, true, false)? "" : "not"),
                      chosen->weight);
            pe__set_next_role(rsc, RSC_ROLE_STOPPED, "node availability");
            chosen = NULL;
        }
    }

    pcmk__unassign_resource(rsc);
    pe__clear_resource_flags(rsc, pe_rsc_provisional);

    if (chosen == NULL) {
        crm_debug("Could not allocate a node for %s", rsc->id);
        pe__set_next_role(rsc, RSC_ROLE_STOPPED, "unable to allocate");

        for (GList *iter = rsc->actions; iter != NULL; iter = iter->next) {
            pe_action_t *op = (pe_action_t *) iter->data;

            crm_debug("Updating %s for allocation failure", op->uuid);

            if (pcmk__str_eq(op->task, RSC_STOP, pcmk__str_casei)) {
                pe__clear_action_flags(op, pe_action_optional);

            } else if (pcmk__str_eq(op->task, RSC_START, pcmk__str_casei)) {
                pe__clear_action_flags(op, pe_action_runnable);
                //pe__set_resource_flags(rsc, pe_rsc_block);

            } else {
                // Cancel recurring actions, unless for stopped state
                const char *interval_ms_s = NULL;
                const char *target_rc_s = NULL;
                char *rc_stopped = pcmk__itoa(PCMK_OCF_NOT_RUNNING);

                interval_ms_s = g_hash_table_lookup(op->meta,
                                                    XML_LRM_ATTR_INTERVAL_MS);
                target_rc_s = g_hash_table_lookup(op->meta,
                                                  XML_ATTR_TE_TARGET_RC);
                if ((interval_ms_s != NULL)
                    && !pcmk__str_eq(interval_ms_s, "0", pcmk__str_none)
                    && !pcmk__str_eq(rc_stopped, target_rc_s, pcmk__str_none)) {
                    pe__clear_action_flags(op, pe_action_runnable);
                }
                free(rc_stopped);
            }
        }
        return false;
    }

    crm_debug("Assigning %s to %s", rsc->id, pe__node_name(chosen));
    rsc->allocated_to = pe__copy_node(chosen);

    chosen->details->allocated_rsc = g_list_prepend(chosen->details->allocated_rsc,
                                                    rsc);
    chosen->details->num_resources++;
    chosen->count++;
    pcmk__consume_node_capacity(chosen->details->utilization, rsc);

    if (pcmk_is_set(rsc->cluster->flags, pe_flag_show_utilization)) {
        out->message(out, "resource-util", rsc, chosen, __func__);
    }
    return true;
}

/*!
 * \internal
 * \brief Assign a specified resource (of any variant) to a node
 *
 * Assign a specified resource and its children (if any) to a specified node, if
 * the node can run the resource (or unconditionally, if \p force is true). Mark
 * the resources as no longer provisional. If the resources can't be assigned
 * (or \p chosen is NULL), unassign any previous assignments, set next role to
 * stopped, and update any existing actions scheduled for them.
 *
 * \param[in,out] rsc     Resource to assign
 * \param[in,out] chosen  Node to assign \p rsc to
 * \param[in]     force   If true, assign to \p chosen even if unavailable
 *
 * \return true if \p rsc could be assigned, otherwise false
 *
 * \note Assigning a resource to the NULL node using this function is different
 *       from calling pcmk__unassign_resource(), in that it will also update any
 *       actions created for the resource.
 */
bool
pcmk__assign_resource(pe_resource_t *rsc, pe_node_t *node, bool force)
{
    bool changed = false;

    if (rsc->children == NULL) {
        if (rsc->allocated_to != NULL) {
            changed = true;
        }
        pcmk__finalize_assignment(rsc, node, force);

    } else {
        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) iter->data;

            changed |= pcmk__assign_resource(child_rsc, node, force);
        }
    }
    return changed;
}

/*!
 * \internal
 * \brief Remove any assignment of a specified resource to a node
 *
 * If a specified resource has been assigned to a node, remove that assignment
 * and mark the resource as provisional again. This is not done recursively for
 * children, so it should be called only for primitives.
 *
 * \param[in,out] rsc  Resource to unassign
 */
void
pcmk__unassign_resource(pe_resource_t *rsc)
{
    pe_node_t *old = rsc->allocated_to;

    if (old == NULL) {
        return;
    }

    crm_info("Unassigning %s from %s", rsc->id, pe__node_name(old));
    pe__set_resource_flags(rsc, pe_rsc_provisional);
    rsc->allocated_to = NULL;

    /* We're going to free the pe_node_t, but its details member is shared and
     * will remain, so update that appropriately first.
     */
    old->details->allocated_rsc = g_list_remove(old->details->allocated_rsc,
                                                rsc);
    old->details->num_resources--;
    pcmk__release_node_capacity(old->details->utilization, rsc);
    free(old);
}

/*!
 * \internal
 * \brief Check whether a resource has reached its migration threshold on a node
 *
 * \param[in,out] rsc       Resource to check
 * \param[in]     node      Node to check
 * \param[out]    failed    If threshold has been reached, this will be set to
 *                          resource that failed (possibly a parent of \p rsc)
 *
 * \return true if the migration threshold has been reached, false otherwise
 */
bool
pcmk__threshold_reached(pe_resource_t *rsc, const pe_node_t *node,
                        pe_resource_t **failed)
{
    int fail_count, remaining_tries;
    pe_resource_t *rsc_to_ban = rsc;

    // Migration threshold of 0 means never force away
    if (rsc->migration_threshold == 0) {
        return false;
    }

    // If we're ignoring failures, also ignore the migration threshold
    if (pcmk_is_set(rsc->flags, pe_rsc_failure_ignored)) {
        return false;
    }

    // If there are no failures, there's no need to force away
    fail_count = pe_get_failcount(node, rsc, NULL,
                                  pe_fc_effective|pe_fc_fillers, NULL);
    if (fail_count <= 0) {
        return false;
    }

    // If failed resource is anonymous clone instance, we'll force clone away
    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        rsc_to_ban = uber_parent(rsc);
    }

    // How many more times recovery will be tried on this node
    remaining_tries = rsc->migration_threshold - fail_count;

    if (remaining_tries <= 0) {
        crm_warn("%s cannot run on %s due to reaching migration threshold "
                 "(clean up resource to allow again)"
                 CRM_XS " failures=%d migration-threshold=%d",
                 rsc_to_ban->id, pe__node_name(node), fail_count,
                 rsc->migration_threshold);
        if (failed != NULL) {
            *failed = rsc_to_ban;
        }
        return true;
    }

    crm_info("%s can fail %d more time%s on "
             "%s before reaching migration threshold (%d)",
             rsc_to_ban->id, remaining_tries, pcmk__plural_s(remaining_tries),
             pe__node_name(node), rsc->migration_threshold);
    return false;
}

static void *
convert_const_pointer(const void *ptr)
{
    /* Worst function ever */
    return (void *)ptr;
}

/*!
 * \internal
 * \brief Get a node's weight
 *
 * \param[in] node     Unweighted node to check (for node ID)
 * \param[in] nodes    List of weighted nodes to look for \p node in
 *
 * \return Node's weight, or -INFINITY if not found
 */
static int
get_node_weight(const pe_node_t *node, GHashTable *nodes)
{
    pe_node_t *weighted_node = NULL;

    if ((node != NULL) && (nodes != NULL)) {
        weighted_node = g_hash_table_lookup(nodes, node->details->id);
    }
    return (weighted_node == NULL)? -INFINITY : weighted_node->weight;
}

/*!
 * \internal
 * \brief Compare two resources according to which should be allocated first
 *
 * \param[in] a     First resource to compare
 * \param[in] b     Second resource to compare
 * \param[in] data  Sorted list of all nodes in cluster
 *
 * \return -1 if \p a should be allocated before \b, 0 if they are equal,
 *         or +1 if \p a should be allocated after \b
 */
static gint
cmp_resources(gconstpointer a, gconstpointer b, gpointer data)
{
    const pe_resource_t *resource1 = a;
    const pe_resource_t *resource2 = b;
    const GList *nodes = (const GList *) data;

    int rc = 0;
    int r1_weight = -INFINITY;
    int r2_weight = -INFINITY;
    pe_node_t *r1_node = NULL;
    pe_node_t *r2_node = NULL;
    GHashTable *r1_nodes = NULL;
    GHashTable *r2_nodes = NULL;
    const char *reason = NULL;

    // Resources with highest priority should be allocated first
    reason = "priority";
    r1_weight = resource1->priority;
    r2_weight = resource2->priority;
    if (r1_weight > r2_weight) {
        rc = -1;
        goto done;
    }
    if (r1_weight < r2_weight) {
        rc = 1;
        goto done;
    }

    // We need nodes to make any other useful comparisons
    reason = "no node list";
    if (nodes == NULL) {
        goto done;
    }

    // Calculate and log node weights
    resource1->cmds->add_colocated_node_scores(convert_const_pointer(resource1),
                                               resource1->id, &r1_nodes, NULL,
                                               1, pcmk__coloc_select_this_with);
    resource2->cmds->add_colocated_node_scores(convert_const_pointer(resource2),
                                               resource2->id, &r2_nodes, NULL,
                                               1, pcmk__coloc_select_this_with);
    pe__show_node_weights(true, NULL, resource1->id, r1_nodes,
                          resource1->cluster);
    pe__show_node_weights(true, NULL, resource2->id, r2_nodes,
                          resource2->cluster);

    // The resource with highest score on its current node goes first
    reason = "current location";
    if (resource1->running_on != NULL) {
        r1_node = pe__current_node(resource1);
    }
    if (resource2->running_on != NULL) {
        r2_node = pe__current_node(resource2);
    }
    r1_weight = get_node_weight(r1_node, r1_nodes);
    r2_weight = get_node_weight(r2_node, r2_nodes);
    if (r1_weight > r2_weight) {
        rc = -1;
        goto done;
    }
    if (r1_weight < r2_weight) {
        rc = 1;
        goto done;
    }

    // Otherwise a higher weight on any node will do
    reason = "score";
    for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
        const pe_node_t *node = (const pe_node_t *) iter->data;

        r1_weight = get_node_weight(node, r1_nodes);
        r2_weight = get_node_weight(node, r2_nodes);
        if (r1_weight > r2_weight) {
            rc = -1;
            goto done;
        }
        if (r1_weight < r2_weight) {
            rc = 1;
            goto done;
        }
    }

done:
    crm_trace("%s (%d)%s%s %c %s (%d)%s%s: %s",
              resource1->id, r1_weight,
              ((r1_node == NULL)? "" : " on "),
              ((r1_node == NULL)? "" : r1_node->details->id),
              ((rc < 0)? '>' : ((rc > 0)? '<' : '=')),
              resource2->id, r2_weight,
              ((r2_node == NULL)? "" : " on "),
              ((r2_node == NULL)? "" : r2_node->details->id),
              reason);
    if (r1_nodes != NULL) {
        g_hash_table_destroy(r1_nodes);
    }
    if (r2_nodes != NULL) {
        g_hash_table_destroy(r2_nodes);
    }
    return rc;
}

/*!
 * \internal
 * \brief Sort resources in the order they should be allocated to nodes
 *
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__sort_resources(pe_working_set_t *data_set)
{
    GList *nodes = g_list_copy(data_set->nodes);

    nodes = pcmk__sort_nodes(nodes, NULL);
    data_set->resources = g_list_sort_with_data(data_set->resources,
                                                cmp_resources, nodes);
    g_list_free(nodes);
}
