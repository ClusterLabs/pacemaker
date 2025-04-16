/*
 * Copyright 2014-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>
#include <string.h>
#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

// Resource assignment methods by resource variant
static pcmk__assignment_methods_t assignment_methods[] = {
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
        pcmk__clone_create_probe,
        pcmk__clone_internal_constraints,
        pcmk__clone_apply_coloc_score,
        pcmk__colocated_resources,
        pcmk__with_clone_colocations,
        pcmk__clone_with_colocations,
        pcmk__add_colocated_node_scores,
        pcmk__clone_apply_location,
        pcmk__clone_action_flags,
        pcmk__instance_update_ordered_actions,
        pcmk__output_resource_actions,
        pcmk__clone_add_actions_to_graph,
        pcmk__clone_add_graph_meta,
        pcmk__clone_add_utilization,
        pcmk__clone_shutdown_lock,
    },
    {
        pcmk__bundle_assign,
        pcmk__bundle_create_actions,
        pcmk__bundle_create_probe,
        pcmk__bundle_internal_constraints,
        pcmk__bundle_apply_coloc_score,
        pcmk__colocated_resources,
        pcmk__with_bundle_colocations,
        pcmk__bundle_with_colocations,
        pcmk__add_colocated_node_scores,
        pcmk__bundle_apply_location,
        pcmk__bundle_action_flags,
        pcmk__instance_update_ordered_actions,
        pcmk__output_bundle_actions,
        pcmk__bundle_add_actions_to_graph,
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
pcmk__rsc_agent_changed(pcmk_resource_t *rsc, pcmk_node_t *node,
                        const xmlNode *rsc_entry, bool active_on_node)
{
    bool changed = false;
    const char *attr_list[] = {
        PCMK_XA_TYPE,
        PCMK_XA_CLASS,
        PCMK_XA_PROVIDER,
    };

    for (int i = 0; i < PCMK__NELEM(attr_list); i++) {
        const char *value = crm_element_value(rsc->priv->xml, attr_list[i]);
        const char *old_value = crm_element_value(rsc_entry, attr_list[i]);

        if (!pcmk__str_eq(value, old_value, pcmk__str_none)) {
            changed = true;
            trigger_unfencing(rsc, node, "Device definition changed", NULL,
                              rsc->priv->scheduler);
            if (active_on_node) {
                crm_notice("Forcing restart of %s on %s "
                           "because %s changed from '%s' to '%s'",
                           rsc->id, pcmk__node_name(node), attr_list[i],
                           pcmk__s(old_value, ""), pcmk__s(value, ""));
            }
        }
    }
    if (changed && active_on_node) {
        // Make sure the resource is restarted
        custom_action(rsc, stop_key(rsc), PCMK_ACTION_STOP, node, FALSE,
                      rsc->priv->scheduler);
        pcmk__set_rsc_flags(rsc, pcmk__rsc_start_pending);
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
add_rsc_if_matching(GList *result, pcmk_resource_t *rsc, const char *id)
{
    if (pcmk__str_eq(id, rsc->id, pcmk__str_none)
        || pcmk__str_eq(id, rsc->priv->history_id, pcmk__str_none)) {
        result = g_list_prepend(result, rsc);
    }

    for (GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *child = (pcmk_resource_t *) iter->data;

        result = add_rsc_if_matching(result, child, id);
    }
    return result;
}

/*!
 * \internal
 * \brief Find all resources matching a given ID by either ID or clone name
 *
 * \param[in] id         Resource ID to check
 * \param[in] scheduler  Scheduler data
 *
 * \return List of all resources that match \p id
 * \note The caller is responsible for freeing the return value with
 *       g_list_free().
 */
GList *
pcmk__rscs_matching_id(const char *id, const pcmk_scheduler_t *scheduler)
{
    GList *result = NULL;

    CRM_CHECK((id != NULL) && (scheduler != NULL), return NULL);

    for (GList *iter = scheduler->priv->resources;
         iter != NULL; iter = iter->next) {

        result = add_rsc_if_matching(result, (pcmk_resource_t *) iter->data,
                                     id);
    }
    return result;
}

/*!
 * \internal
 * \brief Set the variant-appropriate assignment methods for a resource
 *
 * \param[in,out] data       Resource to set assignment methods for
 * \param[in]     user_data  Ignored
 */
static void
set_assignment_methods_for_rsc(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;

    rsc->priv->cmds = &assignment_methods[rsc->priv->variant];
    g_list_foreach(rsc->priv->children, set_assignment_methods_for_rsc,
                   NULL);
}

/*!
 * \internal
 * \brief Set the variant-appropriate assignment methods for all resources
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__set_assignment_methods(pcmk_scheduler_t *scheduler)
{
    g_list_foreach(scheduler->priv->resources, set_assignment_methods_for_rsc,
                   NULL);
}

/*!
 * \internal
 * \brief Wrapper for colocated_resources() method for readability
 *
 * \param[in]      rsc       Resource to add to colocated list
 * \param[in]      orig_rsc  Resource originally requested
 * \param[in,out]  list      Pointer to list to add to
 *
 * \return (Possibly new) head of list
 */
static inline void
add_colocated_resources(const pcmk_resource_t *rsc,
                        const pcmk_resource_t *orig_rsc, GList **list)
{
    *list = rsc->priv->cmds->colocated_resources(rsc, orig_rsc, *list);
}

// Shared implementation of pcmk__assignment_methods_t:colocated_resources()
GList *
pcmk__colocated_resources(const pcmk_resource_t *rsc,
                          const pcmk_resource_t *orig_rsc,
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

    pcmk__rsc_trace(orig_rsc, "%s is in colocation chain with %s",
                    rsc->id, orig_rsc->id);
    colocated_rscs = g_list_prepend(colocated_rscs, (gpointer) rsc);

    // Follow colocations where this resource is the dependent resource
    colocations = pcmk__this_with_colocations(rsc);
    for (iter = colocations; iter != NULL; iter = iter->next) {
        const pcmk__colocation_t *constraint = iter->data;
        const pcmk_resource_t *primary = constraint->primary;

        if (primary == orig_rsc) {
            continue; // Break colocation loop
        }

        if ((constraint->score == PCMK_SCORE_INFINITY) &&
            (pcmk__colocation_affects(rsc, primary, constraint,
                                      true) == pcmk__coloc_affects_location)) {
            add_colocated_resources(primary, orig_rsc, &colocated_rscs);
        }
    }
    g_list_free(colocations);

    // Follow colocations where this resource is the primary resource
    colocations = pcmk__with_this_colocations(rsc);
    for (iter = colocations; iter != NULL; iter = iter->next) {
        const pcmk__colocation_t *constraint = iter->data;
        const pcmk_resource_t *dependent = constraint->dependent;

        if (dependent == orig_rsc) {
            continue; // Break colocation loop
        }

        if (pcmk__is_clone(rsc) && !pcmk__is_clone(dependent)) {
            continue; // We can't be sure whether dependent will be colocated
        }

        if ((constraint->score == PCMK_SCORE_INFINITY) &&
            (pcmk__colocation_affects(dependent, rsc, constraint,
                                      true) == pcmk__coloc_affects_location)) {
            add_colocated_resources(dependent, orig_rsc, &colocated_rscs);
        }
    }
    g_list_free(colocations);

    return colocated_rscs;
}

// No-op function for variants that don't need to implement add_graph_meta()
void
pcmk__noop_add_graph_meta(const pcmk_resource_t *rsc, xmlNode *xml)
{
}

/*!
 * \internal
 * \brief Output a summary of scheduled actions for a resource
 *
 * \param[in,out] rsc  Resource to output actions for
 */
void
pcmk__output_resource_actions(pcmk_resource_t *rsc)
{
    pcmk_node_t *next = NULL;
    pcmk_node_t *current = NULL;
    pcmk__output_t *out = NULL;

    pcmk__assert(rsc != NULL);

    out = rsc->priv->scheduler->priv->out;
    if (rsc->priv->children != NULL) {

        for (GList *iter = rsc->priv->children;
             iter != NULL; iter = iter->next) {

            pcmk_resource_t *child = (pcmk_resource_t *) iter->data;

            child->priv->cmds->output_actions(child);
        }
        return;
    }

    next = rsc->priv->assigned_node;
    if (rsc->priv->active_nodes != NULL) {
        current = pcmk__current_node(rsc);
        if (rsc->priv->orig_role == pcmk_role_stopped) {
            /* This can occur when resources are being recovered because
             * the current role can change in pcmk__primitive_create_actions()
             */
            rsc->priv->orig_role = pcmk_role_started;
        }
    }

    if ((current == NULL) && pcmk_is_set(rsc->flags, pcmk__rsc_removed)) {
        /* Don't log stopped orphans */
        return;
    }

    out->message(out, "rsc-action", rsc, current, next);
}

/*!
 * \internal
 * \brief Add a resource to a node's list of assigned resources
 *
 * \param[in,out] node  Node to add resource to
 * \param[in]     rsc   Resource to add
 */
static inline void
add_assigned_resource(pcmk_node_t *node, pcmk_resource_t *rsc)
{
    node->priv->assigned_resources =
        g_list_prepend(node->priv->assigned_resources, rsc);
}

/*!
 * \internal
 * \brief Assign a specified resource (of any variant) to a node
 *
 * Assign a specified resource and its children (if any) to a specified node, if
 * the node can run the resource (or unconditionally, if \p force is true). Mark
 * the resources as no longer provisional.
 *
 * If a resource can't be assigned (or \p node is \c NULL), unassign any
 * previous assignment. If \p stop_if_fail is \c true, set next role to stopped
 * and update any existing actions scheduled for the resource.
 *
 * \param[in,out] rsc           Resource to assign
 * \param[in,out] node          Node to assign \p rsc to
 * \param[in]     force         If true, assign to \p node even if unavailable
 * \param[in]     stop_if_fail  If \c true and either \p rsc can't be assigned
 *                              or \p chosen is \c NULL, set next role to
 *                              stopped and update existing actions (if \p rsc
 *                              is not a primitive, this applies to its
 *                              primitive descendants instead)
 *
 * \return \c true if the assignment of \p rsc changed, or \c false otherwise
 *
 * \note Assigning a resource to the NULL node using this function is different
 *       from calling pcmk__unassign_resource(), in that it may also update any
 *       actions created for the resource.
 * \note The \c pcmk__assignment_methods_t:assign() method is preferred, unless
 *       a resource should be assigned to the \c NULL node or every resource in
 *       a tree should be assigned to the same node.
 * \note If \p stop_if_fail is \c false, then \c pcmk__unassign_resource() can
 *       completely undo the assignment. A successful assignment can be either
 *       undone or left alone as final. A failed assignment has the same effect
 *       as calling pcmk__unassign_resource(); there are no side effects on
 *       roles or actions.
 */
bool
pcmk__assign_resource(pcmk_resource_t *rsc, pcmk_node_t *node, bool force,
                      bool stop_if_fail)
{
    bool changed = false;
    pcmk_scheduler_t *scheduler = NULL;

    pcmk__assert(rsc != NULL);
    scheduler = rsc->priv->scheduler;

    if (rsc->priv->children != NULL) {

        for (GList *iter = rsc->priv->children;
             iter != NULL; iter = iter->next) {

            pcmk_resource_t *child_rsc = iter->data;

            changed |= pcmk__assign_resource(child_rsc, node, force,
                                             stop_if_fail);
        }
        return changed;
    }

    // Assigning a primitive

    if (!force && (node != NULL)
        // Allow graph to assume that guest node connections will come up
        && !pcmk__node_available(node, pcmk__node_alive
                                       |pcmk__node_usable
                                       |pcmk__node_no_banned
                                       |pcmk__node_exempt_guest)) {

        pcmk__rsc_debug(rsc,
                        "All nodes for resource %s are unavailable, unclean or "
                        "shutting down (preferring %s @ %s)",
                        rsc->id, pcmk__node_name(node),
                        pcmk_readable_score(node->assign->score));
        if (stop_if_fail) {
            pe__set_next_role(rsc, pcmk_role_stopped, "node availability");
        }
        node = NULL;
    }

    if (rsc->priv->assigned_node != NULL) {
        changed = !pcmk__same_node(rsc->priv->assigned_node, node);
    } else {
        changed = (node != NULL);
    }
    pcmk__unassign_resource(rsc);
    pcmk__clear_rsc_flags(rsc, pcmk__rsc_unassigned);

    if (node == NULL) {
        char *rc_stopped = NULL;

        pcmk__rsc_debug(rsc, "Could not assign %s to a node", rsc->id);

        if (!stop_if_fail) {
            return changed;
        }
        pe__set_next_role(rsc, pcmk_role_stopped, "unable to assign");

        for (GList *iter = rsc->priv->actions;
             iter != NULL; iter = iter->next) {

            pcmk_action_t *op = (pcmk_action_t *) iter->data;

            pcmk__rsc_debug(rsc, "Updating %s for %s assignment failure",
                            op->uuid, rsc->id);

            if (pcmk__str_eq(op->task, PCMK_ACTION_STOP, pcmk__str_none)) {
                pcmk__clear_action_flags(op, pcmk__action_optional);

            } else if (pcmk__str_eq(op->task, PCMK_ACTION_START,
                                    pcmk__str_none)) {
                pcmk__clear_action_flags(op, pcmk__action_runnable);

            } else {
                // Cancel recurring actions, unless for stopped state
                const char *interval_ms_s = NULL;
                const char *target_rc_s = NULL;

                interval_ms_s = g_hash_table_lookup(op->meta,
                                                    PCMK_META_INTERVAL);
                target_rc_s = g_hash_table_lookup(op->meta,
                                                  PCMK__META_OP_TARGET_RC);
                if (rc_stopped == NULL) {
                    rc_stopped = pcmk__itoa(PCMK_OCF_NOT_RUNNING);
                }

                if (!pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches)
                    && !pcmk__str_eq(rc_stopped, target_rc_s, pcmk__str_none)) {

                    pcmk__clear_action_flags(op, pcmk__action_runnable);
                }
            }
        }
        free(rc_stopped);
        return changed;
    }

    pcmk__rsc_debug(rsc, "Assigning %s to %s", rsc->id, pcmk__node_name(node));
    rsc->priv->assigned_node = pe__copy_node(node);

    add_assigned_resource(node, rsc);
    node->priv->num_resources++;
    node->assign->count++;
    pcmk__consume_node_capacity(node->priv->utilization, rsc);

    if (pcmk_is_set(scheduler->flags, pcmk__sched_show_utilization)) {
        pcmk__output_t *out = scheduler->priv->out;

        out->message(out, "resource-util", rsc, node, __func__);
    }
    return changed;
}

/*!
 * \internal
 * \brief Remove any node assignment from a specified resource and its children
 *
 * If a specified resource has been assigned to a node, remove that assignment
 * and mark the resource as provisional again.
 *
 * \param[in,out] rsc  Resource to unassign
 *
 * \note This function is called recursively on \p rsc and its children.
 */
void
pcmk__unassign_resource(pcmk_resource_t *rsc)
{
    pcmk_node_t *old = rsc->priv->assigned_node;

    if (old == NULL) {
        crm_info("Unassigning %s", rsc->id);
    } else {
        crm_info("Unassigning %s from %s", rsc->id, pcmk__node_name(old));
    }

    pcmk__set_rsc_flags(rsc, pcmk__rsc_unassigned);

    if (rsc->priv->children == NULL) {
        if (old == NULL) {
            return;
        }
        rsc->priv->assigned_node = NULL;

        /* We're going to free the pcmk_node_t copy, but its priv member is
         * shared and will remain, so update that appropriately first.
         */
        old->priv->assigned_resources =
            g_list_remove(old->priv->assigned_resources, rsc);
        old->priv->num_resources--;
        pcmk__release_node_capacity(old->priv->utilization, rsc);
        pcmk__free_node_copy(old);
        return;
    }

    for (GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk__unassign_resource((pcmk_resource_t *) iter->data);
    }
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
pcmk__threshold_reached(pcmk_resource_t *rsc, const pcmk_node_t *node,
                        pcmk_resource_t **failed)
{
    int fail_count, remaining_tries;
    pcmk_resource_t *rsc_to_ban = rsc;

    // Migration threshold of 0 means never force away
    if (rsc->priv->ban_after_failures == 0) {
        return false;
    }

    // If we're ignoring failures, also ignore the migration threshold
    if (pcmk_is_set(rsc->flags, pcmk__rsc_ignore_failure)) {
        return false;
    }

    // If there are no failures, there's no need to force away
    fail_count = pe_get_failcount(node, rsc, NULL,
                                  pcmk__fc_effective|pcmk__fc_launched, NULL);
    if (fail_count <= 0) {
        return false;
    }

    // If failed resource is anonymous clone instance, we'll force clone away
    if (!pcmk_is_set(rsc->flags, pcmk__rsc_unique)) {
        rsc_to_ban = uber_parent(rsc);
    }

    // How many more times recovery will be tried on this node
    remaining_tries = rsc->priv->ban_after_failures - fail_count;

    if (remaining_tries <= 0) {
        pcmk__sched_warn(rsc->priv->scheduler,
                         "%s cannot run on %s due to reaching migration "
                         "threshold (clean up resource to allow again) "
                         QB_XS " failures=%d "
                         PCMK_META_MIGRATION_THRESHOLD "=%d",
                         rsc_to_ban->id, pcmk__node_name(node), fail_count,
                         rsc->priv->ban_after_failures);
        if (failed != NULL) {
            *failed = rsc_to_ban;
        }
        return true;
    }

    crm_info("%s can fail %d more time%s on "
             "%s before reaching migration threshold (%d)",
             rsc_to_ban->id, remaining_tries, pcmk__plural_s(remaining_tries),
             pcmk__node_name(node), rsc->priv->ban_after_failures);
    return false;
}

/*!
 * \internal
 * \brief Get a node's score
 *
 * \param[in] node     Node with ID to check
 * \param[in] nodes    List of nodes to look for \p node score in
 *
 * \return Node's score, or -INFINITY if not found
 */
static int
get_node_score(const pcmk_node_t *node, GHashTable *nodes)
{
    pcmk_node_t *found_node = NULL;

    if ((node != NULL) && (nodes != NULL)) {
        found_node = g_hash_table_lookup(nodes, node->priv->id);
    }
    if (found_node == NULL) {
        return -PCMK_SCORE_INFINITY;
    }
    return found_node->assign->score;
}

/*!
 * \internal
 * \brief Compare two resources according to which should be assigned first
 *
 * \param[in] a     First resource to compare
 * \param[in] b     Second resource to compare
 * \param[in] data  Sorted list of all nodes in cluster
 *
 * \return -1 if \p a should be assigned before \b, 0 if they are equal,
 *         or +1 if \p a should be assigned after \b
 */
static gint
cmp_resources(gconstpointer a, gconstpointer b, gpointer data)
{
    /* GLib insists that this function require gconstpointer arguments, but we
     * make a small, temporary change to each argument (setting the
     * pe_rsc_merging flag) during comparison
     */
    pcmk_resource_t *resource1 = (pcmk_resource_t *) a;
    pcmk_resource_t *resource2 = (pcmk_resource_t *) b;
    const GList *nodes = data;

    int rc = 0;
    int r1_score = -PCMK_SCORE_INFINITY;
    int r2_score = -PCMK_SCORE_INFINITY;
    pcmk_node_t *r1_node = NULL;
    pcmk_node_t *r2_node = NULL;
    GHashTable *r1_nodes = NULL;
    GHashTable *r2_nodes = NULL;
    const char *reason = NULL;

    // Resources with highest priority should be assigned first
    reason = "priority";
    r1_score = resource1->priv->priority;
    r2_score = resource2->priv->priority;
    if (r1_score > r2_score) {
        rc = -1;
        goto done;
    }
    if (r1_score < r2_score) {
        rc = 1;
        goto done;
    }

    // We need nodes to make any other useful comparisons
    reason = "no node list";
    if (nodes == NULL) {
        goto done;
    }

    // Calculate and log node scores
    resource1->priv->cmds->add_colocated_node_scores(resource1, NULL,
                                                     resource1->id,
                                                     &r1_nodes, NULL, 1,
                                                     pcmk__coloc_select_this_with);
    resource2->priv->cmds->add_colocated_node_scores(resource2, NULL,
                                                     resource2->id,
                                                     &r2_nodes, NULL, 1,
                                                     pcmk__coloc_select_this_with);
    pe__show_node_scores(true, NULL, resource1->id, r1_nodes,
                         resource1->priv->scheduler);
    pe__show_node_scores(true, NULL, resource2->id, r2_nodes,
                         resource2->priv->scheduler);

    // The resource with highest score on its current node goes first
    reason = "current location";
    if (resource1->priv->active_nodes != NULL) {
        r1_node = pcmk__current_node(resource1);
    }
    if (resource2->priv->active_nodes != NULL) {
        r2_node = pcmk__current_node(resource2);
    }
    r1_score = get_node_score(r1_node, r1_nodes);
    r2_score = get_node_score(r2_node, r2_nodes);
    if (r1_score > r2_score) {
        rc = -1;
        goto done;
    }
    if (r1_score < r2_score) {
        rc = 1;
        goto done;
    }

    // Otherwise a higher score on any node will do
    reason = "score";
    for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
        const pcmk_node_t *node = (const pcmk_node_t *) iter->data;

        r1_score = get_node_score(node, r1_nodes);
        r2_score = get_node_score(node, r2_nodes);
        if (r1_score > r2_score) {
            rc = -1;
            goto done;
        }
        if (r1_score < r2_score) {
            rc = 1;
            goto done;
        }
    }

done:
    crm_trace("%s (%d)%s%s %c %s (%d)%s%s: %s",
              resource1->id, r1_score,
              ((r1_node == NULL)? "" : " on "),
              ((r1_node == NULL)? "" : r1_node->priv->id),
              ((rc < 0)? '>' : ((rc > 0)? '<' : '=')),
              resource2->id, r2_score,
              ((r2_node == NULL)? "" : " on "),
              ((r2_node == NULL)? "" : r2_node->priv->id),
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
 * \brief Sort resources in the order they should be assigned to nodes
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__sort_resources(pcmk_scheduler_t *scheduler)
{
    GList *nodes = g_list_copy(scheduler->nodes);

    nodes = pcmk__sort_nodes(nodes, NULL);
    scheduler->priv->resources =
        g_list_sort_with_data(scheduler->priv->resources, cmp_resources, nodes);
    g_list_free(nodes);
}
