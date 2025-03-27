/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <libxml/tree.h>            // xmlNode

#include <crm/common/scores.h>      // PCMK_SCORE_INFINITY
#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

struct assign_data {
    const pcmk_node_t *prefer;
    bool stop_if_fail;
};

/*!
 * \internal
 * \brief Assign a single bundle replica's resources (other than container)
 *
 * \param[in,out] replica    Replica to assign
 * \param[in]     user_data  Preferred node, if any
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
assign_replica(pcmk__bundle_replica_t *replica, void *user_data)
{
    pcmk_node_t *container_host = NULL;

    struct assign_data *assign_data = user_data;
    const pcmk_node_t *prefer = assign_data->prefer;
    bool stop_if_fail = assign_data->stop_if_fail;

    const pcmk_resource_t *bundle = pe__const_top_resource(replica->container,
                                                           true);

    if (replica->ip != NULL) {
        pcmk__rsc_trace(bundle, "Assigning bundle %s IP %s",
                        bundle->id, replica->ip->id);
        replica->ip->priv->cmds->assign(replica->ip, prefer, stop_if_fail);
    }

    container_host = replica->container->priv->assigned_node;
    if (replica->remote != NULL) {
        if (pcmk__is_pacemaker_remote_node(container_host)) {
            /* REMOTE_CONTAINER_HACK: "Nested" connection resources must be on
             * the same host because Pacemaker Remote only supports a single
             * active connection.
             */
            pcmk__new_colocation("#replica-remote-with-host-remote", NULL,
                                 PCMK_SCORE_INFINITY, replica->remote,
                                 container_host->priv->remote, NULL,
                                 NULL, pcmk__coloc_influence);
        }
        pcmk__rsc_trace(bundle, "Assigning bundle %s connection %s",
                        bundle->id, replica->remote->id);
        replica->remote->priv->cmds->assign(replica->remote, prefer,
                                            stop_if_fail);
    }

    if (replica->child != NULL) {
        pcmk_node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, replica->child->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (!pcmk__same_node(node, replica->node)) {
                node->assign->score = -PCMK_SCORE_INFINITY;
            } else if (!pcmk__threshold_reached(replica->child, node, NULL)) {
                node->assign->score = PCMK_SCORE_INFINITY;
            }
        }

        pcmk__set_rsc_flags(replica->child->priv->parent,
                            pcmk__rsc_assigning);
        pcmk__rsc_trace(bundle, "Assigning bundle %s replica child %s",
                        bundle->id, replica->child->id);
        replica->child->priv->cmds->assign(replica->child, replica->node,
                                           stop_if_fail);
        pcmk__clear_rsc_flags(replica->child->priv->parent,
                              pcmk__rsc_assigning);
    }
    return true;
}

/*!
 * \internal
 * \brief Assign a bundle resource to a node
 *
 * \param[in,out] rsc           Resource to assign to a node
 * \param[in]     prefer        Node to prefer, if all else is equal
 * \param[in]     stop_if_fail  If \c true and a primitive descendant of \p rsc
 *                              can't be assigned to a node, set the
 *                              descendant's next role to stopped and update
 *                              existing actions
 *
 * \return Node that \p rsc is assigned to, if assigned entirely to one node
 *
 * \note If \p stop_if_fail is \c false, then \c pcmk__unassign_resource() can
 *       completely undo the assignment. A successful assignment can be either
 *       undone or left alone as final. A failed assignment has the same effect
 *       as calling pcmk__unassign_resource(); there are no side effects on
 *       roles or actions.
 */
pcmk_node_t *
pcmk__bundle_assign(pcmk_resource_t *rsc, const pcmk_node_t *prefer,
                    bool stop_if_fail)
{
    GList *containers = NULL;
    pcmk_resource_t *bundled_resource = NULL;
    struct assign_data assign_data = { prefer, stop_if_fail };

    pcmk__assert(pcmk__is_bundle(rsc));

    pcmk__rsc_trace(rsc, "Assigning bundle %s", rsc->id);
    pcmk__set_rsc_flags(rsc, pcmk__rsc_assigning);

    pe__show_node_scores(!pcmk__is_set(rsc->priv->scheduler->flags,
                                       pcmk__sched_output_scores),
                         rsc, __func__, rsc->priv->allowed_nodes,
                         rsc->priv->scheduler);

    // Assign all containers first, so we know what nodes the bundle will be on
    containers = g_list_sort(pe__bundle_containers(rsc), pcmk__cmp_instance);
    pcmk__assign_instances(rsc, containers, pe__bundle_max(rsc),
                           rsc->priv->fns->max_per_node(rsc));
    g_list_free(containers);

    // Then assign remaining replica resources
    pe__foreach_bundle_replica(rsc, assign_replica, (void *) &assign_data);

    // Finally, assign the bundled resources to each bundle node
    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource != NULL) {
        pcmk_node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, bundled_resource->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
            if (pe__node_is_bundle_instance(rsc, node)) {
                node->assign->score = 0;
            } else {
                node->assign->score = -PCMK_SCORE_INFINITY;
            }
        }
        bundled_resource->priv->cmds->assign(bundled_resource, prefer,
                                                stop_if_fail);
    }

    pcmk__clear_rsc_flags(rsc, pcmk__rsc_assigning|pcmk__rsc_unassigned);
    return NULL;
}

/*!
 * \internal
 * \brief Create actions for a bundle replica's resources (other than child)
 *
 * \param[in,out] replica    Replica to create actions for
 * \param[in]     user_data  Unused
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
create_replica_actions(pcmk__bundle_replica_t *replica, void *user_data)
{
    if (replica->ip != NULL) {
        replica->ip->priv->cmds->create_actions(replica->ip);
    }
    if (replica->container != NULL) {
        replica->container->priv->cmds->create_actions(replica->container);
    }
    if (replica->remote != NULL) {
        replica->remote->priv->cmds->create_actions(replica->remote);
    }
    return true;
}

/*!
 * \internal
 * \brief Create all actions needed for a given bundle resource
 *
 * \param[in,out] rsc  Bundle resource to create actions for
 */
void
pcmk__bundle_create_actions(pcmk_resource_t *rsc)
{
    pcmk_action_t *action = NULL;
    GList *containers = NULL;
    pcmk_resource_t *bundled_resource = NULL;

    pcmk__assert(pcmk__is_bundle(rsc));

    pe__foreach_bundle_replica(rsc, create_replica_actions, NULL);

    containers = pe__bundle_containers(rsc);
    pcmk__create_instance_actions(rsc, containers);
    g_list_free(containers);

    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource != NULL) {
        bundled_resource->priv->cmds->create_actions(bundled_resource);

        if (pcmk__is_set(bundled_resource->flags, pcmk__rsc_promotable)) {
            pe__new_rsc_pseudo_action(rsc, PCMK_ACTION_PROMOTE, true, true);
            action = pe__new_rsc_pseudo_action(rsc, PCMK_ACTION_PROMOTED,
                                               true, true);
            action->priority = PCMK_SCORE_INFINITY;

            pe__new_rsc_pseudo_action(rsc, PCMK_ACTION_DEMOTE, true, true);
            action = pe__new_rsc_pseudo_action(rsc, PCMK_ACTION_DEMOTED,
                                               true, true);
            action->priority = PCMK_SCORE_INFINITY;
        }
    }
}

/*!
 * \internal
 * \brief Create internal constraints for a bundle replica's resources
 *
 * \param[in,out] replica    Replica to create internal constraints for
 * \param[in,out] user_data  Replica's parent bundle
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
replica_internal_constraints(pcmk__bundle_replica_t *replica, void *user_data)
{
    pcmk_resource_t *bundle = user_data;

    replica->container->priv->cmds->internal_constraints(replica->container);

    // Start bundle -> start replica container
    pcmk__order_starts(bundle, replica->container,
                       pcmk__ar_unrunnable_first_blocks
                       |pcmk__ar_then_implies_first_graphed);

    // Stop bundle -> stop replica child and container
    if (replica->child != NULL) {
        pcmk__order_stops(bundle, replica->child,
                          pcmk__ar_then_implies_first_graphed);
    }
    pcmk__order_stops(bundle, replica->container,
                      pcmk__ar_then_implies_first_graphed);

    // Start replica container -> bundle is started
    pcmk__order_resource_actions(replica->container, PCMK_ACTION_START, bundle,
                                 PCMK_ACTION_RUNNING,
                                 pcmk__ar_first_implies_then_graphed);

    // Stop replica container -> bundle is stopped
    pcmk__order_resource_actions(replica->container, PCMK_ACTION_STOP, bundle,
                                 PCMK_ACTION_STOPPED,
                                 pcmk__ar_first_implies_then_graphed);

    if (replica->ip != NULL) {
        replica->ip->priv->cmds->internal_constraints(replica->ip);

        // Replica IP address -> replica container (symmetric)
        pcmk__order_starts(replica->ip, replica->container,
                           pcmk__ar_unrunnable_first_blocks
                           |pcmk__ar_guest_allowed);
        pcmk__order_stops(replica->container, replica->ip,
                          pcmk__ar_then_implies_first|pcmk__ar_guest_allowed);

        pcmk__new_colocation("#ip-with-container", NULL, PCMK_SCORE_INFINITY,
                             replica->ip, replica->container, NULL, NULL,
                             pcmk__coloc_influence);
    }

    if (replica->remote != NULL) {
        /* This handles ordering and colocating remote relative to container
         * (via "#resource-with-container"). Since IP is also ordered and
         * colocated relative to the container, we don't need to do anything
         * explicit here with IP.
         */
        replica->remote->priv->cmds->internal_constraints(replica->remote);
    }

    if (replica->child != NULL) {
        pcmk__assert(replica->remote != NULL);
        // "Start remote then child" is implicit in scheduler's remote logic
    }
    return true;
}

/*!
 * \internal
 * \brief Create implicit constraints needed for a bundle resource
 *
 * \param[in,out] rsc  Bundle resource to create implicit constraints for
 */
void
pcmk__bundle_internal_constraints(pcmk_resource_t *rsc)
{
    pcmk_resource_t *bundled_resource = NULL;

    pcmk__assert(pcmk__is_bundle(rsc));

    pe__foreach_bundle_replica(rsc, replica_internal_constraints, rsc);

    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource == NULL) {
        return;
    }

    // Start bundle -> start bundled clone
    pcmk__order_resource_actions(rsc, PCMK_ACTION_START, bundled_resource,
                                 PCMK_ACTION_START,
                                 pcmk__ar_then_implies_first_graphed);

    // Bundled clone is started -> bundle is started
    pcmk__order_resource_actions(bundled_resource, PCMK_ACTION_RUNNING,
                                 rsc, PCMK_ACTION_RUNNING,
                                 pcmk__ar_first_implies_then_graphed);

    // Stop bundle -> stop bundled clone
    pcmk__order_resource_actions(rsc, PCMK_ACTION_STOP, bundled_resource,
                                 PCMK_ACTION_STOP,
                                 pcmk__ar_then_implies_first_graphed);

    // Bundled clone is stopped -> bundle is stopped
    pcmk__order_resource_actions(bundled_resource, PCMK_ACTION_STOPPED,
                                 rsc, PCMK_ACTION_STOPPED,
                                 pcmk__ar_first_implies_then_graphed);

    bundled_resource->priv->cmds->internal_constraints(bundled_resource);

    if (!pcmk__is_set(bundled_resource->flags, pcmk__rsc_promotable)) {
        return;
    }
    pcmk__promotable_restart_ordering(rsc);

    // Demote bundle -> demote bundled clone
    pcmk__order_resource_actions(rsc, PCMK_ACTION_DEMOTE, bundled_resource,
                                 PCMK_ACTION_DEMOTE,
                                 pcmk__ar_then_implies_first_graphed);

    // Bundled clone is demoted -> bundle is demoted
    pcmk__order_resource_actions(bundled_resource, PCMK_ACTION_DEMOTED,
                                 rsc, PCMK_ACTION_DEMOTED,
                                 pcmk__ar_first_implies_then_graphed);

    // Promote bundle -> promote bundled clone
    pcmk__order_resource_actions(rsc, PCMK_ACTION_PROMOTE,
                                 bundled_resource, PCMK_ACTION_PROMOTE,
                                 pcmk__ar_then_implies_first_graphed);

    // Bundled clone is promoted -> bundle is promoted
    pcmk__order_resource_actions(bundled_resource, PCMK_ACTION_PROMOTED,
                                 rsc, PCMK_ACTION_PROMOTED,
                                 pcmk__ar_first_implies_then_graphed);
}

struct match_data {
    const pcmk_node_t *node;    // Node to compare against replica
    pcmk_resource_t *container; // Replica container corresponding to node
};

/*!
 * \internal
 * \brief Check whether a replica container is assigned to a given node
 *
 * \param[in]     replica    Replica to check
 * \param[in,out] user_data  struct match_data with node to compare against
 *
 * \return true if the replica does not match (to indicate further replicas
 *         should be processed), otherwise false
 */
static bool
match_replica_container(const pcmk__bundle_replica_t *replica, void *user_data)
{
    struct match_data *match_data = user_data;

    if (pcmk__instance_matches(replica->container, match_data->node,
                               pcmk_role_unknown, false)) {
        match_data->container = replica->container;
        return false; // Match found, don't bother searching further replicas
    }
    return true; // No match, keep searching
}

/*!
 * \internal
 * \brief Get the host to which a bundle node is assigned
 *
 * \param[in] node  Possible bundle node to check
 *
 * \return Node to which the container for \p node is assigned if \p node is a
 *         bundle node, otherwise \p node itself
 */
static const pcmk_node_t *
get_bundle_node_host(const pcmk_node_t *node)
{
    if (pcmk__is_bundle_node(node)) {
        const pcmk_resource_t *container = NULL;

        container = node->priv->remote->priv->launcher;
        return container->priv->fns->location(container, NULL,
                                              pcmk__rsc_node_assigned);
    }
    return node;
}

/*!
 * \internal
 * \brief Find a bundle container compatible with a dependent resource
 *
 * \param[in] dependent  Dependent resource in colocation with bundle
 * \param[in] bundle     Bundle that \p dependent is colocated with
 *
 * \return A container from \p bundle assigned to the same node as \p dependent
 *         if assigned, otherwise assigned to any of dependent's allowed nodes,
 *         otherwise NULL.
 */
static pcmk_resource_t *
compatible_container(const pcmk_resource_t *dependent,
                     const pcmk_resource_t *bundle)
{
    GList *scratch = NULL;
    struct match_data match_data = { NULL, NULL };

    // If dependent is assigned, only check there
    match_data.node = dependent->priv->fns->location(dependent, NULL,
                                                     pcmk__rsc_node_assigned);
    match_data.node = get_bundle_node_host(match_data.node);
    if (match_data.node != NULL) {
        pe__foreach_const_bundle_replica(bundle, match_replica_container,
                                         &match_data);
        return match_data.container;
    }

    // Otherwise, check for any of the dependent's allowed nodes
    scratch = g_hash_table_get_values(dependent->priv->allowed_nodes);
    scratch = pcmk__sort_nodes(scratch, NULL);
    for (const GList *iter = scratch; iter != NULL; iter = iter->next) {
        match_data.node = iter->data;
        match_data.node = get_bundle_node_host(match_data.node);
        if (match_data.node == NULL) {
            continue;
        }

        pe__foreach_const_bundle_replica(bundle, match_replica_container,
                                         &match_data);
        if (match_data.container != NULL) {
            break;
        }
    }
    g_list_free(scratch);
    return match_data.container;
}

struct coloc_data {
    const pcmk__colocation_t *colocation;
    pcmk_resource_t *dependent;
    GList *container_hosts;
    int priority_delta;
};

/*!
 * \internal
 * \brief Apply a colocation score to replica node scores or resource priority
 *
 * \param[in]     replica    Replica of primary bundle resource in colocation
 * \param[in,out] user_data  struct coloc_data for colocation being applied
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
replica_apply_coloc_score(const pcmk__bundle_replica_t *replica,
                          void *user_data)
{
    struct coloc_data *coloc_data = user_data;
    pcmk_node_t *chosen = NULL;
    pcmk_resource_t *container = replica->container;

    if (coloc_data->colocation->score < PCMK_SCORE_INFINITY) {
        int priority_delta =
            container->priv->cmds->apply_coloc_score(coloc_data->dependent,
                                                     container,
                                                     coloc_data->colocation,
                                                     false);

        coloc_data->priority_delta =
            pcmk__add_scores(coloc_data->priority_delta, priority_delta);
        return true;
    }

    chosen = container->priv->fns->location(container, NULL,
                                            pcmk__rsc_node_assigned);
    if ((chosen == NULL)
        || is_set_recursive(container, pcmk__rsc_blocked, true)) {
        return true;
    }

    if ((coloc_data->colocation->primary_role >= pcmk_role_promoted)
        && ((replica->child == NULL)
            || (replica->child->priv->next_role < pcmk_role_promoted))) {
        return true;
    }

    pcmk__rsc_trace(pe__const_top_resource(container, true),
                    "Allowing mandatory colocation %s using %s @%d",
                    coloc_data->colocation->id, pcmk__node_name(chosen),
                    chosen->assign->score);
    coloc_data->container_hosts = g_list_prepend(coloc_data->container_hosts,
                                                 chosen);
    return true;
}

/*!
 * \internal
 * \brief Apply a colocation's score to node scores or resource priority
 *
 * Given a colocation constraint, apply its score to the dependent's
 * allowed node scores (if we are still placing resources) or priority (if
 * we are choosing promotable clone instance roles).
 *
 * \param[in,out] dependent      Dependent resource in colocation
 * \param[in]     primary        Primary resource in colocation
 * \param[in]     colocation     Colocation constraint to apply
 * \param[in]     for_dependent  true if called on behalf of dependent
 *
 * \return The score added to the dependent's priority
 */
int
pcmk__bundle_apply_coloc_score(pcmk_resource_t *dependent,
                               const pcmk_resource_t *primary,
                               const pcmk__colocation_t *colocation,
                               bool for_dependent)
{
    struct coloc_data coloc_data = { colocation, dependent, NULL, 0 };

    /* This should never be called for the bundle itself as a dependent.
     * Instead, we add its colocation constraints to its containers and bundled
     * primitive and call the apply_coloc_score() method for them as dependents.
     */
    pcmk__assert(pcmk__is_bundle(primary) && pcmk__is_primitive(dependent)
                 && (colocation != NULL) && !for_dependent);

    if (pcmk__is_set(primary->flags, pcmk__rsc_unassigned)) {
        pcmk__rsc_trace(primary,
                        "Skipping applying colocation %s "
                        "because %s is still provisional",
                        colocation->id, primary->id);
        return 0;
    }
    pcmk__rsc_trace(primary, "Applying colocation %s (%s with %s at %s)",
                    colocation->id, dependent->id, primary->id,
                    pcmk_readable_score(colocation->score));

    /* If the constraint dependent is a clone or bundle, "dependent" here is one
     * of its instances. Look for a compatible instance of this bundle.
     */
    if (colocation->dependent->priv->variant > pcmk__rsc_variant_group) {
        const pcmk_resource_t *primary_container = NULL;

        primary_container = compatible_container(dependent, primary);
        if (primary_container != NULL) { // Success, we found one
            pcmk__rsc_debug(primary, "Pairing %s with %s",
                            dependent->id, primary_container->id);

            return dependent->priv->cmds->apply_coloc_score(dependent,
                                                            primary_container,
                                                            colocation, true);
        }

        if (colocation->score >= PCMK_SCORE_INFINITY) {
            // Failure, and it's fatal
            pcmk__notice("%s cannot run because there is no compatible "
                         "instance of %s to colocate with",
                         dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true, true);

        } else { // Failure, but we can ignore it
            pcmk__rsc_debug(primary,
                            "%s cannot be colocated with any instance of %s",
                            dependent->id, primary->id);
        }
        return 0;
    }

    pe__foreach_const_bundle_replica(primary, replica_apply_coloc_score,
                                     &coloc_data);

    if (colocation->score >= PCMK_SCORE_INFINITY) {
        pcmk__colocation_intersect_nodes(dependent, primary, colocation,
                                         coloc_data.container_hosts, false);
    }
    g_list_free(coloc_data.container_hosts);
    return coloc_data.priority_delta;
}

// Bundle implementation of pcmk__assignment_methods_t:with_this_colocations()
void
pcmk__with_bundle_colocations(const pcmk_resource_t *rsc,
                              const pcmk_resource_t *orig_rsc, GList **list)
{
    const pcmk_resource_t *bundled_rsc = NULL;

    pcmk__assert(pcmk__is_bundle(rsc) && (orig_rsc != NULL) && (list != NULL));

    // The bundle itself and its containers always get its colocations
    if ((orig_rsc == rsc)
        || pcmk__is_set(orig_rsc->flags, pcmk__rsc_replica_container)) {

        pcmk__add_with_this_list(list, rsc->priv->with_this_colocations,
                                 orig_rsc);
        return;
    }

    /* The bundled resource gets the colocations if it's promotable and we've
     * begun choosing roles
     */
    bundled_rsc = pe__bundled_resource(rsc);
    if ((bundled_rsc == NULL)
        || !pcmk__is_set(bundled_rsc->flags, pcmk__rsc_promotable)
        || (pe__const_top_resource(orig_rsc, false) != bundled_rsc)) {
        return;
    }

    if (orig_rsc == bundled_rsc) {
        if (pe__clone_flag_is_set(orig_rsc,
                                  pcmk__clone_promotion_constrained)) {
            /* orig_rsc is the clone and we're setting roles (or have already
             * done so)
             */
            pcmk__add_with_this_list(list, rsc->priv->with_this_colocations,
                                     orig_rsc);
        }

    } else if (!pcmk__is_set(orig_rsc->flags, pcmk__rsc_unassigned)) {
        /* orig_rsc is an instance and is already assigned. If something
         * requests colocations for orig_rsc now, it's for setting roles.
         */
        pcmk__add_with_this_list(list, rsc->priv->with_this_colocations,
                                 orig_rsc);
    }
}

// Bundle implementation of pcmk__assignment_methods_t:this_with_colocations()
void
pcmk__bundle_with_colocations(const pcmk_resource_t *rsc,
                              const pcmk_resource_t *orig_rsc, GList **list)
{
    const pcmk_resource_t *bundled_rsc = NULL;

    pcmk__assert(pcmk__is_bundle(rsc) && (orig_rsc != NULL) && (list != NULL));

    // The bundle itself and its containers always get its colocations
    if ((orig_rsc == rsc)
        || pcmk__is_set(orig_rsc->flags, pcmk__rsc_replica_container)) {

        pcmk__add_this_with_list(list, rsc->priv->this_with_colocations,
                                 orig_rsc);
        return;
    }

    /* The bundled resource gets the colocations if it's promotable and we've
     * begun choosing roles
     */
    bundled_rsc = pe__bundled_resource(rsc);
    if ((bundled_rsc == NULL)
        || !pcmk__is_set(bundled_rsc->flags, pcmk__rsc_promotable)
        || (pe__const_top_resource(orig_rsc, false) != bundled_rsc)) {
        return;
    }

    if (orig_rsc == bundled_rsc) {
        if (pe__clone_flag_is_set(orig_rsc,
                                  pcmk__clone_promotion_constrained)) {
            /* orig_rsc is the clone and we're setting roles (or have already
             * done so)
             */
            pcmk__add_this_with_list(list, rsc->priv->this_with_colocations,
                                     orig_rsc);
        }

    } else if (!pcmk__is_set(orig_rsc->flags, pcmk__rsc_unassigned)) {
        /* orig_rsc is an instance and is already assigned. If something
         * requests colocations for orig_rsc now, it's for setting roles.
         */
        pcmk__add_this_with_list(list, rsc->priv->this_with_colocations,
                                 orig_rsc);
    }
}

/*!
 * \internal
 * \brief Return action flags for a given bundle resource action
 *
 * \param[in,out] action  Bundle resource action to get flags for
 * \param[in]     node    If not NULL, limit effects to this node
 *
 * \return Flags appropriate to \p action on \p node
 */
uint32_t
pcmk__bundle_action_flags(pcmk_action_t *action, const pcmk_node_t *node)
{
    GList *containers = NULL;
    uint32_t flags = 0;
    pcmk_resource_t *bundled_resource = NULL;

    pcmk__assert((action != NULL) && pcmk__is_bundle(action->rsc));

    bundled_resource = pe__bundled_resource(action->rsc);
    if (bundled_resource != NULL) {
        GList *children = bundled_resource->priv->children;

        // Clone actions are done on the bundled clone resource, not container
        switch (get_complex_task(bundled_resource, action->task)) {
            case pcmk__action_unspecified:
            case pcmk__action_notify:
            case pcmk__action_notified:
            case pcmk__action_promote:
            case pcmk__action_promoted:
            case pcmk__action_demote:
            case pcmk__action_demoted:
                return pcmk__collective_action_flags(action, children, node);
            default:
                break;
        }
    }

    containers = pe__bundle_containers(action->rsc);
    flags = pcmk__collective_action_flags(action, containers, node);
    g_list_free(containers);
    return flags;
}

/*!
 * \internal
 * \brief Apply a location constraint to a bundle replica
 *
 * \param[in,out] replica    Replica to apply constraint to
 * \param[in,out] user_data  Location constraint to apply
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
apply_location_to_replica(pcmk__bundle_replica_t *replica, void *user_data)
{
    pcmk__location_t *location = user_data;

    replica->container->priv->cmds->apply_location(replica->container,
                                                   location);
    if (replica->ip != NULL) {
        replica->ip->priv->cmds->apply_location(replica->ip, location);
    }
    return true;
}

/*!
 * \internal
 * \brief Apply a location constraint to a bundle resource's allowed node scores
 *
 * \param[in,out] rsc       Bundle resource to apply constraint to
 * \param[in,out] location  Location constraint to apply
 */
void
pcmk__bundle_apply_location(pcmk_resource_t *rsc, pcmk__location_t *location)
{
    pcmk_resource_t *bundled_resource = NULL;

    pcmk__assert((location != NULL) && pcmk__is_bundle(rsc));

    pcmk__apply_location(rsc, location);
    pe__foreach_bundle_replica(rsc, apply_location_to_replica, location);

    bundled_resource = pe__bundled_resource(rsc);
    if ((bundled_resource != NULL)
        && ((location->role_filter == pcmk_role_unpromoted)
            || (location->role_filter == pcmk_role_promoted))) {

        bundled_resource->priv->cmds->apply_location(bundled_resource,
                                                     location);
        bundled_resource->priv->location_constraints =
            g_list_prepend(bundled_resource->priv->location_constraints,
                           location);
    }
}

#define XPATH_REMOTE "//nvpair[@name='" PCMK_REMOTE_RA_ADDR "']"

/*!
 * \internal
 * \brief Add a bundle replica's actions to transition graph
 *
 * \param[in,out] replica    Replica to add to graph
 * \param[in]     user_data  Bundle that replica belongs to (for logging only)
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
add_replica_actions_to_graph(pcmk__bundle_replica_t *replica, void *user_data)
{
    if ((replica->remote != NULL)
        && pe__bundle_needs_remote_name(replica->remote)) {

        /* REMOTE_CONTAINER_HACK: Allow remote nodes to run containers that
         * run the remote executor inside, without needing a separate IP for
         * the container. This is done by configuring the inner remote's
         * connection host as the magic string "#uname", then
         * replacing it with the underlying host when needed.
         */
        xmlNode *nvpair = pcmk__xpath_find_one(replica->remote->priv->xml->doc,
                                               XPATH_REMOTE, LOG_ERR);
        const char *calculated_addr = NULL;

        // Replace the value in replica->remote->xml (if appropriate)
        calculated_addr = pe__add_bundle_remote_name(replica->remote, nvpair,
                                                     PCMK_XA_VALUE);
        if (calculated_addr != NULL) {
            /* Since this is for the bundle as a resource, and not any
             * particular action, replace the value in the default
             * parameters (not evaluated for node). create_graph_action()
             * will grab it from there to replace it in node-evaluated
             * parameters.
             */
            GHashTable *params = NULL;

            params = pe_rsc_params(replica->remote, NULL,
                                   replica->remote->priv->scheduler);
            pcmk__insert_dup(params, PCMK_REMOTE_RA_ADDR, calculated_addr);
        } else {
            pcmk_resource_t *bundle = user_data;

            /* The only way to get here is if the remote connection is
             * neither currently running nor scheduled to run. That means we
             * won't be doing any operations that require addr (only start
             * requires it; we additionally use it to compare digests when
             * unpacking status, promote, and migrate_from history, but
             * that's already happened by this point).
             */
            pcmk__rsc_info(bundle,
                           "Unable to determine address for bundle %s "
                           "remote connection", bundle->id);
        }
    }
    if (replica->ip != NULL) {
        replica->ip->priv->cmds->add_actions_to_graph(replica->ip);
    }
    replica->container->priv->cmds->add_actions_to_graph(replica->container);
    if (replica->remote != NULL) {
        replica->remote->priv->cmds->add_actions_to_graph(replica->remote);
    }
    return true;
}

/*!
 * \internal
 * \brief Add a bundle resource's actions to the transition graph
 *
 * \param[in,out] rsc  Bundle resource whose actions should be added
 */
void
pcmk__bundle_add_actions_to_graph(pcmk_resource_t *rsc)
{
    pcmk_resource_t *bundled_resource = NULL;

    pcmk__assert(pcmk__is_bundle(rsc));

    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource != NULL) {
        bundled_resource->priv->cmds->add_actions_to_graph(bundled_resource);
    }
    pe__foreach_bundle_replica(rsc, add_replica_actions_to_graph, rsc);
}

struct probe_data {
    pcmk_resource_t *bundle;    // Bundle being probed
    pcmk_node_t *node;          // Node to create probes on
    bool any_created;           // Whether any probes have been created
};

/*!
 * \internal
 * \brief Order a bundle replica's start after another replica's probe
 *
 * \param[in,out] replica    Replica to order start for
 * \param[in,out] user_data  Replica with probe to order after
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
order_replica_start_after(pcmk__bundle_replica_t *replica, void *user_data)
{
    pcmk__bundle_replica_t *probed_replica = user_data;

    if ((replica == probed_replica) || (replica->container == NULL)) {
        return true;
    }
    pcmk__new_ordering(probed_replica->container,
                       pcmk__op_key(probed_replica->container->id,
                                    PCMK_ACTION_MONITOR, 0),
                       NULL, replica->container,
                       pcmk__op_key(replica->container->id, PCMK_ACTION_START,
                                    0),
                       NULL, pcmk__ar_ordered|pcmk__ar_if_on_same_node,
                       replica->container->priv->scheduler);
    return true;
}

/*!
 * \internal
 * \brief Create probes for a bundle replica's resources
 *
 * \param[in,out] replica    Replica to create probes for
 * \param[in,out] user_data  struct probe_data
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
create_replica_probes(pcmk__bundle_replica_t *replica, void *user_data)
{
    struct probe_data *probe_data = user_data;
    pcmk_resource_t *bundle = probe_data->bundle;

    if ((replica->ip != NULL)
        && replica->ip->priv->cmds->create_probe(replica->ip,
                                                 probe_data->node)) {
        probe_data->any_created = true;
    }
    if ((replica->child != NULL)
        && pcmk__same_node(probe_data->node, replica->node)
        && replica->child->priv->cmds->create_probe(replica->child,
                                                    probe_data->node)) {
        probe_data->any_created = true;
    }
    if (replica->container->priv->cmds->create_probe(replica->container,
                                                     probe_data->node)) {
        probe_data->any_created = true;

        /* If we're limited to one replica per host (due to
         * the lack of an IP range probably), then we don't
         * want any of our peer containers starting until
         * we've established that no other copies are already
         * running.
         *
         * Partly this is to ensure that the maximum replicas per host is
         * observed, but also to ensure that the containers
         * don't fail to start because the necessary port
         * mappings (which won't include an IP for uniqueness)
         * are already taken
         */
        if (bundle->priv->fns->max_per_node(bundle) == 1) {
            pe__foreach_bundle_replica(bundle, order_replica_start_after,
                                       replica);
        }
    }
    if ((replica->remote != NULL)
        && replica->remote->priv->cmds->create_probe(replica->remote,
                                                     probe_data->node)) {
        /* Do not probe the remote resource until we know where the container is
         * running. This is required for REMOTE_CONTAINER_HACK to correctly
         * probe remote resources.
         */
        char *probe_uuid = pcmk__op_key(replica->remote->id,
                                        PCMK_ACTION_MONITOR, 0);
        pcmk_action_t *probe = NULL;

        probe = find_first_action(replica->remote->priv->actions, probe_uuid,
                                  NULL, probe_data->node);
        free(probe_uuid);
        if (probe != NULL) {
            probe_data->any_created = true;
            pcmk__rsc_trace(bundle, "Ordering %s probe on %s",
                            replica->remote->id,
                            pcmk__node_name(probe_data->node));
            pcmk__new_ordering(replica->container,
                               pcmk__op_key(replica->container->id,
                                            PCMK_ACTION_START, 0),
                               NULL, replica->remote, NULL, probe,
                               pcmk__ar_nested_remote_probe,
                               bundle->priv->scheduler);
        }
    }
    return true;
}

/*!
 * \internal
 *
 * \brief Schedule any probes needed for a bundle resource on a node
 *
 * \param[in,out] rsc   Bundle resource to create probes for
 * \param[in,out] node  Node to create probe on
 *
 * \return true if any probe was created, otherwise false
 */
bool
pcmk__bundle_create_probe(pcmk_resource_t *rsc, pcmk_node_t *node)
{
    struct probe_data probe_data = { rsc, node, false };

    pcmk__assert(pcmk__is_bundle(rsc));
    pe__foreach_bundle_replica(rsc, create_replica_probes, &probe_data);
    return probe_data.any_created;
}

/*!
 * \internal
 * \brief Output actions for one bundle replica
 *
 * \param[in,out] replica    Replica to output actions for
 * \param[in]     user_data  Unused
 *
 * \return true (to indicate that any further replicas should be processed)
 */
static bool
output_replica_actions(pcmk__bundle_replica_t *replica, void *user_data)
{
    if (replica->ip != NULL) {
        replica->ip->priv->cmds->output_actions(replica->ip);
    }
    replica->container->priv->cmds->output_actions(replica->container);
    if (replica->remote != NULL) {
        replica->remote->priv->cmds->output_actions(replica->remote);
    }
    if (replica->child != NULL) {
        replica->child->priv->cmds->output_actions(replica->child);
    }
    return true;
}

/*!
 * \internal
 * \brief Output a summary of scheduled actions for a bundle resource
 *
 * \param[in,out] rsc  Bundle resource to output actions for
 */
void
pcmk__output_bundle_actions(pcmk_resource_t *rsc)
{
    pcmk__assert(pcmk__is_bundle(rsc));
    pe__foreach_bundle_replica(rsc, output_replica_actions, NULL);
}

// Bundle implementation of pcmk__assignment_methods_t:add_utilization()
void
pcmk__bundle_add_utilization(const pcmk_resource_t *rsc,
                             const pcmk_resource_t *orig_rsc, GList *all_rscs,
                             GHashTable *utilization)
{
    pcmk_resource_t *container = NULL;

    pcmk__assert(pcmk__is_bundle(rsc));

    if (!pcmk__is_set(rsc->flags, pcmk__rsc_unassigned)) {
        return;
    }

    /* All bundle replicas are identical, so using the utilization of the first
     * is sufficient for any. Only the implicit container resource can have
     * utilization values.
     */
    container = pe__first_container(rsc);
    if (container != NULL) {
        container->priv->cmds->add_utilization(container, orig_rsc, all_rscs,
                                               utilization);
    }
}

// Bundle implementation of pcmk__assignment_methods_t:shutdown_lock()
void
pcmk__bundle_shutdown_lock(pcmk_resource_t *rsc)
{
    pcmk__assert(pcmk__is_bundle(rsc));
    // Bundles currently don't support shutdown locks
}
