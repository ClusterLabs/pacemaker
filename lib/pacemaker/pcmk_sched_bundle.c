/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

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
assign_replica(pe__bundle_replica_t *replica, void *user_data)
{
    pe_node_t *container_host = NULL;
    const pe_node_t *prefer = user_data;
    const pe_resource_t *bundle = pe__const_top_resource(replica->container,
                                                         true);

    if (replica->ip != NULL) {
        pe_rsc_trace(bundle, "Assigning bundle %s IP %s",
                     bundle->id, replica->ip->id);
        replica->ip->cmds->assign(replica->ip, prefer);
    }

    container_host = replica->container->allocated_to;
    if (replica->remote != NULL) {
        if (pe__is_guest_or_remote_node(container_host)) {
            /* REMOTE_CONTAINER_HACK: "Nested" connection resources must be on
             * the same host because Pacemaker Remote only supports a single
             * active connection.
             */
            pcmk__new_colocation("replica-remote-with-host-remote", NULL,
                                 INFINITY, replica->remote,
                                 container_host->details->remote_rsc, NULL,
                                 NULL, true);
        }
        pe_rsc_trace(bundle, "Assigning bundle %s connection %s",
                     bundle->id, replica->remote->id);
        replica->remote->cmds->assign(replica->remote, prefer);
    }

    if (replica->child != NULL) {
        pe_node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, replica->child->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (!pe__same_node(node, replica->node)) {
                node->weight = -INFINITY;
            } else if (!pcmk__threshold_reached(replica->child, node, NULL)) {
                node->weight = INFINITY;
            }
        }

        pe__set_resource_flags(replica->child->parent, pe_rsc_allocating);
        pe_rsc_trace(bundle, "Assigning bundle %s replica child %s",
                     bundle->id, replica->child->id);
        replica->child->cmds->assign(replica->child, replica->node);
        pe__clear_resource_flags(replica->child->parent, pe_rsc_allocating);
    }
    return true;
}

/*!
 * \internal
 * \brief Assign a bundle resource to a node
 *
 * \param[in,out] rsc     Resource to assign to a node
 * \param[in]     prefer  Node to prefer, if all else is equal
 *
 * \return Node that \p rsc is assigned to, if assigned entirely to one node
 */
pe_node_t *
pcmk__bundle_assign(pe_resource_t *rsc, const pe_node_t *prefer)
{
    GList *containers = NULL;
    pe_resource_t *bundled_resource = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));

    pe_rsc_trace(rsc, "Assigning bundle %s", rsc->id);
    pe__set_resource_flags(rsc, pe_rsc_allocating);

    pe__show_node_scores(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
                         rsc, __func__, rsc->allowed_nodes, rsc->cluster);

    // Assign all containers first, so we know what nodes the bundle will be on
    containers = g_list_sort(pe__bundle_containers(rsc), pcmk__cmp_instance);
    pcmk__assign_instances(rsc, containers, pe__bundle_max(rsc),
                           rsc->fns->max_per_node(rsc));
    g_list_free(containers);

    // Then assign remaining replica resources
    pe__foreach_bundle_replica(rsc, assign_replica, (void *) prefer);

    // Finally, assign the bundled resources to each bundle node
    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource != NULL) {
        pe_node_t *node = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, bundled_resource->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
            if (pe__node_is_bundle_instance(rsc, node)) {
                node->weight = 0;
            } else {
                node->weight = -INFINITY;
            }
        }
        bundled_resource->cmds->assign(bundled_resource, prefer);
    }

    pe__clear_resource_flags(rsc, pe_rsc_allocating|pe_rsc_provisional);
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
create_replica_actions(pe__bundle_replica_t *replica, void *user_data)
{
    if (replica->ip != NULL) {
        replica->ip->cmds->create_actions(replica->ip);
    }
    if (replica->container != NULL) {
        replica->container->cmds->create_actions(replica->container);
    }
    if (replica->remote != NULL) {
        replica->remote->cmds->create_actions(replica->remote);
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
pcmk__bundle_create_actions(pe_resource_t *rsc)
{
    pe_action_t *action = NULL;
    GList *containers = NULL;
    pe_resource_t *bundled_resource = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));

    pe__foreach_bundle_replica(rsc, create_replica_actions, NULL);

    containers = pe__bundle_containers(rsc);
    pcmk__create_instance_actions(rsc, containers);
    g_list_free(containers);

    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource != NULL) {
        bundled_resource->cmds->create_actions(bundled_resource);

        if (pcmk_is_set(bundled_resource->flags, pe_rsc_promotable)) {
            pe__new_rsc_pseudo_action(rsc, RSC_PROMOTE, true, true);
            action = pe__new_rsc_pseudo_action(rsc, RSC_PROMOTED, true, true);
            action->priority = INFINITY;

            pe__new_rsc_pseudo_action(rsc, RSC_DEMOTE, true, true);
            action = pe__new_rsc_pseudo_action(rsc, RSC_DEMOTED, true, true);
            action->priority = INFINITY;
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
replica_internal_constraints(pe__bundle_replica_t *replica, void *user_data)
{
    pe_resource_t *bundle = user_data;

    replica->container->cmds->internal_constraints(replica->container);

    // Start bundle -> start replica container
    pcmk__order_starts(bundle, replica->container,
                       pe_order_runnable_left|pe_order_implies_first_printed);

    // Stop bundle -> stop replica child and container
    if (replica->child != NULL) {
        pcmk__order_stops(bundle, replica->child,
                          pe_order_implies_first_printed);
    }
    pcmk__order_stops(bundle, replica->container,
                      pe_order_implies_first_printed);

    // Start replica container -> bundle is started
    pcmk__order_resource_actions(replica->container, RSC_START, bundle,
                                 RSC_STARTED,
                                 pe_order_implies_then_printed);

    // Stop replica container -> bundle is stopped
    pcmk__order_resource_actions(replica->container, RSC_STOP, bundle,
                                 RSC_STOPPED,
                                 pe_order_implies_then_printed);

    if (replica->ip != NULL) {
        replica->ip->cmds->internal_constraints(replica->ip);

        // Replica IP address -> replica container (symmetric)
        pcmk__order_starts(replica->ip, replica->container,
                           pe_order_runnable_left|pe_order_preserve);
        pcmk__order_stops(replica->container, replica->ip,
                          pe_order_implies_first|pe_order_preserve);

        pcmk__new_colocation("ip-with-container", NULL, INFINITY, replica->ip,
                             replica->container, NULL, NULL, true);
    }

    if (replica->remote != NULL) {
        /* This handles ordering and colocating remote relative to container
         * (via "resource-with-container"). Since IP is also ordered and
         * colocated relative to the container, we don't need to do anything
         * explicit here with IP.
         */
        replica->remote->cmds->internal_constraints(replica->remote);
    }

    if (replica->child != NULL) {
        CRM_ASSERT(replica->remote != NULL);
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
pcmk__bundle_internal_constraints(pe_resource_t *rsc)
{
    pe_resource_t *bundled_resource = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));

    pe__foreach_bundle_replica(rsc, replica_internal_constraints, rsc);

    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource == NULL) {
        return;
    }

    // Start bundle -> start bundled clone
    pcmk__order_resource_actions(rsc, RSC_START, bundled_resource,
                                 RSC_START, pe_order_implies_first_printed);

    // Bundled clone is started -> bundle is started
    pcmk__order_resource_actions(bundled_resource, RSC_STARTED,
                                 rsc, RSC_STARTED,
                                 pe_order_implies_then_printed);

    // Stop bundle -> stop bundled clone
    pcmk__order_resource_actions(rsc, RSC_STOP, bundled_resource, RSC_STOP,
                                 pe_order_implies_first_printed);

    // Bundled clone is stopped -> bundle is stopped
    pcmk__order_resource_actions(bundled_resource, RSC_STOPPED,
                                 rsc, RSC_STOPPED,
                                 pe_order_implies_then_printed);

    bundled_resource->cmds->internal_constraints(bundled_resource);

    if (!pcmk_is_set(bundled_resource->flags, pe_rsc_promotable)) {
        return;
    }
    pcmk__promotable_restart_ordering(rsc);

    // Demote bundle -> demote bundled clone
    pcmk__order_resource_actions(rsc, RSC_DEMOTE, bundled_resource, RSC_DEMOTE,
                                 pe_order_implies_first_printed);

    // Bundled clone is demoted -> bundle is demoted
    pcmk__order_resource_actions(bundled_resource, RSC_DEMOTED,
                                 rsc, RSC_DEMOTED,
                                 pe_order_implies_then_printed);

    // Promote bundle -> promote bundled clone
    pcmk__order_resource_actions(rsc, RSC_PROMOTE,
                                 bundled_resource, RSC_PROMOTE,
                                 pe_order_implies_first_printed);

    // Bundled clone is promoted -> bundle is promoted
    pcmk__order_resource_actions(bundled_resource, RSC_PROMOTED,
                                 rsc, RSC_PROMOTED,
                                 pe_order_implies_then_printed);
}

struct match_data {
    const pe_node_t *node;     // Node to compare against replica
    pe_resource_t *container;  // Replica container corresponding to node
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
match_replica_container(const pe__bundle_replica_t *replica, void *user_data)
{
    struct match_data *match_data = user_data;

    if (pcmk__instance_matches(replica->container, match_data->node,
                               RSC_ROLE_UNKNOWN, false)) {
        match_data->container = replica->container;
        return false; // Match found, don't bother searching further replicas
    }
    return true; // No match, keep searching
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
static pe_resource_t *
compatible_container(const pe_resource_t *dependent,
                     const pe_resource_t *bundle)
{
    GList *scratch = NULL;
    struct match_data match_data = { NULL, NULL };

    // If dependent is assigned, only check there
    match_data.node = dependent->fns->location(dependent, NULL, 0);
    if (match_data.node != NULL) {
        pe__foreach_const_bundle_replica(bundle, match_replica_container,
                                         &match_data);
        return match_data.container;
    }

    // Otherwise, check for any of the dependent's allowed nodes
    scratch = g_hash_table_get_values(dependent->allowed_nodes);
    scratch = pcmk__sort_nodes(scratch, NULL);
    for (const GList *iter = scratch; iter != NULL; iter = iter->next) {
        match_data.node = iter->data;
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
    pe_resource_t *dependent;
    GList *container_hosts;
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
replica_apply_coloc_score(const pe__bundle_replica_t *replica, void *user_data)
{
    struct coloc_data *coloc_data = user_data;
    pe_node_t *chosen = NULL;

    if (coloc_data->colocation->score < INFINITY) {
        replica->container->cmds->apply_coloc_score(coloc_data->dependent,
                                                    replica->container,
                                                    coloc_data->colocation,
                                                    false);
        return true;
    }

    chosen = replica->container->fns->location(replica->container, NULL, 0);
    if ((chosen == NULL)
        || is_set_recursive(replica->container, pe_rsc_block, true)) {
        return true;
    }

    if ((coloc_data->colocation->primary_role >= RSC_ROLE_PROMOTED)
        && ((replica->child == NULL)
            || (replica->child->next_role < RSC_ROLE_PROMOTED))) {
        return true;
    }

    pe_rsc_trace(pe__const_top_resource(replica->container, true),
                 "Allowing mandatory colocation %s using %s @%d",
                 coloc_data->colocation->id, pe__node_name(chosen),
                 chosen->weight);
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
 */
void
pcmk__bundle_apply_coloc_score(pe_resource_t *dependent,
                               const pe_resource_t *primary,
                               const pcmk__colocation_t *colocation,
                               bool for_dependent)
{
    struct coloc_data coloc_data = { colocation, dependent, NULL };

    /* This should never be called for the bundle itself as a dependent.
     * Instead, we add its colocation constraints to its containers and call the
     * apply_coloc_score() method for the containers as dependents.
     */
    CRM_ASSERT((primary != NULL) && (primary->variant == pe_container)
               && (dependent != NULL) && (dependent->variant == pe_native)
               && (colocation != NULL) && !for_dependent);

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        pe_rsc_trace(primary,
                     "Skipping applying colocation %s "
                     "because %s is still provisional",
                     colocation->id, primary->id);
        return;
    }
    pe_rsc_trace(primary, "Applying colocation %s (%s with %s at %s)",
                 colocation->id, dependent->id, primary->id,
                 pcmk_readable_score(colocation->score));

    /* If the constraint dependent is a clone or bundle, "dependent" here is one
     * of its instances. Look for a compatible instance of this bundle.
     */
    if (colocation->dependent->variant > pe_group) {
        const pe_resource_t *primary_container = compatible_container(dependent,
                                                                      primary);

        if (primary_container != NULL) { // Success, we found one
            pe_rsc_debug(primary, "Pairing %s with %s",
                         dependent->id, primary_container->id);
            dependent->cmds->apply_coloc_score(dependent, primary_container,
                                               colocation, true);

        } else if (colocation->score >= INFINITY) { // Failure, and it's fatal
            crm_notice("%s cannot run because there is no compatible "
                       "instance of %s to colocate with",
                       dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true);

        } else { // Failure, but we can ignore it
            pe_rsc_debug(primary,
                         "%s cannot be colocated with any instance of %s",
                         dependent->id, primary->id);
        }
        return;
    }

    pe__foreach_const_bundle_replica(primary, replica_apply_coloc_score,
                                     &coloc_data);

    if (colocation->score >= INFINITY) {
        node_list_exclude(dependent->allowed_nodes, coloc_data.container_hosts,
                          FALSE);
    }
    g_list_free(coloc_data.container_hosts);
}

// Bundle implementation of resource_alloc_functions_t:with_this_colocations()
void
pcmk__with_bundle_colocations(const pe_resource_t *rsc,
                              const pe_resource_t *orig_rsc, GList **list)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container)
               && (orig_rsc != NULL) && (list != NULL));

    if (rsc == orig_rsc) { // Colocations are wanted for bundle itself
        pcmk__add_with_this_list(list, rsc->rsc_cons_lhs);

    // Only the bundle replicas' containers get the bundle's constraints
    } else if (pcmk_is_set(orig_rsc->flags, pe_rsc_replica_container)) {
        pcmk__add_collective_constraints(list, orig_rsc, rsc, true);
    }
}

// Bundle implementation of resource_alloc_functions_t:this_with_colocations()
void
pcmk__bundle_with_colocations(const pe_resource_t *rsc,
                              const pe_resource_t *orig_rsc, GList **list)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container)
               && (orig_rsc != NULL) && (list != NULL));

    if (rsc == orig_rsc) { // Colocations are wanted for bundle itself
        pcmk__add_this_with_list(list, rsc->rsc_cons);

    // Only the bundle replicas' containers get the bundle's constraints
    } else if (pcmk_is_set(orig_rsc->flags, pe_rsc_replica_container)) {
        pcmk__add_collective_constraints(list, orig_rsc, rsc, false);
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
pcmk__bundle_action_flags(pe_action_t *action, const pe_node_t *node)
{
    GList *containers = NULL;
    uint32_t flags = 0;
    pe_resource_t *bundled_resource = NULL;

    CRM_ASSERT((action != NULL) && (action->rsc != NULL)
               && (action->rsc->variant == pe_container));

    bundled_resource = pe__bundled_resource(action->rsc);
    if (bundled_resource != NULL) {
        // Clone actions are done on the bundled clone resource, not container
        switch (get_complex_task(bundled_resource, action->task)) {
            case no_action:
            case action_notify:
            case action_notified:
            case action_promote:
            case action_promoted:
            case action_demote:
            case action_demoted:
                return pcmk__collective_action_flags(action,
                                                     bundled_resource->children,
                                                     node);
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
apply_location_to_replica(pe__bundle_replica_t *replica, void *user_data)
{
    pe__location_t *location = user_data;

    if (replica->container != NULL) {
        replica->container->cmds->apply_location(replica->container, location);
    }
    if (replica->ip != NULL) {
        replica->ip->cmds->apply_location(replica->ip, location);
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
pcmk__bundle_apply_location(pe_resource_t *rsc, pe__location_t *location)
{
    pe_resource_t *bundled_resource = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container)
               && (location != NULL));

    pcmk__apply_location(rsc, location);
    pe__foreach_bundle_replica(rsc, apply_location_to_replica, location);

    bundled_resource = pe__bundled_resource(rsc);
    if ((bundled_resource != NULL)
        && ((location->role_filter == RSC_ROLE_UNPROMOTED)
            || (location->role_filter == RSC_ROLE_PROMOTED))) {
        bundled_resource->cmds->apply_location(bundled_resource, location);
        bundled_resource->rsc_location = g_list_prepend(
            bundled_resource->rsc_location, location);
    }
}

#define XPATH_REMOTE "//nvpair[@name='" XML_RSC_ATTR_REMOTE_RA_ADDR "']"

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
add_replica_actions_to_graph(pe__bundle_replica_t *replica, void *user_data)
{
    if ((replica->remote != NULL) && (replica->container != NULL)
        && pe__bundle_needs_remote_name(replica->remote)) {

        /* REMOTE_CONTAINER_HACK: Allow remote nodes to run containers that
         * run pacemaker-remoted inside, without needing a separate IP for
         * the container. This is done by configuring the inner remote's
         * connection host as the magic string "#uname", then
         * replacing it with the underlying host when needed.
         */
        xmlNode *nvpair = get_xpath_object(XPATH_REMOTE, replica->remote->xml,
                                           LOG_ERR);
        const char *calculated_addr = NULL;

        // Replace the value in replica->remote->xml (if appropriate)
        calculated_addr = pe__add_bundle_remote_name(replica->remote,
                                                     replica->remote->cluster,
                                                     nvpair, "value");
        if (calculated_addr != NULL) {
            /* Since this is for the bundle as a resource, and not any
             * particular action, replace the value in the default
             * parameters (not evaluated for node). create_graph_action()
             * will grab it from there to replace it in node-evaluated
             * parameters.
             */
            GHashTable *params = pe_rsc_params(replica->remote,
                                               NULL, replica->remote->cluster);

            g_hash_table_replace(params,
                                 strdup(XML_RSC_ATTR_REMOTE_RA_ADDR),
                                 strdup(calculated_addr));
        } else {
            pe_resource_t *bundle = user_data;

            /* The only way to get here is if the remote connection is
             * neither currently running nor scheduled to run. That means we
             * won't be doing any operations that require addr (only start
             * requires it; we additionally use it to compare digests when
             * unpacking status, promote, and migrate_from history, but
             * that's already happened by this point).
             */
            pe_rsc_info(bundle,
                        "Unable to determine address for bundle %s "
                        "remote connection", bundle->id);
        }
    }
    if (replica->ip != NULL) {
        replica->ip->cmds->add_actions_to_graph(replica->ip);
    }
    if (replica->container != NULL) {
        replica->container->cmds->add_actions_to_graph(replica->container);
    }
    if (replica->remote != NULL) {
        replica->remote->cmds->add_actions_to_graph(replica->remote);
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
pcmk__bundle_add_actions_to_graph(pe_resource_t *rsc)
{
    pe_resource_t *bundled_resource = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));

    bundled_resource = pe__bundled_resource(rsc);
    if (bundled_resource != NULL) {
        bundled_resource->cmds->add_actions_to_graph(bundled_resource);
    }
    pe__foreach_bundle_replica(rsc, add_replica_actions_to_graph, rsc);
}

struct probe_data {
    pe_resource_t *bundle;  // Bundle being probed
    pe_node_t *node;        // Node to create probes on
    bool any_created;       // Whether any probes have been created
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
order_replica_start_after(pe__bundle_replica_t *replica, void *user_data)
{
    pe__bundle_replica_t *probed_replica = user_data;

    if ((replica == probed_replica) || (replica->container == NULL)) {
        return true;
    }
    pcmk__new_ordering(probed_replica->container,
                       pcmk__op_key(probed_replica->container->id, RSC_STATUS,
                                    0),
                       NULL, replica->container,
                       pcmk__op_key(replica->container->id, RSC_START, 0), NULL,
                       pe_order_optional|pe_order_same_node,
                       replica->container->cluster);
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
create_replica_probes(pe__bundle_replica_t *replica, void *user_data)
{
    struct probe_data *probe_data = user_data;

    if ((replica->ip != NULL)
        && replica->ip->cmds->create_probe(replica->ip, probe_data->node)) {
        probe_data->any_created = true;
    }
    if ((replica->child != NULL)
        && pe__same_node(probe_data->node, replica->node)
        && replica->child->cmds->create_probe(replica->child,
                                              probe_data->node)) {
        probe_data->any_created = true;
    }
    if ((replica->container != NULL)
        && replica->container->cmds->create_probe(replica->container,
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
        if (probe_data->bundle->fns->max_per_node(probe_data->bundle) == 1) {
            pe__foreach_bundle_replica(probe_data->bundle,
                                       order_replica_start_after, replica);
        }
    }
    if ((replica->container != NULL) && (replica->remote != NULL)
        && replica->remote->cmds->create_probe(replica->remote,
                                               probe_data->node)) {
        /* Do not probe the remote resource until we know where the container is
         * running. This is required for REMOTE_CONTAINER_HACK to correctly
         * probe remote resources.
         */
        char *probe_uuid = pcmk__op_key(replica->remote->id, RSC_STATUS, 0);
        pe_action_t *probe = find_first_action(replica->remote->actions,
                                               probe_uuid, NULL,
                                               probe_data->node);

        free(probe_uuid);
        if (probe != NULL) {
            probe_data->any_created = true;
            pe_rsc_trace(probe_data->bundle, "Ordering %s probe on %s",
                         replica->remote->id, pe__node_name(probe_data->node));
            pcmk__new_ordering(replica->container,
                               pcmk__op_key(replica->container->id, RSC_START,
                                            0),
                               NULL, replica->remote, NULL, probe,
                               pe_order_probe, probe_data->bundle->cluster);
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
pcmk__bundle_create_probe(pe_resource_t *rsc, pe_node_t *node)
{
    struct probe_data probe_data = { rsc, node, false };

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));
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
output_replica_actions(pe__bundle_replica_t *replica, void *user_data)
{
    if (replica->ip != NULL) {
        replica->ip->cmds->output_actions(replica->ip);
    }
    if (replica->container != NULL) {
        replica->container->cmds->output_actions(replica->container);
    }
    if (replica->remote != NULL) {
        replica->remote->cmds->output_actions(replica->remote);
    }
    if (replica->child != NULL) {
        replica->child->cmds->output_actions(replica->child);
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
pcmk__output_bundle_actions(pe_resource_t *rsc)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));
    pe__foreach_bundle_replica(rsc, output_replica_actions, NULL);
}

// Bundle implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__bundle_add_utilization(const pe_resource_t *rsc,
                             const pe_resource_t *orig_rsc, GList *all_rscs,
                             GHashTable *utilization)
{
    pe_resource_t *container = NULL;

    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    /* All bundle replicas are identical, so using the utilization of the first
     * is sufficient for any. Only the implicit container resource can have
     * utilization values.
     */
    container = pe__first_container(rsc);
    if (container != NULL) {
        container->cmds->add_utilization(container, orig_rsc, all_rscs,
                                         utilization);
    }
}

// Bundle implementation of resource_alloc_functions_t:shutdown_lock()
void
pcmk__bundle_shutdown_lock(pe_resource_t *rsc)
{
    CRM_ASSERT((rsc != NULL) && (rsc->variant == pe_container));
    // Bundles currently don't support shutdown locks
}
