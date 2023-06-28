/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Assign a clone resource's instances to nodes
 *
 * \param[in,out] rsc     Clone resource to assign
 * \param[in]     prefer  Node to prefer, if all else is equal
 *
 * \return NULL (clones are not assigned to a single node)
 */
pe_node_t *
pcmk__clone_assign(pe_resource_t *rsc, const pe_node_t *prefer)
{
    CRM_ASSERT(pe_rsc_is_clone(rsc));

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return NULL; // Assignment has already been done
    }

    // Detect assignment loops
    if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Breaking assignment loop involving %s", rsc->id);
        return NULL;
    }
    pe__set_resource_flags(rsc, pe_rsc_allocating);

    // If this clone is promotable, consider nodes' promotion scores
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__add_promotion_scores(rsc);
    }

    /* If this clone is colocated with any other resources, assign those first.
     * Since the this_with_colocations() method boils down to a copy of rsc_cons
     * for clones, we can use that here directly for efficiency.
     */
    for (GList *iter = rsc->rsc_cons; iter != NULL; iter = iter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) iter->data;

        pe_rsc_trace(rsc, "%s: Assigning colocation %s primary %s first",
                     rsc->id, constraint->id, constraint->primary->id);
        constraint->primary->cmds->assign(constraint->primary, prefer);
    }

    /* If any resources are colocated with this one, consider their preferences.
     * Because the with_this_colocations() method boils down to a copy of
     * rsc_cons_lhs for clones, we can use that here directly for efficiency.
     */
    g_list_foreach(rsc->rsc_cons_lhs, pcmk__add_dependent_scores, rsc);

    pe__show_node_scores(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
                         rsc, __func__, rsc->allowed_nodes, rsc->cluster);

    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance);
    pcmk__assign_instances(rsc, rsc->children, pe__clone_max(rsc),
                           pe__clone_node_max(rsc));

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__set_instance_roles(rsc);
    }

    pe__clear_resource_flags(rsc, pe_rsc_provisional|pe_rsc_allocating);
    pe_rsc_trace(rsc, "Assigned clone %s", rsc->id);
    return NULL;
}

/*!
 * \internal
 * \brief Create all actions needed for a given clone resource
 *
 * \param[in,out] rsc  Clone resource to create actions for
 */
void
pcmk__clone_create_actions(pe_resource_t *rsc)
{
    CRM_ASSERT(pe_rsc_is_clone(rsc));

    pe_rsc_trace(rsc, "Creating actions for clone %s", rsc->id);
    pcmk__create_instance_actions(rsc, rsc->children);
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__create_promotable_actions(rsc);
    }
}

/*!
 * \internal
 * \brief Create implicit constraints needed for a clone resource
 *
 * \param[in,out] rsc  Clone resource to create implicit constraints for
 */
void
pcmk__clone_internal_constraints(pe_resource_t *rsc)
{
    bool ordered = false;

    CRM_ASSERT(pe_rsc_is_clone(rsc));

    pe_rsc_trace(rsc, "Creating internal constraints for clone %s", rsc->id);

    // Restart ordering: Stop -> stopped -> start -> started
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_START, rsc, RSC_STARTED,
                                 pe_order_runnable_left);
    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_STOPPED,
                                 pe_order_runnable_left);

    // Demoted -> stop and started -> promote
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_STOP,
                                     pe_order_optional);
        pcmk__order_resource_actions(rsc, RSC_STARTED, rsc, RSC_PROMOTE,
                                     pe_order_runnable_left);
    }

    ordered = pe__clone_is_ordered(rsc);
    if (ordered) {
        /* Ordered clone instances must start and stop by instance number. The
         * instances might have been previously shuffled for assignment or
         * promotion purposes, so re-sort them.
         */
        rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);
    }
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *instance = (pe_resource_t *) iter->data;

        instance->cmds->internal_constraints(instance);

        // Start clone -> start instance -> clone started
        pcmk__order_starts(rsc, instance, pe_order_runnable_left
                                          |pe_order_implies_first_printed);
        pcmk__order_resource_actions(instance, RSC_START, rsc, RSC_STARTED,
                                     pe_order_implies_then_printed);

        // Stop clone -> stop instance -> clone stopped
        pcmk__order_stops(rsc, instance, pe_order_implies_first_printed);
        pcmk__order_resource_actions(instance, RSC_STOP, rsc, RSC_STOPPED,
                                     pe_order_implies_then_printed);

        /* Instances of ordered clones must be started and stopped by instance
         * number. Since only some instances may be starting or stopping, order
         * each instance relative to every later instance.
         */
        if (ordered) {
            for (GList *later = iter->next;
                 later != NULL; later = later->next) {
                pcmk__order_starts(instance, (pe_resource_t *) later->data,
                                   pe_order_optional);
                pcmk__order_stops((pe_resource_t *) later->data, instance,
                                  pe_order_optional);
            }
        }
    }
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__order_promotable_instances(rsc);
    }
}

/*!
 * \internal
 * \brief Check whether colocated resources can be interleaved
 *
 * \param[in] colocation  Colocation constraint with clone as primary
 *
 * \return true if colocated resources can be interleaved, otherwise false
 */
static bool
can_interleave(const pcmk__colocation_t *colocation)
{
    const pe_resource_t *dependent = colocation->dependent;

    // Only colocations between clone or bundle resources use interleaving
    if (dependent->variant <= pe_group) {
        return false;
    }

    // Only the dependent needs to be marked for interleaving
    if (!crm_is_true(g_hash_table_lookup(dependent->meta,
                                         XML_RSC_ATTR_INTERLEAVE))) {
        return false;
    }

    /* @TODO Do we actually care about multiple primary instances sharing a
     * dependent instance?
     */
    if (dependent->fns->max_per_node(dependent)
        != colocation->primary->fns->max_per_node(colocation->primary)) {
        pcmk__config_err("Cannot interleave %s and %s because they do not "
                         "support the same number of instances per node",
                         dependent->id, colocation->primary->id);
        return false;
    }

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
pcmk__clone_apply_coloc_score(pe_resource_t *dependent,
                              const pe_resource_t *primary,
                              const pcmk__colocation_t *colocation,
                              bool for_dependent)
{
    const GList *iter = NULL;

    /* This should never be called for the clone itself as a dependent. Instead,
     * we add its colocation constraints to its instances and call the
     * apply_coloc_score() method for the instances as dependents.
     */
    CRM_ASSERT(!for_dependent);

    CRM_ASSERT((colocation != NULL) && pe_rsc_is_clone(primary)
               && (dependent != NULL) && (dependent->variant == pe_native));

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        pe_rsc_trace(primary,
                     "Delaying processing colocation %s "
                     "because cloned primary %s is still provisional",
                     colocation->id, primary->id);
        return;
    }

    pe_rsc_trace(primary, "Processing colocation %s (%s with clone %s @%s)",
                 colocation->id, dependent->id, primary->id,
                 pcmk_readable_score(colocation->score));

    // Apply role-specific colocations
    if (pcmk_is_set(primary->flags, pe_rsc_promotable)
        && (colocation->primary_role != RSC_ROLE_UNKNOWN)) {

        if (pcmk_is_set(dependent->flags, pe_rsc_provisional)) {
            // We're assigning the dependent to a node
            pcmk__update_dependent_with_promotable(primary, dependent,
                                                   colocation);
            return;
        }

        if (colocation->dependent_role == RSC_ROLE_PROMOTED) {
            // We're choosing a role for the dependent
            pcmk__update_promotable_dependent_priority(primary, dependent,
                                                       colocation);
            return;
        }
    }

    // Apply interleaved colocations
    if (can_interleave(colocation)) {
        const pe_resource_t *primary_instance = NULL;

        primary_instance = pcmk__find_compatible_instance(dependent, primary,
                                                          RSC_ROLE_UNKNOWN,
                                                          false);
        if (primary_instance != NULL) {
            pe_rsc_debug(primary, "Interleaving %s with %s",
                         dependent->id, primary_instance->id);
            dependent->cmds->apply_coloc_score(dependent, primary_instance,
                                               colocation, true);

        } else if (colocation->score >= INFINITY) {
            crm_notice("%s cannot run because it cannot interleave with "
                       "any instance of %s", dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true);

        } else {
            pe_rsc_debug(primary,
                         "%s will not colocate with %s "
                         "because no instance can interleave with it",
                         dependent->id, primary->id);
        }

        return;
    }

    // Apply mandatory colocations
    if (colocation->score >= INFINITY) {
        GList *primary_nodes = NULL;

        // Dependent can run only where primary will have unblocked instances
        for (iter = primary->children; iter != NULL; iter = iter->next) {
            const pe_resource_t *instance = iter->data;
            pe_node_t *chosen = instance->fns->location(instance, NULL, 0);

            if ((chosen != NULL)
                && !is_set_recursive(instance, pe_rsc_block, TRUE)) {
                pe_rsc_trace(primary, "Allowing %s: %s %d",
                             colocation->id, pe__node_name(chosen),
                             chosen->weight);
                primary_nodes = g_list_prepend(primary_nodes, chosen);
            }
        }
        node_list_exclude(dependent->allowed_nodes, primary_nodes, FALSE);
        g_list_free(primary_nodes);
        return;
    }

    // Apply optional colocations
    for (iter = primary->children; iter != NULL; iter = iter->next) {
        const pe_resource_t *instance = iter->data;

        instance->cmds->apply_coloc_score(dependent, instance, colocation,
                                          false);
    }
}

// Clone implementation of resource_alloc_functions_t:with_this_colocations()
void
pcmk__with_clone_colocations(const pe_resource_t *rsc,
                             const pe_resource_t *orig_rsc, GList **list)
{
    CRM_CHECK((rsc != NULL) && (orig_rsc != NULL) && (list != NULL), return);

    if (rsc == orig_rsc) { // Colocations are wanted for clone itself
        pcmk__add_with_this_list(list, rsc->rsc_cons_lhs);
    } else {
        pcmk__add_collective_constraints(list, orig_rsc, rsc, true);
    }
}

// Clone implementation of resource_alloc_functions_t:this_with_colocations()
void
pcmk__clone_with_colocations(const pe_resource_t *rsc,
                             const pe_resource_t *orig_rsc, GList **list)
{
    CRM_CHECK((rsc != NULL) && (orig_rsc != NULL) && (list != NULL), return);

    if (rsc == orig_rsc) { // Colocations are wanted for clone itself
        pcmk__add_this_with_list(list, rsc->rsc_cons);
    } else {
        pcmk__add_collective_constraints(list, orig_rsc, rsc, false);
    }
}

/*!
 * \internal
 * \brief Return action flags for a given clone resource action
 *
 * \param[in,out] action  Action to get flags for
 * \param[in]     node    If not NULL, limit effects to this node
 *
 * \return Flags appropriate to \p action on \p node
 */
uint32_t
pcmk__clone_action_flags(pe_action_t *action, const pe_node_t *node)
{
    CRM_ASSERT((action != NULL) && pe_rsc_is_clone(action->rsc));

    return pcmk__collective_action_flags(action, action->rsc->children, node);
}

/*!
 * \internal
 * \brief Apply a location constraint to a clone resource's allowed node scores
 *
 * \param[in,out] rsc       Clone resource to apply constraint to
 * \param[in,out] location  Location constraint to apply
 */
void
pcmk__clone_apply_location(pe_resource_t *rsc, pe__location_t *location)
{
    CRM_CHECK((location != NULL) && pe_rsc_is_clone(rsc), return);

    pcmk__apply_location(rsc, location);

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *instance = (pe_resource_t *) iter->data;

        instance->cmds->apply_location(instance, location);
    }
}

// GFunc wrapper for calling the action_flags() resource method
static void
call_action_flags(gpointer data, gpointer user_data)
{
    pe_resource_t *rsc = user_data;

    rsc->cmds->action_flags((pe_action_t *) data, NULL);
}

/*!
 * \internal
 * \brief Add a clone resource's actions to the transition graph
 *
 * \param[in,out] rsc  Resource whose actions should be added
 */
void
pcmk__clone_add_actions_to_graph(pe_resource_t *rsc)
{
    CRM_ASSERT(pe_rsc_is_clone(rsc));

    g_list_foreach(rsc->actions, call_action_flags, rsc);
    pe__create_clone_notifications(rsc);

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) iter->data;

        child_rsc->cmds->add_actions_to_graph(child_rsc);
    }

    pcmk__add_rsc_actions_to_graph(rsc);
    pe__free_clone_notification_data(rsc);
}

/*!
 * \internal
 * \brief Check whether a resource or any children have been probed on a node
 *
 * \param[in] rsc   Resource to check
 * \param[in] node  Node to check
 *
 * \return true if \p node is in the known_on table of \p rsc or any of its
 *         children, otherwise false
 */
static bool
rsc_probed_on(const pe_resource_t *rsc, const pe_node_t *node)
{
    if (rsc->children != NULL) {
        for (GList *child_iter = rsc->children; child_iter != NULL;
             child_iter = child_iter->next) {

            pe_resource_t *child = (pe_resource_t *) child_iter->data;

            if (rsc_probed_on(child, node)) {
                return true;
            }
        }
        return false;
    }

    if (rsc->known_on != NULL) {
        GHashTableIter iter;
        pe_node_t *known_node = NULL;

        g_hash_table_iter_init(&iter, rsc->known_on);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &known_node)) {
            if (pe__same_node(node, known_node)) {
                return true;
            }
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Find clone instance that has been probed on given node
 *
 * \param[in] clone  Clone resource to check
 * \param[in] node   Node to check
 *
 * \return Instance of \p clone that has been probed on \p node if any,
 *         otherwise NULL
 */
static pe_resource_t *
find_probed_instance_on(const pe_resource_t *clone, const pe_node_t *node)
{
    for (GList *iter = clone->children; iter != NULL; iter = iter->next) {
        pe_resource_t *instance = (pe_resource_t *) iter->data;

        if (rsc_probed_on(instance, node)) {
            return instance;
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief Probe an anonymous clone on a node
 *
 * \param[in,out] clone  Anonymous clone to probe
 * \param[in,out] node   Node to probe \p clone on
 */
static bool
probe_anonymous_clone(pe_resource_t *clone, pe_node_t *node)
{
    // Check whether we already probed an instance on this node
    pe_resource_t *child = find_probed_instance_on(clone, node);

    // Otherwise, check if we plan to start an instance on this node
    for (GList *iter = clone->children; (iter != NULL) && (child == NULL);
         iter = iter->next) {
        pe_resource_t *instance = (pe_resource_t *) iter->data;
        const pe_node_t *instance_node = NULL;

        instance_node = instance->fns->location(instance, NULL, 0);
        if (pe__same_node(instance_node, node)) {
            child = instance;
        }
    }

    // Otherwise, use the first clone instance
    if (child == NULL) {
        child = clone->children->data;
    }

    // Anonymous clones only need to probe a single instance
    return child->cmds->create_probe(child, node);
}

/*!
 * \internal
 * \brief Schedule any probes needed for a resource on a node
 *
 * \param[in,out] rsc   Resource to create probe for
 * \param[in,out] node  Node to create probe on
 *
 * \return true if any probe was created, otherwise false
 */
bool
pcmk__clone_create_probe(pe_resource_t *rsc, pe_node_t *node)
{
    CRM_ASSERT((node != NULL) && pe_rsc_is_clone(rsc));

    if (rsc->exclusive_discover) {
        /* The clone is configured to be probed only where a location constraint
         * exists with resource-discovery set to exclusive.
         *
         * This check is not strictly necessary here since the instance's
         * create_probe() method would also check, but doing it here is more
         * efficient (especially for unique clones with a large number of
         * instances), and affects the CRM_meta_notify_available_uname variable
         * passed with notify actions.
         */
        pe_node_t *allowed = g_hash_table_lookup(rsc->allowed_nodes,
                                                 node->details->id);

        if ((allowed == NULL)
            || (allowed->rsc_discover_mode != pe_discover_exclusive)) {
            /* This node is not marked for resource discovery. Remove it from
             * allowed_nodes so that notifications contain only nodes that the
             * clone can possibly run on.
             */
            pe_rsc_trace(rsc,
                         "Skipping probe for %s on %s because resource has "
                         "exclusive discovery but is not allowed on node",
                         rsc->id, pe__node_name(node));
            g_hash_table_remove(rsc->allowed_nodes, node->details->id);
            return false;
        }
    }

    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);
    if (pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        return pcmk__probe_resource_list(rsc->children, node);
    } else {
        return probe_anonymous_clone(rsc, node);
    }
}

/*!
 * \internal
 * \brief Add meta-attributes relevant to transition graph actions to XML
 *
 * Add clone-specific meta-attributes needed for transition graph actions.
 *
 * \param[in]     rsc  Clone resource whose meta-attributes should be added
 * \param[in,out] xml  Transition graph action attributes XML to add to
 */
void
pcmk__clone_add_graph_meta(const pe_resource_t *rsc, xmlNode *xml)
{
    char *name = NULL;

    CRM_ASSERT(pe_rsc_is_clone(rsc) && (xml != NULL));

    name = crm_meta_name(XML_RSC_ATTR_UNIQUE);
    crm_xml_add(xml, name, pe__rsc_bool_str(rsc, pe_rsc_unique));
    free(name);

    name = crm_meta_name(XML_RSC_ATTR_NOTIFY);
    crm_xml_add(xml, name, pe__rsc_bool_str(rsc, pe_rsc_notify));
    free(name);

    name = crm_meta_name(XML_RSC_ATTR_INCARNATION_MAX);
    crm_xml_add_int(xml, name, pe__clone_max(rsc));
    free(name);

    name = crm_meta_name(XML_RSC_ATTR_INCARNATION_NODEMAX);
    crm_xml_add_int(xml, name, pe__clone_node_max(rsc));
    free(name);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        int promoted_max = pe__clone_promoted_max(rsc);
        int promoted_node_max = pe__clone_promoted_node_max(rsc);

        name = crm_meta_name(XML_RSC_ATTR_PROMOTED_MAX);
        crm_xml_add_int(xml, name, promoted_max);
        free(name);

        name = crm_meta_name(XML_RSC_ATTR_PROMOTED_NODEMAX);
        crm_xml_add_int(xml, name, promoted_node_max);
        free(name);

        /* @COMPAT Maintain backward compatibility with resource agents that
         * expect the old names (deprecated since 2.0.0).
         */
        name = crm_meta_name(PCMK_XA_PROMOTED_MAX_LEGACY);
        crm_xml_add_int(xml, name, promoted_max);
        free(name);

        name = crm_meta_name(PCMK_XA_PROMOTED_NODE_MAX_LEGACY);
        crm_xml_add_int(xml, name, promoted_node_max);
        free(name);
    }
}

// Clone implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__clone_add_utilization(const pe_resource_t *rsc,
                            const pe_resource_t *orig_rsc, GList *all_rscs,
                            GHashTable *utilization)
{
    bool existing = false;
    pe_resource_t *child = NULL;

    CRM_ASSERT(pe_rsc_is_clone(rsc) && (orig_rsc != NULL)
               && (utilization != NULL));

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    // Look for any child already existing in the list
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        child = (pe_resource_t *) iter->data;
        if (g_list_find(all_rscs, child)) {
            existing = true; // Keep checking remaining children
        } else {
            // If this is a clone of a group, look for group's members
            for (GList *member_iter = child->children; member_iter != NULL;
                 member_iter = member_iter->next) {

                pe_resource_t *member = (pe_resource_t *) member_iter->data;

                if (g_list_find(all_rscs, member) != NULL) {
                    // Add *child's* utilization, not group member's
                    child->cmds->add_utilization(child, orig_rsc, all_rscs,
                                                 utilization);
                    existing = true;
                    break;
                }
            }
        }
    }

    if (!existing && (rsc->children != NULL)) {
        // If nothing was found, still add first child's utilization
        child = (pe_resource_t *) rsc->children->data;

        child->cmds->add_utilization(child, orig_rsc, all_rscs, utilization);
    }
}

// Clone implementation of resource_alloc_functions_t:shutdown_lock()
void
pcmk__clone_shutdown_lock(pe_resource_t *rsc)
{
    CRM_ASSERT(pe_rsc_is_clone(rsc));
    return; // Clones currently don't support shutdown locks
}
