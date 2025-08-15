/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Assign a clone resource's instances to nodes
 *
 * \param[in,out] rsc           Clone resource to assign
 * \param[in]     prefer        Node to prefer, if all else is equal
 * \param[in]     stop_if_fail  If \c true and a primitive descendant of \p rsc
 *                              can't be assigned to a node, set the
 *                              descendant's next role to stopped and update
 *                              existing actions
 *
 * \return NULL (clones are not assigned to a single node)
 *
 * \note If \p stop_if_fail is \c false, then \c pcmk__unassign_resource() can
 *       completely undo the assignment. A successful assignment can be either
 *       undone or left alone as final. A failed assignment has the same effect
 *       as calling pcmk__unassign_resource(); there are no side effects on
 *       roles or actions.
 */
pcmk_node_t *
pcmk__clone_assign(pcmk_resource_t *rsc, const pcmk_node_t *prefer,
                   bool stop_if_fail)
{
    GList *colocations = NULL;

    pcmk__assert(pcmk__is_clone(rsc));

    if (!pcmk_is_set(rsc->flags, pcmk__rsc_unassigned)) {
        return NULL; // Assignment has already been done
    }

    // Detect assignment loops
    if (pcmk_is_set(rsc->flags, pcmk__rsc_assigning)) {
        pcmk__rsc_debug(rsc, "Breaking assignment loop involving %s", rsc->id);
        return NULL;
    }
    pcmk__set_rsc_flags(rsc, pcmk__rsc_assigning);

    // If this clone is promotable, consider nodes' promotion scores
    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
        pcmk__add_promotion_scores(rsc);
    }

    // If this clone is colocated with any other resources, assign those first
    colocations = pcmk__this_with_colocations(rsc);
    for (GList *iter = colocations; iter != NULL; iter = iter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) iter->data;
        pcmk_resource_t *primary = constraint->primary;

        pcmk__rsc_trace(rsc, "%s: Assigning colocation %s primary %s first",
                        rsc->id, constraint->id, primary->id);
        primary->priv->cmds->assign(primary, prefer, stop_if_fail);
    }
    g_list_free(colocations);

    // If any resources are colocated with this one, consider their preferences
    colocations = pcmk__with_this_colocations(rsc);
    g_list_foreach(colocations, pcmk__add_dependent_scores, rsc);
    g_list_free(colocations);

    pe__show_node_scores(!pcmk_is_set(rsc->priv->scheduler->flags,
                                      pcmk__sched_output_scores),
                         rsc, __func__, rsc->priv->allowed_nodes,
                         rsc->priv->scheduler);

    rsc->priv->children = g_list_sort(rsc->priv->children, pcmk__cmp_instance);
    pcmk__assign_instances(rsc, rsc->priv->children, pe__clone_max(rsc),
                           pe__clone_node_max(rsc));

    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
        pcmk__set_instance_roles(rsc);
    }

    pcmk__clear_rsc_flags(rsc, pcmk__rsc_unassigned|pcmk__rsc_assigning);
    pcmk__rsc_trace(rsc, "Assigned clone %s", rsc->id);
    return NULL;
}

/*!
 * \internal
 * \brief Create all actions needed for a given clone resource
 *
 * \param[in,out] rsc  Clone resource to create actions for
 */
void
pcmk__clone_create_actions(pcmk_resource_t *rsc)
{
    pcmk__assert(pcmk__is_clone(rsc));

    pcmk__rsc_trace(rsc, "Creating actions for clone %s", rsc->id);
    pcmk__create_instance_actions(rsc, rsc->priv->children);
    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
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
pcmk__clone_internal_constraints(pcmk_resource_t *rsc)
{
    bool ordered = false;

    pcmk__assert(pcmk__is_clone(rsc));

    pcmk__rsc_trace(rsc, "Creating internal constraints for clone %s", rsc->id);

    // Restart ordering: Stop -> stopped -> start -> started
    pcmk__order_resource_actions(rsc, PCMK_ACTION_STOPPED,
                                 rsc, PCMK_ACTION_START,
                                 pcmk__ar_ordered);
    pcmk__order_resource_actions(rsc, PCMK_ACTION_START,
                                 rsc, PCMK_ACTION_RUNNING,
                                 pcmk__ar_unrunnable_first_blocks);
    pcmk__order_resource_actions(rsc, PCMK_ACTION_STOP,
                                 rsc, PCMK_ACTION_STOPPED,
                                 pcmk__ar_unrunnable_first_blocks);

    // Demoted -> stop and started -> promote
    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
        pcmk__order_resource_actions(rsc, PCMK_ACTION_DEMOTED,
                                     rsc, PCMK_ACTION_STOP,
                                     pcmk__ar_ordered);
        pcmk__order_resource_actions(rsc, PCMK_ACTION_RUNNING,
                                     rsc, PCMK_ACTION_PROMOTE,
                                     pcmk__ar_unrunnable_first_blocks);
    }

    ordered = pe__clone_is_ordered(rsc);
    if (ordered) {
        /* Ordered clone instances must start and stop by instance number. The
         * instances might have been previously shuffled for assignment or
         * promotion purposes, so re-sort them.
         */
        rsc->priv->children = g_list_sort(rsc->priv->children,
                                          pcmk__cmp_instance_number);
    }
    for (GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *instance = (pcmk_resource_t *) iter->data;

        instance->priv->cmds->internal_constraints(instance);

        // Start clone -> start instance -> clone started
        pcmk__order_starts(rsc, instance, pcmk__ar_unrunnable_first_blocks
                                          |pcmk__ar_then_implies_first_graphed);
        pcmk__order_resource_actions(instance, PCMK_ACTION_START,
                                     rsc, PCMK_ACTION_RUNNING,
                                     pcmk__ar_first_implies_then_graphed);

        // Stop clone -> stop instance -> clone stopped
        pcmk__order_stops(rsc, instance, pcmk__ar_then_implies_first_graphed);
        pcmk__order_resource_actions(instance, PCMK_ACTION_STOP,
                                     rsc, PCMK_ACTION_STOPPED,
                                     pcmk__ar_first_implies_then_graphed);

        /* Instances of ordered clones must be started and stopped by instance
         * number. Since only some instances may be starting or stopping, order
         * each instance relative to every later instance.
         */
        if (ordered) {
            for (GList *later = iter->next;
                 later != NULL; later = later->next) {
                pcmk__order_starts(instance, (pcmk_resource_t *) later->data,
                                   pcmk__ar_ordered);
                pcmk__order_stops((pcmk_resource_t *) later->data, instance,
                                  pcmk__ar_ordered);
            }
        }
    }
    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
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
    const pcmk_resource_t *primary = colocation->primary;
    const pcmk_resource_t *dependent = colocation->dependent;

    // Only colocations between clone or bundle resources use interleaving
    if (dependent->priv->variant <= pcmk__rsc_variant_group) {
        return false;
    }

    // Only the dependent needs to be marked for interleaving
    if (!crm_is_true(g_hash_table_lookup(dependent->priv->meta,
                                         PCMK_META_INTERLEAVE))) {
        return false;
    }

    /* @TODO Do we actually care about multiple primary instances sharing a
     * dependent instance?
     */
    if (dependent->priv->fns->max_per_node(dependent)
        != primary->priv->fns->max_per_node(primary)) {
        pcmk__config_err("Cannot interleave %s and %s because they do not "
                         "support the same number of instances per node",
                         dependent->id, primary->id);
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
 *
 * \return The score added to the dependent's priority
 */
int
pcmk__clone_apply_coloc_score(pcmk_resource_t *dependent,
                              const pcmk_resource_t *primary,
                              const pcmk__colocation_t *colocation,
                              bool for_dependent)
{
    const GList *iter = NULL;
    int priority_delta = 0;

    /* This should never be called for the clone itself as a dependent. Instead,
     * we add its colocation constraints to its instances and call the
     * apply_coloc_score() method for the instances as dependents.
     */
    pcmk__assert(!for_dependent && (colocation != NULL)
                 && pcmk__is_clone(primary) && pcmk__is_primitive(dependent));

    if (pcmk_is_set(primary->flags, pcmk__rsc_unassigned)) {
        pcmk__rsc_trace(primary,
                        "Delaying processing colocation %s "
                        "because cloned primary %s is still provisional",
                        colocation->id, primary->id);
        return 0;
    }

    pcmk__rsc_trace(primary, "Processing colocation %s (%s with clone %s @%s)",
                    colocation->id, dependent->id, primary->id,
                    pcmk_readable_score(colocation->score));

    // Apply role-specific colocations
    if (pcmk_is_set(primary->flags, pcmk__rsc_promotable)
        && (colocation->primary_role != pcmk_role_unknown)) {

        if (pcmk_is_set(dependent->flags, pcmk__rsc_unassigned)) {
            // We're assigning the dependent to a node
            pcmk__update_dependent_with_promotable(primary, dependent,
                                                   colocation);
            return 0;
        }

        if (colocation->dependent_role == pcmk_role_promoted) {
            // We're choosing a role for the dependent
            return pcmk__update_promotable_dependent_priority(primary,
                                                              dependent,
                                                              colocation);
        }
    }

    // Apply interleaved colocations
    if (can_interleave(colocation)) {
        const pcmk_resource_t *primary_instance = NULL;

        primary_instance = pcmk__find_compatible_instance(dependent, primary,
                                                          pcmk_role_unknown,
                                                          false);
        if (primary_instance != NULL) {
            pcmk__rsc_debug(primary, "Interleaving %s with %s",
                            dependent->id, primary_instance->id);

            return dependent->priv->cmds->apply_coloc_score(dependent,
                                                            primary_instance,
                                                            colocation, true);
        }

        if (colocation->score >= PCMK_SCORE_INFINITY) {
            crm_notice("%s cannot run because it cannot interleave with "
                       "any instance of %s", dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true, true);

        } else {
            pcmk__rsc_debug(primary,
                            "%s will not colocate with %s "
                            "because no instance can interleave with it",
                            dependent->id, primary->id);
        }

        return 0;
    }

    // Apply mandatory colocations
    if (colocation->score >= PCMK_SCORE_INFINITY) {
        GList *primary_nodes = NULL;

        // Dependent can run only where primary will have unblocked instances
        for (iter = primary->priv->children;
             iter != NULL; iter = iter->next) {

            const pcmk_resource_t *instance = iter->data;
            pcmk_node_t *chosen = NULL;

            chosen = instance->priv->fns->location(instance, NULL,
                                                   pcmk__rsc_node_assigned);
            if ((chosen != NULL)
                && !is_set_recursive(instance, pcmk__rsc_blocked, TRUE)) {
                pcmk__rsc_trace(primary, "Allowing %s: %s %d",
                                colocation->id, pcmk__node_name(chosen),
                                chosen->assign->score);
                primary_nodes = g_list_prepend(primary_nodes, chosen);
            }
        }
        pcmk__colocation_intersect_nodes(dependent, primary, colocation,
                                         primary_nodes, false);
        g_list_free(primary_nodes);
        return 0;
    }

    // Apply optional colocations
    for (iter = primary->priv->children; iter != NULL; iter = iter->next) {
        const pcmk_resource_t *instance = iter->data;
        int instance_delta = instance->priv->cmds->apply_coloc_score(dependent,
                                                                     instance,
                                                                     colocation,
                                                                     false);

        priority_delta = pcmk__add_scores(priority_delta, instance_delta);
    }
    return priority_delta;
}

// Clone implementation of pcmk__assignment_methods_t:with_this_colocations()
void
pcmk__with_clone_colocations(const pcmk_resource_t *rsc,
                             const pcmk_resource_t *orig_rsc, GList **list)
{
    const pcmk_resource_t *parent = NULL;

    CRM_CHECK((rsc != NULL) && (orig_rsc != NULL) && (list != NULL), return);
    parent = rsc->priv->parent;

    pcmk__add_with_this_list(list, rsc->priv->with_this_colocations,
                             orig_rsc);

    if (parent != NULL) {
        parent->priv->cmds->with_this_colocations(parent, orig_rsc, list);
    }
}

// Clone implementation of pcmk__assignment_methods_t:this_with_colocations()
void
pcmk__clone_with_colocations(const pcmk_resource_t *rsc,
                             const pcmk_resource_t *orig_rsc, GList **list)
{
    const pcmk_resource_t *parent = NULL;

    CRM_CHECK((rsc != NULL) && (orig_rsc != NULL) && (list != NULL), return);
    parent = rsc->priv->parent;

    pcmk__add_this_with_list(list, rsc->priv->this_with_colocations,
                             orig_rsc);

    if (parent != NULL) {
        parent->priv->cmds->this_with_colocations(parent, orig_rsc, list);
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
pcmk__clone_action_flags(pcmk_action_t *action, const pcmk_node_t *node)
{
    pcmk__assert((action != NULL) && pcmk__is_clone(action->rsc));

    return pcmk__collective_action_flags(action, action->rsc->priv->children,
                                         node);
}

/*!
 * \internal
 * \brief Apply a location constraint to a clone resource's allowed node scores
 *
 * \param[in,out] rsc       Clone resource to apply constraint to
 * \param[in,out] location  Location constraint to apply
 */
void
pcmk__clone_apply_location(pcmk_resource_t *rsc, pcmk__location_t *location)
{
    CRM_CHECK((location != NULL) && pcmk__is_clone(rsc), return);

    pcmk__apply_location(rsc, location);

    for (GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *instance = (pcmk_resource_t *) iter->data;

        instance->priv->cmds->apply_location(instance, location);
    }
}

// GFunc wrapper for calling the action_flags() resource method
static void
call_action_flags(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = user_data;

    rsc->priv->cmds->action_flags((pcmk_action_t *) data, NULL);
}

/*!
 * \internal
 * \brief Add a clone resource's actions to the transition graph
 *
 * \param[in,out] rsc  Resource whose actions should be added
 */
void
pcmk__clone_add_actions_to_graph(pcmk_resource_t *rsc)
{
    pcmk__assert(pcmk__is_clone(rsc));

    g_list_foreach(rsc->priv->actions, call_action_flags, rsc);
    pe__create_clone_notifications(rsc);

    for (GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *child_rsc = (pcmk_resource_t *) iter->data;

        child_rsc->priv->cmds->add_actions_to_graph(child_rsc);
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
 * \return true if \p node is in the probed_nodes table of \p rsc or any of its
 *         children, otherwise false
 */
static bool
rsc_probed_on(const pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    if (rsc->priv->children != NULL) {
        for (GList *child_iter = rsc->priv->children;
             child_iter != NULL; child_iter = child_iter->next) {

            pcmk_resource_t *child = (pcmk_resource_t *) child_iter->data;

            if (rsc_probed_on(child, node)) {
                return true;
            }
        }
        return false;
    }

    if (rsc->priv->probed_nodes != NULL) {
        GHashTableIter iter;
        pcmk_node_t *known_node = NULL;

        g_hash_table_iter_init(&iter, rsc->priv->probed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &known_node)) {
            if (pcmk__same_node(node, known_node)) {
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
static pcmk_resource_t *
find_probed_instance_on(const pcmk_resource_t *clone, const pcmk_node_t *node)
{
    for (GList *iter = clone->priv->children;
         iter != NULL; iter = iter->next) {

        pcmk_resource_t *instance = (pcmk_resource_t *) iter->data;

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
probe_anonymous_clone(pcmk_resource_t *clone, pcmk_node_t *node)
{
    // Check whether we already probed an instance on this node
    pcmk_resource_t *child = find_probed_instance_on(clone, node);

    // Otherwise, check if we plan to start an instance on this node
    for (GList *iter = clone->priv->children;
         (iter != NULL) && (child == NULL); iter = iter->next) {

        pcmk_resource_t *instance = (pcmk_resource_t *) iter->data;
        const pcmk_node_t *instance_node = NULL;

        instance_node = instance->priv->fns->location(instance, NULL,
                                                      pcmk__rsc_node_assigned);
        if (pcmk__same_node(instance_node, node)) {
            child = instance;
        }
    }

    // Otherwise, use the first clone instance
    if (child == NULL) {
        clone->priv->children = g_list_sort(clone->priv->children,
                                            pcmk__cmp_instance_number);
        child = clone->priv->children->data;
    }

    // Anonymous clones only need to probe a single instance
    return child->priv->cmds->create_probe(child, node);
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
pcmk__clone_create_probe(pcmk_resource_t *rsc, pcmk_node_t *node)
{
    pcmk__assert((node != NULL) && pcmk__is_clone(rsc));

    if (pcmk_is_set(rsc->flags, pcmk__rsc_exclusive_probes)) {
        /* The clone is configured to be probed only where a location constraint
         * exists with PCMK_XA_RESOURCE_DISCOVERY set to exclusive.
         *
         * This check is not strictly necessary here since the instance's
         * create_probe() method would also check, but doing it here is more
         * efficient (especially for unique clones with a large number of
         * instances), and affects the CRM_meta_notify_available_uname variable
         * passed with notify actions.
         */
        pcmk_node_t *allowed = g_hash_table_lookup(rsc->priv->allowed_nodes,
                                                   node->priv->id);

        if ((allowed == NULL)
            || (allowed->assign->probe_mode != pcmk__probe_exclusive)) {
            /* This node is not marked for resource discovery. Remove it from
             * allowed nodes so that notifications contain only nodes that the
             * clone can possibly run on.
             */
            pcmk__rsc_trace(rsc,
                            "Skipping probe for %s on %s because resource has "
                            "exclusive discovery but is not allowed on node",
                            rsc->id, pcmk__node_name(node));
            g_hash_table_remove(rsc->priv->allowed_nodes, node->priv->id);
            return false;
        }
    }

    if (pcmk_is_set(rsc->flags, pcmk__rsc_unique)) {
        return pcmk__probe_resource_list(rsc->priv->children, node);
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
pcmk__clone_add_graph_meta(const pcmk_resource_t *rsc, xmlNode *xml)
{
    char *name = NULL;

    pcmk__assert(pcmk__is_clone(rsc) && (xml != NULL));

    name = crm_meta_name(PCMK_META_GLOBALLY_UNIQUE);
    crm_xml_add(xml, name, pcmk__flag_text(rsc->flags, pcmk__rsc_unique));
    free(name);

    name = crm_meta_name(PCMK_META_NOTIFY);
    crm_xml_add(xml, name, pcmk__flag_text(rsc->flags, pcmk__rsc_notify));
    free(name);

    name = crm_meta_name(PCMK_META_CLONE_MAX);
    crm_xml_add_int(xml, name, pe__clone_max(rsc));
    free(name);

    name = crm_meta_name(PCMK_META_CLONE_NODE_MAX);
    crm_xml_add_int(xml, name, pe__clone_node_max(rsc));
    free(name);

    if (pcmk_is_set(rsc->flags, pcmk__rsc_promotable)) {
        int promoted_max = pe__clone_promoted_max(rsc);
        int promoted_node_max = pe__clone_promoted_node_max(rsc);

        name = crm_meta_name(PCMK_META_PROMOTED_MAX);
        crm_xml_add_int(xml, name, promoted_max);
        free(name);

        name = crm_meta_name(PCMK_META_PROMOTED_NODE_MAX);
        crm_xml_add_int(xml, name, promoted_node_max);
        free(name);

        /* @COMPAT Maintain backward compatibility with resource agents that
         * expect the old names (deprecated since 2.0.0).
         */
        name = crm_meta_name(PCMK__META_PROMOTED_MAX_LEGACY);
        crm_xml_add_int(xml, name, promoted_max);
        free(name);

        name = crm_meta_name(PCMK__META_PROMOTED_NODE_MAX_LEGACY);
        crm_xml_add_int(xml, name, promoted_node_max);
        free(name);
    }
}

// Clone implementation of pcmk__assignment_methods_t:add_utilization()
void
pcmk__clone_add_utilization(const pcmk_resource_t *rsc,
                            const pcmk_resource_t *orig_rsc, GList *all_rscs,
                            GHashTable *utilization)
{
    bool existing = false;
    pcmk_resource_t *child = NULL;

    pcmk__assert(pcmk__is_clone(rsc) && (orig_rsc != NULL)
                 && (utilization != NULL));

    if (!pcmk_is_set(rsc->flags, pcmk__rsc_unassigned)) {
        return;
    }

    // Look for any child already existing in the list
    for (GList *iter = rsc->priv->children;
         iter != NULL; iter = iter->next) {

        child = (pcmk_resource_t *) iter->data;
        if (g_list_find(all_rscs, child)) {
            existing = true; // Keep checking remaining children
        } else {
            // If this is a clone of a group, look for group's members
            for (GList *member_iter = child->priv->children;
                 member_iter != NULL; member_iter = member_iter->next) {

                pcmk_resource_t *member = (pcmk_resource_t *) member_iter->data;

                if (g_list_find(all_rscs, member) != NULL) {
                    // Add *child's* utilization, not group member's
                    child->priv->cmds->add_utilization(child, orig_rsc,
                                                       all_rscs, utilization);
                    existing = true;
                    break;
                }
            }
        }
    }

    if (!existing && (rsc->priv->children != NULL)) {
        // If nothing was found, still add first child's utilization
        child = (pcmk_resource_t *) rsc->priv->children->data;

        child->priv->cmds->add_utilization(child, orig_rsc, all_rscs,
                                           utilization);
    }
}

// Clone implementation of pcmk__assignment_methods_t:shutdown_lock()
void
pcmk__clone_shutdown_lock(pcmk_resource_t *rsc)
{
    pcmk__assert(pcmk__is_clone(rsc));
    return; // Clones currently don't support shutdown locks
}
