/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/* This file is intended for code usable with both clone instances and bundle
 * replica containers.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Check whether a clone or bundle has instances for all available nodes
 *
 * \param[in] collective  Clone or bundle to check
 *
 * \return true if \p collective has enough instances for all of its available
 *         allowed nodes, otherwise false
 */
static bool
can_run_everywhere(const pe_resource_t *collective)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;
    int available_nodes = 0;
    int max_instances = 0;

    switch (collective->variant) {
        case pe_clone:
            max_instances = pe__clone_max(collective);
            break;
        case pe_container:
            max_instances = pe__bundle_max(collective);
            break;
        default:
            return false; // Not actually possible
    }

    g_hash_table_iter_init(&iter, collective->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        if (pcmk__node_available(node, false, false)
            && (max_instances < ++available_nodes)) {
            return false;
        }
    }
    return true;
}

/*!
 * \internal
 * \brief Check whether a node is allowed to run an instance
 *
 * \param[in] instance      Clone instance or bundle container to check
 * \param[in] node          Node to check
 * \param[in] max_per_node  Maximum number of instances allowed to run on a node
 *
 * \return true if \p node is allowed to run \p instance, otherwise false
 */
static bool
can_run_instance(const pe_resource_t *instance, const pe_node_t *node,
                 int max_per_node)
{
    pe_node_t *allowed_node = NULL;

    if (pcmk_is_set(instance->flags, pe_rsc_orphan)) {
        pe_rsc_trace(instance, "%s cannot run on %s: orphaned",
                     instance->id, pe__node_name(node));
        return false;
    }

    if (!pcmk__node_available(node, false, false)) {
        pe_rsc_trace(instance,
                     "%s cannot run on %s: node cannot run resources",
                     instance->id, pe__node_name(node));
        return false;
    }

    allowed_node = pcmk__top_allowed_node(instance, node);
    if (allowed_node == NULL) {
        crm_warn("%s cannot run on %s: node not allowed",
                 instance->id, pe__node_name(node));
        return false;
    }

    if (allowed_node->weight < 0) {
        pe_rsc_trace(instance, "%s cannot run on %s: parent score is %s there",
                     instance->id, pe__node_name(node),
                     pcmk_readable_score(allowed_node->weight));
        return false;
    }

    if (allowed_node->count >= max_per_node) {
        pe_rsc_trace(instance,
                     "%s cannot run on %s: node already has %d instance%s",
                     instance->id, pe__node_name(node), max_per_node,
                     pcmk__plural_s(max_per_node));
        return false;
    }

    pe_rsc_trace(instance, "%s can run on %s (%d already running)",
                 instance->id, pe__node_name(node), allowed_node->count);
    return true;
}

/*!
 * \internal
 * \brief Ban a clone instance or bundle replica from unavailable allowed nodes
 *
 * \param[in,out] instance      Clone instance or bundle replica to ban
 * \param[in]     max_per_node  Maximum instances allowed to run on a node
 */
static void
ban_unavailable_allowed_nodes(pe_resource_t *instance, int max_per_node)
{
    if (instance->allowed_nodes != NULL) {
        GHashTableIter iter;
        pe_node_t *node = NULL;

        g_hash_table_iter_init(&iter, instance->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
            if (!can_run_instance(instance, node, max_per_node)) {
                pe_rsc_trace(instance, "Banning %s from unavailable node %s",
                             instance->id, pe__node_name(node));
                node->weight = -INFINITY;
                for (GList *child_iter = instance->children;
                     child_iter != NULL; child_iter = child_iter->next) {
                    pe_resource_t *child = (pe_resource_t *) child_iter->data;
                    pe_node_t *child_node = NULL;

                    child_node = pe_hash_table_lookup(child->allowed_nodes,
                                                      node->details->id);
                    if (child_node != NULL) {
                        pe_rsc_trace(instance,
                                     "Banning %s child %s "
                                     "from unavailable node %s",
                                     instance->id, child->id,
                                     pe__node_name(node));
                        child_node->weight = -INFINITY;
                    }
                }
            }
        }
    }
}

/*!
 * \internal
 * \brief Create a hash table with a single node in it
 *
 * \param[in] node  Node to copy into new table
 *
 * \return Newly created hash table containing a copy of \p node
 * \note The caller is responsible for freeing the result with
 *       g_hash_table_destroy().
 */
static GHashTable *
new_node_table(pe_node_t *node)
{
    GHashTable *table = pcmk__strkey_table(NULL, free);

    node = pe__copy_node(node);
    g_hash_table_insert(table, (gpointer) node->details->id, node);
    return table;
}

/*!
 * \internal
 * \brief Apply a resource's parent's colocation scores to a node table
 *
 * \param[in]     rsc    Resource whose colocations should be applied
 * \param[in,out] nodes  Node table to apply colocations to
 */
static void
apply_parent_colocations(const pe_resource_t *rsc, GHashTable **nodes)
{
    GList *iter = NULL;
    pcmk__colocation_t *colocation = NULL;
    pe_resource_t *other = NULL;
    float factor = 0.0;

    /* Because the this_with_colocations() and with_this_colocations() methods
     * boil down to copies of rsc_cons and rsc_cons_lhs for clones and bundles,
     * we can use those here directly for efficiency.
     */
    for (iter = rsc->parent->rsc_cons; iter != NULL; iter = iter->next) {
        colocation = (pcmk__colocation_t *) iter->data;
        other = colocation->primary;
        factor = colocation->score / (float) INFINITY,
        other->cmds->add_colocated_node_scores(other, rsc->id, nodes,
                                               colocation, factor,
                                               pcmk__coloc_select_default);
    }
    for (iter = rsc->parent->rsc_cons_lhs; iter != NULL; iter = iter->next) {
        colocation = (pcmk__colocation_t *) iter->data;
        if (!pcmk__colocation_has_influence(colocation, rsc)) {
            continue;
        }
        other = colocation->dependent;
        factor = colocation->score / (float) INFINITY,
        other->cmds->add_colocated_node_scores(other, rsc->id, nodes,
                                               colocation, factor,
                                               pcmk__coloc_select_nonnegative);
    }
}

/*!
 * \internal
 * \brief Compare clone or bundle instances based on colocation scores
 *
 * Determine the relative order in which two clone or bundle instances should be
 * assigned to nodes, considering the scores of colocation constraints directly
 * or indirectly involving them.
 *
 * \param[in] instance1  First instance to compare
 * \param[in] instance2  Second instance to compare
 *
 * \return A negative number if \p instance1 should be assigned first,
 *         a positive number if \p instance2 should be assigned first,
 *         or 0 if assignment order doesn't matter
 */
static int
cmp_instance_by_colocation(const pe_resource_t *instance1,
                           const pe_resource_t *instance2)
{
    int rc = 0;
    pe_node_t *node1 = NULL;
    pe_node_t *node2 = NULL;
    pe_node_t *current_node1 = pe__current_node(instance1);
    pe_node_t *current_node2 = pe__current_node(instance2);
    GHashTable *colocated_scores1 = NULL;
    GHashTable *colocated_scores2 = NULL;

    CRM_ASSERT((instance1 != NULL) && (instance1->parent != NULL)
               && (instance2 != NULL) && (instance2->parent != NULL)
               && (current_node1 != NULL) && (current_node2 != NULL));

    // Create node tables initialized with each node
    colocated_scores1 = new_node_table(current_node1);
    colocated_scores2 = new_node_table(current_node2);

    // Apply parental colocations
    apply_parent_colocations(instance1, &colocated_scores1);
    apply_parent_colocations(instance2, &colocated_scores2);

    // Find original nodes again, with scores updated for colocations
    node1 = g_hash_table_lookup(colocated_scores1, current_node1->details->id);
    node2 = g_hash_table_lookup(colocated_scores2, current_node2->details->id);

    // Compare nodes by updated scores
    if (node1->weight < node2->weight) {
        crm_trace("Assign %s (%d on %s) after %s (%d on %s)",
                  instance1->id, node1->weight, pe__node_name(node1),
                  instance2->id, node2->weight, pe__node_name(node2));
        rc = 1;

    } else if (node1->weight > node2->weight) {
        crm_trace("Assign %s (%d on %s) before %s (%d on %s)",
                  instance1->id, node1->weight, pe__node_name(node1),
                  instance2->id, node2->weight, pe__node_name(node2));
        rc = -1;
    }

    g_hash_table_destroy(colocated_scores1);
    g_hash_table_destroy(colocated_scores2);
    return rc;
}

/*!
 * \internal
 * \brief Check whether a resource or any of its children are failed
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc or any of its children are failed, otherwise false
 */
static bool
did_fail(const pe_resource_t *rsc)
{
    if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
        return true;
    }
    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        if (did_fail((const pe_resource_t *) iter->data)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether a node is allowed to run a resource
 *
 * \param[in]     rsc   Resource to check
 * \param[in,out] node  Node to check (will be set NULL if not allowed)
 *
 * \return true if *node is either NULL or allowed for \p rsc, otherwise false
 */
static bool
node_is_allowed(const pe_resource_t *rsc, pe_node_t **node)
{
    if (*node != NULL) {
        pe_node_t *allowed = pe_hash_table_lookup(rsc->allowed_nodes,
                                                  (*node)->details->id);
        if ((allowed == NULL) || (allowed->weight < 0)) {
            pe_rsc_trace(rsc, "%s: current location (%s) is unavailable",
                         rsc->id, pe__node_name(*node));
            *node = NULL;
            return false;
        }
    }
    return true;
}

/*!
 * \internal
 * \brief Compare two clone or bundle instances' instance numbers
 *
 * \param[in] a  First instance to compare
 * \param[in] b  Second instance to compare
 *
 * \return A negative number if \p a's instance number is lower,
 *         a positive number if \p b's instance number is lower,
 *         or 0 if their instance numbers are the same
 */
gint
pcmk__cmp_instance_number(gconstpointer a, gconstpointer b)
{
    const pe_resource_t *instance1 = (const pe_resource_t *) a;
    const pe_resource_t *instance2 = (const pe_resource_t *) b;
    char *div1 = NULL;
    char *div2 = NULL;

    CRM_ASSERT((instance1 != NULL) && (instance2 != NULL));

    // Clone numbers are after a colon, bundle numbers after a dash
    div1 = strrchr(instance1->id, ':');
    if (div1 == NULL) {
        div1 = strrchr(instance1->id, '-');
    }
    div2 = strrchr(instance2->id, ':');
    if (div2 == NULL) {
        div2 = strrchr(instance2->id, '-');
    }
    CRM_ASSERT((div1 != NULL) && (div2 != NULL));

    return (gint) (strtol(div1 + 1, NULL, 10) - strtol(div2 + 1, NULL, 10));
}

/*!
 * \internal
 * \brief Compare clone or bundle instances according to assignment order
 *
 * Compare two clone or bundle instances according to the order they should be
 * assigned to nodes, preferring (in order):
 *
 *  - Active instance that is less multiply active
 *  - Instance that is not active on a disallowed node
 *  - Instance with higher configured priority
 *  - Active instance whose current node can run resources
 *  - Active instance whose parent is allowed on current node
 *  - Active instance whose current node has fewer other instances
 *  - Active instance
 *  - Instance that isn't failed
 *  - Instance whose colocations result in higher score on current node
 *  - Instance with lower ID in lexicographic order
 *
 * \param[in] a          First instance to compare
 * \param[in] b          Second instance to compare
 *
 * \return A negative number if \p a should be assigned first,
 *         a positive number if \p b should be assigned first,
 *         or 0 if assignment order doesn't matter
 */
gint
pcmk__cmp_instance(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    pe_node_t *node1 = NULL;
    pe_node_t *node2 = NULL;
    unsigned int nnodes1 = 0;
    unsigned int nnodes2 = 0;

    bool can1 = true;
    bool can2 = true;

    const pe_resource_t *instance1 = (const pe_resource_t *) a;
    const pe_resource_t *instance2 = (const pe_resource_t *) b;

    CRM_ASSERT((instance1 != NULL) && (instance2 != NULL));

    node1 = instance1->fns->active_node(instance1, &nnodes1, NULL);
    node2 = instance2->fns->active_node(instance2, &nnodes2, NULL);

    /* If both instances are running and at least one is multiply
     * active, prefer instance that's running on fewer nodes.
     */
    if ((nnodes1 > 0) && (nnodes2 > 0)) {
        if (nnodes1 < nnodes2) {
            crm_trace("Assign %s (active on %d) before %s (active on %d): "
                      "less multiply active",
                      instance1->id, nnodes1, instance2->id, nnodes2);
            return -1;

        } else if (nnodes1 > nnodes2) {
            crm_trace("Assign %s (active on %d) after %s (active on %d): "
                      "more multiply active",
                      instance1->id, nnodes1, instance2->id, nnodes2);
            return 1;
        }
    }

    /* An instance that is either inactive or active on an allowed node is
     * preferred over an instance that is active on a no-longer-allowed node.
     */
    can1 = node_is_allowed(instance1, &node1);
    can2 = node_is_allowed(instance2, &node2);
    if (can1 && !can2) {
        crm_trace("Assign %s before %s: not active on a disallowed node",
                  instance1->id, instance2->id);
        return -1;

    } else if (!can1 && can2) {
        crm_trace("Assign %s after %s: active on a disallowed node",
                  instance1->id, instance2->id);
        return 1;
    }

    // Prefer instance with higher configured priority
    if (instance1->priority > instance2->priority) {
        crm_trace("Assign %s before %s: priority (%d > %d)",
                  instance1->id, instance2->id,
                  instance1->priority, instance2->priority);
        return -1;

    } else if (instance1->priority < instance2->priority) {
        crm_trace("Assign %s after %s: priority (%d < %d)",
                  instance1->id, instance2->id,
                  instance1->priority, instance2->priority);
        return 1;
    }

    // Prefer active instance
    if ((node1 == NULL) && (node2 == NULL)) {
        crm_trace("No assignment preference for %s vs. %s: inactive",
                  instance1->id, instance2->id);
        return 0;

    } else if (node1 == NULL) {
        crm_trace("Assign %s after %s: active", instance1->id, instance2->id);
        return 1;

    } else if (node2 == NULL) {
        crm_trace("Assign %s before %s: active", instance1->id, instance2->id);
        return -1;
    }

    // Prefer instance whose current node can run resources
    can1 = pcmk__node_available(node1, false, false);
    can2 = pcmk__node_available(node2, false, false);
    if (can1 && !can2) {
        crm_trace("Assign %s before %s: current node can run resources",
                  instance1->id, instance2->id);
        return -1;

    } else if (!can1 && can2) {
        crm_trace("Assign %s after %s: current node can't run resources",
                  instance1->id, instance2->id);
        return 1;
    }

    // Prefer instance whose parent is allowed to run on instance's current node
    node1 = pcmk__top_allowed_node(instance1, node1);
    node2 = pcmk__top_allowed_node(instance2, node2);
    if ((node1 == NULL) && (node2 == NULL)) {
        crm_trace("No assignment preference for %s vs. %s: "
                  "parent not allowed on either instance's current node",
                  instance1->id, instance2->id);
        return 0;

    } else if (node1 == NULL) {
        crm_trace("Assign %s after %s: parent not allowed on current node",
                  instance1->id, instance2->id);
        return 1;

    } else if (node2 == NULL) {
        crm_trace("Assign %s before %s: parent allowed on current node",
                  instance1->id, instance2->id);
        return -1;
    }

    // Prefer instance whose current node is running fewer other instances
    if (node1->count < node2->count) {
        crm_trace("Assign %s before %s: fewer active instances on current node",
                  instance1->id, instance2->id);
        return -1;

    } else if (node1->count > node2->count) {
        crm_trace("Assign %s after %s: more active instances on current node",
                  instance1->id, instance2->id);
        return 1;
    }

    // Prefer instance that isn't failed
    can1 = did_fail(instance1);
    can2 = did_fail(instance2);
    if (!can1 && can2) {
        crm_trace("Assign %s before %s: not failed",
                  instance1->id, instance2->id);
        return -1;
    } else if (can1 && !can2) {
        crm_trace("Assign %s after %s: failed",
                  instance1->id, instance2->id);
        return 1;
    }

    // Prefer instance with higher cumulative colocation score on current node
    rc = cmp_instance_by_colocation(instance1, instance2);
    if (rc != 0) {
        return rc;
    }

    // Prefer instance with lower instance number
    rc = pcmk__cmp_instance_number(instance1, instance2);
    if (rc < 0) {
        crm_trace("Assign %s before %s: instance number",
                  instance1->id, instance2->id);
    } else if (rc > 0) {
        crm_trace("Assign %s after %s: instance number",
                  instance1->id, instance2->id);
    } else {
        crm_trace("No assignment preference for %s vs. %s",
                  instance1->id, instance2->id);
    }
    return rc;
}

/*!
 * \internal
 * \brief Choose a node for an instance
 *
 * \param[in,out] instance      Clone instance or bundle replica container
 * \param[in]     prefer        If not NULL, attempt early assignment to this
 *                              node, if still the best choice; otherwise,
 *                              perform final assignment
 * \param[in]     max_per_node  Assign at most this many instances to one node
 *
 * \return true if \p instance could be assigned to a node, otherwise false
 */
static bool
assign_instance(pe_resource_t *instance, const pe_node_t *prefer,
                int max_per_node)
{
    pe_node_t *chosen = NULL;
    pe_node_t *allowed = NULL;

    CRM_ASSERT(instance != NULL);
    pe_rsc_trace(instance, "Assigning %s (preferring %s)", instance->id,
                 ((prefer == NULL)? "no node" : prefer->details->uname));

    CRM_CHECK(pcmk_is_set(instance->flags, pe_rsc_provisional),
              return (instance->fns->location(instance, NULL, FALSE) != NULL));

    if (pcmk_is_set(instance->flags, pe_rsc_allocating)) {
        pe_rsc_debug(instance,
                     "Assignment loop detected involving %s colocations",
                     instance->id);
        return false;
    }

    if (prefer != NULL) { // Possible early assignment to preferred node

        // Get preferred node with instance's scores
        allowed = g_hash_table_lookup(instance->allowed_nodes,
                                      prefer->details->id);

        if ((allowed == NULL) || (allowed->weight < 0)) {
            pe_rsc_trace(instance,
                         "Not assigning %s to preferred node %s: unavailable",
                         instance->id, pe__node_name(prefer));
            return false;
        }
    }

    ban_unavailable_allowed_nodes(instance, max_per_node);

    if (prefer == NULL) { // Final assignment
        chosen = instance->cmds->assign(instance, NULL);

    } else { // Possible early assignment to preferred node
        GHashTable *backup = pcmk__copy_node_table(instance->allowed_nodes);

        chosen = instance->cmds->assign(instance, prefer);

        // Revert nodes if preferred node won't be assigned
        if ((chosen != NULL) && !pe__same_node(chosen, prefer)) {
            crm_info("Not assigning %s to preferred node %s: %s is better",
                     instance->id, pe__node_name(prefer),
                     pe__node_name(chosen));
            g_hash_table_destroy(instance->allowed_nodes);
            instance->allowed_nodes = backup;
            pcmk__unassign_resource(instance);
            chosen = NULL;
        } else if (backup != NULL) {
            g_hash_table_destroy(backup);
        }
    }

    // The parent tracks how many instances have been assigned to each node
    if (chosen != NULL) {
        allowed = pcmk__top_allowed_node(instance, chosen);
        if (allowed == NULL) {
            /* The instance is allowed on the node, but its parent isn't. This
             * shouldn't be possible if the resource is managed, and we won't be
             * able to limit the number of instances assigned to the node.
             */
            CRM_LOG_ASSERT(!pcmk_is_set(instance->flags, pe_rsc_managed));

        } else {
            allowed->count++;
        }
    }
    return chosen != NULL;
}

/*!
 * \internal
 * \brief Reset the node counts of a resource's allowed nodes to zero
 *
 * \param[in,out] rsc  Resource to reset
 *
 * \return Number of nodes that are available to run resources
 */
static unsigned int
reset_allowed_node_counts(pe_resource_t *rsc)
{
    unsigned int available_nodes = 0;
    pe_node_t *node = NULL;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        node->count = 0;
        if (pcmk__node_available(node, false, false)) {
            available_nodes++;
        }
    }
    return available_nodes;
}

/*!
 * \internal
 * \brief Check whether an instance has a preferred node
 *
 * \param[in] rsc               Clone or bundle being assigned (for logs only)
 * \param[in] instance          Clone instance or bundle replica container
 * \param[in] optimal_per_node  Optimal number of instances per node
 *
 * \return Instance's current node if still available, otherwise NULL
 */
static const pe_node_t *
preferred_node(const pe_resource_t *rsc, const pe_resource_t *instance,
               int optimal_per_node)
{
    const pe_node_t *node = NULL;
    const pe_node_t *parent_node = NULL;

    // Check whether instance is active, healthy, and not yet assigned
    if ((instance->running_on == NULL)
        || !pcmk_is_set(instance->flags, pe_rsc_provisional)
        || pcmk_is_set(instance->flags, pe_rsc_failed)) {
        return NULL;
    }

    // Check whether instance's current node can run resources
    node = pe__current_node(instance);
    if (!pcmk__node_available(node, true, false)) {
        pe_rsc_trace(rsc, "Not assigning %s to %s early (unavailable)",
                     instance->id, pe__node_name(node));
        return NULL;
    }

    // Check whether node already has optimal number of instances assigned
    parent_node = pcmk__top_allowed_node(instance, node);
    if ((parent_node != NULL) && (parent_node->count >= optimal_per_node)) {
        pe_rsc_trace(rsc,
                     "Not assigning %s to %s early "
                     "(optimal instances already assigned)",
                     instance->id, pe__node_name(node));
        return NULL;
    }

    return node;
}

/*!
 * \internal
 * \brief Assign collective instances to nodes
 *
 * \param[in,out] collective    Clone or bundle resource being assigned
 * \param[in,out] instances     List of clone instances or bundle containers
 * \param[in]     max_total     Maximum instances to assign in total
 * \param[in]     max_per_node  Maximum instances to assign to any one node
 */
void
pcmk__assign_instances(pe_resource_t *collective, GList *instances,
                       int max_total, int max_per_node)
{
    // Reuse node count to track number of assigned instances
    unsigned int available_nodes = reset_allowed_node_counts(collective);

    int optimal_per_node = 0;
    int assigned = 0;
    GList *iter = NULL;
    pe_resource_t *instance = NULL;
    const pe_node_t *current = NULL;

    if (available_nodes > 0) {
        optimal_per_node = max_total / available_nodes;
    }
    if (optimal_per_node < 1) {
        optimal_per_node = 1;
    }

    pe_rsc_debug(collective,
                 "Assigning up to %d %s instance%s to up to %u node%s "
                 "(at most %d per host, %d optimal)",
                 max_total, collective->id, pcmk__plural_s(max_total),
                 available_nodes, pcmk__plural_s(available_nodes),
                 max_per_node, optimal_per_node);

    // Assign as many instances as possible to their current location
    for (iter = instances; (iter != NULL) && (assigned < max_total);
         iter = iter->next) {
        instance = (pe_resource_t *) iter->data;

        current = preferred_node(collective, instance, optimal_per_node);
        if ((current != NULL)
            && assign_instance(instance, current, max_per_node)) {
            pe_rsc_trace(collective, "Assigned %s to current node %s",
                         instance->id, pe__node_name(current));
            assigned++;
        }
    }

    pe_rsc_trace(collective, "Assigned %d of %d instance%s to current node",
                 assigned, max_total, pcmk__plural_s(max_total));

    for (iter = instances; iter != NULL; iter = iter->next) {
        instance = (pe_resource_t *) iter->data;

        if (!pcmk_is_set(instance->flags, pe_rsc_provisional)) {
            continue; // Already assigned
        }

        if (instance->running_on != NULL) {
            current = pe__current_node(instance);
            if (pcmk__top_allowed_node(instance, current) == NULL) {
                const char *unmanaged = "";

                if (!pcmk_is_set(instance->flags, pe_rsc_managed)) {
                    unmanaged = "Unmanaged resource ";
                }
                crm_notice("%s%s is running on %s which is no longer allowed",
                           unmanaged, instance->id, pe__node_name(current));
            }
        }

        if (assigned >= max_total) {
            pe_rsc_debug(collective,
                         "Not assigning %s because maximum %d instances "
                         "already assigned",
                         instance->id, max_total);
            resource_location(instance, NULL, -INFINITY,
                              "collective_limit_reached", collective->cluster);

        } else if (assign_instance(instance, NULL, max_per_node)) {
            assigned++;
        }
    }

    pe_rsc_debug(collective, "Assigned %d of %d possible instance%s of %s",
                 assigned, max_total, pcmk__plural_s(max_total),
                 collective->id);
}

enum instance_state {
    instance_starting   = (1 << 0),
    instance_stopping   = (1 << 1),

    /* This indicates that some instance is restarting. It's not the same as
     * instance_starting|instance_stopping, which would indicate that some
     * instance is starting, and some instance (not necessarily the same one) is
     * stopping.
     */
    instance_restarting = (1 << 2),

    instance_active     = (1 << 3),

    instance_all        = instance_starting|instance_stopping
                          |instance_restarting|instance_active,
};

/*!
 * \internal
 * \brief Check whether an instance is active, starting, and/or stopping
 *
 * \param[in]     instance  Clone instance or bundle replica container
 * \param[in,out] state     Whether any instance is starting, stopping, etc.
 */
static void
check_instance_state(const pe_resource_t *instance, uint32_t *state)
{
    const GList *iter = NULL;
    uint32_t instance_state = 0; // State of just this instance

    // No need to check further if all conditions have already been detected
    if (pcmk_all_flags_set(*state, instance_all)) {
        return;
    }

    // If instance is a collective (a cloned group), check its children instead
    if (instance->variant > pe_native) {
        for (iter = instance->children;
             (iter != NULL) && !pcmk_all_flags_set(*state, instance_all);
             iter = iter->next) {
            check_instance_state((const pe_resource_t *) iter->data, state);
        }
        return;
    }

    // If we get here, instance is a primitive

    if (instance->running_on != NULL) {
        instance_state |= instance_active;
    }

    // Check each of the instance's actions for runnable start or stop
    for (iter = instance->actions;
         (iter != NULL) && !pcmk_all_flags_set(instance_state,
                                               instance_starting
                                               |instance_stopping);
         iter = iter->next) {

        const pe_action_t *action = (const pe_action_t *) iter->data;
        const bool optional = pcmk_is_set(action->flags, pe_action_optional);

        if (pcmk__str_eq(RSC_START, action->task, pcmk__str_none)) {
            if (!optional && pcmk_is_set(action->flags, pe_action_runnable)) {
                pe_rsc_trace(instance, "Instance is starting due to %s",
                             action->uuid);
                instance_state |= instance_starting;
            } else {
                pe_rsc_trace(instance, "%s doesn't affect %s state (%s)",
                             action->uuid, instance->id,
                             (optional? "optional" : "unrunnable"));
            }

        } else if (pcmk__str_eq(RSC_STOP, action->task, pcmk__str_none)) {
            /* Only stop actions can be pseudo-actions for primitives. That
             * indicates that the node they are on is being fenced, so the stop
             * is implied rather than actually executed.
             */
            if (!optional
                && pcmk_any_flags_set(action->flags,
                                      pe_action_pseudo|pe_action_runnable)) {
                pe_rsc_trace(instance, "Instance is stopping due to %s",
                             action->uuid);
                instance_state |= instance_stopping;
            } else {
                pe_rsc_trace(instance, "%s doesn't affect %s state (%s)",
                             action->uuid, instance->id,
                             (optional? "optional" : "unrunnable"));
            }
        }
    }

    if (pcmk_all_flags_set(instance_state,
                           instance_starting|instance_stopping)) {
        instance_state |= instance_restarting;
    }
    *state |= instance_state;
}

/*!
 * \internal
 * \brief Create actions for collective resource instances
 *
 * \param[in,out] collective    Clone or bundle resource to create actions for
 * \param[in,out] instances     List of clone instances or bundle containers
 */
void
pcmk__create_instance_actions(pe_resource_t *collective, GList *instances)
{
    uint32_t state = 0;

    pe_action_t *stop = NULL;
    pe_action_t *stopped = NULL;

    pe_action_t *start = NULL;
    pe_action_t *started = NULL;

    pe_rsc_trace(collective, "Creating collective instance actions for %s",
                 collective->id);

    // Create actions for each instance appropriate to its variant
    for (GList *iter = instances; iter != NULL; iter = iter->next) {
        pe_resource_t *instance = (pe_resource_t *) iter->data;

        instance->cmds->create_actions(instance);
        check_instance_state(instance, &state);
    }

    // Create pseudo-actions for rsc start and started
    start = pe__new_rsc_pseudo_action(collective, RSC_START,
                                      !pcmk_is_set(state, instance_starting),
                                      true);
    started = pe__new_rsc_pseudo_action(collective, RSC_STARTED,
                                        !pcmk_is_set(state, instance_starting),
                                        false);
    started->priority = INFINITY;
    if (pcmk_any_flags_set(state, instance_active|instance_starting)) {
        pe__set_action_flags(started, pe_action_runnable);
    }

    // Create pseudo-actions for rsc stop and stopped
    stop = pe__new_rsc_pseudo_action(collective, RSC_STOP,
                                     !pcmk_is_set(state, instance_stopping),
                                     true);
    stopped = pe__new_rsc_pseudo_action(collective, RSC_STOPPED,
                                        !pcmk_is_set(state, instance_stopping),
                                        true);
    stopped->priority = INFINITY;
    if (!pcmk_is_set(state, instance_restarting)) {
        pe__set_action_flags(stop, pe_action_migrate_runnable);
    }

    if (collective->variant == pe_clone) {
        pe__create_clone_notif_pseudo_ops(collective, start, started, stop,
                                          stopped);
    }
}

/*!
 * \internal
 * \brief Get a list of clone instances or bundle replica containers
 *
 * \param[in] rsc  Clone or bundle resource
 *
 * \return Clone instances if \p rsc is a clone, or a newly created list of
 *         \p rsc's replica containers if \p rsc is a bundle
 * \note The caller must call free_instance_list() on the result when the list
 *       is no longer needed.
 */
static inline GList *
get_instance_list(const pe_resource_t *rsc)
{
    if (rsc->variant == pe_container) {
        return pe__bundle_containers(rsc);
    } else {
        return rsc->children;
    }
}

/*!
 * \internal
 * \brief Free any memory created by get_instance_list()
 *
 * \param[in]     rsc   Clone or bundle resource passed to get_instance_list()
 * \param[in,out] list  Return value of get_instance_list() for \p rsc
 */
static inline void
free_instance_list(const pe_resource_t *rsc, GList *list)
{
    if (list != rsc->children) {
        g_list_free(list);
    }
}

/*!
 * \internal
 * \brief Check whether an instance is compatible with a role and node
 *
 * \param[in] instance  Clone instance or bundle replica container
 * \param[in] node      Instance must match this node
 * \param[in] role      If not RSC_ROLE_UNKNOWN, instance must match this role
 * \param[in] current   If true, compare instance's original node and role,
 *                      otherwise compare assigned next node and role
 *
 * \return true if \p instance is compatible with \p node and \p role,
 *         otherwise false
 */
bool
pcmk__instance_matches(const pe_resource_t *instance, const pe_node_t *node,
                       enum rsc_role_e role, bool current)
{
    pe_node_t *instance_node = NULL;

    CRM_CHECK((instance != NULL) && (node != NULL), return false);

    if ((role != RSC_ROLE_UNKNOWN)
        && (role != instance->fns->state(instance, current))) {
        pe_rsc_trace(instance,
                     "%s is not a compatible instance (role is not %s)",
                     instance->id, role2text(role));
        return false;
    }

    if (!is_set_recursive(instance, pe_rsc_block, true)) {
        // We only want instances that haven't failed
        instance_node = instance->fns->location(instance, NULL, current);
    }

    if (instance_node == NULL) {
        pe_rsc_trace(instance,
                     "%s is not a compatible instance (not assigned to a node)",
                     instance->id);
        return false;
    }

    if (!pe__same_node(instance_node, node)) {
        pe_rsc_trace(instance,
                     "%s is not a compatible instance (assigned to %s not %s)",
                     instance->id, pe__node_name(instance_node),
                     pe__node_name(node));
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Find an instance that matches a given resource by node and role
 *
 * \param[in] match_rsc  Resource that instance must match (for logging only)
 * \param[in] rsc        Clone or bundle resource to check for matching instance
 * \param[in] node       Instance must match this node
 * \param[in] role       If not RSC_ROLE_UNKNOWN, instance must match this role
 * \param[in] current    If true, compare instance's original node and role,
 *                       otherwise compare assigned next node and role
 *
 * \return \p rsc instance matching \p node and \p role if any, otherwise NULL
 */
static pe_resource_t *
find_compatible_instance_on_node(const pe_resource_t *match_rsc,
                                 const pe_resource_t *rsc,
                                 const pe_node_t *node, enum rsc_role_e role,
                                 bool current)
{
    GList *instances = NULL;

    instances = get_instance_list(rsc);
    for (GList *iter = instances; iter != NULL; iter = iter->next) {
        pe_resource_t *instance = (pe_resource_t *) iter->data;

        if (pcmk__instance_matches(instance, node, role, current)) {
            pe_rsc_trace(match_rsc,
                         "Found %s %s instance %s compatible with %s on %s",
                         role == RSC_ROLE_UNKNOWN? "matching" : role2text(role),
                         rsc->id, instance->id, match_rsc->id,
                         pe__node_name(node));
            free_instance_list(rsc, instances); // Only frees list, not contents
            return instance;
        }
    }
    free_instance_list(rsc, instances);

    pe_rsc_trace(match_rsc, "No %s %s instance found compatible with %s on %s",
                 ((role == RSC_ROLE_UNKNOWN)? "matching" : role2text(role)),
                 rsc->id, match_rsc->id, pe__node_name(node));
    return NULL;
}

/*!
 * \internal
 * \brief Find a clone instance or bundle container compatible with a resource
 *
 * \param[in] match_rsc  Resource that instance must match
 * \param[in] rsc        Clone or bundle resource to check for matching instance
 * \param[in] role       If not RSC_ROLE_UNKNOWN, instance must match this role
 * \param[in] current    If true, compare instance's original node and role,
 *                       otherwise compare assigned next node and role
 *
 * \return Compatible (by \p role and \p match_rsc location) instance of \p rsc
 *         if any, otherwise NULL
 */
pe_resource_t *
pcmk__find_compatible_instance(const pe_resource_t *match_rsc,
                               const pe_resource_t *rsc, enum rsc_role_e role,
                               bool current)
{
    pe_resource_t *instance = NULL;
    GList *nodes = NULL;
    const pe_node_t *node = match_rsc->fns->location(match_rsc, NULL, current);

    // If match_rsc has a node, check only that node
    if (node != NULL) {
        return find_compatible_instance_on_node(match_rsc, rsc, node, role,
                                                current);
    }

    // Otherwise check for an instance matching any of match_rsc's allowed nodes
    nodes = pcmk__sort_nodes(g_hash_table_get_values(match_rsc->allowed_nodes),
                             NULL);
    for (GList *iter = nodes; (iter != NULL) && (instance == NULL);
         iter = iter->next) {
        instance = find_compatible_instance_on_node(match_rsc, rsc,
                                                    (pe_node_t *) iter->data,
                                                    role, current);
    }

    if (instance == NULL) {
        pe_rsc_debug(rsc, "No %s instance found compatible with %s",
                     rsc->id, match_rsc->id);
    }
    g_list_free(nodes);
    return instance;
}

/*!
 * \internal
 * \brief Unassign an instance if mandatory ordering has no interleave match
 *
 * \param[in]     first          'First' action in an ordering
 * \param[in]     then           'Then' action in an ordering
 * \param[in,out] then_instance  'Then' instance that has no interleave match
 * \param[in]     type           Group of enum pe_ordering flags to apply
 * \param[in]     current        If true, "then" action is stopped or demoted
 *
 * \return true if \p then_instance was unassigned, otherwise false
 */
static bool
unassign_if_mandatory(const pe_action_t *first, const pe_action_t *then,
                      pe_resource_t *then_instance, uint32_t type, bool current)
{
    // Allow "then" instance to go down even without an interleave match
    if (current) {
        pe_rsc_trace(then->rsc,
                     "%s has no instance to order before stopping "
                     "or demoting %s",
                     first->rsc->id, then_instance->id);

    /* If the "first" action must be runnable, but there is no "first"
     * instance, the "then" instance must not be allowed to come up.
     */
    } else if (pcmk_any_flags_set(type, pe_order_runnable_left
                                        |pe_order_implies_then)) {
        pe_rsc_info(then->rsc,
                    "Inhibiting %s from being active "
                    "because there is no %s instance to interleave",
                    then_instance->id, first->rsc->id);
        return pcmk__assign_resource(then_instance, NULL, true);
    }
    return false;
}

/*!
 * \internal
 * \brief Find first matching action for a clone instance or bundle container
 *
 * \param[in] action       Action in an interleaved ordering
 * \param[in] instance     Clone instance or bundle container being interleaved
 * \param[in] action_name  Action to look for
 * \param[in] node         If not NULL, require action to be on this node
 * \param[in] for_first    If true, \p instance is the 'first' resource in the
 *                         ordering, otherwise it is the 'then' resource
 *
 * \return First action for \p instance (or in some cases if \p instance is a
 *         bundle container, its containerized resource) that matches
 *         \p action_name and \p node if any, otherwise NULL
 */
static pe_action_t *
find_instance_action(const pe_action_t *action, const pe_resource_t *instance,
                     const char *action_name, const pe_node_t *node,
                     bool for_first)
{
    const pe_resource_t *rsc = NULL;
    pe_action_t *matching_action = NULL;

    /* If instance is a bundle container, sometimes we should interleave the
     * action for the container itself, and sometimes for the containerized
     * resource.
     *
     * For example, given "start bundle A then bundle B", B likely requires the
     * service inside A's container to be active, rather than just the
     * container, so we should interleave the action for A's containerized
     * resource. On the other hand, it's possible B's container itself requires
     * something from A, so we should interleave the action for B's container.
     *
     * Essentially, for 'first', we should use the containerized resource for
     * everything except stop, and for 'then', we should use the container for
     * everything except promote and demote (which can only be performed on the
     * containerized resource).
     */
    if ((for_first && !pcmk__str_any_of(action->task, CRMD_ACTION_STOP,
                                        CRMD_ACTION_STOPPED, NULL))

        || (!for_first && pcmk__str_any_of(action->task, CRMD_ACTION_PROMOTE,
                                           CRMD_ACTION_PROMOTED,
                                           CRMD_ACTION_DEMOTE,
                                           CRMD_ACTION_DEMOTED, NULL))) {

        rsc = pe__get_rsc_in_container(instance);
    }
    if (rsc == NULL) {
        rsc = instance; // No containerized resource, use instance itself
    } else {
        node = NULL; // Containerized actions are on bundle-created guest
    }

    matching_action = find_first_action(rsc->actions, NULL, action_name, node);
    if (matching_action != NULL) {
        return matching_action;
    }

    if (pcmk_is_set(instance->flags, pe_rsc_orphan)
        || pcmk__str_any_of(action_name, RSC_STOP, RSC_DEMOTE, NULL)) {
        crm_trace("No %s action found for %s%s",
                  action_name,
                  pcmk_is_set(instance->flags, pe_rsc_orphan)? "orphan " : "",
                  instance->id);
    } else {
        crm_err("No %s action found for %s to interleave (bug?)",
                action_name, instance->id);
    }
    return NULL;
}

/*!
 * \internal
 * \brief Get the original action name of a bundle or clone action
 *
 * Given an action for a bundle or clone, get the original action name,
 * mapping notify to the action being notified, and if the instances are
 * primitives, mapping completion actions to the action that was completed
 * (for example, stopped to stop).
 *
 * \param[in] action  Clone or bundle action to check
 *
 * \return Original action name for \p action
 */
static const char *
orig_action_name(const pe_action_t *action)
{
    const pe_resource_t *instance = action->rsc->children->data; // Any instance
    char *action_type = NULL;
    const char *action_name = action->task;
    enum action_tasks orig_task = no_action;

    if (pcmk__strcase_any_of(action->task, CRMD_ACTION_NOTIFY,
                             CRMD_ACTION_NOTIFIED, NULL)) {
        // action->uuid is RSC_(confirmed-){pre,post}_notify_ACTION_INTERVAL
        CRM_CHECK(parse_op_key(action->uuid, NULL, &action_type, NULL),
                  return task2text(no_action));
        action_name = strstr(action_type, "_notify_");
        CRM_CHECK(action_name != NULL, return task2text(no_action));
        action_name += strlen("_notify_");
    }
    orig_task = get_complex_task(instance, action_name);
    free(action_type);
    return task2text(orig_task);
}

/*!
 * \internal
 * \brief Update two interleaved actions according to an ordering between them
 *
 * Given information about an ordering of two interleaved actions, update the
 * actions' flags (and runnable_before members if appropriate) as appropriate
 * for the ordering. Effects may cascade to other orderings involving the
 * actions as well.
 *
 * \param[in,out] first     'First' action in an ordering
 * \param[in,out] then      'Then' action in an ordering
 * \param[in]     node      If not NULL, limit scope of ordering to this node
 * \param[in]     filter    Action flags to limit scope of certain updates (may
 *                          include pe_action_optional to affect only mandatory
 *                          actions, and pe_action_runnable to affect only
 *                          runnable actions)
 * \param[in]     type      Group of enum pe_ordering flags to apply
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
static uint32_t
update_interleaved_actions(pe_action_t *first, pe_action_t *then,
                           const pe_node_t *node, uint32_t filter,
                           uint32_t type)
{
    GList *instances = NULL;
    uint32_t changed = pcmk__updated_none;
    const char *orig_first_task = orig_action_name(first);

    // Stops and demotes must be interleaved with instance on current node
    bool current = pcmk__ends_with(first->uuid, "_" CRMD_ACTION_STOPPED "_0")
                   || pcmk__ends_with(first->uuid,
                                      "_" CRMD_ACTION_DEMOTED "_0");

    // Update the specified actions for each "then" instance individually
    instances = get_instance_list(then->rsc);
    for (GList *iter = instances; iter != NULL; iter = iter->next) {
        pe_resource_t *first_instance = NULL;
        pe_resource_t *then_instance = iter->data;

        pe_action_t *first_action = NULL;
        pe_action_t *then_action = NULL;

        // Find a "first" instance to interleave with this "then" instance
        first_instance = pcmk__find_compatible_instance(then_instance,
                                                        first->rsc,
                                                        RSC_ROLE_UNKNOWN,
                                                        current);

        if (first_instance == NULL) { // No instance can be interleaved
            if (unassign_if_mandatory(first, then, then_instance, type,
                                      current)) {
                pcmk__set_updated_flags(changed, first, pcmk__updated_then);
            }
            continue;
        }

        first_action = find_instance_action(first, first_instance,
                                            orig_first_task, node, true);
        if (first_action == NULL) {
            continue;
        }

        then_action = find_instance_action(then, then_instance, then->task,
                                           node, false);
        if (then_action == NULL) {
            continue;
        }

        if (order_actions(first_action, then_action, type)) {
            pcmk__set_updated_flags(changed, first,
                                    pcmk__updated_first|pcmk__updated_then);
        }

        changed |= then_instance->cmds->update_ordered_actions(
            first_action, then_action, node,
            first_instance->cmds->action_flags(first_action, node), filter,
            type, then->rsc->cluster);
    }
    free_instance_list(then->rsc, instances);
    return changed;
}

/*!
 * \internal
 * \brief Check whether two actions in an ordering can be interleaved
 *
 * \param[in] first  'First' action in the ordering
 * \param[in] then   'Then' action in the ordering
 *
 * \return true if \p first and \p then can be interleaved, otherwise false
 */
static bool
can_interleave_actions(const pe_action_t *first, const pe_action_t *then)
{
    bool interleave = false;
    pe_resource_t *rsc = NULL;

    if ((first->rsc == NULL) || (then->rsc == NULL)) {
        crm_trace("Not interleaving %s with %s: not resource actions",
                  first->uuid, then->uuid);
        return false;
    }

    if (first->rsc == then->rsc) {
        crm_trace("Not interleaving %s with %s: same resource",
                  first->uuid, then->uuid);
        return false;
    }

    if ((first->rsc->variant < pe_clone) || (then->rsc->variant < pe_clone)) {
        crm_trace("Not interleaving %s with %s: not clones or bundles",
                  first->uuid, then->uuid);
        return false;
    }

    if (pcmk__ends_with(then->uuid, "_stop_0")
        || pcmk__ends_with(then->uuid, "_demote_0")) {
        rsc = first->rsc;
    } else {
        rsc = then->rsc;
    }

    interleave = crm_is_true(g_hash_table_lookup(rsc->meta,
                                                 XML_RSC_ATTR_INTERLEAVE));
    pe_rsc_trace(rsc, "'%s then %s' will %sbe interleaved (based on %s)",
                 first->uuid, then->uuid, (interleave? "" : "not "), rsc->id);
    return interleave;
}

/*!
 * \internal
 * \brief Update non-interleaved instance actions according to an ordering
 *
 * Given information about an ordering of two non-interleaved actions, update
 * the actions' flags (and runnable_before members if appropriate) as
 * appropriate for the ordering. Effects may cascade to other orderings
 * involving the actions as well.
 *
 * \param[in,out] instance  Clone instance or bundle container
 * \param[in,out] first     "First" action in ordering
 * \param[in]     then      "Then" action in ordering (for \p instance's parent)
 * \param[in]     node      If not NULL, limit scope of ordering to this node
 * \param[in]     flags     Action flags for \p first for ordering purposes
 * \param[in]     filter    Action flags to limit scope of certain updates (may
 *                          include pe_action_optional to affect only mandatory
 *                          actions, and pe_action_runnable to affect only
 *                          runnable actions)
 * \param[in]     type      Group of enum pe_ordering flags to apply
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
static uint32_t
update_noninterleaved_actions(pe_resource_t *instance, pe_action_t *first,
                              const pe_action_t *then, const pe_node_t *node,
                              uint32_t flags, uint32_t filter, uint32_t type)
{
    pe_action_t *instance_action = NULL;
    uint32_t instance_flags = 0;
    uint32_t changed = pcmk__updated_none;

    // Check whether instance has an equivalent of "then" action
    instance_action = find_first_action(instance->actions, NULL, then->task,
                                        node);
    if (instance_action == NULL) {
        return changed;
    }

    // Check whether action is runnable
    instance_flags = instance->cmds->action_flags(instance_action, node);
    if (!pcmk_is_set(instance_flags, pe_action_runnable)) {
        return changed;
    }

    // If so, update actions for the instance
    changed = instance->cmds->update_ordered_actions(first, instance_action,
                                                     node, flags, filter, type,
                                                     instance->cluster);

    // Propagate any changes to later actions
    if (pcmk_is_set(changed, pcmk__updated_then)) {
        for (GList *after_iter = instance_action->actions_after;
             after_iter != NULL; after_iter = after_iter->next) {
            pe_action_wrapper_t *after = after_iter->data;

            pcmk__update_action_for_orderings(after->action, instance->cluster);
        }
    }

    return changed;
}

/*!
 * \internal
 * \brief Update two actions according to an ordering between them
 *
 * Given information about an ordering of two clone or bundle actions, update
 * the actions' flags (and runnable_before members if appropriate) as
 * appropriate for the ordering. Effects may cascade to other orderings
 * involving the actions as well.
 *
 * \param[in,out] first     'First' action in an ordering
 * \param[in,out] then      'Then' action in an ordering
 * \param[in]     node      If not NULL, limit scope of ordering to this node
 *                          (only used when interleaving instances)
 * \param[in]     flags     Action flags for \p first for ordering purposes
 * \param[in]     filter    Action flags to limit scope of certain updates (may
 *                          include pe_action_optional to affect only mandatory
 *                          actions, and pe_action_runnable to affect only
 *                          runnable actions)
 * \param[in]     type      Group of enum pe_ordering flags to apply
 * \param[in,out] data_set  Cluster working set
 *
 * \return Group of enum pcmk__updated flags indicating what was updated
 */
uint32_t
pcmk__instance_update_ordered_actions(pe_action_t *first, pe_action_t *then,
                                      const pe_node_t *node, uint32_t flags,
                                      uint32_t filter, uint32_t type,
                                      pe_working_set_t *data_set)
{
    CRM_ASSERT((first != NULL) && (then != NULL) && (data_set != NULL));

    if (then->rsc == NULL) {
        return pcmk__updated_none;

    } else if (can_interleave_actions(first, then)) {
        return update_interleaved_actions(first, then, node, filter, type);

    } else {
        uint32_t changed = pcmk__updated_none;
        GList *instances = get_instance_list(then->rsc);

        // Update actions for the clone or bundle resource itself
        changed |= pcmk__update_ordered_actions(first, then, node, flags,
                                                filter, type, data_set);

        // Update the 'then' clone instances or bundle containers individually
        for (GList *iter = instances; iter != NULL; iter = iter->next) {
            pe_resource_t *instance = iter->data;

            changed |= update_noninterleaved_actions(instance, first, then,
                                                     node, flags, filter, type);
        }
        free_instance_list(then->rsc, instances);
        return changed;
    }
}

#define pe__clear_action_summary_flags(flags, action, flag) do {        \
        flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                     "Action summary", action->rsc->id, \
                                     flags, flag, #flag);               \
    } while (0)

/*!
 * \internal
 * \brief Return action flags for a given clone or bundle action
 *
 * \param[in,out] action     Action for a clone or bundle
 * \param[in]     instances  Clone instances or bundle containers
 * \param[in]     node       If not NULL, limit effects to this node
 *
 * \return Flags appropriate to \p action on \p node
 */
uint32_t
pcmk__collective_action_flags(pe_action_t *action, const GList *instances,
                              const pe_node_t *node)
{
    bool any_runnable = false;
    const char *action_name = orig_action_name(action);

    // Set original assumptions (optional and runnable may be cleared below)
    uint32_t flags = pe_action_optional|pe_action_runnable|pe_action_pseudo;

    for (const GList *iter = instances; iter != NULL; iter = iter->next) {
        const pe_resource_t *instance = iter->data;
        const pe_node_t *instance_node = NULL;
        pe_action_t *instance_action = NULL;
        uint32_t instance_flags;

        // Node is relevant only to primitive instances
        if (instance->variant == pe_native) {
            instance_node = node;
        }

        instance_action = find_first_action(instance->actions, NULL,
                                            action_name, instance_node);
        if (instance_action == NULL) {
            pe_rsc_trace(action->rsc, "%s has no %s action on %s",
                         instance->id, action_name, pe__node_name(node));
            continue;
        }

        pe_rsc_trace(action->rsc, "%s has %s for %s on %s",
                     instance->id, instance_action->uuid, action_name,
                     pe__node_name(node));

        instance_flags = instance->cmds->action_flags(instance_action, node);

        // If any instance action is mandatory, so is the collective action
        if (pcmk_is_set(flags, pe_action_optional)
            && !pcmk_is_set(instance_flags, pe_action_optional)) {
            pe_rsc_trace(instance, "%s is mandatory because %s is",
                         action->uuid, instance_action->uuid);
            pe__clear_action_summary_flags(flags, action, pe_action_optional);
            pe__clear_action_flags(action, pe_action_optional);
        }

        // If any instance action is runnable, so is the collective action
        if (pcmk_is_set(instance_flags, pe_action_runnable)) {
            any_runnable = true;
        }
    }

    if (!any_runnable) {
        pe_rsc_trace(action->rsc,
                     "%s is not runnable because no instance can run %s",
                     action->uuid, action_name);
        pe__clear_action_summary_flags(flags, action, pe_action_runnable);
        if (node == NULL) {
            pe__clear_action_flags(action, pe_action_runnable);
        }
    }

    return flags;
}

/*!
 * \internal
 * \brief Add a collective resource's colocations to a list for an instance
 *
 * \param[in,out] list        Colocation list to add to
 * \param[in]     instance    Clone or bundle instance or instance group member
 * \param[in]     collective  Clone or bundle resource with colocations to add
 * \param[in]     with_this   If true, add collective's "with this" colocations,
 *                            otherwise add its "this with" colocations
 */
void
pcmk__add_collective_constraints(GList **list, const pe_resource_t *instance,
                                 const pe_resource_t *collective,
                                 bool with_this)
{
    const GList *colocations = NULL;
    bool everywhere = false;

    CRM_CHECK((list != NULL) && (instance != NULL), return);

    if (collective == NULL) {
        return;
    }
    switch (collective->variant) {
        case pe_clone:
        case pe_container:
            break;
        default:
            return;
    }

    everywhere = can_run_everywhere(collective);

    if (with_this) {
        colocations = collective->rsc_cons_lhs;
    } else {
        colocations = collective->rsc_cons;
    }

    for (const GList *iter = colocations; iter != NULL; iter = iter->next) {
        const pcmk__colocation_t *colocation = iter->data;

        if (with_this
            && !pcmk__colocation_has_influence(colocation, instance)) {
           continue;
        }
        if (!everywhere || (colocation->score < 0)
            || (!with_this && (colocation->score == INFINITY))) {

            if (with_this) {
                pcmk__add_with_this(list, colocation, instance);
            } else {
                pcmk__add_this_with(list, colocation, instance);
            }
        }
    }
}
