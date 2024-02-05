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
#include <crm/common/xml_internal.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Check whether a node is available to run resources
 *
 * \param[in] node            Node to check
 * \param[in] consider_score  If true, consider a negative score unavailable
 * \param[in] consider_guest  If true, consider a guest node unavailable whose
 *                            resource will not be active
 *
 * \return true if node is online and not shutting down, unclean, or in standby
 *         or maintenance mode, otherwise false
 */
bool
pcmk__node_available(const pcmk_node_t *node, bool consider_score,
                     bool consider_guest)
{
    if ((node == NULL) || (node->details == NULL) || !node->details->online
            || node->details->shutdown || node->details->unclean
            || node->details->standby || node->details->maintenance) {
        return false;
    }

    if (consider_score && (node->weight < 0)) {
        return false;
    }

    // @TODO Go through all callers to see which should set consider_guest
    if (consider_guest && pe__is_guest_node(node)) {
        pcmk_resource_t *guest = node->details->remote_rsc->container;

        if (guest->fns->location(guest, NULL, FALSE) == NULL) {
            return false;
        }
    }

    return true;
}

/*!
 * \internal
 * \brief Copy a hash table of node objects
 *
 * \param[in] nodes  Hash table to copy
 *
 * \return New copy of nodes (or NULL if nodes is NULL)
 */
GHashTable *
pcmk__copy_node_table(GHashTable *nodes)
{
    GHashTable *new_table = NULL;
    GHashTableIter iter;
    pcmk_node_t *node = NULL;

    if (nodes == NULL) {
        return NULL;
    }
    new_table = pcmk__strkey_table(NULL, free);
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        pcmk_node_t *new_node = pe__copy_node(node);

        g_hash_table_insert(new_table, (gpointer) new_node->details->id,
                            new_node);
    }
    return new_table;
}

/*!
 * \internal
 * \brief Free a table of node tables
 *
 * \param[in,out] data  Table to free
 *
 * \note This is a \c GDestroyNotify wrapper for \c g_hash_table_destroy().
 */
static void
destroy_node_tables(gpointer data)
{
    g_hash_table_destroy((GHashTable *) data);
}

/*!
 * \internal
 * \brief Recursively copy the node tables of a resource
 *
 * Build a hash table containing copies of the allowed nodes tables of \p rsc
 * and its entire tree of descendants. The key is the resource ID, and the value
 * is a copy of the resource's node table.
 *
 * \param[in]     rsc   Resource whose node table to copy
 * \param[in,out] copy  Where to store the copied node tables
 *
 * \note \p *copy should be \c NULL for the top-level call.
 * \note The caller is responsible for freeing \p copy using
 *       \c g_hash_table_destroy().
 */
void
pcmk__copy_node_tables(const pcmk_resource_t *rsc, GHashTable **copy)
{
    CRM_ASSERT((rsc != NULL) && (copy != NULL));

    if (*copy == NULL) {
        *copy = pcmk__strkey_table(NULL, destroy_node_tables);
    }

    g_hash_table_insert(*copy, rsc->id,
                        pcmk__copy_node_table(rsc->allowed_nodes));

    for (const GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pcmk__copy_node_tables((const pcmk_resource_t *) iter->data, copy);
    }
}

/*!
 * \internal
 * \brief Recursively restore the node tables of a resource from backup
 *
 * Given a hash table containing backup copies of the allowed nodes tables of
 * \p rsc and its entire tree of descendants, replace the resources' current
 * node tables with the backed-up copies.
 *
 * \param[in,out] rsc     Resource whose node tables to restore
 * \param[in]     backup  Table of backup node tables (created by
 *                        \c pcmk__copy_node_tables())
 *
 * \note This function frees the resources' current node tables.
 */
void
pcmk__restore_node_tables(pcmk_resource_t *rsc, GHashTable *backup)
{
    CRM_ASSERT((rsc != NULL) && (backup != NULL));

    g_hash_table_destroy(rsc->allowed_nodes);

    // Copy to avoid danger with multiple restores
    rsc->allowed_nodes = g_hash_table_lookup(backup, rsc->id);
    rsc->allowed_nodes = pcmk__copy_node_table(rsc->allowed_nodes);

    for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
        pcmk__restore_node_tables((pcmk_resource_t *) iter->data, backup);
    }
}

/*!
 * \internal
 * \brief Copy a list of node objects
 *
 * \param[in] list   List to copy
 * \param[in] reset  Set copies' scores to 0
 *
 * \return New list of shallow copies of nodes in original list
 */
GList *
pcmk__copy_node_list(const GList *list, bool reset)
{
    GList *result = NULL;

    for (const GList *iter = list; iter != NULL; iter = iter->next) {
        pcmk_node_t *new_node = NULL;
        pcmk_node_t *this_node = iter->data;

        new_node = pe__copy_node(this_node);
        if (reset) {
            new_node->weight = 0;
        }
        result = g_list_prepend(result, new_node);
    }
    return result;
}

/*!
 * \internal
 * \brief Compare two nodes for assignment preference
 *
 * Given two nodes, check which one is more preferred by assignment criteria
 * such as node score and utilization.
 *
 * \param[in] a     First node to compare
 * \param[in] b     Second node to compare
 * \param[in] data  Node to prefer if all else equal
 *
 * \return -1 if \p a is preferred, +1 if \p b is preferred, or 0 if they are
 *         equally preferred
 */
static gint
compare_nodes(gconstpointer a, gconstpointer b, gpointer data)
{
    const pcmk_node_t *node1 = (const pcmk_node_t *) a;
    const pcmk_node_t *node2 = (const pcmk_node_t *) b;
    const pcmk_node_t *preferred = (const pcmk_node_t *) data;

    int node1_score = -INFINITY;
    int node2_score = -INFINITY;

    int result = 0;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    // Compare node scores

    if (pcmk__node_available(node1, false, false)) {
        node1_score = node1->weight;
    }
    if (pcmk__node_available(node2, false, false)) {
        node2_score = node2->weight;
    }

    if (node1_score > node2_score) {
        crm_trace("%s before %s (score %d > %d)",
                  pcmk__node_name(node1), pcmk__node_name(node2),
                  node1_score, node2_score);
        return -1;
    }

    if (node1_score < node2_score) {
        crm_trace("%s after %s (score %d < %d)",
                  pcmk__node_name(node1), pcmk__node_name(node2),
                  node1_score, node2_score);
        return 1;
    }

    // If appropriate, compare node utilization

    if (pcmk__str_eq(node1->details->data_set->placement_strategy,
                     PCMK_VALUE_MINIMAL, pcmk__str_casei)) {
        goto equal;
    }

    if (pcmk__str_eq(node1->details->data_set->placement_strategy,
                     PCMK_VALUE_BALANCED, pcmk__str_casei)) {

        result = pcmk__compare_node_capacities(node1, node2);
        if (result < 0) {
            crm_trace("%s before %s (greater capacity by %d attributes)",
                      pcmk__node_name(node1), pcmk__node_name(node2),
                      result * -1);
            return -1;
        } else if (result > 0) {
            crm_trace("%s after %s (lower capacity by %d attributes)",
                      pcmk__node_name(node1), pcmk__node_name(node2), result);
            return 1;
        }
    }

    // Compare number of resources already assigned to node

    if (node1->details->num_resources < node2->details->num_resources) {
        crm_trace("%s before %s (%d resources < %d)",
                  pcmk__node_name(node1), pcmk__node_name(node2),
                  node1->details->num_resources, node2->details->num_resources);
        return -1;

    } else if (node1->details->num_resources > node2->details->num_resources) {
        crm_trace("%s after %s (%d resources > %d)",
                  pcmk__node_name(node1), pcmk__node_name(node2),
                  node1->details->num_resources, node2->details->num_resources);
        return 1;
    }

    // Check whether one node is already running desired resource

    if (preferred != NULL) {
        if (pcmk__same_node(preferred, node1)) {
            crm_trace("%s before %s (preferred node)",
                      pcmk__node_name(node1), pcmk__node_name(node2));
            return -1;
        } else if (pcmk__same_node(preferred, node2)) {
            crm_trace("%s after %s (not preferred node)",
                      pcmk__node_name(node1), pcmk__node_name(node2));
            return 1;
        }
    }

    // If all else is equal, prefer node with lowest-sorting name
equal:
    result = strcmp(node1->details->uname, node2->details->uname);
    if (result < 0) {
        crm_trace("%s before %s (name)",
                  pcmk__node_name(node1), pcmk__node_name(node2));
        return -1;
    } else if (result > 0) {
        crm_trace("%s after %s (name)",
                  pcmk__node_name(node1), pcmk__node_name(node2));
        return 1;
    }

    crm_trace("%s == %s", pcmk__node_name(node1), pcmk__node_name(node2));
    return 0;
}

/*!
 * \internal
 * \brief Sort a list of nodes by assigment preference
 *
 * \param[in,out] nodes        Node list to sort
 * \param[in]     active_node  Node where resource being assigned is active
 *
 * \return New head of sorted list
 */
GList *
pcmk__sort_nodes(GList *nodes, pcmk_node_t *active_node)
{
    return g_list_sort_with_data(nodes, compare_nodes, active_node);
}

/*!
 * \internal
 * \brief Check whether any node is available to run resources
 *
 * \param[in] nodes  Nodes to check
 *
 * \return true if any node in \p nodes is available to run resources,
 *         otherwise false
 */
bool
pcmk__any_node_available(GHashTable *nodes)
{
    GHashTableIter iter;
    const pcmk_node_t *node = NULL;

    if (nodes == NULL) {
        return false;
    }
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if (pcmk__node_available(node, true, false)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Apply node health values for all nodes in cluster
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__apply_node_health(pcmk_scheduler_t *scheduler)
{
    int base_health = 0;
    enum pcmk__health_strategy strategy;
    const char *strategy_str =
        pcmk__cluster_option(scheduler->config_hash,
                             PCMK_OPT_NODE_HEALTH_STRATEGY);

    strategy = pcmk__parse_health_strategy(strategy_str);
    if (strategy == pcmk__health_strategy_none) {
        return;
    }
    crm_info("Applying node health strategy '%s'", strategy_str);

    // The progressive strategy can use a base health score
    if (strategy == pcmk__health_strategy_progressive) {
        base_health = pe__health_score(PCMK_OPT_NODE_HEALTH_BASE, scheduler);
    }

    for (GList *iter = scheduler->nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;
        int health = pe__sum_node_health_scores(node, base_health);

        // An overall health score of 0 has no effect
        if (health == 0) {
            continue;
        }
        crm_info("Overall system health of %s is %d",
                 pcmk__node_name(node), health);

        // Use node health as a location score for each resource on the node
        for (GList *r = scheduler->resources; r != NULL; r = r->next) {
            pcmk_resource_t *rsc = (pcmk_resource_t *) r->data;

            bool constrain = true;

            if (health < 0) {
                /* Negative health scores do not apply to resources with
                 * PCMK_META_ALLOW_UNHEALTHY_NODES=true.
                 */
                constrain = !crm_is_true(g_hash_table_lookup(rsc->meta,
                                         PCMK_META_ALLOW_UNHEALTHY_NODES));
            }
            if (constrain) {
                pcmk__new_location(strategy_str, rsc, health, NULL, node);
            } else {
                pcmk__rsc_trace(rsc, "%s is immune from health ban on %s",
                                rsc->id, pcmk__node_name(node));
            }
        }
    }
}

/*!
 * \internal
 * \brief Check for a node in a resource's parent's allowed nodes
 *
 * \param[in] rsc   Resource whose parent should be checked
 * \param[in] node  Node to check for
 *
 * \return Equivalent of \p node from \p rsc's parent's allowed nodes if any,
 *         otherwise NULL
 */
pcmk_node_t *
pcmk__top_allowed_node(const pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    GHashTable *allowed_nodes = NULL;

    if ((rsc == NULL) || (node == NULL)) {
        return NULL;
    } else if (rsc->parent == NULL) {
        allowed_nodes = rsc->allowed_nodes;
    } else {
        allowed_nodes = rsc->parent->allowed_nodes;
    }
    return g_hash_table_lookup(allowed_nodes, node->details->id);
}
