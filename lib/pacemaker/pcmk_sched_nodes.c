/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/lrmd.h>       // lrmd_event_data_t
#include <crm/common/xml_internal.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Check whether a node is available to run resources
 *
 * \param[in] node  Node to check
 *
 * \return true if node is online and not shutting down, unclean, or in standby
 *         or maintenance mode, otherwise false
 */
bool
pcmk__node_available(const pe_node_t *node)
{
    // @TODO Should we add (node->weight >= 0)?
    return (node != NULL) && (node->details != NULL) && node->details->online
            && !node->details->shutdown && !node->details->unclean
            && !node->details->standby && !node->details->maintenance;
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
    pe_node_t *node = NULL;

    if (nodes == NULL) {
        return NULL;
    }
    new_table = pcmk__strkey_table(NULL, free);
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        pe_node_t *new_node = pe__copy_node(node);

        g_hash_table_insert(new_table, (gpointer) new_node->details->id,
                            new_node);
    }
    return new_table;
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

    for (const GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        pe_node_t *new_node = NULL;
        pe_node_t *this_node = (pe_node_t *) gIter->data;

        new_node = pe__copy_node(this_node);
        if (reset) {
            new_node->weight = 0;
        }
        result = g_list_prepend(result, new_node);
    }
    return result;
}

struct node_weight_s {
    pe_node_t *active;
    pe_working_set_t *data_set;
};

/*!
 * \internal
 * \brief Compare two nodes for allocation desirability
 *
 * Given two nodes, check which one is more preferred by allocation criteria
 * such as node weight and utilization.
 *
 * \param[in] a     First node to compare
 * \param[in] b     Second node to compare
 * \param[in] data  Sort data (as struct node_weight_s *)
 *
 * \return -1 if \p a is preferred, +1 if \p b is preferred, or 0 if they are
 *         equally preferred
 */
static gint
compare_nodes(gconstpointer a, gconstpointer b, gpointer data)
{
    const pe_node_t *node1 = (const pe_node_t *) a;
    const pe_node_t *node2 = (const pe_node_t *) b;
    struct node_weight_s *nw = data;

    int node1_weight = 0;
    int node2_weight = 0;

    int result = 0;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    // Compare node weights

    node1_weight = pcmk__node_available(node1)? node1->weight : -INFINITY;
    node2_weight = pcmk__node_available(node2)? node2->weight : -INFINITY;

    if (node1_weight > node2_weight) {
        crm_trace("%s (%d) > %s (%d) : weight",
                  node1->details->uname, node1_weight, node2->details->uname,
                  node2_weight);
        return -1;
    }

    if (node1_weight < node2_weight) {
        crm_trace("%s (%d) < %s (%d) : weight",
                  node1->details->uname, node1_weight, node2->details->uname,
                  node2_weight);
        return 1;
    }

    crm_trace("%s (%d) == %s (%d) : weight",
              node1->details->uname, node1_weight, node2->details->uname,
              node2_weight);

    // If appropriate, compare node utilization

    if (pcmk__str_eq(nw->data_set->placement_strategy, "minimal",
                     pcmk__str_casei)) {
        goto equal;
    }

    if (pcmk__str_eq(nw->data_set->placement_strategy, "balanced",
                     pcmk__str_casei)) {
        result = pcmk__compare_node_capacities(node1, node2);
        if (result < 0) {
            crm_trace("%s > %s : capacity (%d)",
                      node1->details->uname, node2->details->uname, result);
            return -1;
        } else if (result > 0) {
            crm_trace("%s < %s : capacity (%d)",
                      node1->details->uname, node2->details->uname, result);
            return 1;
        }
    }

    // Compare number of allocated resources

    if (node1->details->num_resources < node2->details->num_resources) {
        crm_trace("%s (%d) > %s (%d) : resources",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return -1;

    } else if (node1->details->num_resources > node2->details->num_resources) {
        crm_trace("%s (%d) < %s (%d) : resources",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return 1;
    }

    // Check whether one node is already running desired resource

    if (nw->active != NULL) {
        if (nw->active->details == node1->details) {
            crm_trace("%s (%d) > %s (%d) : active",
                      node1->details->uname, node1->details->num_resources,
                      node2->details->uname, node2->details->num_resources);
            return -1;
        } else if (nw->active->details == node2->details) {
            crm_trace("%s (%d) < %s (%d) : active",
                      node1->details->uname, node1->details->num_resources,
                      node2->details->uname, node2->details->num_resources);
            return 1;
        }
    }

    // If all else is equal, prefer node with lowest-sorting name
equal:
    crm_trace("%s = %s", node1->details->uname, node2->details->uname);
    return strcmp(node1->details->uname, node2->details->uname);
}

/*!
 * \internal
 * \brief Sort a list of nodes by allocation desirability
 *
 * \param[in] nodes        Node list to sort
 * \param[in] active_node  If not NULL, node currently running resource
 * \param[in] data_set     Cluster working set
 *
 * \return New head of sorted list
 */
GList *
pcmk__sort_nodes(GList *nodes, pe_node_t *active_node,
                 pe_working_set_t *data_set)
{
    struct node_weight_s nw = { active_node, data_set };

    return g_list_sort_with_data(nodes, compare_nodes, &nw);
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
    pe_node_t *node = NULL;

    if (nodes == NULL) {
        return false;
    }
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if ((node->weight >= 0) && pcmk__node_available(node)) {
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Add node attribute value to an integer, if it is a health attribute
 *
 * \param[in] key        Name of node attribute
 * \param[in] value      String value of node attribute
 * \param[in] user_data  Address of integer to which \p value should be added
 *                       if \p key is a node health attribute
 */
static void
add_node_health_value(gpointer key, gpointer value, gpointer user_data)
{
    if (pcmk__starts_with((const char *) key, "#health")) {
        int score = char2score((const char *) value);
        int *health = (int *) user_data;

        *health = pe__add_scores(score, *health);
    }
}

gboolean
apply_system_health(pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    const char *health_strategy = pe_pref(data_set->config_hash, "node-health-strategy");
    int base_health = 0;

    if (pcmk__str_eq(health_strategy, "none", pcmk__str_null_matches | pcmk__str_casei)) {
        /* Prevent any accidental health -> score translation */
        pcmk__score_red = 0;
        pcmk__score_yellow = 0;
        pcmk__score_green = 0;
        return TRUE;

    } else if (pcmk__str_eq(health_strategy, "migrate-on-red", pcmk__str_casei)) {

        /* Resources on nodes which have health values of red are
         * weighted away from that node.
         */
        pcmk__score_red = -INFINITY;
        pcmk__score_yellow = 0;
        pcmk__score_green = 0;

    } else if (pcmk__str_eq(health_strategy, "only-green", pcmk__str_casei)) {

        /* Resources on nodes which have health values of red or yellow
         * are forced away from that node.
         */
        pcmk__score_red = -INFINITY;
        pcmk__score_yellow = -INFINITY;
        pcmk__score_green = 0;

    } else if (pcmk__str_eq(health_strategy, "progressive", pcmk__str_casei)) {
        /* Same as the above, but use the r/y/g scores provided by the user
         * Defaults are provided by the pe_prefs table
         * Also, custom health "base score" can be used
         */
        base_health = char2score(pe_pref(data_set->config_hash,
                                         "node-health-base"));

    } else if (pcmk__str_eq(health_strategy, "custom", pcmk__str_casei)) {

        /* Requires the admin to configure the rsc_location constaints for
         * processing the stored health scores
         */
        /* TODO: Check for the existence of appropriate node health constraints */
        return TRUE;

    } else {
        crm_err("Unknown node health strategy: %s", health_strategy);
        return FALSE;
    }

    crm_info("Applying automated node health strategy: %s", health_strategy);

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        int system_health = base_health;
        pe_node_t *node = (pe_node_t *) gIter->data;

        /* Search through the node hash table for system health entries. */
        g_hash_table_foreach(node->details->attrs, add_node_health_value,
                             &system_health);

        crm_info(" Node %s has an combined system health of %d",
                 node->details->uname, system_health);

        /* If the health is non-zero, then create a new location constraint so
         * that the weight will be added later on.
         */
        if (system_health != 0) {

            GList *gIter2 = data_set->resources;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                pe_resource_t *rsc = (pe_resource_t *) gIter2->data;

                pcmk__new_location(health_strategy, rsc, system_health, NULL,
                                   node, data_set);
            }
        }
    }

    return TRUE;
}
