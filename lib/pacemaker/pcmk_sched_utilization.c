/*
 * Copyright 2014-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <limits.h>                 // INT_MIN, INT_MAX

#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Get integer utilization from a string
 *
 * \param[in] s  String representation of a node utilization value
 *
 * \return Integer equivalent of \p s
 * \todo It would make sense to restrict utilization values to nonnegative
 *       integers, but the documentation just says "integers" and we didn't
 *       restrict them initially, so for backward compatibility, allow any
 *       integer.
 */
static int
utilization_value(const char *s)
{
    int value = 0;

    if ((s != NULL) && (pcmk__scan_min_int(s, &value, INT_MIN) == EINVAL)) {
        pcmk__config_warn("Using 0 for utilization instead of "
                          "invalid value '%s'", s);
        value = 0;
    }
    return value;
}


/*
 * Functions for comparing node capacities
 */

struct compare_data {
    const pcmk_node_t *node1;
    const pcmk_node_t *node2;
    bool node2_only;
    int result;
};

/*!
 * \internal
 * \brief Compare a single utilization attribute for two nodes
 *
 * Compare one utilization attribute for two nodes, decrementing the result if
 * the first node has greater capacity, and incrementing it if the second node
 * has greater capacity.
 *
 * \param[in]     key        Utilization attribute name to compare
 * \param[in]     value      Utilization attribute value to compare
 * \param[in,out] user_data  Comparison data (as struct compare_data*)
 */
static void
compare_utilization_value(gpointer key, gpointer value, gpointer user_data)
{
    int node1_capacity = 0;
    int node2_capacity = 0;
    struct compare_data *data = user_data;
    const char *node2_value = NULL;

    if (data->node2_only) {
        if (g_hash_table_lookup(data->node1->priv->utilization, key)) {
            return; // We've already compared this attribute
        }
    } else {
        node1_capacity = utilization_value((const char *) value);
    }

    node2_value = g_hash_table_lookup(data->node2->priv->utilization, key);
    node2_capacity = utilization_value(node2_value);

    if (node1_capacity > node2_capacity) {
        data->result--;
    } else if (node1_capacity < node2_capacity) {
        data->result++;
    }
}

/*!
 * \internal
 * \brief Compare utilization capacities of two nodes
 *
 * \param[in] node1  First node to compare
 * \param[in] node2  Second node to compare
 *
 * \return Negative integer if node1 has more free capacity,
 *         0 if the capacities are equal, or a positive integer
 *         if node2 has more free capacity
 */
int
pcmk__compare_node_capacities(const pcmk_node_t *node1,
                              const pcmk_node_t *node2)
{
    struct compare_data data = {
        .node1      = node1,
        .node2      = node2,
        .node2_only = false,
        .result     = 0,
    };

    // Compare utilization values that node1 and maybe node2 have
    g_hash_table_foreach(node1->priv->utilization, compare_utilization_value,
                         &data);

    // Compare utilization values that only node2 has
    data.node2_only = true;
    g_hash_table_foreach(node2->priv->utilization, compare_utilization_value,
                         &data);

    return data.result;
}


/*
 * Functions for updating node capacities
 */

struct calculate_data {
    GHashTable *current_utilization;
    bool plus;
};

/*!
 * \internal
 * \brief Update a single utilization attribute with a new value
 *
 * \param[in]     key        Name of utilization attribute to update
 * \param[in]     value      Value to add or substract
 * \param[in,out] user_data  Calculation data (as struct calculate_data *)
 */
static void
update_utilization_value(gpointer key, gpointer value, gpointer user_data)
{
    struct calculate_data *data = user_data;
    const char *current = g_hash_table_lookup(data->current_utilization, key);
    long long result = utilization_value(current)
                       + (data->plus? 1LL : -1LL) * utilization_value(value);

    if (result < INT_MIN) {
        result = INT_MIN;
    } else if (result > INT_MAX) {
        result = INT_MAX;
    }
    g_hash_table_replace(data->current_utilization,
                         strdup(key), pcmk__itoa((int) result));
}

/*!
 * \internal
 * \brief Subtract a resource's utilization from node capacity
 *
 * \param[in,out] current_utilization  Current node utilization attributes
 * \param[in]     rsc                  Resource with utilization to subtract
 */
void
pcmk__consume_node_capacity(GHashTable *current_utilization,
                            const pcmk_resource_t *rsc)
{
    struct calculate_data data = {
        .current_utilization = current_utilization,
        .plus = false,
    };

    g_hash_table_foreach(rsc->priv->utilization, update_utilization_value,
                         &data);
}

/*!
 * \internal
 * \brief Add a resource's utilization to node capacity
 *
 * \param[in,out] current_utilization  Current node utilization attributes
 * \param[in]     rsc                  Resource with utilization to add
 */
void
pcmk__release_node_capacity(GHashTable *current_utilization,
                            const pcmk_resource_t *rsc)
{
    struct calculate_data data = {
        .current_utilization = current_utilization,
        .plus = true,
    };

    g_hash_table_foreach(rsc->priv->utilization, update_utilization_value,
                         &data);
}


/*
 * Functions for checking for sufficient node capacity
 */

struct capacity_data {
    const pcmk_node_t *node;
    const char *rsc_id;
    bool is_enough;
};

/*!
 * \internal
 * \brief Check whether a single utilization attribute has sufficient capacity
 *
 * \param[in]     key        Name of utilization attribute to check
 * \param[in]     value      Amount of utilization required
 * \param[in,out] user_data  Capacity data (as struct capacity_data *)
 */
static void
check_capacity(gpointer key, gpointer value, gpointer user_data)
{
    int required = 0;
    int remaining = 0;
    const char *node_value_s = NULL;
    struct capacity_data *data = user_data;

    node_value_s = g_hash_table_lookup(data->node->priv->utilization, key);

    required = utilization_value(value);
    remaining = utilization_value(node_value_s);

    if (required > remaining) {
        crm_debug("Remaining capacity for %s on %s (%d) is insufficient "
                  "for resource %s usage (%d)",
                  (const char *) key, pcmk__node_name(data->node), remaining,
                  data->rsc_id, required);
        data->is_enough = false;
    }
}

/*!
 * \internal
 * \brief Check whether a node has sufficient capacity for a resource
 *
 * \param[in] node         Node to check
 * \param[in] rsc_id       ID of resource to check (for debug logs only)
 * \param[in] utilization  Required utilization amounts
 *
 * \return true if node has sufficient capacity for resource, otherwise false
 */
static bool
have_enough_capacity(const pcmk_node_t *node, const char *rsc_id,
                     GHashTable *utilization)
{
    struct capacity_data data = {
        .node = node,
        .rsc_id = rsc_id,
        .is_enough = true,
    };

    g_hash_table_foreach(utilization, check_capacity, &data);
    return data.is_enough;
}

/*!
 * \internal
 * \brief Sum the utilization requirements of a list of resources
 *
 * \param[in] orig_rsc  Resource being assigned (for logging purposes)
 * \param[in] rscs      Resources whose utilization should be summed
 *
 * \return Newly allocated hash table with sum of all utilization values
 * \note It is the caller's responsibility to free the return value using
 *       g_hash_table_destroy().
 */
static GHashTable *
sum_resource_utilization(const pcmk_resource_t *orig_rsc, GList *rscs)
{
    GHashTable *utilization = pcmk__strkey_table(free, free);

    for (GList *iter = rscs; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        rsc->priv->cmds->add_utilization(rsc, orig_rsc, rscs, utilization);
    }
    return utilization;
}

/*!
 * \internal
 * \brief Ban resource from nodes with insufficient utilization capacity
 *
 * \param[in,out] rsc  Resource to check
 *
 * \return Allowed node for \p rsc with most spare capacity, if there are no
 *         nodes with enough capacity for \p rsc and all its colocated resources
 */
const pcmk_node_t *
pcmk__ban_insufficient_capacity(pcmk_resource_t *rsc)
{
    bool any_capable = false;
    char *rscs_id = NULL;
    pcmk_node_t *node = NULL;
    const pcmk_node_t *most_capable_node = NULL;
    GList *colocated_rscs = NULL;
    GHashTable *unassigned_utilization = NULL;
    GHashTableIter iter;

    CRM_CHECK(rsc != NULL, return NULL);

    // The default placement strategy ignores utilization
    if (pcmk__str_eq(rsc->priv->scheduler->priv->placement_strategy,
                     PCMK_VALUE_DEFAULT, pcmk__str_casei)) {
        return NULL;
    }

    // Check whether any resources are colocated with this one
    colocated_rscs = rsc->priv->cmds->colocated_resources(rsc, NULL, NULL);
    if (colocated_rscs == NULL) {
        return NULL;
    }

    rscs_id = crm_strdup_printf("%s and its colocated resources", rsc->id);

    // If rsc isn't in the list, add it so we include its utilization
    if (g_list_find(colocated_rscs, rsc) == NULL) {
        colocated_rscs = g_list_append(colocated_rscs, rsc);
    }

    // Sum utilization of colocated resources that haven't been assigned yet
    unassigned_utilization = sum_resource_utilization(rsc, colocated_rscs);

    // Check whether any node has enough capacity for all the resources
    g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
        if (!pcmk__node_available(node, pcmk__node_alive
                                        |pcmk__node_usable
                                        |pcmk__node_no_negative)) {
            continue;
        }

        if (have_enough_capacity(node, rscs_id, unassigned_utilization)) {
            any_capable = true;
        }

        // Keep track of node with most free capacity
        if ((most_capable_node == NULL)
            || (pcmk__compare_node_capacities(node, most_capable_node) < 0)) {
            most_capable_node = node;
        }
    }

    if (any_capable) {
        // If so, ban resource from any node with insufficient capacity
        g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
            if (pcmk__node_available(node, pcmk__node_alive
                                           |pcmk__node_usable
                                           |pcmk__node_no_negative)
                && !have_enough_capacity(node, rscs_id,
                                         unassigned_utilization)) {
                pcmk__rsc_debug(rsc, "%s does not have enough capacity for %s",
                                pcmk__node_name(node), rscs_id);
                resource_location(rsc, node, -PCMK_SCORE_INFINITY,
                                  "__limit_utilization__",
                                  rsc->priv->scheduler);
            }
        }
        most_capable_node = NULL;

    } else {
        // Otherwise, ban from nodes with insufficient capacity for rsc alone
        g_hash_table_iter_init(&iter, rsc->priv->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
            if (pcmk__node_available(node, pcmk__node_alive
                                           |pcmk__node_usable
                                           |pcmk__node_no_negative)
                && !have_enough_capacity(node, rsc->id,
                                         rsc->priv->utilization)) {
                pcmk__rsc_debug(rsc, "%s does not have enough capacity for %s",
                                pcmk__node_name(node), rsc->id);
                resource_location(rsc, node, -PCMK_SCORE_INFINITY,
                                  "__limit_utilization__",
                                  rsc->priv->scheduler);
            }
        }
    }

    g_hash_table_destroy(unassigned_utilization);
    g_list_free(colocated_rscs);
    free(rscs_id);

    pe__show_node_scores(true, rsc, "Post-utilization",
                         rsc->priv->allowed_nodes, rsc->priv->scheduler);
    return most_capable_node;
}

/*!
 * \internal
 * \brief Create a new load_stopped pseudo-op for a node
 *
 * \param[in,out] node  Node to create op for
 *
 * \return Newly created load_stopped op
 */
static pcmk_action_t *
new_load_stopped_op(pcmk_node_t *node)
{
    char *load_stopped_task = crm_strdup_printf(PCMK_ACTION_LOAD_STOPPED "_%s",
                                                node->priv->name);
    pcmk_action_t *load_stopped = get_pseudo_op(load_stopped_task,
                                                node->priv->scheduler);

    if (load_stopped->node == NULL) {
        load_stopped->node = pe__copy_node(node);
        pcmk__clear_action_flags(load_stopped, pcmk__action_optional);
    }
    free(load_stopped_task);
    return load_stopped;
}

/*!
 * \internal
 * \brief Create utilization-related internal constraints for a resource
 *
 * \param[in,out] rsc            Resource to create constraints for
 * \param[in]     allowed_nodes  List of allowed next nodes for \p rsc
 */
void
pcmk__create_utilization_constraints(pcmk_resource_t *rsc,
                                     const GList *allowed_nodes)
{
    const GList *iter = NULL;
    pcmk_action_t *load_stopped = NULL;

    pcmk__rsc_trace(rsc,
                    "Creating utilization constraints for %s - strategy: %s",
                    rsc->id, rsc->priv->scheduler->priv->placement_strategy);

    // "stop rsc then load_stopped" constraints for current nodes
    for (iter = rsc->priv->active_nodes; iter != NULL; iter = iter->next) {
        load_stopped = new_load_stopped_op(iter->data);
        pcmk__new_ordering(rsc, stop_key(rsc), NULL, NULL, NULL, load_stopped,
                           pcmk__ar_if_on_same_node_or_target,
                           rsc->priv->scheduler);
    }

    // "load_stopped then start/migrate_to rsc" constraints for allowed nodes
    for (iter = allowed_nodes; iter; iter = iter->next) {
        load_stopped = new_load_stopped_op(iter->data);
        pcmk__new_ordering(NULL, NULL, load_stopped, rsc, start_key(rsc), NULL,
                           pcmk__ar_if_on_same_node_or_target,
                           rsc->priv->scheduler);
        pcmk__new_ordering(NULL, NULL, load_stopped,
                           rsc,
                           pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_TO, 0),
                           NULL,
                           pcmk__ar_if_on_same_node_or_target,
                           rsc->priv->scheduler);
    }
}

/*!
 * \internal
 * \brief Output node capacities if enabled
 *
 * \param[in]     desc       Prefix for output
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__show_node_capacities(const char *desc, pcmk_scheduler_t *scheduler)
{
    if (!pcmk_is_set(scheduler->flags, pcmk__sched_show_utilization)) {
        return;
    }
    for (const GList *iter = scheduler->nodes;
         iter != NULL; iter = iter->next) {
        const pcmk_node_t *node = (const pcmk_node_t *) iter->data;
        pcmk__output_t *out = scheduler->priv->out;

        // Utilization doesn't apply to bundle nodes
        if (pcmk__is_bundle_node(node)) {
            continue;
        }

        out->message(out, "node-capacity", node, desc);
    }
}
