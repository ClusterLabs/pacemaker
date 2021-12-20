/*
 * Copyright 2014-2022 the Pacemaker project contributors
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

static void group_add_unallocated_utilization(GHashTable * all_utilization, pe_resource_t * rsc,
                                              GList *all_rscs);

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
        pe_warn("Using 0 for utilization instead of invalid value '%s'", value);
        value = 0;
    }
    return value;
}


/*
 * Functions for comparing node capacities
 */

struct compare_data {
    const pe_node_t *node1;
    const pe_node_t *node2;
    bool node2_only;
    int result;
};

/*!
 * \internal
 * \brief Compare a single utilization attribute for two nodes
 *
 * Compare one utilization attribute for two nodes, incrementing the result if
 * the first node has greater capacity, and decrementing it if the second node
 * has greater capacity.
 *
 * \param[in] key        Utilization attribute name to compare
 * \param[in] value      Utilization attribute value to compare
 * \param[in] user_data  Comparison data (as struct compare_data*)
 */
static void
compare_utilization_value(gpointer key, gpointer value, gpointer user_data)
{
    int node1_capacity = 0;
    int node2_capacity = 0;
    struct compare_data *data = user_data;
    const char *node2_value = NULL;

    if (data->node2_only) {
        if (g_hash_table_lookup(data->node1->details->utilization, key)) {
            return; // We've already compared this attribute
        }
    } else {
        node1_capacity = utilization_value((const char *) value);
    }

    node2_value = g_hash_table_lookup(data->node2->details->utilization, key);
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
pcmk__compare_node_capacities(const pe_node_t *node1, const pe_node_t *node2)
{
    struct compare_data data = {
        .node1      = node1,
        .node2      = node2,
        .node2_only = false,
        .result     = 0,
    };

    // Compare utilization values that node1 and maybe node2 have
    g_hash_table_foreach(node1->details->utilization, compare_utilization_value,
                         &data);

    // Compare utilization values that only node2 has
    data.node2_only = true;
    g_hash_table_foreach(node2->details->utilization, compare_utilization_value,
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
 * \param[in] key        Name of utilization attribute to update
 * \param[in] value      Value to add or substract
 * \param[in] user_data  Calculation data (as struct calculate_data *)
 */
static void
update_utilization_value(gpointer key, gpointer value, gpointer user_data)
{
    int result = 0;
    const char *current = NULL;
    struct calculate_data *data = user_data;

    current = g_hash_table_lookup(data->current_utilization, key);
    if (data->plus) {
        result = utilization_value(current) + utilization_value(value);
    } else if (current) {
        result = utilization_value(current) - utilization_value(value);
    }
    g_hash_table_replace(data->current_utilization,
                         strdup(key), pcmk__itoa(result));
}

/*!
 * \internal
 * \brief Subtract a resource's utilization from node capacity
 *
 * \param[in] current_utilization  Current node utilization attributes
 * \param[in] rsc                  Resource with utilization to subtract
 */
void
pcmk__consume_node_capacity(GHashTable *current_utilization, pe_resource_t *rsc)
{
    struct calculate_data data = {
        .current_utilization = current_utilization,
        .plus = false,
    };

    g_hash_table_foreach(rsc->utilization, update_utilization_value, &data);
}

/*!
 * \internal
 * \brief Add a resource's utilization to node capacity
 *
 * \param[in] current_utilization  Current node utilization attributes
 * \param[in] rsc                  Resource with utilization to add
 */
void
pcmk__release_node_capacity(GHashTable *current_utilization, pe_resource_t *rsc)
{
    struct calculate_data data = {
        .current_utilization = current_utilization,
        .plus = true,
    };

    g_hash_table_foreach(rsc->utilization, update_utilization_value, &data);
}


/*
 * Functions for checking for sufficient node capacity
 */

struct capacity_data {
    pe_node_t *node;
    const char *rsc_id;
    bool is_enough;
};

/*!
 * \internal
 * \brief Check whether a single utilization attribute has sufficient capacity
 *
 * \param[in] key        Name of utilization attribute to check
 * \param[in] value      Amount of utilization required
 * \param[in] user_data  Capacity data (as struct capacity_data *)
 */
static void
check_capacity(gpointer key, gpointer value, gpointer user_data)
{
    int required = 0;
    int remaining = 0;
    const char *node_value_s = NULL;
    struct capacity_data *data = user_data;

    node_value_s = g_hash_table_lookup(data->node->details->utilization, key);

    required = utilization_value(value);
    remaining = utilization_value(node_value_s);

    if (required > remaining) {
        crm_debug("Remaining capacity for %s on %s (%d) is insufficient "
                  "for resource %s usage (%d)",
                  (const char *) key, data->node->details->uname, remaining,
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
have_enough_capacity(pe_node_t *node, const char *rsc_id,
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


static void
native_add_unallocated_utilization(GHashTable * all_utilization, pe_resource_t * rsc)
{
    if (pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        pcmk__release_node_capacity(all_utilization, rsc);
    }
}

static void
add_unallocated_utilization(GHashTable * all_utilization, pe_resource_t * rsc,
                    GList *all_rscs, pe_resource_t * orig_rsc)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    if (rsc->variant == pe_native) {
        pe_rsc_trace(orig_rsc, "%s: Adding %s as colocated utilization",
                     orig_rsc->id, rsc->id);
        native_add_unallocated_utilization(all_utilization, rsc);

    } else if (rsc->variant == pe_group) {
        pe_rsc_trace(orig_rsc, "%s: Adding %s as colocated utilization",
                     orig_rsc->id, rsc->id);
        group_add_unallocated_utilization(all_utilization, rsc, all_rscs);

    } else if (pe_rsc_is_clone(rsc)) {
        GList *gIter1 = NULL;
        gboolean existing = FALSE;

        /* Check if there's any child already existing in the list */
        gIter1 = rsc->children;
        for (; gIter1 != NULL; gIter1 = gIter1->next) {
            pe_resource_t *child = (pe_resource_t *) gIter1->data;
            GList *gIter2 = NULL;

            if (g_list_find(all_rscs, child)) {
                existing = TRUE;

            } else {
                /* Check if there's any child of another cloned group already existing in the list */
                gIter2 = child->children;
                for (; gIter2 != NULL; gIter2 = gIter2->next) {
                    pe_resource_t *grandchild = (pe_resource_t *) gIter2->data;

                    if (g_list_find(all_rscs, grandchild)) {
                        pe_rsc_trace(orig_rsc, "%s: Adding %s as colocated utilization",
                                     orig_rsc->id, child->id);
                        add_unallocated_utilization(all_utilization, child, all_rscs, orig_rsc);
                        existing = TRUE;
                        break;
                    }
                }
            }
        }

        // rsc->children is always non-NULL but this makes static analysis happy
        if (!existing && (rsc->children != NULL)) {
            pe_resource_t *first_child = (pe_resource_t *) rsc->children->data;

            pe_rsc_trace(orig_rsc, "%s: Adding %s as colocated utilization",
                         orig_rsc->id, ID(first_child->xml));
            add_unallocated_utilization(all_utilization, first_child, all_rscs, orig_rsc);
        }
    }
}

static GHashTable *
sum_unallocated_utilization(pe_resource_t * rsc, GList *colocated_rscs)
{
    GList *gIter = NULL;
    GList *all_rscs = NULL;
    GHashTable *all_utilization = pcmk__strkey_table(free, free);

    all_rscs = g_list_copy(colocated_rscs);
    if (g_list_find(all_rscs, rsc) == FALSE) {
        all_rscs = g_list_append(all_rscs, rsc);
    }

    for (gIter = all_rscs; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *listed_rsc = (pe_resource_t *) gIter->data;

        if (!pcmk_is_set(listed_rsc->flags, pe_rsc_provisional)) {
            continue;
        }

        pe_rsc_trace(rsc, "%s: Processing unallocated colocated %s", rsc->id, listed_rsc->id);
        add_unallocated_utilization(all_utilization, listed_rsc, all_rscs, rsc);
    }

    g_list_free(all_rscs);

    return all_utilization;
}

void
process_utilization(pe_resource_t * rsc, pe_node_t ** prefer, pe_working_set_t * data_set)
{
    CRM_CHECK(rsc && prefer && data_set, return);
    if (!pcmk__str_eq(data_set->placement_strategy, "default", pcmk__str_casei)) {
        GHashTableIter iter;
        GList *colocated_rscs = NULL;
        gboolean any_capable = FALSE;
        pe_node_t *node = NULL;

        colocated_rscs = rsc->cmds->colocated_resources(rsc, NULL, NULL);
        if (colocated_rscs) {
            GHashTable *unallocated_utilization = NULL;
            char *rscs_id = crm_strdup_printf("%s and its colocated resources",
                                              rsc->id);
            pe_node_t *most_capable_node = NULL;

            unallocated_utilization = sum_unallocated_utilization(rsc, colocated_rscs);

            g_hash_table_iter_init(&iter, rsc->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
                if (!pcmk__node_available(node) || (node->weight < 0)) {
                    continue;
                }

                if (have_enough_capacity(node, rscs_id, unallocated_utilization)) {
                    any_capable = TRUE;
                }

                if (most_capable_node == NULL ||
                    pcmk__compare_node_capacities(node, most_capable_node) < 0) {
                    /* < 0 means 'node' is more capable */
                    most_capable_node = node;
                }
            }

            if (any_capable) {
                g_hash_table_iter_init(&iter, rsc->allowed_nodes);
                while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
                    if (!pcmk__node_available(node) || (node->weight < 0)) {
                        continue;
                    }

                    if (!have_enough_capacity(node, rscs_id,
                                              unallocated_utilization)) {
                        pe_rsc_debug(rsc,
                                     "Resource %s and its colocated resources"
                                     " cannot be allocated to node %s: not enough capacity",
                                     rsc->id, node->details->uname);
                        resource_location(rsc, node, -INFINITY, "__limit_utilization__", data_set);
                    }
                }

            } else if (*prefer == NULL) {
                *prefer = most_capable_node;
            }

            if (unallocated_utilization) {
                g_hash_table_destroy(unallocated_utilization);
            }

            g_list_free(colocated_rscs);
            free(rscs_id);
        }

        if (any_capable == FALSE) {
            g_hash_table_iter_init(&iter, rsc->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
                if (!pcmk__node_available(node) || (node->weight < 0)) {
                    continue;
                }

                if (!have_enough_capacity(node, rsc->id, rsc->utilization)) {
                    pe_rsc_debug(rsc,
                                 "Resource %s cannot be allocated to node %s:"
                                 " not enough capacity",
                                 rsc->id, node->details->uname);
                    resource_location(rsc, node, -INFINITY, "__limit_utilization__", data_set);
                }
            }
        }
        pe__show_node_weights(true, rsc, "Post-utilization", rsc->allowed_nodes, data_set);
    }
}

#define VARIANT_GROUP 1
#include <lib/pengine/variant.h>

static void
group_add_unallocated_utilization(GHashTable * all_utilization, pe_resource_t * rsc,
                                  GList *all_rscs)
{
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);
    if (group_data->colocated || pe_rsc_is_clone(rsc->parent)) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            if (pcmk_is_set(child_rsc->flags, pe_rsc_provisional) &&
                g_list_find(all_rscs, child_rsc) == FALSE) {
                native_add_unallocated_utilization(all_utilization, child_rsc);
            }
        }

    } else {
        if (group_data->first_child &&
            pcmk_is_set(group_data->first_child->flags, pe_rsc_provisional) &&
            g_list_find(all_rscs, group_data->first_child) == FALSE) {
            native_add_unallocated_utilization(all_utilization, group_data->first_child);
        }
    }
}


