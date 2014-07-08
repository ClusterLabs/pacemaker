/*
 * Copyright (C) 2014 Gao,Yan <ygao@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <allocate.h>
#include <utils.h>

static GListPtr find_colocated_rscs(GListPtr colocated_rscs, resource_t * rsc,
                                    resource_t * orig_rsc);

static GListPtr group_find_colocated_rscs(GListPtr colocated_rscs, resource_t * rsc,
                                          resource_t * orig_rsc);

static void group_add_unallocated_utilization(GHashTable * all_utilization, resource_t * rsc,
                                              GListPtr all_rscs);

struct compare_data {
    const node_t *node1;
    const node_t *node2;
    int result;
};

static void
do_compare_capacity1(gpointer key, gpointer value, gpointer user_data)
{
    int node1_capacity = 0;
    int node2_capacity = 0;
    struct compare_data *data = user_data;

    node1_capacity = crm_parse_int(value, "0");
    node2_capacity =
        crm_parse_int(g_hash_table_lookup(data->node2->details->utilization, key), "0");

    if (node1_capacity > node2_capacity) {
        data->result--;
    } else if (node1_capacity < node2_capacity) {
        data->result++;
    }
}

static void
do_compare_capacity2(gpointer key, gpointer value, gpointer user_data)
{
    int node1_capacity = 0;
    int node2_capacity = 0;
    struct compare_data *data = user_data;

    if (g_hash_table_lookup_extended(data->node1->details->utilization, key, NULL, NULL)) {
        return;
    }

    node1_capacity = 0;
    node2_capacity = crm_parse_int(value, "0");

    if (node1_capacity > node2_capacity) {
        data->result--;
    } else if (node1_capacity < node2_capacity) {
        data->result++;
    }
}

/* rc < 0 if 'node1' has more capacity remaining
 * rc > 0 if 'node1' has less capacity remaining
 */
int
compare_capacity(const node_t * node1, const node_t * node2)
{
    struct compare_data data;

    data.node1 = node1;
    data.node2 = node2;
    data.result = 0;

    g_hash_table_foreach(node1->details->utilization, do_compare_capacity1, &data);
    g_hash_table_foreach(node2->details->utilization, do_compare_capacity2, &data);

    return data.result;
}

struct calculate_data {
    GHashTable *current_utilization;
    gboolean plus;
};

static void
do_calculate_utilization(gpointer key, gpointer value, gpointer user_data)
{
    const char *current = NULL;
    char *result = NULL;
    struct calculate_data *data = user_data;

    current = g_hash_table_lookup(data->current_utilization, key);
    if (data->plus) {
        result = crm_itoa(crm_parse_int(current, "0") + crm_parse_int(value, "0"));
        g_hash_table_replace(data->current_utilization, strdup(key), result);

    } else if (current) {
        result = crm_itoa(crm_parse_int(current, "0") - crm_parse_int(value, "0"));
        g_hash_table_replace(data->current_utilization, strdup(key), result);
    }
}

/* Specify 'plus' to FALSE when allocating
 * Otherwise to TRUE when deallocating
 */
void
calculate_utilization(GHashTable * current_utilization,
                      GHashTable * utilization, gboolean plus)
{
    struct calculate_data data;

    data.current_utilization = current_utilization;
    data.plus = plus;

    g_hash_table_foreach(utilization, do_calculate_utilization, &data);
}


struct capacity_data {
    node_t *node;
    const char *rsc_id;
    gboolean is_enough;
};

static void
check_capacity(gpointer key, gpointer value, gpointer user_data)
{
    int required = 0;
    int remaining = 0;
    struct capacity_data *data = user_data;

    required = crm_parse_int(value, "0");
    remaining = crm_parse_int(g_hash_table_lookup(data->node->details->utilization, key), "0");

    if (required > remaining) {
        CRM_ASSERT(data->rsc_id);
        CRM_ASSERT(data->node);

        crm_debug("Node %s has no enough %s for %s: required=%d remaining=%d",
                  data->node->details->uname, (char *)key, data->rsc_id, required, remaining);
        data->is_enough = FALSE;
    }
}

static gboolean
have_enough_capacity(node_t * node, const char * rsc_id, GHashTable * utilization)
{
    struct capacity_data data;

    data.node = node;
    data.rsc_id = rsc_id;
    data.is_enough = TRUE;

    g_hash_table_foreach(utilization, check_capacity, &data);

    return data.is_enough;
}


static void
native_add_unallocated_utilization(GHashTable * all_utilization, resource_t * rsc)
{
    if(is_set(rsc->flags, pe_rsc_provisional) == FALSE) {
        return;
    }

    calculate_utilization(all_utilization, rsc->utilization, TRUE);
}

static void
add_unallocated_utilization(GHashTable * all_utilization, resource_t * rsc,
                    GListPtr all_rscs, resource_t * orig_rsc)
{
    if(is_set(rsc->flags, pe_rsc_provisional) == FALSE) {
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

    } else if (rsc->variant == pe_clone ||
               rsc->variant == pe_master) {
        GListPtr gIter1 = NULL;
        gboolean existing = FALSE;

        /* Check if there's any child already existing in the list */
        gIter1 = rsc->children;
        for (; gIter1 != NULL; gIter1 = gIter1->next) {
            resource_t *child = (resource_t *) gIter1->data;
            GListPtr gIter2 = NULL;

            if (g_list_find(all_rscs, child)) {
                existing = TRUE;

            } else {
                /* Check if there's any child of another cloned group already existing in the list */
                gIter2 = child->children;
                for (; gIter2 != NULL; gIter2 = gIter2->next) {
                    resource_t *grandchild = (resource_t *) gIter2->data;

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

        if (existing == FALSE) {
            resource_t *first_child = (resource_t *) rsc->children->data;

            pe_rsc_trace(orig_rsc, "%s: Adding %s as colocated utilization",
                         orig_rsc->id, ID(first_child->xml));
            add_unallocated_utilization(all_utilization, first_child, all_rscs, orig_rsc);
        }
    }
}

static GHashTable *
sum_unallocated_utilization(resource_t * rsc, GListPtr colocated_rscs)
{
    GListPtr gIter = NULL;
    GListPtr all_rscs = NULL;
    GHashTable *all_utilization = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                          g_hash_destroy_str, g_hash_destroy_str);

    all_rscs = g_list_copy(colocated_rscs);
    if (g_list_find(all_rscs, rsc) == FALSE) {
        all_rscs = g_list_append(all_rscs, rsc);
    }

    for (gIter = all_rscs; gIter != NULL; gIter = gIter->next) {
        resource_t *listed_rsc = (resource_t *) gIter->data;

        if(is_set(listed_rsc->flags, pe_rsc_provisional) == FALSE) {
            continue;
        }

        pe_rsc_trace(rsc, "%s: Processing unallocated colocated %s", rsc->id, listed_rsc->id);
        add_unallocated_utilization(all_utilization, listed_rsc, all_rscs, rsc);
    }

    g_list_free(all_rscs);

    return all_utilization;
}

static GListPtr
find_colocated_rscs(GListPtr colocated_rscs, resource_t * rsc, resource_t * orig_rsc)
{
    GListPtr gIter = NULL;

    if (rsc == NULL) {
        return colocated_rscs;

    } else if (g_list_find(colocated_rscs, rsc)) {
        return colocated_rscs;
    }

    crm_trace("%s: %s is supposed to be colocated with %s", orig_rsc->id, rsc->id, orig_rsc->id);
    colocated_rscs = g_list_append(colocated_rscs, rsc);

    for (gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;
        resource_t *rsc_rh = constraint->rsc_rh;

        /* Break colocation loop */
        if (rsc_rh == orig_rsc) {
            continue;
        }

        if (constraint->score == INFINITY
            && filter_colocation_constraint(rsc, rsc_rh, constraint, TRUE) == influence_rsc_location) {

            if (rsc_rh->variant == pe_group) {
                /* Need to use group_variant_data */
                colocated_rscs = group_find_colocated_rscs(colocated_rscs, rsc_rh, orig_rsc);

            } else {
                colocated_rscs = find_colocated_rscs(colocated_rscs, rsc_rh, orig_rsc);
            }
        }
    }

    for (gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        rsc_colocation_t *constraint = (rsc_colocation_t *) gIter->data;
        resource_t *rsc_lh = constraint->rsc_lh;

        /* Break colocation loop */
        if (rsc_lh == orig_rsc) {
            continue;
        }

        if (rsc_lh->variant <= pe_group && rsc->variant > pe_group) {
            /* We do not know if rsc_lh will be colocated with orig_rsc in this case */
            continue;
        }

        if (constraint->score == INFINITY
            && filter_colocation_constraint(rsc_lh, rsc, constraint, TRUE) == influence_rsc_location) {

            if (rsc_lh->variant == pe_group) {
                /* Need to use group_variant_data */
                colocated_rscs = group_find_colocated_rscs(colocated_rscs, rsc_lh, orig_rsc);

            } else {
                colocated_rscs = find_colocated_rscs(colocated_rscs, rsc_lh, orig_rsc);
            }
        }
    }

    return colocated_rscs;
}

void
process_utilization(resource_t * rsc, node_t ** prefer, pe_working_set_t * data_set)
{
    int alloc_details = scores_log_level + 1;

    if (safe_str_neq(data_set->placement_strategy, "default")) {
        GListPtr gIter = NULL;
        GListPtr colocated_rscs = NULL;
        gboolean any_capable = FALSE;

        colocated_rscs = find_colocated_rscs(colocated_rscs, rsc, rsc);
        if (colocated_rscs) {
            GHashTable *unallocated_utilization = NULL;
            char *rscs_id = crm_concat(rsc->id, "and its colocated resources", ' ');
            node_t *most_capable_node = NULL;

            unallocated_utilization = sum_unallocated_utilization(rsc, colocated_rscs);

            for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
                node_t *node = (node_t *) gIter->data;

                if (have_enough_capacity(node, rscs_id, unallocated_utilization)) {
                    any_capable = TRUE;
                }

                if (most_capable_node == NULL ||
                    compare_capacity(node, most_capable_node) < 0) {
                    /* < 0 means 'node' is more capable */
                    most_capable_node = node;
                }
            }

            if (any_capable) {
                for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
                    node_t *node = (node_t *) gIter->data;

                    if (have_enough_capacity(node, rscs_id, unallocated_utilization) == FALSE) {
                        pe_rsc_debug(rsc, "Resource %s and its colocated resources cannot be allocated to node %s: no enough capacity",
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
            for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
                node_t *node = (node_t *) gIter->data;

                if (have_enough_capacity(node, rsc->id, rsc->utilization) == FALSE) {
                    pe_rsc_debug(rsc, "Resource %s cannot be allocated to node %s: no enough capacity",
                                 rsc->id, node->details->uname);
                    resource_location(rsc, node, -INFINITY, "__limit_utilization__", data_set);
                }
            }
        }
        dump_node_scores(alloc_details, rsc, "Post-utilization", rsc->allowed_nodes);
    }
}

#define VARIANT_GROUP 1
#include <lib/pengine/variant.h>

GListPtr
group_find_colocated_rscs(GListPtr colocated_rscs, resource_t * rsc, resource_t * orig_rsc)
{
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);
    if (group_data->colocated ||
        (rsc->parent &&
         (rsc->parent->variant == pe_clone || rsc->parent->variant == pe_master))) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            colocated_rscs = find_colocated_rscs(colocated_rscs, child_rsc, orig_rsc);
        }

    } else {
        if (group_data->first_child) {
            colocated_rscs = find_colocated_rscs(colocated_rscs, group_data->first_child, orig_rsc);
        }
    }

    colocated_rscs = find_colocated_rscs(colocated_rscs, rsc, orig_rsc);

    return colocated_rscs;
}

static void
group_add_unallocated_utilization(GHashTable * all_utilization, resource_t * rsc,
                                  GListPtr all_rscs)
{
    group_variant_data_t *group_data = NULL;

    get_group_variant_data(group_data, rsc);
    if (group_data->colocated ||
        (rsc->parent &&
         (rsc->parent->variant == pe_clone || rsc->parent->variant == pe_master))) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            if (is_set(child_rsc->flags, pe_rsc_provisional) &&
                g_list_find(all_rscs, child_rsc) == FALSE) {
                native_add_unallocated_utilization(all_utilization, child_rsc);
            }
        }

    } else {
        if (group_data->first_child &&
            is_set(group_data->first_child->flags, pe_rsc_provisional) &&
            g_list_find(all_rscs, group_data->first_child) == FALSE) {
            native_add_unallocated_utilization(all_utilization, group_data->first_child);
        }
    }
}


