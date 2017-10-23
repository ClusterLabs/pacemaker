/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#include <notif.h>
#include <utils.h>

#define VARIANT_CONTAINER 1
#include <lib/pengine/variant.h>

static bool
is_child_container_node(container_variant_data_t *data, pe_node_t *node)
{
    for (GListPtr gIter = data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;
        if(node->details == tuple->node->details) {
            return TRUE;
        }
    }
    return FALSE;
}

gint sort_clone_instance(gconstpointer a, gconstpointer b, gpointer data_set);
void distribute_children(resource_t *rsc, GListPtr children, GListPtr nodes,
                         int max, int per_host_max, pe_working_set_t * data_set);

static GListPtr get_container_list(resource_t *rsc) 
{
    GListPtr containers = NULL;
    container_variant_data_t *data = NULL;

    if(rsc->variant == pe_container) {
        get_container_variant_data(data, rsc);
        for (GListPtr gIter = data->tuples; gIter != NULL; gIter = gIter->next) {
            container_grouping_t *tuple = (container_grouping_t *)gIter->data;
            containers = g_list_append(containers, tuple->docker);
        }
    }
    return containers;
}

static GListPtr get_containers_or_children(resource_t *rsc) 
{
    GListPtr containers = NULL;
    container_variant_data_t *data = NULL;

    if(rsc->variant == pe_container) {
        get_container_variant_data(data, rsc);
        for (GListPtr gIter = data->tuples; gIter != NULL; gIter = gIter->next) {
            container_grouping_t *tuple = (container_grouping_t *)gIter->data;
            containers = g_list_append(containers, tuple->docker);
        }
        return containers;
    } else {
        return rsc->children;
    }
}

static bool
migration_threshold_reached(resource_t *rsc, node_t *node,
                            pe_working_set_t *data_set)
{
    int fail_count, countdown;

    /* Migration threshold of 0 means never force away */
    if (rsc->migration_threshold == 0) {
        return FALSE;
    }

    /* If there are no failures, there's no need to force away */
    fail_count = get_failcount_all(node, rsc, NULL, data_set);
    if (fail_count <= 0) {
        return FALSE;
    }

    /* How many more times recovery will be tried on this node */
    countdown = QB_MAX(rsc->migration_threshold - fail_count, 0);

    if (countdown == 0) {
        crm_warn("Forcing %s away from %s after %d failures (max=%d)",
                 rsc->id, node->details->uname, fail_count,
                 rsc->migration_threshold);
        return TRUE;
    }

    crm_info("%s can fail %d more times on %s before being forced off",
             rsc->id, countdown, node->details->uname);
    return FALSE;
}

node_t *
container_color(resource_t * rsc, node_t * prefer, pe_working_set_t * data_set)
{
    GListPtr containers = NULL;
    GListPtr nodes = NULL;
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(rsc != NULL, return NULL);

    get_container_variant_data(container_data, rsc);

    set_bit(rsc->flags, pe_rsc_allocating);
    containers = get_container_list(rsc);

    dump_node_scores(show_scores ? 0 : scores_log_level, rsc, __FUNCTION__, rsc->allowed_nodes);

    nodes = g_hash_table_get_values(rsc->allowed_nodes);
    nodes = g_list_sort_with_data(nodes, sort_node_weight, NULL);
    containers = g_list_sort_with_data(containers, sort_clone_instance, data_set);
    distribute_children(rsc, containers, nodes,
                        container_data->replicas, container_data->replicas_per_host, data_set);
    g_list_free(nodes);
    g_list_free(containers);

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;
        pe_node_t *docker_host = tuple->docker->allocated_to;

        CRM_ASSERT(tuple);
        if(tuple->ip) {
            tuple->ip->cmds->allocate(tuple->ip, prefer, data_set);
        }

        if(tuple->remote && is_remote_node(docker_host)) {
            /* We need 'nested' connection resources to be on the same
             * host because pacemaker-remoted only supports a single
             * active connection
             */
            rsc_colocation_new("child-remote-with-docker-remote", NULL,
                               INFINITY, tuple->remote, docker_host->details->remote_rsc, NULL, NULL, data_set);
        }

        if(tuple->remote) {
            tuple->remote->cmds->allocate(tuple->remote, prefer, data_set);
        }

        // Explicitly allocate tuple->child before the container->child
        if(tuple->child) {
            pe_node_t *node = NULL;
            GHashTableIter iter;
            g_hash_table_iter_init(&iter, tuple->child->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
                if(node->details != tuple->node->details) {
                    node->weight = -INFINITY;
                } else if(migration_threshold_reached(tuple->child, node, data_set) == FALSE) {
                    node->weight = INFINITY;
                }
            }

            set_bit(tuple->child->parent->flags, pe_rsc_allocating);
            tuple->child->cmds->allocate(tuple->child, tuple->node, data_set);
            clear_bit(tuple->child->parent->flags, pe_rsc_allocating);
        }
    }

    if(container_data->child) {
        pe_node_t *node = NULL;
        GHashTableIter iter;
        g_hash_table_iter_init(&iter, container_data->child->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
            if(is_child_container_node(container_data, node)) {
                node->weight = 0;
            } else {
                node->weight = -INFINITY;
            }
        }
        container_data->child->cmds->allocate(container_data->child, prefer, data_set);
    }

    clear_bit(rsc->flags, pe_rsc_allocating);
    clear_bit(rsc->flags, pe_rsc_provisional);
    return NULL;
}


void
container_create_actions(resource_t * rsc, pe_working_set_t * data_set)
{
    pe_action_t *action = NULL;
    GListPtr containers = NULL;
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    containers = get_container_list(rsc);
    get_container_variant_data(container_data, rsc);
    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        if(tuple->ip) {
            tuple->ip->cmds->create_actions(tuple->ip, data_set);
        }
        if(tuple->docker) {
            tuple->docker->cmds->create_actions(tuple->docker, data_set);
        }
        if(tuple->remote) {
            tuple->remote->cmds->create_actions(tuple->remote, data_set);
        }
    }

    clone_create_pseudo_actions(rsc, containers, NULL, NULL,  data_set);

    if(container_data->child) {
        container_data->child->cmds->create_actions(container_data->child, data_set);

        if(container_data->child->variant == pe_master) {
            /* promote */
            action = create_pseudo_resource_op(rsc, RSC_PROMOTE, TRUE, TRUE, data_set);
            action = create_pseudo_resource_op(rsc, RSC_PROMOTED, TRUE, TRUE, data_set);
            action->priority = INFINITY;

            /* demote */
            action = create_pseudo_resource_op(rsc, RSC_DEMOTE, TRUE, TRUE, data_set);
            action = create_pseudo_resource_op(rsc, RSC_DEMOTED, TRUE, TRUE, data_set);
            action->priority = INFINITY;
        }
    }

    g_list_free(containers);
}

void
container_internal_constraints(resource_t * rsc, pe_working_set_t * data_set)
{
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    get_container_variant_data(container_data, rsc);

    if(container_data->child) {
        new_rsc_order(rsc, RSC_START, container_data->child, RSC_START, pe_order_implies_first_printed, data_set);
        new_rsc_order(rsc, RSC_STOP, container_data->child, RSC_STOP, pe_order_implies_first_printed, data_set);

        if(container_data->child->children) {
            new_rsc_order(container_data->child, RSC_STARTED, rsc, RSC_STARTED, pe_order_implies_then_printed, data_set);
            new_rsc_order(container_data->child, RSC_STOPPED, rsc, RSC_STOPPED, pe_order_implies_then_printed, data_set);
        } else {
            new_rsc_order(container_data->child, RSC_START, rsc, RSC_STARTED, pe_order_implies_then_printed, data_set);
            new_rsc_order(container_data->child, RSC_STOP, rsc, RSC_STOPPED, pe_order_implies_then_printed, data_set);
        }
    }

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        CRM_ASSERT(tuple->docker);

        tuple->docker->cmds->internal_constraints(tuple->docker, data_set);

        order_start_start(rsc, tuple->docker, pe_order_runnable_left | pe_order_implies_first_printed);

        if(tuple->child) {
            order_stop_stop(rsc, tuple->child, pe_order_implies_first_printed);
        }
        order_stop_stop(rsc, tuple->docker, pe_order_implies_first_printed);
        new_rsc_order(tuple->docker, RSC_START, rsc, RSC_STARTED, pe_order_implies_then_printed, data_set);
        new_rsc_order(tuple->docker, RSC_STOP, rsc, RSC_STOPPED, pe_order_implies_then_printed, data_set);

        if(tuple->ip) {
            tuple->ip->cmds->internal_constraints(tuple->ip, data_set);

            // Start ip then docker
            new_rsc_order(tuple->ip, RSC_START, tuple->docker, RSC_START,
                          pe_order_runnable_left|pe_order_preserve, data_set);
            new_rsc_order(tuple->docker, RSC_STOP, tuple->ip, RSC_STOP,
                          pe_order_implies_first|pe_order_preserve, data_set);

            rsc_colocation_new("ip-with-docker", NULL, INFINITY, tuple->ip, tuple->docker, NULL, NULL, data_set);
        }

        if(tuple->remote) {
            /* This handles ordering and colocating remote relative to docker
             * (via "resource-with-container"). Since IP is also ordered and
             * colocated relative to docker, we don't need to do anything
             * explicit here with IP.
             */
            tuple->remote->cmds->internal_constraints(tuple->remote, data_set);
        }

        if(tuple->child) {
            CRM_ASSERT(tuple->remote);

            // Start of the remote then child is implicit in the PE's remote logic
        }

    }

    if(container_data->child) {
        container_data->child->cmds->internal_constraints(container_data->child, data_set);
        if(container_data->child->variant == pe_master) {
            master_promotion_constraints(rsc, data_set);

            /* child demoted before global demoted */
            new_rsc_order(container_data->child, RSC_DEMOTED, rsc, RSC_DEMOTED, pe_order_implies_then_printed, data_set);

            /* global demote before child demote */
            new_rsc_order(rsc, RSC_DEMOTE, container_data->child, RSC_DEMOTE, pe_order_implies_first_printed, data_set);

            /* child promoted before global promoted */
            new_rsc_order(container_data->child, RSC_PROMOTED, rsc, RSC_PROMOTED, pe_order_implies_then_printed, data_set);

            /* global promote before child promote */
            new_rsc_order(rsc, RSC_PROMOTE, container_data->child, RSC_PROMOTE, pe_order_implies_first_printed, data_set);
        }

    } else {
//    int type = pe_order_optional | pe_order_implies_then | pe_order_restart;
//        custom_action_order(rsc, generate_op_key(rsc->id, RSC_STOP, 0), NULL,
//                            rsc, generate_op_key(rsc->id, RSC_START, 0), NULL, pe_order_optional, data_set);
    }
}



static resource_t *
find_compatible_tuple_by_node(resource_t * rsc_lh, node_t * candidate, resource_t * rsc,
                              enum rsc_role_e filter, gboolean current)
{
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(candidate != NULL, return NULL);
    get_container_variant_data(container_data, rsc);

    crm_trace("Looking for compatible child from %s for %s on %s",
              rsc_lh->id, rsc->id, candidate->details->uname);

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        if(is_child_compatible(tuple->docker, candidate, filter, current)) {
            crm_trace("Pairing %s with %s on %s",
                      rsc_lh->id, tuple->docker->id, candidate->details->uname);
            return tuple->docker;
        }
    }

    crm_trace("Can't pair %s with %s", rsc_lh->id, rsc->id);
    return NULL;
}

static resource_t *
find_compatible_tuple(resource_t *rsc_lh, resource_t * rsc, enum rsc_role_e filter,
                      gboolean current)
{
    GListPtr scratch = NULL;
    resource_t *pair = NULL;
    node_t *active_node_lh = NULL;

    active_node_lh = rsc_lh->fns->location(rsc_lh, NULL, current);
    if (active_node_lh) {
        return find_compatible_tuple_by_node(rsc_lh, active_node_lh, rsc, filter, current);
    }

    scratch = g_hash_table_get_values(rsc_lh->allowed_nodes);
    scratch = g_list_sort_with_data(scratch, sort_node_weight, NULL);

    for (GListPtr gIter = scratch; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        pair = find_compatible_tuple_by_node(rsc_lh, node, rsc, filter, current);
        if (pair) {
            goto done;
        }
    }

    pe_rsc_debug(rsc, "Can't pair %s with %s", rsc_lh->id, rsc->id);
  done:
    g_list_free(scratch);
    return pair;
}

void
container_rsc_colocation_lh(resource_t * rsc, resource_t * rsc_rh, rsc_colocation_t * constraint)
{
    /* -- Never called --
     *
     * Instead we add the colocation constraints to the child and call from there
     */
    CRM_ASSERT(FALSE);
}

int copies_per_node(resource_t * rsc) 
{
    /* Strictly speaking, there should be a 'copies_per_node' addition
     * to the resource function table and each case would be a
     * function.  However that would be serious overkill to return an
     * int.  In fact, it seems to me that both function tables
     * could/should be replaced by resources.{c,h} full of
     * rsc_{some_operation} functions containing a switch as below
     * which calls out to functions named {variant}_{some_operation}
     * as needed.
     */
    switch(rsc->variant) {
        case pe_unknown:
            return 0;
        case pe_native:
        case pe_group:
            return 1;
        case pe_clone:
        case pe_master:
            {
                const char *max_clones_node = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INCARNATION_NODEMAX);
                return crm_parse_int(max_clones_node, "1");
            }
        case pe_container:
            {
                container_variant_data_t *data = NULL;
                get_container_variant_data(data, rsc);
                return data->replicas_per_host;
            }
    }
    return 0;
}

void
container_rsc_colocation_rh(resource_t * rsc_lh, resource_t * rsc, rsc_colocation_t * constraint)
{
    GListPtr allocated_rhs = NULL;
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(constraint != NULL, return);
    CRM_CHECK(rsc_lh != NULL, pe_err("rsc_lh was NULL for %s", constraint->id); return);
    CRM_CHECK(rsc != NULL, pe_err("rsc was NULL for %s", constraint->id); return);
    CRM_ASSERT(rsc_lh->variant == pe_native);

    if (is_set(rsc->flags, pe_rsc_provisional)) {
        pe_rsc_trace(rsc, "%s is still provisional", rsc->id);
        return;

    } else if(constraint->rsc_lh->variant > pe_group) {
        resource_t *rh_child = find_compatible_tuple(rsc_lh, rsc, RSC_ROLE_UNKNOWN, FALSE);

        if (rh_child) {
            pe_rsc_debug(rsc, "Pairing %s with %s", rsc_lh->id, rh_child->id);
            rsc_lh->cmds->rsc_colocation_lh(rsc_lh, rh_child, constraint);

        } else if (constraint->score >= INFINITY) {
            crm_notice("Cannot pair %s with instance of %s", rsc_lh->id, rsc->id);
            assign_node(rsc_lh, NULL, TRUE);

        } else {
            pe_rsc_debug(rsc, "Cannot pair %s with instance of %s", rsc_lh->id, rsc->id);
        }

        return;
    }

    get_container_variant_data(container_data, rsc);
    pe_rsc_trace(rsc, "Processing constraint %s: %s -> %s %d",
                 constraint->id, rsc_lh->id, rsc->id, constraint->score);

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        if (constraint->score < INFINITY) {
            tuple->docker->cmds->rsc_colocation_rh(rsc_lh, tuple->docker, constraint);

        } else {
            node_t *chosen = tuple->docker->fns->location(tuple->docker, NULL, FALSE);

            if (chosen != NULL && is_set_recursive(tuple->docker, pe_rsc_block, TRUE) == FALSE) {
                pe_rsc_trace(rsc, "Allowing %s: %s %d", constraint->id, chosen->details->uname, chosen->weight);
                allocated_rhs = g_list_prepend(allocated_rhs, chosen);
            }
        }
    }

    if (constraint->score >= INFINITY) {
        node_list_exclude(rsc_lh->allowed_nodes, allocated_rhs, FALSE);
    }
    g_list_free(allocated_rhs);
}

enum pe_action_flags
container_action_flags(action_t * action, node_t * node)
{
    GListPtr containers = NULL;
    enum pe_action_flags flags = 0;
    container_variant_data_t *data = NULL;

    get_container_variant_data(data, action->rsc);
    if(data->child) {
        enum action_tasks task = get_complex_task(data->child, action->task, TRUE);
        switch(task) {
            case no_action:
            case action_notify:
            case action_notified:
            case action_promote:
            case action_promoted:
            case action_demote:
            case action_demoted:
                return summary_action_flags(action, data->child->children, node);
            default:
                break;
        }
    }

    containers = get_container_list(action->rsc);
    flags = summary_action_flags(action, containers, node);
    g_list_free(containers);
    return flags;
}

resource_t *
find_compatible_child_by_node(resource_t * local_child, node_t * local_node, resource_t * rsc,
                              enum rsc_role_e filter, gboolean current)
{
    GListPtr gIter = NULL;
    GListPtr children = NULL;

    if (local_node == NULL) {
        crm_err("Can't colocate unrunnable child %s with %s", local_child->id, rsc->id);
        return NULL;
    }

    crm_trace("Looking for compatible child from %s for %s on %s",
              local_child->id, rsc->id, local_node->details->uname);

    children = get_containers_or_children(rsc);
    for (gIter = children; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        if(is_child_compatible(child_rsc, local_node, filter, current)) {
            crm_trace("Pairing %s with %s on %s",
                      local_child->id, child_rsc->id, local_node->details->uname);
            return child_rsc;
        }
    }

    crm_trace("Can't pair %s with %s", local_child->id, rsc->id);
    if(children != rsc->children) {
        g_list_free(children);
    }
    return NULL;
}

static container_grouping_t *
tuple_for_docker(resource_t *rsc, resource_t *docker, node_t *node)
{
    if(rsc->variant == pe_container) {
        container_variant_data_t *data = NULL;
        get_container_variant_data(data, rsc);
        for (GListPtr gIter = data->tuples; gIter != NULL; gIter = gIter->next) {
            container_grouping_t *tuple = (container_grouping_t *)gIter->data;
            if(tuple->child
               && docker == tuple->docker
               && node->details == tuple->node->details) {
                return tuple;
            }
        }
    }
    return NULL;
}

static enum pe_graph_flags
container_update_interleave_actions(action_t * first, action_t * then, node_t * node, enum pe_action_flags flags,
                     enum pe_action_flags filter, enum pe_ordering type)
{
    GListPtr gIter = NULL;
    GListPtr children = NULL;
    gboolean current = FALSE;
    enum pe_graph_flags changed = pe_graph_none;

    /* Fix this - lazy */
    if (crm_ends_with(first->uuid, "_stopped_0")
        || crm_ends_with(first->uuid, "_demoted_0")) {
        current = TRUE;
    }

    children = get_containers_or_children(then->rsc);
    for (gIter = children; gIter != NULL; gIter = gIter->next) {
        resource_t *then_child = (resource_t *) gIter->data;
        resource_t *first_child = find_compatible_child(then_child, first->rsc, RSC_ROLE_UNKNOWN, current);
        if (first_child == NULL && current) {
            crm_trace("Ignore");

        } else if (first_child == NULL) {
            crm_debug("No match found for %s (%d / %s / %s)", then_child->id, current, first->uuid, then->uuid);

            /* Me no like this hack - but what else can we do?
             *
             * If there is no-one active or about to be active
             *   on the same node as then_child, then they must
             *   not be allowed to start
             */
            if (type & (pe_order_runnable_left | pe_order_implies_then) /* Mandatory */ ) {
                pe_rsc_info(then->rsc, "Inhibiting %s from being active", then_child->id);
                if(assign_node(then_child, NULL, TRUE)) {
                    changed |= pe_graph_updated_then;
                }
            }

        } else {
            pe_action_t *first_action = NULL;
            pe_action_t *then_action = NULL;

            enum action_tasks task = clone_child_action(first);
            const char *first_task = task2text(task);

            container_grouping_t *first_tuple = tuple_for_docker(first->rsc, first_child, node);
            container_grouping_t *then_tuple = tuple_for_docker(then->rsc, then_child, node);

            if(strstr(first->task, "stop") && first_tuple && first_tuple->child) {
                /* Except for 'stopped' we should be looking at the
                 * in-container resource, actions for the child will
                 * happen later and are therefor more likely to align
                 * with the user's intent.
                 */
                first_action = find_first_action(first_tuple->child->actions, NULL, task2text(task), node);
            } else {
                first_action = find_first_action(first_child->actions, NULL, task2text(task), node);
            }

            if(strstr(then->task, "mote") && then_tuple && then_tuple->child) {
                /* Promote/demote actions will never be found for the
                 * docker resource, look in the child instead
                 *
                 * Alternatively treat:
                 *  'XXXX then promote YYYY' as 'XXXX then start container for YYYY', and
                 *  'demote XXXX then stop YYYY' as 'stop container for XXXX then stop YYYY'
                 */
                then_action = find_first_action(then_tuple->child->actions, NULL, then->task, node);
            } else {
                then_action = find_first_action(then_child->actions, NULL, then->task, node);
            }

            if (first_action == NULL) {
                if (is_not_set(first_child->flags, pe_rsc_orphan)
                    && crm_str_eq(first_task, RSC_STOP, TRUE) == FALSE
                    && crm_str_eq(first_task, RSC_DEMOTE, TRUE) == FALSE) {
                    crm_err("Internal error: No action found for %s in %s (first)",
                            first_task, first_child->id);

                } else {
                    crm_trace("No action found for %s in %s%s (first)",
                              first_task, first_child->id,
                              is_set(first_child->flags, pe_rsc_orphan) ? " (ORPHAN)" : "");
                }
                continue;
            }

            /* We're only interested if 'then' is neither stopping nor being demoted */ 
            if (then_action == NULL) {
                if (is_not_set(then_child->flags, pe_rsc_orphan)
                    && crm_str_eq(then->task, RSC_STOP, TRUE) == FALSE
                    && crm_str_eq(then->task, RSC_DEMOTE, TRUE) == FALSE) {
                    crm_err("Internal error: No action found for %s in %s (then)",
                            then->task, then_child->id);

                } else {
                    crm_trace("No action found for %s in %s%s (then)",
                              then->task, then_child->id,
                              is_set(then_child->flags, pe_rsc_orphan) ? " (ORPHAN)" : "");
                }
                continue;
            }

            if (order_actions(first_action, then_action, type)) {
                crm_debug("Created constraint for %s (%d) -> %s (%d) %.6x",
                          first_action->uuid, is_set(first_action->flags, pe_action_optional),
                          then_action->uuid, is_set(then_action->flags, pe_action_optional), type);
                changed |= (pe_graph_updated_first | pe_graph_updated_then);
            }
            if(first_action && then_action) {
                changed |= then_child->cmds->update_actions(first_action, then_action, node,
                                                            first_child->cmds->action_flags(first_action, node),
                                                            filter, type);
            } else {
                crm_err("Nothing found either for %s (%p) or %s (%p) %s",
                        first_child->id, first_action,
                        then_child->id, then_action, task2text(task));
            }
        }
    }

    if(children != then->rsc->children) {
        g_list_free(children);
    }
    return changed;
}

bool can_interleave_actions(pe_action_t *first, pe_action_t *then) 
{
    bool interleave = FALSE;
    resource_t *rsc = NULL;
    const char *interleave_s = NULL;

    if(first->rsc == NULL || then->rsc == NULL) {
        crm_trace("Not interleaving %s with %s (both must be resources)", first->uuid, then->uuid);
        return FALSE;
    } else if(first->rsc == then->rsc) {
        crm_trace("Not interleaving %s with %s (must belong to different resources)", first->uuid, then->uuid);
        return FALSE;
    } else if(first->rsc->variant < pe_clone || then->rsc->variant < pe_clone) {
        crm_trace("Not interleaving %s with %s (both sides must be clones, masters, or bundles)", first->uuid, then->uuid);
        return FALSE;
    }

    if (crm_ends_with(then->uuid, "_stop_0") || crm_ends_with(then->uuid, "_demote_0")) {
        rsc = first->rsc;
    } else {
        rsc = then->rsc;
    }

    interleave_s = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INTERLEAVE);
    interleave = crm_is_true(interleave_s);
    crm_trace("Interleave %s -> %s: %s (based on %s)",
              first->uuid, then->uuid, interleave ? "yes" : "no", rsc->id);

    return interleave;
}

enum pe_graph_flags
container_update_actions(action_t * first, action_t * then, node_t * node, enum pe_action_flags flags,
                     enum pe_action_flags filter, enum pe_ordering type)
{
    enum pe_graph_flags changed = pe_graph_none;

    crm_trace("%s -> %s", first->uuid, then->uuid);

    if(can_interleave_actions(first, then)) {
        changed = container_update_interleave_actions(first, then, node, flags, filter, type);

    } else if(then->rsc) {
        GListPtr gIter = NULL;
        GListPtr children = NULL;

        // Handle the 'primitive' ordering case
        changed |= native_update_actions(first, then, node, flags, filter, type);

        // Now any children (or containers in the case of a bundle)
        children = get_containers_or_children(then->rsc);
        for (gIter = children; gIter != NULL; gIter = gIter->next) {
            resource_t *then_child = (resource_t *) gIter->data;
            enum pe_graph_flags then_child_changed = pe_graph_none;
            action_t *then_child_action = find_first_action(then_child->actions, NULL, then->task, node);

            if (then_child_action) {
                enum pe_action_flags then_child_flags = then_child->cmds->action_flags(then_child_action, node);

                if (is_set(then_child_flags, pe_action_runnable)) {
                    then_child_changed |=
                        then_child->cmds->update_actions(first, then_child_action, node, flags, filter, type);
                }
                changed |= then_child_changed;
                if (then_child_changed & pe_graph_updated_then) {
                    for (GListPtr lpc = then_child_action->actions_after; lpc != NULL; lpc = lpc->next) {
                        action_wrapper_t *next = (action_wrapper_t *) lpc->data;
                        update_action(next->action);
                    }
                }
            }
        }

        if(children != then->rsc->children) {
            g_list_free(children);
        }
    }
    return changed;
}

void
container_rsc_location(resource_t * rsc, rsc_to_node_t * constraint)
{
    container_variant_data_t *container_data = NULL;
    get_container_variant_data(container_data, rsc);

    pe_rsc_trace(rsc, "Processing location constraint %s for %s", constraint->id, rsc->id);

    native_rsc_location(rsc, constraint);

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        if (tuple->docker) {
            tuple->docker->cmds->rsc_location(tuple->docker, constraint);
        }
        if(tuple->ip) {
            tuple->ip->cmds->rsc_location(tuple->ip, constraint);
        }
    }

    if(container_data->child && (constraint->role_filter == RSC_ROLE_SLAVE || constraint->role_filter == RSC_ROLE_MASTER)) {
        container_data->child->cmds->rsc_location(container_data->child, constraint);
        container_data->child->rsc_location = g_list_prepend(container_data->child->rsc_location, constraint);
    }
}

void
container_expand(resource_t * rsc, pe_working_set_t * data_set)
{
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    get_container_variant_data(container_data, rsc);

    if(container_data->child) {
        container_data->child->cmds->expand(container_data->child, data_set);
    }

    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        if (tuple->remote && tuple->docker && container_fix_remote_addr(tuple->remote)) {
            // REMOTE_CONTAINER_HACK: Allow remote nodes that start containers with pacemaker remote inside
            xmlNode *nvpair = get_xpath_object("//nvpair[@name='addr']", tuple->remote->xml, LOG_ERR);
            const char *calculated_addr = container_fix_remote_addr_in(tuple->remote, nvpair, "value");

            if (calculated_addr) {
                crm_trace("Fixed addr for %s on %s", tuple->remote->id, calculated_addr);
                g_hash_table_replace(tuple->remote->parameters, strdup("addr"), strdup(calculated_addr));
            } else {
                crm_err("Could not fix addr for %s", tuple->remote->id);
            }
        }
        if(tuple->ip) {
            tuple->ip->cmds->expand(tuple->ip, data_set);
        }
        if(tuple->docker) {
            tuple->docker->cmds->expand(tuple->docker, data_set);
        }
        if(tuple->remote) {
            tuple->remote->cmds->expand(tuple->remote, data_set);
        }
    }
}

gboolean
container_create_probe(resource_t * rsc, node_t * node, action_t * complete,
                   gboolean force, pe_working_set_t * data_set)
{
    bool any_created = FALSE;
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(rsc != NULL, return FALSE);

    get_container_variant_data(container_data, rsc);
    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        if(tuple->ip) {
            any_created |= tuple->ip->cmds->create_probe(tuple->ip, node, complete, force, data_set);
        }
        if(tuple->child && node->details == tuple->node->details) {
            any_created |= tuple->child->cmds->create_probe(tuple->child, node, complete, force, data_set);
        }
        if(tuple->docker) {
            bool created = tuple->docker->cmds->create_probe(tuple->docker, node, complete, force, data_set);

            if(created) {
                any_created = TRUE;
                /* If we're limited to one replica per host (due to
                 * the lack of an IP range probably), then we don't
                 * want any of our peer containers starting until
                 * we've established that no other copies are already
                 * running.
                 *
                 * Partly this is to ensure that replicas_per_host is
                 * observed, but also to ensure that the containers
                 * don't fail to start because the necessary port
                 * mappings (which won't include an IP for uniqueness)
                 * are already taken
                 */

                for (GListPtr tIter = container_data->tuples; tIter != NULL && container_data->replicas_per_host == 1; tIter = tIter->next) {
                    container_grouping_t *other = (container_grouping_t *)tIter->data;

                    if ((other != tuple) && (other != NULL)
                        && (other->docker != NULL)) {

                        custom_action_order(tuple->docker, generate_op_key(tuple->docker->id, RSC_STATUS, 0), NULL,
                                            other->docker, generate_op_key(other->docker->id, RSC_START, 0), NULL,
                                            pe_order_optional, data_set);
                    }
                }
            }
        }
        if(tuple->remote && tuple->remote->cmds->create_probe(tuple->remote, node, complete, force, data_set)) {
            /* Do not probe the remote resource until we know where docker is running
             * Required for REMOTE_CONTAINER_HACK to correctly probe remote resources
             */
            char *probe_uuid = generate_op_key(tuple->remote->id, RSC_STATUS, 0);
            action_t *probe = find_first_action(tuple->remote->actions, probe_uuid, NULL, node);
            any_created = TRUE;

            crm_trace("Ordering %s probe on %s", tuple->remote->id, node->details->uname);
            custom_action_order(tuple->docker, generate_op_key(tuple->docker->id, RSC_START, 0), NULL,
                                tuple->remote, NULL, probe, pe_order_probe, data_set);
            free(probe_uuid);
        }
    }
    return any_created;
}

void
container_append_meta(resource_t * rsc, xmlNode * xml)
{
}

GHashTable *
container_merge_weights(resource_t * rsc, const char *rhs, GHashTable * nodes, const char *attr,
                    float factor, enum pe_weights flags)
{
    return rsc_merge_weights(rsc, rhs, nodes, attr, factor, flags);
}

void container_LogActions(
    resource_t * rsc, pe_working_set_t * data_set, gboolean terminal)
{
    container_variant_data_t *container_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    get_container_variant_data(container_data, rsc);
    for (GListPtr gIter = container_data->tuples; gIter != NULL; gIter = gIter->next) {
        container_grouping_t *tuple = (container_grouping_t *)gIter->data;

        CRM_ASSERT(tuple);
        if(tuple->ip) {
            LogActions(tuple->ip, data_set, terminal);
        }
        if(tuple->docker) {
            LogActions(tuple->docker, data_set, terminal);
        }
        if(tuple->remote) {
            LogActions(tuple->remote, data_set, terminal);
        }
        if(tuple->child) {
            LogActions(tuple->child, data_set, terminal);
        }
    }
}
