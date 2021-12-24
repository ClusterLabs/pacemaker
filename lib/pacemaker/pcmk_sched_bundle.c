/*
 * Copyright 2004-2021 the Pacemaker project contributors
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

#define PE__VARIANT_BUNDLE 1
#include <lib/pengine/variant.h>

static bool
is_bundle_node(pe__bundle_variant_data_t *data, pe_node_t *node)
{
    for (GList *gIter = data->replicas; gIter != NULL; gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (node->details == replica->node->details) {
            return TRUE;
        }
    }
    return FALSE;
}

gint sort_clone_instance(gconstpointer a, gconstpointer b, gpointer data_set);
void distribute_children(pe_resource_t *rsc, GList *children, GList *nodes,
                         int max, int per_host_max, pe_working_set_t * data_set);

static GList *
get_container_list(pe_resource_t *rsc)
{
    GList *containers = NULL;

    if (rsc->variant == pe_container) {
        pe__bundle_variant_data_t *data = NULL;

        get_bundle_variant_data(data, rsc);
        for (GList *gIter = data->replicas; gIter != NULL;
             gIter = gIter->next) {
            pe__bundle_replica_t *replica = gIter->data;

            containers = g_list_append(containers, replica->container);
        }
    }
    return containers;
}

static inline GList *
get_containers_or_children(pe_resource_t *rsc)
{
    return (rsc->variant == pe_container)?
           get_container_list(rsc) : rsc->children;
}

pe_node_t *
pcmk__bundle_allocate(pe_resource_t *rsc, pe_node_t *prefer,
                      pe_working_set_t *data_set)
{
    GList *containers = NULL;
    GList *nodes = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(rsc != NULL, return NULL);

    get_bundle_variant_data(bundle_data, rsc);

    pe__set_resource_flags(rsc, pe_rsc_allocating);
    containers = get_container_list(rsc);

    pe__show_node_weights(!pcmk_is_set(data_set->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, data_set);

    nodes = g_hash_table_get_values(rsc->allowed_nodes);
    nodes = pcmk__sort_nodes(nodes, NULL, data_set);
    containers = g_list_sort_with_data(containers, sort_clone_instance, data_set);
    distribute_children(rsc, containers, nodes, bundle_data->nreplicas,
                        bundle_data->nreplicas_per_host, data_set);
    g_list_free(nodes);
    g_list_free(containers);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;
        pe_node_t *container_host = NULL;

        CRM_ASSERT(replica);
        if (replica->ip) {
            pe_rsc_trace(rsc, "Allocating bundle %s IP %s",
                         rsc->id, replica->ip->id);
            replica->ip->cmds->allocate(replica->ip, prefer, data_set);
        }

        container_host = replica->container->allocated_to;
        if (replica->remote && pe__is_guest_or_remote_node(container_host)) {
            /* We need 'nested' connection resources to be on the same
             * host because pacemaker-remoted only supports a single
             * active connection
             */
            pcmk__new_colocation("child-remote-with-docker-remote", NULL,
                                 INFINITY, replica->remote,
                                 container_host->details->remote_rsc, NULL,
                                 NULL, true, data_set);
        }

        if (replica->remote) {
            pe_rsc_trace(rsc, "Allocating bundle %s connection %s",
                         rsc->id, replica->remote->id);
            replica->remote->cmds->allocate(replica->remote, prefer,
                                            data_set);
        }

        // Explicitly allocate replicas' children before bundle child
        if (replica->child) {
            pe_node_t *node = NULL;
            GHashTableIter iter;

            g_hash_table_iter_init(&iter, replica->child->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
                if (node->details != replica->node->details) {
                    node->weight = -INFINITY;
                } else if (!pcmk__threshold_reached(replica->child, node,
                                                    data_set, NULL)) {
                    node->weight = INFINITY;
                }
            }

            pe__set_resource_flags(replica->child->parent, pe_rsc_allocating);
            pe_rsc_trace(rsc, "Allocating bundle %s replica child %s",
                         rsc->id, replica->child->id);
            replica->child->cmds->allocate(replica->child, replica->node,
                                           data_set);
            pe__clear_resource_flags(replica->child->parent,
                                       pe_rsc_allocating);
        }
    }

    if (bundle_data->child) {
        pe_node_t *node = NULL;
        GHashTableIter iter;
        g_hash_table_iter_init(&iter, bundle_data->child->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
            if (is_bundle_node(bundle_data, node)) {
                node->weight = 0;
            } else {
                node->weight = -INFINITY;
            }
        }
        pe_rsc_trace(rsc, "Allocating bundle %s child %s",
                     rsc->id, bundle_data->child->id);
        bundle_data->child->cmds->allocate(bundle_data->child, prefer, data_set);
    }

    pe__clear_resource_flags(rsc, pe_rsc_allocating|pe_rsc_provisional);
    return NULL;
}


void
pcmk__bundle_create_actions(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    pe_action_t *action = NULL;
    GList *containers = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    containers = get_container_list(rsc);
    get_bundle_variant_data(bundle_data, rsc);
    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        if (replica->ip) {
            replica->ip->cmds->create_actions(replica->ip, data_set);
        }
        if (replica->container) {
            replica->container->cmds->create_actions(replica->container,
                                                     data_set);
        }
        if (replica->remote) {
            replica->remote->cmds->create_actions(replica->remote, data_set);
        }
    }

    clone_create_pseudo_actions(rsc, containers, NULL, NULL,  data_set);

    if (bundle_data->child) {
        bundle_data->child->cmds->create_actions(bundle_data->child, data_set);

        if (pcmk_is_set(bundle_data->child->flags, pe_rsc_promotable)) {
            /* promote */
            pcmk__new_rsc_pseudo_action(rsc, RSC_PROMOTE, true, true);
            action = pcmk__new_rsc_pseudo_action(rsc, RSC_PROMOTED, true, true);
            action->priority = INFINITY;

            /* demote */
            pcmk__new_rsc_pseudo_action(rsc, RSC_DEMOTE, true, true);
            action = pcmk__new_rsc_pseudo_action(rsc, RSC_DEMOTED, true, true);
            action->priority = INFINITY;
        }
    }

    g_list_free(containers);
}

void
pcmk__bundle_internal_constraints(pe_resource_t *rsc,
                                  pe_working_set_t *data_set)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    get_bundle_variant_data(bundle_data, rsc);

    if (bundle_data->child) {
        pcmk__order_resource_actions(rsc, RSC_START, bundle_data->child,
                                     RSC_START, pe_order_implies_first_printed,
                                     data_set);
        pcmk__order_resource_actions(rsc, RSC_STOP, bundle_data->child,
                                     RSC_STOP, pe_order_implies_first_printed,
                                     data_set);

        if (bundle_data->child->children) {
            pcmk__order_resource_actions(bundle_data->child, RSC_STARTED, rsc,
                                         RSC_STARTED,
                                         pe_order_implies_then_printed,
                                         data_set);
            pcmk__order_resource_actions(bundle_data->child, RSC_STOPPED, rsc,
                                         RSC_STOPPED,
                                         pe_order_implies_then_printed,
                                         data_set);
        } else {
            pcmk__order_resource_actions(bundle_data->child, RSC_START, rsc,
                                         RSC_STARTED,
                                         pe_order_implies_then_printed,
                                         data_set);
            pcmk__order_resource_actions(bundle_data->child, RSC_STOP, rsc,
                                         RSC_STOPPED,
                                         pe_order_implies_then_printed,
                                         data_set);
        }
    }

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        CRM_ASSERT(replica->container);

        replica->container->cmds->internal_constraints(replica->container,
                                                       data_set);

        pcmk__order_starts(rsc, replica->container,
                           pe_order_runnable_left|pe_order_implies_first_printed,
                           data_set);

        if (replica->child) {
            pcmk__order_stops(rsc, replica->child,
                              pe_order_implies_first_printed, data_set);
        }
        pcmk__order_stops(rsc, replica->container,
                          pe_order_implies_first_printed, data_set);
        pcmk__order_resource_actions(replica->container, RSC_START, rsc,
                                     RSC_STARTED, pe_order_implies_then_printed,
                                     data_set);
        pcmk__order_resource_actions(replica->container, RSC_STOP, rsc,
                                     RSC_STOPPED, pe_order_implies_then_printed,
                                     data_set);

        if (replica->ip) {
            replica->ip->cmds->internal_constraints(replica->ip, data_set);

            // Start IP then container
            pcmk__order_starts(replica->ip, replica->container,
                               pe_order_runnable_left|pe_order_preserve,
                               data_set);
            pcmk__order_stops(replica->container, replica->ip,
                              pe_order_implies_first|pe_order_preserve,
                              data_set);

            pcmk__new_colocation("ip-with-docker", NULL, INFINITY, replica->ip,
                                 replica->container, NULL, NULL, true,
                                 data_set);
        }

        if (replica->remote) {
            /* This handles ordering and colocating remote relative to container
             * (via "resource-with-container"). Since IP is also ordered and
             * colocated relative to the container, we don't need to do anything
             * explicit here with IP.
             */
            replica->remote->cmds->internal_constraints(replica->remote,
                                                        data_set);
        }

        if (replica->child) {
            CRM_ASSERT(replica->remote);

            // "Start remote then child" is implicit in scheduler's remote logic
        }

    }

    if (bundle_data->child) {
        bundle_data->child->cmds->internal_constraints(bundle_data->child, data_set);
        if (pcmk_is_set(bundle_data->child->flags, pe_rsc_promotable)) {
            promote_demote_constraints(rsc, data_set);

            /* child demoted before global demoted */
            pcmk__order_resource_actions(bundle_data->child, RSC_DEMOTED, rsc,
                                         RSC_DEMOTED,
                                         pe_order_implies_then_printed,
                                         data_set);

            /* global demote before child demote */
            pcmk__order_resource_actions(rsc, RSC_DEMOTE, bundle_data->child,
                                         RSC_DEMOTE,
                                         pe_order_implies_first_printed,
                                         data_set);

            /* child promoted before global promoted */
            pcmk__order_resource_actions(bundle_data->child, RSC_PROMOTED, rsc,
                                         RSC_PROMOTED,
                                         pe_order_implies_then_printed,
                                         data_set);

            /* global promote before child promote */
            pcmk__order_resource_actions(rsc, RSC_PROMOTE, bundle_data->child,
                                         RSC_PROMOTE,
                                         pe_order_implies_first_printed,
                                         data_set);
        }
    }
}

static pe_resource_t *
compatible_replica_for_node(pe_resource_t *rsc_lh, pe_node_t *candidate,
                            pe_resource_t *rsc, enum rsc_role_e filter,
                            gboolean current)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(candidate != NULL, return NULL);
    get_bundle_variant_data(bundle_data, rsc);

    crm_trace("Looking for compatible child from %s for %s on %s",
              rsc_lh->id, rsc->id, candidate->details->uname);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (is_child_compatible(replica->container, candidate, filter, current)) {
            crm_trace("Pairing %s with %s on %s",
                      rsc_lh->id, replica->container->id,
                      candidate->details->uname);
            return replica->container;
        }
    }

    crm_trace("Can't pair %s with %s", rsc_lh->id, rsc->id);
    return NULL;
}

static pe_resource_t *
compatible_replica(pe_resource_t *rsc_lh, pe_resource_t *rsc,
                   enum rsc_role_e filter, gboolean current,
                   pe_working_set_t *data_set)
{
    GList *scratch = NULL;
    pe_resource_t *pair = NULL;
    pe_node_t *active_node_lh = NULL;

    active_node_lh = rsc_lh->fns->location(rsc_lh, NULL, current);
    if (active_node_lh) {
        return compatible_replica_for_node(rsc_lh, active_node_lh, rsc, filter,
                                           current);
    }

    scratch = g_hash_table_get_values(rsc_lh->allowed_nodes);
    scratch = pcmk__sort_nodes(scratch, NULL, data_set);

    for (GList *gIter = scratch; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        pair = compatible_replica_for_node(rsc_lh, node, rsc, filter, current);
        if (pair) {
            goto done;
        }
    }

    pe_rsc_debug(rsc, "Can't pair %s with %s", rsc_lh->id, (rsc? rsc->id : "none"));
  done:
    g_list_free(scratch);
    return pair;
}

void
pcmk__bundle_rsc_colocation_lh(pe_resource_t *dependent, pe_resource_t *primary,
                               pcmk__colocation_t *constraint,
                               pe_working_set_t *data_set)
{
    /* -- Never called --
     *
     * Instead we add the colocation constraints to the child and call from there
     */
    CRM_ASSERT(FALSE);
}

int copies_per_node(pe_resource_t * rsc) 
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
            {
                const char *max_clones_node = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_INCARNATION_NODEMAX);

                if (max_clones_node == NULL) {
                    return 1;

                } else {
                    int max_i;

                    pcmk__scan_min_int(max_clones_node, &max_i, 0);
                    return max_i;
                }
            }
        case pe_container:
            {
                pe__bundle_variant_data_t *data = NULL;
                get_bundle_variant_data(data, rsc);
                return data->nreplicas_per_host;
            }
    }
    return 0;
}

void
pcmk__bundle_rsc_colocation_rh(pe_resource_t *dependent, pe_resource_t *primary,
                               pcmk__colocation_t *constraint,
                               pe_working_set_t *data_set)
{
    GList *allocated_primaries = NULL;
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(constraint != NULL, return);
    CRM_CHECK(dependent != NULL,
              pe_err("dependent was NULL for %s", constraint->id); return);
    CRM_CHECK(primary != NULL,
              pe_err("primary was NULL for %s", constraint->id); return);
    CRM_ASSERT(dependent->variant == pe_native);

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        pe_rsc_trace(primary, "%s is still provisional", primary->id);
        return;

    } else if(constraint->dependent->variant > pe_group) {
        pe_resource_t *primary_replica = compatible_replica(dependent, primary,
                                                            RSC_ROLE_UNKNOWN,
                                                            FALSE, data_set);

        if (primary_replica) {
            pe_rsc_debug(primary, "Pairing %s with %s",
                         dependent->id, primary_replica->id);
            dependent->cmds->rsc_colocation_lh(dependent, primary_replica,
                                               constraint, data_set);

        } else if (constraint->score >= INFINITY) {
            crm_notice("Cannot pair %s with instance of %s",
                       dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true);

        } else {
            pe_rsc_debug(primary, "Cannot pair %s with instance of %s",
                         dependent->id, primary->id);
        }

        return;
    }

    get_bundle_variant_data(bundle_data, primary);
    pe_rsc_trace(primary, "Processing constraint %s: %s -> %s %d",
                 constraint->id, dependent->id, primary->id, constraint->score);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (constraint->score < INFINITY) {
            replica->container->cmds->rsc_colocation_rh(dependent,
                                                        replica->container,
                                                        constraint, data_set);

        } else {
            pe_node_t *chosen = replica->container->fns->location(replica->container,
                                                                  NULL, FALSE);

            if ((chosen == NULL)
                || is_set_recursive(replica->container, pe_rsc_block, TRUE)) {
                continue;
            }
            if ((constraint->primary_role >= RSC_ROLE_PROMOTED)
                && (replica->child == NULL)) {
                continue;
            }
            if ((constraint->primary_role >= RSC_ROLE_PROMOTED)
                && (replica->child->next_role < RSC_ROLE_PROMOTED)) {
                continue;
            }

            pe_rsc_trace(primary, "Allowing %s: %s %d",
                         constraint->id, chosen->details->uname,
                         chosen->weight);
            allocated_primaries = g_list_prepend(allocated_primaries, chosen);
        }
    }

    if (constraint->score >= INFINITY) {
        node_list_exclude(dependent->allowed_nodes, allocated_primaries, FALSE);
    }
    g_list_free(allocated_primaries);
}

enum pe_action_flags
pcmk__bundle_action_flags(pe_action_t *action, pe_node_t *node)
{
    GList *containers = NULL;
    enum pe_action_flags flags = 0;
    pe__bundle_variant_data_t *data = NULL;

    get_bundle_variant_data(data, action->rsc);
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

pe_resource_t *
find_compatible_child_by_node(pe_resource_t * local_child, pe_node_t * local_node, pe_resource_t * rsc,
                              enum rsc_role_e filter, gboolean current)
{
    GList *gIter = NULL;
    GList *children = NULL;

    if (local_node == NULL) {
        crm_err("Can't colocate unrunnable child %s with %s", local_child->id, rsc->id);
        return NULL;
    }

    crm_trace("Looking for compatible child from %s for %s on %s",
              local_child->id, rsc->id, local_node->details->uname);

    children = get_containers_or_children(rsc);
    for (gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

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

static pe__bundle_replica_t *
replica_for_container(pe_resource_t *rsc, pe_resource_t *container,
                      pe_node_t *node)
{
    if (rsc->variant == pe_container) {
        pe__bundle_variant_data_t *data = NULL;

        get_bundle_variant_data(data, rsc);
        for (GList *gIter = data->replicas; gIter != NULL;
             gIter = gIter->next) {
            pe__bundle_replica_t *replica = gIter->data;

            if (replica->child
                && (container == replica->container)
                && (node->details == replica->node->details)) {
                return replica;
            }
        }
    }
    return NULL;
}

static enum pe_graph_flags
multi_update_interleave_actions(pe_action_t *first, pe_action_t *then,
                                pe_node_t *node, enum pe_action_flags flags,
                                enum pe_action_flags filter,
                                enum pe_ordering type,
                                pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    GList *children = NULL;
    gboolean current = FALSE;
    enum pe_graph_flags changed = pe_graph_none;

    /* Fix this - lazy */
    if (pcmk__ends_with(first->uuid, "_stopped_0")
        || pcmk__ends_with(first->uuid, "_demoted_0")) {
        current = TRUE;
    }

    children = get_containers_or_children(then->rsc);
    for (gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *then_child = gIter->data;
        pe_resource_t *first_child = find_compatible_child(then_child,
                                                           first->rsc,
                                                           RSC_ROLE_UNKNOWN,
                                                           current, data_set);
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
                if (pcmk__assign_resource(then_child, NULL, true)) {
                    pe__set_graph_flags(changed, first, pe_graph_updated_then);
                }
            }

        } else {
            pe_action_t *first_action = NULL;
            pe_action_t *then_action = NULL;

            enum action_tasks task = clone_child_action(first);
            const char *first_task = task2text(task);

            pe__bundle_replica_t *first_replica = NULL;
            pe__bundle_replica_t *then_replica = NULL;

            first_replica = replica_for_container(first->rsc, first_child,
                                                  node);
            if (strstr(first->task, "stop") && first_replica && first_replica->child) {
                /* Except for 'stopped' we should be looking at the
                 * in-container resource, actions for the child will
                 * happen later and are therefor more likely to align
                 * with the user's intent.
                 */
                first_action = find_first_action(first_replica->child->actions,
                                                 NULL, task2text(task), node);
            } else {
                first_action = find_first_action(first_child->actions, NULL, task2text(task), node);
            }

            then_replica = replica_for_container(then->rsc, then_child, node);
            if (strstr(then->task, "mote")
                && then_replica && then_replica->child) {
                /* Promote/demote actions will never be found for the
                 * container resource, look in the child instead
                 *
                 * Alternatively treat:
                 *  'XXXX then promote YYYY' as 'XXXX then start container for YYYY', and
                 *  'demote XXXX then stop YYYY' as 'stop container for XXXX then stop YYYY'
                 */
                then_action = find_first_action(then_replica->child->actions,
                                                NULL, then->task, node);
            } else {
                then_action = find_first_action(then_child->actions, NULL, then->task, node);
            }

            if (first_action == NULL) {
                if (!pcmk_is_set(first_child->flags, pe_rsc_orphan)
                    && !pcmk__str_any_of(first_task, RSC_STOP, RSC_DEMOTE, NULL)) {
                    crm_err("Internal error: No action found for %s in %s (first)",
                            first_task, first_child->id);

                } else {
                    crm_trace("No action found for %s in %s%s (first)",
                              first_task, first_child->id,
                              pcmk_is_set(first_child->flags, pe_rsc_orphan)? " (ORPHAN)" : "");
                }
                continue;
            }

            /* We're only interested if 'then' is neither stopping nor being demoted */ 
            if (then_action == NULL) {
                if (!pcmk_is_set(then_child->flags, pe_rsc_orphan)
                    && !pcmk__str_any_of(then->task, RSC_STOP, RSC_DEMOTE, NULL)) {
                    crm_err("Internal error: No action found for %s in %s (then)",
                            then->task, then_child->id);

                } else {
                    crm_trace("No action found for %s in %s%s (then)",
                              then->task, then_child->id,
                              pcmk_is_set(then_child->flags, pe_rsc_orphan)? " (ORPHAN)" : "");
                }
                continue;
            }

            if (order_actions(first_action, then_action, type)) {
                crm_debug("Created constraint for %s (%d) -> %s (%d) %.6x",
                          first_action->uuid,
                          pcmk_is_set(first_action->flags, pe_action_optional),
                          then_action->uuid,
                          pcmk_is_set(then_action->flags, pe_action_optional),
                          type);
                pe__set_graph_flags(changed, first,
                                    pe_graph_updated_first|pe_graph_updated_then);
            }
            if(first_action && then_action) {
                changed |= then_child->cmds->update_actions(first_action,
                    then_action, node,
                    first_child->cmds->action_flags(first_action, node),
                    filter, type, data_set);
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

static bool
can_interleave_actions(pe_action_t *first, pe_action_t *then)
{
    bool interleave = FALSE;
    pe_resource_t *rsc = NULL;
    const char *interleave_s = NULL;

    if(first->rsc == NULL || then->rsc == NULL) {
        crm_trace("Not interleaving %s with %s (both must be resources)", first->uuid, then->uuid);
        return FALSE;
    } else if(first->rsc == then->rsc) {
        crm_trace("Not interleaving %s with %s (must belong to different resources)", first->uuid, then->uuid);
        return FALSE;
    } else if(first->rsc->variant < pe_clone || then->rsc->variant < pe_clone) {
        crm_trace("Not interleaving %s with %s (both sides must be clones or bundles)", first->uuid, then->uuid);
        return FALSE;
    }

    if (pcmk__ends_with(then->uuid, "_stop_0")
        || pcmk__ends_with(then->uuid, "_demote_0")) {
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
pcmk__multi_update_actions(pe_action_t *first, pe_action_t *then,
                           pe_node_t *node, enum pe_action_flags flags,
                           enum pe_action_flags filter, enum pe_ordering type,
                           pe_working_set_t *data_set)
{
    enum pe_graph_flags changed = pe_graph_none;

    crm_trace("%s -> %s", first->uuid, then->uuid);

    if(can_interleave_actions(first, then)) {
        changed = multi_update_interleave_actions(first, then, node, flags,
                                                  filter, type, data_set);

    } else if(then->rsc) {
        GList *gIter = NULL;
        GList *children = NULL;

        // Handle the 'primitive' ordering case
        changed |= native_update_actions(first, then, node, flags, filter,
                                         type, data_set);

        // Now any children (or containers in the case of a bundle)
        children = get_containers_or_children(then->rsc);
        for (gIter = children; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *then_child = (pe_resource_t *) gIter->data;
            enum pe_graph_flags then_child_changed = pe_graph_none;
            pe_action_t *then_child_action = find_first_action(then_child->actions, NULL, then->task, node);

            if (then_child_action) {
                enum pe_action_flags then_child_flags = then_child->cmds->action_flags(then_child_action, node);

                if (pcmk_is_set(then_child_flags, pe_action_runnable)) {
                    then_child_changed |= then_child->cmds->update_actions(first,
                        then_child_action, node, flags, filter, type, data_set);
                }
                changed |= then_child_changed;
                if (then_child_changed & pe_graph_updated_then) {
                    for (GList *lpc = then_child_action->actions_after; lpc != NULL; lpc = lpc->next) {
                        pe_action_wrapper_t *next = (pe_action_wrapper_t *) lpc->data;

                        pcmk__update_action_for_orderings(next->action,
                                                          data_set);
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
pcmk__bundle_rsc_location(pe_resource_t *rsc, pe__location_t *constraint)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    get_bundle_variant_data(bundle_data, rsc);

    pcmk__apply_location(constraint, rsc);

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        if (replica->container) {
            replica->container->cmds->rsc_location(replica->container,
                                                   constraint);
        }
        if (replica->ip) {
            replica->ip->cmds->rsc_location(replica->ip, constraint);
        }
    }

    if (bundle_data->child
        && ((constraint->role_filter == RSC_ROLE_UNPROMOTED)
            || (constraint->role_filter == RSC_ROLE_PROMOTED))) {
        bundle_data->child->cmds->rsc_location(bundle_data->child, constraint);
        bundle_data->child->rsc_location = g_list_prepend(bundle_data->child->rsc_location,
                                                          constraint);
    }
}

void
pcmk__bundle_expand(pe_resource_t *rsc, pe_working_set_t * data_set)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    get_bundle_variant_data(bundle_data, rsc);

    if (bundle_data->child) {
        bundle_data->child->cmds->expand(bundle_data->child, data_set);
    }

    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        if (replica->remote && replica->container
            && pe__bundle_needs_remote_name(replica->remote, data_set)) {

            /* REMOTE_CONTAINER_HACK: Allow remote nodes to run containers that
             * run pacemaker-remoted inside, without needing a separate IP for
             * the container. This is done by configuring the inner remote's
             * connection host as the magic string "#uname", then
             * replacing it with the underlying host when needed.
             */
            xmlNode *nvpair = get_xpath_object("//nvpair[@name='" XML_RSC_ATTR_REMOTE_RA_ADDR "']",
                                               replica->remote->xml, LOG_ERR);
            const char *calculated_addr = NULL;

            // Replace the value in replica->remote->xml (if appropriate)
            calculated_addr = pe__add_bundle_remote_name(replica->remote,
                                                         data_set,
                                                         nvpair, "value");
            if (calculated_addr) {
                /* Since this is for the bundle as a resource, and not any
                 * particular action, replace the value in the default
                 * parameters (not evaluated for node). action2xml() will grab
                 * it from there to replace it in node-evaluated parameters.
                 */
                GHashTable *params = pe_rsc_params(replica->remote,
                                                   NULL, data_set);

                crm_trace("Set address for bundle connection %s to bundle host %s",
                          replica->remote->id, calculated_addr);
                g_hash_table_replace(params,
                                     strdup(XML_RSC_ATTR_REMOTE_RA_ADDR),
                                     strdup(calculated_addr));
            } else {
                /* The only way to get here is if the remote connection is
                 * neither currently running nor scheduled to run. That means we
                 * won't be doing any operations that require addr (only start
                 * requires it; we additionally use it to compare digests when
                 * unpacking status, promote, and migrate_from history, but
                 * that's already happened by this point).
                 */
                crm_info("Unable to determine address for bundle %s remote connection",
                         rsc->id);
            }
        }
        if (replica->ip) {
            replica->ip->cmds->expand(replica->ip, data_set);
        }
        if (replica->container) {
            replica->container->cmds->expand(replica->container, data_set);
        }
        if (replica->remote) {
            replica->remote->cmds->expand(replica->remote, data_set);
        }
    }
}

gboolean
pcmk__bundle_create_probe(pe_resource_t *rsc, pe_node_t *node,
                          pe_action_t *complete, gboolean force,
                          pe_working_set_t * data_set)
{
    bool any_created = FALSE;
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(rsc != NULL, return FALSE);

    get_bundle_variant_data(bundle_data, rsc);
    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
        if (replica->ip) {
            any_created |= replica->ip->cmds->create_probe(replica->ip, node,
                                                           complete, force,
                                                           data_set);
        }
        if (replica->child && (node->details == replica->node->details)) {
            any_created |= replica->child->cmds->create_probe(replica->child,
                                                              node, complete,
                                                              force, data_set);
        }
        if (replica->container) {
            bool created = replica->container->cmds->create_probe(replica->container,
                                                                  node, complete,
                                                                  force, data_set);

            if(created) {
                any_created = TRUE;
                /* If we're limited to one replica per host (due to
                 * the lack of an IP range probably), then we don't
                 * want any of our peer containers starting until
                 * we've established that no other copies are already
                 * running.
                 *
                 * Partly this is to ensure that nreplicas_per_host is
                 * observed, but also to ensure that the containers
                 * don't fail to start because the necessary port
                 * mappings (which won't include an IP for uniqueness)
                 * are already taken
                 */

                for (GList *tIter = bundle_data->replicas;
                     tIter && (bundle_data->nreplicas_per_host == 1);
                     tIter = tIter->next) {
                    pe__bundle_replica_t *other = tIter->data;

                    if ((other != replica) && (other != NULL)
                        && (other->container != NULL)) {

                        pcmk__new_ordering(replica->container,
                                           pcmk__op_key(replica->container->id, RSC_STATUS, 0),
                                           NULL, other->container,
                                           pcmk__op_key(other->container->id, RSC_START, 0),
                                           NULL,
                                           pe_order_optional|pe_order_same_node,
                                           data_set);
                    }
                }
            }
        }
        if (replica->container && replica->remote
            && replica->remote->cmds->create_probe(replica->remote, node,
                                                   complete, force,
                                                   data_set)) {

            /* Do not probe the remote resource until we know where the
             * container is running. This is required for REMOTE_CONTAINER_HACK
             * to correctly probe remote resources.
             */
            char *probe_uuid = pcmk__op_key(replica->remote->id, RSC_STATUS,
                                               0);
            pe_action_t *probe = find_first_action(replica->remote->actions,
                                                   probe_uuid, NULL, node);

            free(probe_uuid);
            if (probe) {
                any_created = TRUE;
                crm_trace("Ordering %s probe on %s",
                          replica->remote->id, node->details->uname);
                pcmk__new_ordering(replica->container,
                                   pcmk__op_key(replica->container->id, RSC_START, 0),
                                   NULL, replica->remote, NULL, probe,
                                   pe_order_probe, data_set);
            }
        }
    }
    return any_created;
}

void
pcmk__bundle_append_meta(pe_resource_t *rsc, xmlNode *xml)
{
}

void
pcmk__output_bundle_actions(pe_resource_t *rsc)
{
    pe__bundle_variant_data_t *bundle_data = NULL;

    CRM_CHECK(rsc != NULL, return);

    get_bundle_variant_data(bundle_data, rsc);
    for (GList *gIter = bundle_data->replicas; gIter != NULL;
         gIter = gIter->next) {
        pe__bundle_replica_t *replica = gIter->data;

        CRM_ASSERT(replica);
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
    }
}

// Bundle implementation of resource_alloc_functions_t:add_utilization()
void
pcmk__bundle_add_utilization(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                             GList *all_rscs, GHashTable *utilization)
{
    pe__bundle_variant_data_t *bundle_data = NULL;
    pe__bundle_replica_t *replica = NULL;

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return;
    }

    get_bundle_variant_data(bundle_data, rsc);
    if (bundle_data->replicas == NULL) {
        return;
    }

    /* All bundle replicas are identical, so using the utilization of the first
     * is sufficient for any. Only the implicit container resource can have
     * utilization values.
     */
    replica = (pe__bundle_replica_t *) bundle_data->replicas->data;
    if (replica->container != NULL) {
        replica->container->cmds->add_utilization(replica->container, orig_rsc,
                                                  all_rscs, utilization);
    }
}
