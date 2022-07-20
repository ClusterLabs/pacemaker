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

#define VARIANT_CLONE 1
#include <lib/pengine/variant.h>

/*!
 * \internal
 * \brief Assign a clone resource to a node
 *
 * \param[in,out] rsc     Resource to assign to a node
 * \param[in]     prefer  Node to prefer, if all else is equal
 *
 * \return Node that \p rsc is assigned to, if assigned entirely to one node
 */
pe_node_t *
pcmk__clone_allocate(pe_resource_t *rsc, const pe_node_t *prefer)
{
    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return NULL;

    } else if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__add_promotion_scores(rsc);
    }

    pe__set_resource_flags(rsc, pe_rsc_allocating);

    /* If this clone is colocated with any other resources, assign those first.
     * Since the this_with_colocations() method boils down to a copy of rsc_cons
     * for clones, we can use that here directly for efficiency.
     */
    for (GList *gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        pe_rsc_trace(rsc, "%s: Allocating %s first",
                     rsc->id, constraint->primary->id);
        constraint->primary->cmds->assign(constraint->primary, prefer);
    }

    /* If any resources are colocated with this one, consider their preferences.
     * Because the with_this_colocations() method boils down to a copy of
     * rsc_cons_lhs for clones, we can use that here directly for efficiency.
     */
    for (GList *gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;

        if (pcmk__colocation_has_influence(constraint, NULL)) {
            pe_resource_t *dependent = constraint->dependent;
            const char *attr = constraint->node_attribute;
            const float factor = constraint->score / (float) INFINITY;
            const uint32_t flags = pcmk__coloc_select_active
                                   |pcmk__coloc_select_nonnegative;

            pcmk__add_colocated_node_scores(dependent, rsc->id,
                                            &rsc->allowed_nodes, attr, factor,
                                            flags);
        }
    }

    pe__show_node_weights(!pcmk_is_set(rsc->cluster->flags, pe_flag_show_scores),
                          rsc, __func__, rsc->allowed_nodes, rsc->cluster);

    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance);
    pcmk__assign_instances(rsc, rsc->children, pe__clone_max(rsc),
                           pe__clone_node_max(rsc));

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__set_instance_roles(rsc);
    }

    pe__clear_resource_flags(rsc, pe_rsc_provisional|pe_rsc_allocating);
    pe_rsc_trace(rsc, "Done allocating %s", rsc->id);
    return NULL;
}

static pe_action_t *
find_rsc_action(pe_resource_t *rsc, const char *task)
{
    pe_action_t *match = NULL;
    GList *actions = pe__resource_actions(rsc, NULL, task, FALSE);

    for (GList *item = actions; item != NULL; item = item->next) {
        pe_action_t *op = (pe_action_t *) item->data;

        if (!pcmk_is_set(op->flags, pe_action_optional)) {
            if (match != NULL) {
                // More than one match, don't return any
                match = NULL;
                break;
            }
            match = op;
        }
    }
    g_list_free(actions);
    return match;
}

static void
child_ordering_constraints(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    pe_action_t *stop = NULL;
    pe_action_t *start = NULL;
    pe_action_t *last_stop = NULL;
    pe_action_t *last_start = NULL;
    GList *gIter = NULL;

    if (!pe__clone_is_ordered(rsc)) {
        return;
    }

    /* we have to maintain a consistent sorted child list when building order constraints */
    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);

    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        stop = find_rsc_action(child, RSC_STOP);
        if (stop) {
            if (last_stop) {
                /* child/child relative stop */
                order_actions(stop, last_stop, pe_order_optional);
            }
            last_stop = stop;
        }

        start = find_rsc_action(child, RSC_START);
        if (start) {
            if (last_start) {
                /* child/child relative start */
                order_actions(last_start, start, pe_order_optional);
            }
            last_start = start;
        }
    }
}

void
clone_create_actions(pe_resource_t *rsc)
{
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    pe_rsc_debug(rsc, "Creating actions for clone %s", rsc->id);
    pcmk__create_instance_actions(rsc, rsc->children, &clone_data->start_notify,
                                  &clone_data->stop_notify);
    child_ordering_constraints(rsc, rsc->cluster);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__create_promotable_actions(rsc);
    }
}

void
clone_internal_constraints(pe_resource_t *rsc)
{
    pe_resource_t *last_rsc = NULL;
    GList *gIter;
    bool ordered = pe__clone_is_ordered(rsc);

    pe_rsc_trace(rsc, "Internal constraints for %s", rsc->id);
    pcmk__order_resource_actions(rsc, RSC_STOPPED, rsc, RSC_START,
                                 pe_order_optional);
    pcmk__order_resource_actions(rsc, RSC_START, rsc, RSC_STARTED,
                                 pe_order_runnable_left);
    pcmk__order_resource_actions(rsc, RSC_STOP, rsc, RSC_STOPPED,
                                 pe_order_runnable_left);

    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__order_resource_actions(rsc, RSC_DEMOTED, rsc, RSC_STOP,
                                     pe_order_optional);
        pcmk__order_resource_actions(rsc, RSC_STARTED, rsc, RSC_PROMOTE,
                                     pe_order_runnable_left);
    }

    if (ordered) {
        /* we have to maintain a consistent sorted child list when building order constraints */
        rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);
    }
    for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->internal_constraints(child_rsc);

        pcmk__order_starts(rsc, child_rsc,
                           pe_order_runnable_left|pe_order_implies_first_printed);
        pcmk__order_resource_actions(child_rsc, RSC_START, rsc, RSC_STARTED,
                                     pe_order_implies_then_printed);
        if (ordered && (last_rsc != NULL)) {
            pcmk__order_starts(last_rsc, child_rsc, pe_order_optional);
        }

        pcmk__order_stops(rsc, child_rsc, pe_order_implies_first_printed);
        pcmk__order_resource_actions(child_rsc, RSC_STOP, rsc, RSC_STOPPED,
                                     pe_order_implies_then_printed);
        if (ordered && (last_rsc != NULL)) {
            pcmk__order_stops(child_rsc, last_rsc, pe_order_optional);
        }

        last_rsc = child_rsc;
    }
    if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        pcmk__order_promotable_instances(rsc);
    }
}

/*!
 * \internal
 * \brief Apply a colocation's score to node weights or resource priority
 *
 * Given a colocation constraint, apply its score to the dependent's
 * allowed node weights (if we are still placing resources) or priority (if
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
    GList *gIter = NULL;
    gboolean do_interleave = FALSE;
    const char *interleave_s = NULL;

    /* This should never be called for the clone itself as a dependent. Instead,
     * we add its colocation constraints to its instances and call the
     * apply_coloc_score() for the instances as dependents.
     */
    CRM_ASSERT(!for_dependent);

    CRM_CHECK((colocation != NULL) && (dependent != NULL) && (primary != NULL),
              return);
    CRM_CHECK(dependent->variant == pe_native, return);

    pe_rsc_trace(primary, "Processing constraint %s: %s -> %s %d",
                 colocation->id, dependent->id, primary->id, colocation->score);

    if (pcmk_is_set(primary->flags, pe_rsc_promotable)) {
        if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
            // We haven't placed the primary yet, so we can't apply colocation
            pe_rsc_trace(primary, "%s is still provisional", primary->id);
            return;

        } else if (colocation->primary_role == RSC_ROLE_UNKNOWN) {
            // This isn't a role-specfic colocation, so handle normally
            pe_rsc_trace(primary, "Handling %s as a clone colocation",
                         colocation->id);

        } else if (pcmk_is_set(dependent->flags, pe_rsc_provisional)) {
            // We're placing the dependent
            pcmk__update_dependent_with_promotable(primary, dependent,
                                                   colocation);
            return;

        } else if (colocation->dependent_role == RSC_ROLE_PROMOTED) {
            // We're choosing roles for the dependent
            pcmk__update_promotable_dependent_priority(primary, dependent,
                                                       colocation);
            return;
        }
    }

    // Only the dependent needs to be marked for interleave
    interleave_s = g_hash_table_lookup(colocation->dependent->meta,
                                       XML_RSC_ATTR_INTERLEAVE);
    if (crm_is_true(interleave_s)
        && (colocation->dependent->variant > pe_group)) {
        /* @TODO Do we actually care about multiple primary copies sharing a
         * dependent copy anymore?
         */
        if (copies_per_node(colocation->dependent) != copies_per_node(colocation->primary)) {
            pcmk__config_err("Cannot interleave %s and %s because they do not "
                             "support the same number of instances per node",
                             colocation->dependent->id,
                             colocation->primary->id);

        } else {
            do_interleave = TRUE;
        }
    }

    if (pcmk_is_set(primary->flags, pe_rsc_provisional)) {
        pe_rsc_trace(primary, "%s is still provisional", primary->id);
        return;

    } else if (do_interleave) {
        pe_resource_t *primary_instance = NULL;

        primary_instance = pcmk__find_compatible_instance(dependent, primary,
                                                          RSC_ROLE_UNKNOWN,
                                                          false);
        if (primary_instance != NULL) {
            pe_rsc_debug(primary, "Pairing %s with %s",
                         dependent->id, primary_instance->id);
            dependent->cmds->apply_coloc_score(dependent, primary_instance,
                                               colocation, true);

        } else if (colocation->score >= INFINITY) {
            crm_notice("Cannot pair %s with instance of %s",
                       dependent->id, primary->id);
            pcmk__assign_resource(dependent, NULL, true);

        } else {
            pe_rsc_debug(primary, "Cannot pair %s with instance of %s",
                         dependent->id, primary->id);
        }

        return;

    } else if (colocation->score >= INFINITY) {
        GList *affected_nodes = NULL;

        gIter = primary->children;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
            pe_node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);

            if (chosen != NULL && is_set_recursive(child_rsc, pe_rsc_block, TRUE) == FALSE) {
                pe_rsc_trace(primary, "Allowing %s: %s %d",
                             colocation->id, pe__node_name(chosen),
                             chosen->weight);
                affected_nodes = g_list_prepend(affected_nodes, chosen);
            }
        }

        node_list_exclude(dependent->allowed_nodes, affected_nodes, FALSE);
        g_list_free(affected_nodes);
        return;
    }

    gIter = primary->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->apply_coloc_score(dependent, child_rsc, colocation,
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

enum pe_action_flags
clone_action_flags(pe_action_t *action, const pe_node_t *node)
{
    return pcmk__collective_action_flags(action, action->rsc->children, node);
}

void
clone_rsc_location(pe_resource_t *rsc, pe__location_t *constraint)
{
    GList *gIter = rsc->children;

    pe_rsc_trace(rsc, "Processing location constraint %s for %s", constraint->id, rsc->id);

    pcmk__apply_location(rsc, constraint);

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->apply_location(child_rsc, constraint);
    }
}

/*!
 * \internal
 * \brief Add a resource's actions to the transition graph
 *
 * \param[in,out] rsc  Resource whose actions should be added
 */
void
clone_expand(pe_resource_t *rsc)
{
    GList *gIter = NULL;
    clone_variant_data_t *clone_data = NULL;

    get_clone_variant_data(clone_data, rsc);

    g_list_foreach(rsc->actions, (GFunc) rsc->cmds->action_flags, NULL);

    pe__create_clone_notifications(rsc);

    /* Now that the notifcations have been created we can expand the children */

    gIter = rsc->children;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->add_actions_to_graph(child_rsc);
    }

    pcmk__add_rsc_actions_to_graph(rsc);

    /* The notifications are in the graph now, we can destroy the notify_data */
    pe__free_notification_data(clone_data->demote_notify);
    clone_data->demote_notify = NULL;
    pe__free_notification_data(clone_data->stop_notify);
    clone_data->stop_notify = NULL;
    pe__free_notification_data(clone_data->start_notify);
    clone_data->start_notify = NULL;
    pe__free_notification_data(clone_data->promote_notify);
    clone_data->promote_notify = NULL;
}

// Check whether a resource or any of its children is known on node
static bool
rsc_known_on(const pe_resource_t *rsc, const pe_node_t *node)
{
    if (rsc->children) {
        for (GList *child_iter = rsc->children; child_iter != NULL;
             child_iter = child_iter->next) {

            pe_resource_t *child = (pe_resource_t *) child_iter->data;

            if (rsc_known_on(child, node)) {
                return TRUE;
            }
        }

    } else if (rsc->known_on) {
        GHashTableIter iter;
        pe_node_t *known_node = NULL;

        g_hash_table_iter_init(&iter, rsc->known_on);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &known_node)) {
            if (node->details == known_node->details) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// Look for an instance of clone that is known on node
static pe_resource_t *
find_instance_on(const pe_resource_t *clone, const pe_node_t *node)
{
    for (GList *gIter = clone->children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        if (rsc_known_on(child, node)) {
            return child;
        }
    }
    return NULL;
}

// For anonymous clones, only a single instance needs to be probed
static bool
probe_anonymous_clone(pe_resource_t *rsc, pe_node_t *node,
                      pe_working_set_t *data_set)
{
    // First, check if we probed an instance on this node last time
    pe_resource_t *child = find_instance_on(rsc, node);

    // Otherwise, check if we plan to start an instance on this node
    if (child == NULL) {
        for (GList *child_iter = rsc->children; child_iter && !child;
             child_iter = child_iter->next) {

            pe_node_t *local_node = NULL;
            pe_resource_t *child_rsc = (pe_resource_t *) child_iter->data;

            if (child_rsc) { /* make clang analyzer happy */
                local_node = child_rsc->fns->location(child_rsc, NULL, FALSE);
                if (local_node && (local_node->details == node->details)) {
                    child = child_rsc;
                }
            }
        }
    }

    // Otherwise, use the first clone instance
    if (child == NULL) {
        child = rsc->children->data;
    }
    CRM_ASSERT(child);
    return child->cmds->create_probe(child, node);
}

/*!
 * \internal
 *
 * \brief Schedule any probes needed for a resource on a node
 *
 * \param[in,out] rsc   Resource to create probe for
 * \param[in,out] node  Node to create probe on
 *
 * \return true if any probe was created, otherwise false
 */
bool
clone_create_probe(pe_resource_t *rsc, pe_node_t *node)
{
    CRM_ASSERT(rsc);

    rsc->children = g_list_sort(rsc->children, pcmk__cmp_instance_number);
    if (rsc->children == NULL) {
        pe_warn("Clone %s has no children", rsc->id);
        return false;
    }

    if (rsc->exclusive_discover) {
        pe_node_t *allowed = g_hash_table_lookup(rsc->allowed_nodes, node->details->id);
        if (allowed && allowed->rsc_discover_mode != pe_discover_exclusive) {
            /* exclusive discover is enabled and this node is not marked
             * as a node this resource should be discovered on
             *
             * remove the node from allowed_nodes so that the
             * notification contains only nodes that we might ever run
             * on
             */
            g_hash_table_remove(rsc->allowed_nodes, node->details->id);

            /* Bit of a shortcut - might as well take it */
            return false;
        }
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        return pcmk__probe_resource_list(rsc->children, node);
    } else {
        return probe_anonymous_clone(rsc, node, rsc->cluster);
    }
}

void
clone_append_meta(const pe_resource_t *rsc, xmlNode *xml)
{
    char *name = NULL;

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
    return; // Clones currently don't support shutdown locks
}
