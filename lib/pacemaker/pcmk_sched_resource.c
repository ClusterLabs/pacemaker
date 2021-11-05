/*
 * Copyright 2014-2021 the Pacemaker project contributors
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

// Shared implementation of resource_alloc_functions_t:colocated_resources()
GList *
pcmk__colocated_resources(pe_resource_t *rsc, pe_resource_t *orig_rsc,
                          GList *colocated_rscs)
{
    GList *gIter = NULL;

    if (orig_rsc == NULL) {
        orig_rsc = rsc;
    }

    if ((rsc == NULL) || (g_list_find(colocated_rscs, rsc) != NULL)) {
        return colocated_rscs;
    }

    pe_rsc_trace(orig_rsc, "%s is in colocation chain with %s",
                 rsc->id, orig_rsc->id);
    colocated_rscs = g_list_append(colocated_rscs, rsc);

    // Follow colocations where this resource is the dependent resource
    for (gIter = rsc->rsc_cons; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;
        pe_resource_t *primary = constraint->primary;

        if (primary == orig_rsc) {
            continue; // Break colocation loop
        }

        if ((constraint->score == INFINITY) &&
            (pcmk__colocation_affects(rsc, primary, constraint,
                                      true) == pcmk__coloc_affects_location)) {

            colocated_rscs = primary->cmds->colocated_resources(primary,
                                                                orig_rsc,
                                                                colocated_rscs);
        }
    }

    // Follow colocations where this resource is the primary resource
    for (gIter = rsc->rsc_cons_lhs; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *constraint = (pcmk__colocation_t *) gIter->data;
        pe_resource_t *dependent = constraint->dependent;

        if (dependent == orig_rsc) {
            continue; // Break colocation loop
        }

        if (pe_rsc_is_clone(rsc) && !pe_rsc_is_clone(dependent)) {
            continue; // We can't be sure whether dependent will be colocated
        }

        if ((constraint->score == INFINITY) &&
            (pcmk__colocation_affects(dependent, rsc, constraint,
                                      true) == pcmk__coloc_affects_location)) {

            colocated_rscs = dependent->cmds->colocated_resources(dependent,
                                                                  orig_rsc,
                                                                  colocated_rscs);
        }
    }

    return colocated_rscs;
}

/*!
 * \internal
 * \brief Assign a specified primitive resource to a node
 *
 * Assign a specified primitive resource to a specified node, if the node can
 * run the resource (or unconditionally, if \p force is true). Mark the resource
 * as no longer provisional. If the primitive can't be assigned (or \p chosen is
 * NULL), unassign any previous assignment for it, set its next role to stopped,
 * and update any existing actions scheduled for it. This is not done
 * recursively for children, so it should be called only for primitives.
 *
 * \param[in] rsc     Resource to assign
 * \param[in] chosen  Node to assign \p rsc to
 * \param[in] force   If true, assign to \p chosen even if unavailable
 *
 * \return true if \p rsc could be assigned, otherwise false
 *
 * \note Assigning a resource to the NULL node using this function is different
 *       from calling pcmk__unassign_resource(), in that it will also update any
 *       actions created for the resource.
 */
bool
pcmk__assign_primitive(pe_resource_t *rsc, pe_node_t *chosen, bool force)
{
    pcmk__output_t *out = rsc->cluster->priv;

    CRM_ASSERT(rsc->variant == pe_native);

    if (!force && (chosen != NULL)) {
        if ((chosen->weight < 0)
            // Allow the graph to assume that guest node connections will come up
            || (!can_run_resources(chosen) && !pe__is_guest_node(chosen))) {

            crm_debug("All nodes for resource %s are unavailable, unclean or "
                      "shutting down (%s can%s run resources, with weight %d)",
                      rsc->id, chosen->details->uname,
                      (can_run_resources(chosen)? "" : "not"), chosen->weight);
            pe__set_next_role(rsc, RSC_ROLE_STOPPED, "node availability");
            chosen = NULL;
        }
    }

    pcmk__unassign_resource(rsc);
    pe__clear_resource_flags(rsc, pe_rsc_provisional);

    if (chosen == NULL) {
        crm_debug("Could not allocate a node for %s", rsc->id);
        pe__set_next_role(rsc, RSC_ROLE_STOPPED, "unable to allocate");

        for (GList *iter = rsc->actions; iter != NULL; iter = iter->next) {
            pe_action_t *op = (pe_action_t *) iter->data;

            crm_debug("Updating %s for allocation failure", op->uuid);

            if (pcmk__str_eq(op->task, RSC_STOP, pcmk__str_casei)) {
                pe__clear_action_flags(op, pe_action_optional);

            } else if (pcmk__str_eq(op->task, RSC_START, pcmk__str_casei)) {
                pe__clear_action_flags(op, pe_action_runnable);
                //pe__set_resource_flags(rsc, pe_rsc_block);

            } else {
                // Cancel recurring actions, unless for stopped state
                const char *interval_ms_s = NULL;
                const char *target_rc_s = NULL;
                char *rc_stopped = pcmk__itoa(PCMK_OCF_NOT_RUNNING);

                interval_ms_s = g_hash_table_lookup(op->meta,
                                                    XML_LRM_ATTR_INTERVAL_MS);
                target_rc_s = g_hash_table_lookup(op->meta,
                                                  XML_ATTR_TE_TARGET_RC);
                if ((interval_ms_s != NULL)
                    && !pcmk__str_eq(interval_ms_s, "0", pcmk__str_none)
                    && !pcmk__str_eq(rc_stopped, target_rc_s, pcmk__str_none)) {
                    pe__clear_action_flags(op, pe_action_runnable);
                }
                free(rc_stopped);
            }
        }
        return false;
    }

    crm_debug("Assigning %s to %s", rsc->id, chosen->details->uname);
    rsc->allocated_to = pe__copy_node(chosen);

    chosen->details->allocated_rsc = g_list_prepend(chosen->details->allocated_rsc,
                                                    rsc);
    chosen->details->num_resources++;
    chosen->count++;
    calculate_utilization(chosen->details->utilization, rsc->utilization,
                          FALSE);

    if (pcmk_is_set(rsc->cluster->flags, pe_flag_show_utilization)) {
        out->message(out, "resource-util", rsc, chosen, __func__);
    }
    return true;
}

/*!
 * \internal
 * \brief Assign a specified resource (of any variant) to a node
 *
 * Assign a specified resource and its children (if any) to a specified node, if
 * the node can run the resource (or unconditionally, if \p force is true). Mark
 * the resources as no longer provisional. If the resources can't be assigned
 * (or \p chosen is NULL), unassign any previous assignments, set next role to
 * stopped, and update any existing actions scheduled for them.
 *
 * \param[in] rsc     Resource to assign
 * \param[in] chosen  Node to assign \p rsc to
 * \param[in] force   If true, assign to \p chosen even if unavailable
 *
 * \return true if \p rsc could be assigned, otherwise false
 *
 * \note Assigning a resource to the NULL node using this function is different
 *       from calling pcmk__unassign_resource(), in that it will also update any
 *       actions created for the resource.
 */
bool
pcmk__assign_resource(pe_resource_t *rsc, pe_node_t *node, bool force)
{
    bool changed = false;

    if (rsc->children == NULL) {
        if (rsc->allocated_to != NULL) {
            changed = true;
        }
        pcmk__assign_primitive(rsc, node, force);

    } else {
        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) iter->data;

            changed |= pcmk__assign_resource(child_rsc, node, force);
        }
    }
    return changed;
}

/*!
 * \internal
 * \brief Remove any assignment of a specified resource to a node
 *
 * If a specified resource has been assigned to a node, remove that assignment
 * and mark the resource as provisional again. This is not done recursively for
 * children, so it should be called only for primitives.
 *
 * \param[in] rsc  Resource to unassign
 */
void
pcmk__unassign_resource(pe_resource_t *rsc)
{
    pe_node_t *old = rsc->allocated_to;

    if (old == NULL) {
        return;
    }

    crm_info("Unassigning %s from %s", rsc->id, old->details->uname);
    pe__set_resource_flags(rsc, pe_rsc_provisional);
    rsc->allocated_to = NULL;

    /* We're going to free the pe_node_t, but its details member is shared and
     * will remain, so update that appropriately first.
     */
    old->details->allocated_rsc = g_list_remove(old->details->allocated_rsc,
                                                rsc);
    old->details->num_resources--;
    calculate_utilization(old->details->utilization, rsc->utilization, TRUE);
    free(old);
}
