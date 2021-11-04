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
