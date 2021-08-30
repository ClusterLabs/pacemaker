/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Order all actions appropriately relative to a fencing operation
 *
 * Ensure start operations of affected resources are ordered after fencing,
 * imply stop and demote operations of affected resources by marking them as
 * pseudo-actions, etc.
 *
 * \param[in]     stonith_op  Fencing operation
 * \param[in,out] data_set    Working set of cluster
 */
void
pcmk__order_vs_fence(pe_action_t *stonith_op, pe_working_set_t *data_set)
{
    CRM_CHECK(stonith_op && data_set, return);
    for (GList *r = data_set->resources; r != NULL; r = r->next) {
        rsc_stonith_ordering((pe_resource_t *) r->data, stonith_op, data_set);
    }
}

/*!
 * \internal
 * \brief Create pseudo-op for guest node fence, and order relative to it
 *
 * \param[in] node      Guest node to fence
 * \param[in] data_set  Working set of CIB state
 */
void
pcmk__fence_guest(pe_node_t *node, pe_working_set_t *data_set)
{
    pe_resource_t *container = node->details->remote_rsc->container;
    pe_action_t *stop = NULL;
    pe_action_t *stonith_op = NULL;

    /* The fence action is just a label; we don't do anything differently for
     * off vs. reboot. We specify it explicitly, rather than let it default to
     * cluster's default action, because we are not _initiating_ fencing -- we
     * are creating a pseudo-event to describe fencing that is already occurring
     * by other means (container recovery).
     */
    const char *fence_action = "off";

    /* Check whether guest's container resource has any explicit stop or
     * start (the stop may be implied by fencing of the guest's host).
     */
    if (container) {
        stop = find_first_action(container->actions, NULL, CRMD_ACTION_STOP,
                                 NULL);

        if (find_first_action(container->actions, NULL, CRMD_ACTION_START,
                              NULL)) {
            fence_action = "reboot";
        }
    }

    /* Create a fence pseudo-event, so we have an event to order actions
     * against, and the controller can always detect it.
     */
    stonith_op = pe_fence_op(node, fence_action, FALSE, "guest is unclean",
                             FALSE, data_set);
    pe__set_action_flags(stonith_op, pe_action_pseudo|pe_action_runnable);

    /* We want to imply stops/demotes after the guest is stopped, not wait until
     * it is restarted, so we always order pseudo-fencing after stop, not start
     * (even though start might be closer to what is done for a real reboot).
     */
    if ((stop != NULL) && pcmk_is_set(stop->flags, pe_action_pseudo)) {
        pe_action_t *parent_stonith_op = pe_fence_op(stop->node, NULL, FALSE,
                                                     NULL, FALSE, data_set);

        crm_info("Implying guest node %s is down (action %d) after %s fencing",
                 node->details->uname, stonith_op->id,
                 stop->node->details->uname);
        order_actions(parent_stonith_op, stonith_op,
                      pe_order_runnable_left|pe_order_implies_then);

    } else if (stop) {
        order_actions(stop, stonith_op,
                      pe_order_runnable_left|pe_order_implies_then);
        crm_info("Implying guest node %s is down (action %d) "
                 "after container %s is stopped (action %d)",
                 node->details->uname, stonith_op->id,
                 container->id, stop->id);
    } else {
        /* If we're fencing the guest node but there's no stop for the guest
         * resource, we must think the guest is already stopped. However, we may
         * think so because its resource history was just cleaned. To avoid
         * unnecessarily considering the guest node down if it's really up,
         * order the pseudo-fencing after any stop of the connection resource,
         * which will be ordered after any container (re-)probe.
         */
        stop = find_first_action(node->details->remote_rsc->actions, NULL,
                                 RSC_STOP, NULL);

        if (stop) {
            order_actions(stop, stonith_op, pe_order_optional);
            crm_info("Implying guest node %s is down (action %d) "
                     "after connection is stopped (action %d)",
                     node->details->uname, stonith_op->id, stop->id);
        } else {
            /* Not sure why we're fencing, but everything must already be
             * cleanly stopped.
             */
            crm_info("Implying guest node %s is down (action %d) ",
                     node->details->uname, stonith_op->id);
        }
    }

    // Order/imply other actions relative to pseudo-fence as with real fence
    pcmk__order_vs_fence(stonith_op, data_set);
}

/*!
 * \internal
 * \brief Check whether a resource is a fencing device that supports unfencing
 *
 * \param[in] rsc       Resource to check
 * \param[in] data_set  Cluster working set
 *
 * \return true if \p rsc is a fencing device that supports unfencing,
 *         otherwise false
 */
bool
pcmk__is_unfence_device(const pe_resource_t *rsc,
                        const pe_working_set_t *data_set)
{
    return pcmk_is_set(rsc->flags, pe_rsc_fence_device)
           && pcmk_is_set(data_set->flags, pe_flag_enable_unfencing);
}
