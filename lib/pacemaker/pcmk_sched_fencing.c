/*
 * Copyright 2004-2022 the Pacemaker project contributors
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
 * \brief Check whether a resource is known on a particular node
 *
 * \param[in] rsc   Resource to check
 * \param[in] node  Node to check
 *
 * \return TRUE if resource (or parent if an anonymous clone) is known
 */
static bool
rsc_is_known_on(pe_resource_t *rsc, const pe_node_t *node)
{
   if (pe_hash_table_lookup(rsc->known_on, node->details->id)) {
       return TRUE;

   } else if ((rsc->variant == pe_native)
              && pe_rsc_is_anon_clone(rsc->parent)
              && pe_hash_table_lookup(rsc->parent->known_on, node->details->id)) {
       /* We check only the parent, not the uber-parent, because we cannot
        * assume that the resource is known if it is in an anonymously cloned
        * group (which may be only partially known).
        */
       return TRUE;
   }
   return FALSE;
}

/*!
 * \internal
 * \brief Order a resource's start and promote actions relative to fencing
 *
 * \param[in] rsc         Resource to be ordered
 * \param[in] stonith_op  Fence action
 * \param[in] data_set    Cluster working set
 */
static void
order_start_vs_fencing(pe_resource_t *rsc, pe_action_t *stonith_op,
                       pe_working_set_t *data_set)
{
    pe_node_t *target;
    GList *gIter = NULL;

    CRM_CHECK(stonith_op && stonith_op->node, return);
    target = stonith_op->node;

    for (gIter = rsc->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        switch (action->needs) {
            case rsc_req_nothing:
                // Anything other than start or promote requires nothing
                break;

            case rsc_req_stonith:
                order_actions(stonith_op, action, pe_order_optional);
                break;

            case rsc_req_quorum:
                if (pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)
                    && pe_hash_table_lookup(rsc->allowed_nodes, target->details->id)
                    && !rsc_is_known_on(rsc, target)) {

                    /* If we don't know the status of the resource on the node
                     * we're about to shoot, we have to assume it may be active
                     * there. Order the resource start after the fencing. This
                     * is analogous to waiting for all the probes for a resource
                     * to complete before starting it.
                     *
                     * The most likely explanation is that the DC died and took
                     * its status with it.
                     */
                    pe_rsc_debug(rsc, "Ordering %s after %s recovery", action->uuid,
                                 target->details->uname);
                    order_actions(stonith_op, action,
                                  pe_order_optional | pe_order_runnable_left);
                }
                break;
        }
    }
}

/*!
 * \internal
 * \brief Order a resource's stop and demote actions relative to fencing
 *
 * \param[in] rsc         Resource to be ordered
 * \param[in] stonith_op  Fence action
 * \param[in] data_set    Cluster working set
 */
static void
order_stop_vs_fencing(pe_resource_t *rsc, pe_action_t *stonith_op,
                      pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    GList *action_list = NULL;
    bool order_implicit = false;

    pe_resource_t *top = uber_parent(rsc);
    pe_action_t *parent_stop = NULL;
    pe_node_t *target;

    CRM_CHECK(stonith_op && stonith_op->node, return);
    target = stonith_op->node;

    /* Get a list of stop actions potentially implied by the fencing */
    action_list = pe__resource_actions(rsc, target, RSC_STOP, FALSE);

    /* If resource requires fencing, implicit actions must occur after fencing.
     *
     * Implied stops and demotes of resources running on guest nodes are always
     * ordered after fencing, even if the resource does not require fencing,
     * because guest node "fencing" is actually just a resource stop.
     */
    if (pcmk_is_set(rsc->flags, pe_rsc_needs_fencing)
        || pe__is_guest_node(target)) {

        order_implicit = true;
    }

    if (action_list && order_implicit) {
        parent_stop = find_first_action(top->actions, NULL, RSC_STOP, NULL);
    }

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        // The stop would never complete, so convert it into a pseudo-action.
        pe__set_action_flags(action, pe_action_pseudo|pe_action_runnable);

        if (order_implicit) {
            pe__set_action_flags(action, pe_action_implied_by_stonith);

            /* Order the stonith before the parent stop (if any).
             *
             * Also order the stonith before the resource stop, unless the
             * resource is inside a bundle -- that would cause a graph loop.
             * We can rely on the parent stop's ordering instead.
             *
             * User constraints must not order a resource in a guest node
             * relative to the guest node container resource. The
             * pe_order_preserve flag marks constraints as generated by the
             * cluster and thus immune to that check (and is irrelevant if
             * target is not a guest).
             */
            if (!pe_rsc_is_bundled(rsc)) {
                order_actions(stonith_op, action, pe_order_preserve);
            }
            order_actions(stonith_op, parent_stop, pe_order_preserve);
        }

        if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
            crm_notice("Stop of failed resource %s is implicit %s %s is fenced",
                       rsc->id, (order_implicit? "after" : "because"),
                       target->details->uname);
        } else {
            crm_info("%s is implicit %s %s is fenced",
                     action->uuid, (order_implicit? "after" : "because"),
                     target->details->uname);
        }

        if (pcmk_is_set(rsc->flags, pe_rsc_notify)) {
            pcmk__order_notifs_after_fencing(action, rsc, stonith_op);
        }

#if 0
        /* It might be a good idea to stop healthy resources on a node about to
         * be fenced, when possible.
         *
         * However, fencing must be done before a failed resource's
         * (pseudo-)stop action, so that could create a loop. For example, given
         * a group of A and B running on node N with a failed stop of B:
         *
         *    fence N -> stop B (pseudo-op) -> stop A -> fence N
         *
         * The block below creates the stop A -> fence N ordering and therefore
         * must (at least for now) be disabled. Instead, run the block above and
         * treat all resources on N as B would be (i.e., as a pseudo-op after
         * the fencing).
         *
         * @TODO Maybe break the "A requires B" dependency in
         * pcmk__update_action_for_orderings() and use this block for healthy
         * resources instead of the above.
         */
         crm_info("Moving healthy resource %s off %s before fencing",
                  rsc->id, node->details->uname);
         pcmk__new_ordering(rsc, stop_key(rsc), NULL, NULL,
                            strdup(CRM_OP_FENCE), stonith_op,
                            pe_order_optional, data_set);
#endif
    }

    g_list_free(action_list);

    /* Get a list of demote actions potentially implied by the fencing */
    action_list = pe__resource_actions(rsc, target, RSC_DEMOTE, FALSE);

    for (gIter = action_list; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (!(action->node->details->online) || action->node->details->unclean
            || pcmk_is_set(rsc->flags, pe_rsc_failed)) {

            if (pcmk_is_set(rsc->flags, pe_rsc_failed)) {
                pe_rsc_info(rsc,
                            "Demote of failed resource %s is implicit after %s is fenced",
                            rsc->id, target->details->uname);
            } else {
                pe_rsc_info(rsc, "%s is implicit after %s is fenced",
                            action->uuid, target->details->uname);
            }

            /* The demote would never complete and is now implied by the
             * fencing, so convert it into a pseudo-action.
             */
            pe__set_action_flags(action, pe_action_pseudo|pe_action_runnable);

            if (pe_rsc_is_bundled(rsc)) {
                // Do nothing, let recovery be ordered after parent's implied stop

            } else if (order_implicit) {
                order_actions(stonith_op, action, pe_order_preserve|pe_order_optional);
            }
        }
    }

    g_list_free(action_list);
}

/*!
 * \internal
 * \brief Order resource actions properly relative to fencing
 *
 * \param[in] rsc         Resource whose actions should be ordered
 * \param[in] stonith_op  Fencing operation to be ordered against
 * \param[in] data_set    Cluster working set
 */
static void
rsc_stonith_ordering(pe_resource_t *rsc, pe_action_t *stonith_op,
                     pe_working_set_t *data_set)
{
    if (rsc->children) {
        GList *gIter = NULL;

        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            rsc_stonith_ordering(child_rsc, stonith_op, data_set);
        }

    } else if (!pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pe_rsc_trace(rsc,
                     "Skipping fencing constraints for unmanaged resource: %s",
                     rsc->id);

    } else {
        order_start_vs_fencing(rsc, stonith_op, data_set);
        order_stop_vs_fencing(rsc, stonith_op, data_set);
    }
}

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
 * \brief Order an action after unfencing
 *
 * \param[in] rsc       Resource that action is for
 * \param[in] node      Node that action is on
 * \param[in] action    Action to be ordered after unfencing
 * \param[in] order     Ordering flags
 * \param[in] data_set  Cluster working set
 */
void
pcmk__order_vs_unfence(pe_resource_t *rsc, pe_node_t *node, pe_action_t *action,
                       enum pe_ordering order, pe_working_set_t *data_set)
{
    /* When unfencing is in use, we order unfence actions before any probe or
     * start of resources that require unfencing, and also of fence devices.
     *
     * This might seem to violate the principle that fence devices require
     * only quorum. However, fence agents that unfence often don't have enough
     * information to even probe or start unless the node is first unfenced.
     */
    if ((pcmk_is_set(rsc->flags, pe_rsc_fence_device)
         && pcmk_is_set(data_set->flags, pe_flag_enable_unfencing))
        || pcmk_is_set(rsc->flags, pe_rsc_needs_unfencing)) {

        /* Start with an optional ordering. Requiring unfencing would result in
         * the node being unfenced, and all its resources being stopped,
         * whenever a new resource is added -- which would be highly suboptimal.
         */
        pe_action_t *unfence = pe_fence_op(node, "on", TRUE, NULL, FALSE, data_set);

        order_actions(unfence, action, order);

        if (!pcmk__node_unfenced(node)) {
            // But unfencing is required if it has never been done
            char *reason = crm_strdup_printf("required by %s %s",
                                             rsc->id, action->task);

            trigger_unfencing(NULL, node, reason, NULL, data_set);
            free(reason);
        }
    }
}

/*!
 * \internal
 * \brief Create pseudo-op for guest node fence, and order relative to it
 *
 * \param[in] node      Guest node to fence
 */
void
pcmk__fence_guest(pe_node_t *node)
{
    pe_resource_t *container = NULL;
    pe_action_t *stop = NULL;
    pe_action_t *stonith_op = NULL;

    /* The fence action is just a label; we don't do anything differently for
     * off vs. reboot. We specify it explicitly, rather than let it default to
     * cluster's default action, because we are not _initiating_ fencing -- we
     * are creating a pseudo-event to describe fencing that is already occurring
     * by other means (container recovery).
     */
    const char *fence_action = "off";

    CRM_ASSERT(node != NULL);

    /* Check whether guest's container resource has any explicit stop or
     * start (the stop may be implied by fencing of the guest's host).
     */
    container = node->details->remote_rsc->container;
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
                             FALSE, node->details->data_set);
    pe__set_action_flags(stonith_op, pe_action_pseudo|pe_action_runnable);

    /* We want to imply stops/demotes after the guest is stopped, not wait until
     * it is restarted, so we always order pseudo-fencing after stop, not start
     * (even though start might be closer to what is done for a real reboot).
     */
    if ((stop != NULL) && pcmk_is_set(stop->flags, pe_action_pseudo)) {
        pe_action_t *parent_stonith_op = pe_fence_op(stop->node, NULL, FALSE,
                                                     NULL, FALSE,
                                                     node->details->data_set);

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
    pcmk__order_vs_fence(stonith_op, node->details->data_set);
}

/*!
 * \internal
 * \brief Check whether node has already been unfenced
 *
 * \param[in] node  Node to check
 *
 * \return true if node has a nonzero #node-unfenced attribute (or none),
 *         otherwise false
 */
bool
pcmk__node_unfenced(pe_node_t *node)
{
    const char *unfenced = pe_node_attribute_raw(node, CRM_ATTR_UNFENCED);

    return !pcmk__str_eq(unfenced, "0", pcmk__str_null_matches);
}
