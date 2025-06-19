/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

enum remote_connection_state {
    remote_state_unknown = 0,
    remote_state_alive = 1,
    remote_state_resting = 2,
    remote_state_failed = 3,
    remote_state_stopped = 4
};

static const char *
state2text(enum remote_connection_state state)
{
    switch (state) {
        case remote_state_unknown:
            return "unknown";
        case remote_state_alive:
            return "alive";
        case remote_state_resting:
            return "resting";
        case remote_state_failed:
            return "failed";
        case remote_state_stopped:
            return "stopped";
    }

    return "impossible";
}

/* We always use pcmk__ar_guest_allowed with these convenience functions to
 * exempt internally generated constraints from the prohibition of user
 * constraints involving remote connection resources.
 *
 * The start ordering additionally uses pcmk__ar_unrunnable_first_blocks so that
 * the specified action is not runnable if the start is not runnable.
 */

static inline void
order_start_then_action(pcmk_resource_t *first_rsc, pcmk_action_t *then_action,
                        uint32_t extra)
{
    if ((first_rsc != NULL) && (then_action != NULL)) {

        pcmk__new_ordering(first_rsc, start_key(first_rsc), NULL,
                           then_action->rsc, NULL, then_action,
                           pcmk__ar_guest_allowed
                           |pcmk__ar_unrunnable_first_blocks
                           |extra,
                           first_rsc->priv->scheduler);
    }
}

static inline void
order_action_then_stop(pcmk_action_t *first_action, pcmk_resource_t *then_rsc,
                       uint32_t extra)
{
    if ((first_action != NULL) && (then_rsc != NULL)) {
        pcmk__new_ordering(first_action->rsc, NULL, first_action,
                           then_rsc, stop_key(then_rsc), NULL,
                           pcmk__ar_guest_allowed|extra,
                           then_rsc->priv->scheduler);
    }
}

static enum remote_connection_state
get_remote_node_state(const pcmk_node_t *node)
{
    const pcmk_resource_t *remote_rsc = NULL;
    const pcmk_node_t *cluster_node = NULL;

    pcmk__assert(node != NULL);

    remote_rsc = node->priv->remote;
    pcmk__assert(remote_rsc != NULL);

    cluster_node = pcmk__current_node(remote_rsc);

    /* If the cluster node the remote connection resource resides on
     * is unclean or went offline, we can't process any operations
     * on that remote node until after it starts elsewhere.
     */
    if ((remote_rsc->priv->next_role == pcmk_role_stopped)
        || (remote_rsc->priv->assigned_node == NULL)) {

        // The connection resource is not going to run anywhere

        if ((cluster_node != NULL) && cluster_node->details->unclean) {
            /* The remote connection is failed because its resource is on a
             * failed node and can't be recovered elsewhere, so we must fence.
             */
            return remote_state_failed;
        }

        if (!pcmk_is_set(remote_rsc->flags, pcmk__rsc_failed)) {
            /* Connection resource is cleanly stopped */
            return remote_state_stopped;
        }

        /* Connection resource is failed */

        if ((remote_rsc->priv->next_role == pcmk_role_stopped)
            && (remote_rsc->priv->remote_reconnect_ms > 0U)
            && pcmk_is_set(node->priv->flags, pcmk__node_remote_fenced)
            && !pe__shutdown_requested(node)) {

            /* We won't know whether the connection is recoverable until the
             * reconnect interval expires and we reattempt connection.
             */
            return remote_state_unknown;
        }

        /* The remote connection is in a failed state. If there are any
         * resources known to be active on it (stop) or in an unknown state
         * (probe), we must assume the worst and fence it.
         */
        return remote_state_failed;

    } else if (cluster_node == NULL) {
        /* Connection is recoverable but not currently running anywhere, so see
         * if we can recover it first
         */
        return remote_state_unknown;

    } else if (!pcmk__node_available(cluster_node, pcmk__node_alive)) {
        // Connection is running on a dead node, see if we can recover it first
        return remote_state_resting;

    } else if (pcmk__list_of_multiple(remote_rsc->priv->active_nodes)
               && (remote_rsc->priv->partial_migration_source != NULL)
               && (remote_rsc->priv->partial_migration_target != NULL)) {
        /* We're in the middle of migrating a connection resource, so wait until
         * after the migration completes before performing any actions.
         */
        return remote_state_resting;

    }
    return remote_state_alive;
}

/*!
 * \internal
 * \brief Order actions on remote node relative to actions for the connection
 *
 * \param[in,out] action    An action scheduled on a Pacemaker Remote node
 */
static void
apply_remote_ordering(pcmk_action_t *action)
{
    pcmk_resource_t *remote_rsc = NULL;
    enum pcmk__action_type task = pcmk__parse_action(action->task);
    enum remote_connection_state state = get_remote_node_state(action->node);

    uint32_t order_opts = pcmk__ar_none;

    if (action->rsc == NULL) {
        return;
    }

    pcmk__assert(pcmk__is_pacemaker_remote_node(action->node));

    remote_rsc = action->node->priv->remote;
    pcmk__assert(remote_rsc != NULL);

    crm_trace("Order %s action %s relative to %s%s (state: %s)",
              action->task, action->uuid,
              pcmk_is_set(remote_rsc->flags, pcmk__rsc_failed)? "failed " : "",
              remote_rsc->id, state2text(state));

    if (pcmk__strcase_any_of(action->task, PCMK_ACTION_MIGRATE_TO,
                             PCMK_ACTION_MIGRATE_FROM, NULL)) {
        /* Migration ops map to pcmk__action_unspecified, but we need to apply
         * the same ordering as for stop or demote (see get_router_node()).
         */
        task = pcmk__action_stop;
    }

    switch (task) {
        case pcmk__action_start:
        case pcmk__action_promote:
            order_opts = pcmk__ar_none;

            if (state == remote_state_failed) {
                /* Force recovery, by making this action required */
                pcmk__set_relation_flags(order_opts,
                                         pcmk__ar_first_implies_then);
            }

            /* Ensure connection is up before running this action */
            order_start_then_action(remote_rsc, action, order_opts);
            break;

        case pcmk__action_stop:
            if (state == remote_state_alive) {
                order_action_then_stop(action, remote_rsc,
                                       pcmk__ar_then_implies_first);

            } else if (state == remote_state_failed) {
                /* The resource is active on the node, but since we don't have a
                 * valid connection, the only way to stop the resource is by
                 * fencing the node. There is no need to order the stop relative
                 * to the remote connection, since the stop will become implied
                 * by the fencing.
                 */
                pe_fence_node(remote_rsc->priv->scheduler, action->node,
                              "resources are active but "
                              "connection is unrecoverable",
                              FALSE);

            } else if (remote_rsc->priv->next_role == pcmk_role_stopped) {
                /* State must be remote_state_unknown or remote_state_stopped.
                 * Since the connection is not coming back up in this
                 * transition, stop this resource first.
                 */
                order_action_then_stop(action, remote_rsc,
                                       pcmk__ar_then_implies_first);

            } else {
                /* The connection is going to be started somewhere else, so
                 * stop this resource after that completes.
                 */
                order_start_then_action(remote_rsc, action, pcmk__ar_none);
            }
            break;

        case pcmk__action_demote:
            /* Only order this demote relative to the connection start if the
             * connection isn't being torn down. Otherwise, the demote would be
             * blocked because the connection start would not be allowed.
             */
            if ((state == remote_state_resting)
                || (state == remote_state_unknown)) {

                order_start_then_action(remote_rsc, action, pcmk__ar_none);
            } /* Otherwise we can rely on the stop ordering */
            break;

        default:
            /* Wait for the connection resource to be up */
            if (pcmk__action_is_recurring(action)) {
                /* In case we ever get the recovery logic wrong, force
                 * recurring monitors to be restarted, even if just
                 * the connection was re-established
                 */
                order_start_then_action(remote_rsc, action,
                                        pcmk__ar_first_implies_then);

            } else {
                pcmk_node_t *cluster_node = pcmk__current_node(remote_rsc);

                if ((task == pcmk__action_monitor)
                    && (state == remote_state_failed)) {
                    /* We would only be here if we do not know the state of the
                     * resource on the remote node. Since we have no way to find
                     * out, it is necessary to fence the node.
                     */
                    pe_fence_node(remote_rsc->priv->scheduler, action->node,
                                  "resources are in unknown state "
                                  "and connection is unrecoverable", FALSE);
                }

                if ((cluster_node != NULL) && (state == remote_state_stopped)) {
                    /* The connection is currently up, but is going down
                     * permanently. Make sure we check services are actually
                     * stopped _before_ we let the connection get closed.
                     */
                    order_action_then_stop(action, remote_rsc,
                                           pcmk__ar_unrunnable_first_blocks);

                } else {
                    order_start_then_action(remote_rsc, action, pcmk__ar_none);
                }
            }
            break;
    }
}

static void
apply_launcher_ordering(pcmk_action_t *action)
{
    pcmk_resource_t *remote_rsc = NULL;
    pcmk_resource_t *launcher = NULL;
    enum pcmk__action_type task = pcmk__parse_action(action->task);

    pcmk__assert(action->rsc != NULL);
    pcmk__assert(pcmk__is_pacemaker_remote_node(action->node));

    remote_rsc = action->node->priv->remote;
    pcmk__assert(remote_rsc != NULL);

    launcher = remote_rsc->priv->launcher;
    pcmk__assert(launcher != NULL);

    if (pcmk_is_set(launcher->flags, pcmk__rsc_failed)) {
        pe_fence_node(action->rsc->priv->scheduler, action->node,
                      "container failed", FALSE);
    }

    crm_trace("Order %s action %s relative to %s%s for %s%s",
              action->task, action->uuid,
              pcmk_is_set(remote_rsc->flags, pcmk__rsc_failed)? "failed " : "",
              remote_rsc->id,
              pcmk_is_set(launcher->flags, pcmk__rsc_failed)? "failed " : "",
              launcher->id);

    if (pcmk__strcase_any_of(action->task, PCMK_ACTION_MIGRATE_TO,
                             PCMK_ACTION_MIGRATE_FROM, NULL)) {
        /* Migration ops map to pcmk__action_unspecified, but we need to apply
         * the same ordering as for stop or demote (see get_router_node()).
         */
        task = pcmk__action_stop;
    }

    switch (task) {
        case pcmk__action_start:
        case pcmk__action_promote:
            // Force resource recovery if the launcher is recovered
            order_start_then_action(launcher, action,
                                    pcmk__ar_first_implies_then);

            // Wait for the connection resource to be up, too
            order_start_then_action(remote_rsc, action, pcmk__ar_none);
            break;

        case pcmk__action_stop:
        case pcmk__action_demote:
            if (pcmk_is_set(launcher->flags, pcmk__rsc_failed)) {
                /* When the launcher representing a guest node fails, any stop
                 * or demote actions for resources running on the guest node
                 * are implied by the launcher stopping. This is similar to
                 * how fencing operations work for cluster nodes and remote
                 * nodes.
                 */
            } else {
                /* Ensure the operation happens before the connection is brought
                 * down.
                 *
                 * If we really wanted to, we could order these after the
                 * connection start, IFF the launcher's current role was
                 * stopped (otherwise we re-introduce an ordering loop when the
                 * connection is restarting).
                 */
                order_action_then_stop(action, remote_rsc, pcmk__ar_none);
            }
            break;

        default:
            /* Wait for the connection resource to be up */
            if (pcmk__action_is_recurring(action)) {
                /* In case we ever get the recovery logic wrong, force
                 * recurring monitors to be restarted, even if just
                 * the connection was re-established
                 */
                if (task != pcmk__action_unspecified) {
                    order_start_then_action(remote_rsc, action,
                                            pcmk__ar_first_implies_then);
                }
            } else {
                order_start_then_action(remote_rsc, action, pcmk__ar_none);
            }
            break;
    }
}

/*!
 * \internal
 * \brief Order all relevant actions relative to remote connection actions
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__order_remote_connection_actions(pcmk_scheduler_t *scheduler)
{
    if (!pcmk_is_set(scheduler->flags, pcmk__sched_have_remote_nodes)) {
        return;
    }

    crm_trace("Creating remote connection orderings");

    for (GList *iter = scheduler->priv->actions;
         iter != NULL; iter = iter->next) {
        pcmk_action_t *action = iter->data;
        pcmk_resource_t *remote = NULL;

        // We are only interested in resource actions
        if (action->rsc == NULL) {
            continue;
        }

        /* Special case: If we are clearing the failcount of an actual
         * remote connection resource, then make sure this happens before
         * any start of the resource in this transition.
         */
        if (pcmk_is_set(action->rsc->flags, pcmk__rsc_is_remote_connection)
            && pcmk__str_eq(action->task, PCMK_ACTION_CLEAR_FAILCOUNT,
                            pcmk__str_none)) {

            pcmk__new_ordering(action->rsc, NULL, action, action->rsc,
                               pcmk__op_key(action->rsc->id, PCMK_ACTION_START,
                                            0),
                               NULL, pcmk__ar_ordered, scheduler);

            continue;
        }

        // We are only interested in actions assigned to a node
        if (action->node == NULL) {
            continue;
        }

        if (!pcmk__is_pacemaker_remote_node(action->node)) {
            continue;
        }

        /* We are only interested in real actions.
         *
         * @TODO This is probably wrong; pseudo-actions might be converted to
         * real actions and vice versa later in update_actions() at the end of
         * pcmk__apply_orderings().
         */
        if (pcmk_is_set(action->flags, pcmk__action_pseudo)) {
            continue;
        }

        remote = action->node->priv->remote;
        if (remote == NULL) {
            // Orphaned
            continue;
        }

        /* Another special case: if a resource is moving to a Pacemaker Remote
         * node, order the stop on the original node after any start of the
         * remote connection. This ensures that if the connection fails to
         * start, we leave the resource running on the original node.
         */
        if (pcmk__str_eq(action->task, PCMK_ACTION_START, pcmk__str_none)) {
            for (GList *item = action->rsc->priv->actions; item != NULL;
                 item = item->next) {
                pcmk_action_t *rsc_action = item->data;

                if (!pcmk__same_node(rsc_action->node, action->node)
                    && pcmk__str_eq(rsc_action->task, PCMK_ACTION_STOP,
                                    pcmk__str_none)) {
                    pcmk__new_ordering(remote, start_key(remote), NULL,
                                       action->rsc, NULL, rsc_action,
                                       pcmk__ar_ordered, scheduler);
                }
            }
        }

        /* The action occurs across a remote connection, so create
         * ordering constraints that guarantee the action occurs while the node
         * is active (after start, before stop ... things like that).
         *
         * This is somewhat brittle in that we need to make sure the results of
         * this ordering are compatible with the result of get_router_node().
         * It would probably be better to add PCMK__XA_ROUTER_NODE as part of
         * this logic rather than create_graph_action().
         */
        if (remote->priv->launcher != NULL) {
            crm_trace("Container ordering for %s", action->uuid);
            apply_launcher_ordering(action);

        } else {
            crm_trace("Remote ordering for %s", action->uuid);
            apply_remote_ordering(action);
        }
    }
}

/*!
 * \internal
 * \brief Check whether a node is a failed remote node
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is a failed remote node, false otherwise
 */
bool
pcmk__is_failed_remote_node(const pcmk_node_t *node)
{
    return pcmk__is_remote_node(node) && (node->priv->remote != NULL)
           && (get_remote_node_state(node) == remote_state_failed);
}

/*!
 * \internal
 * \brief Check whether a given resource corresponds to a given node as guest
 *
 * \param[in] rsc   Resource to check
 * \param[in] node  Node to check
 *
 * \return true if \p node is a guest node and \p rsc is its containing
 *         resource, otherwise false
 */
bool
pcmk__rsc_corresponds_to_guest(const pcmk_resource_t *rsc,
                               const pcmk_node_t *node)
{
    return (rsc != NULL) && (rsc->priv->launched != NULL) && (node != NULL)
            && (node->priv->remote != NULL)
            && (node->priv->remote->priv->launcher == rsc);
}

/*!
 * \internal
 * \brief Get proper connection host that a remote action must be routed through
 *
 * A remote connection resource might be starting, stopping, or migrating in the
 * same transition that an action needs to be executed on its Pacemaker Remote
 * node. Determine the proper node that the remote action should be routed
 * through.
 *
 * \param[in] action  (Potentially remote) action to route
 *
 * \return Connection host that action should be routed through if remote,
 *         otherwise NULL
 */
pcmk_node_t *
pcmk__connection_host_for_action(const pcmk_action_t *action)
{
    pcmk_node_t *began_on = NULL;
    pcmk_node_t *ended_on = NULL;
    bool partial_migration = false;
    const char *task = action->task;
    pcmk_resource_t *remote = NULL;

    if (pcmk__str_eq(task, PCMK_ACTION_STONITH, pcmk__str_none)
        || !pcmk__is_pacemaker_remote_node(action->node)) {
        return NULL;
    }

    remote = action->node->priv->remote;
    pcmk__assert(remote != NULL);

    began_on = pcmk__current_node(remote);
    ended_on = remote->priv->assigned_node;
    if ((remote->priv->launcher == NULL)
        && (remote->priv->partial_migration_target != NULL)) {
        partial_migration = true;
    }

    if (began_on == NULL) {
        crm_trace("Routing %s for %s through remote connection's "
                  "next node %s (starting)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (ended_on? ended_on->priv->name : "none"),
                  partial_migration? " (partial migration)" : "");
        return ended_on;
    }

    if (ended_on == NULL) {
        crm_trace("Routing %s for %s through remote connection's "
                  "current node %s (stopping)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (began_on? began_on->priv->name : "none"),
                  partial_migration? " (partial migration)" : "");
        return began_on;
    }

    if (pcmk__same_node(began_on, ended_on)) {
        crm_trace("Routing %s for %s through remote connection's "
                  "current node %s (not moving)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (began_on? began_on->priv->name : "none"),
                  partial_migration? " (partial migration)" : "");
        return began_on;
    }

    /* If we get here, the remote connection is moving during this transition.
     * This means some actions for resources behind the connection will get
     * routed through the cluster node the connection resource is currently on,
     * and others are routed through the cluster node the connection will end up
     * on.
     */

    if (pcmk__str_eq(task, PCMK_ACTION_NOTIFY, pcmk__str_none)) {
        task = g_hash_table_lookup(action->meta, "notify_operation");
    }

    /*
     * Stop, demote, and migration actions must occur before the connection can
     * move (these actions are required before the remote resource can stop). In
     * this case, we know these actions have to be routed through the initial
     * cluster node the connection resource lived on before the move takes
     * place.
     *
     * The exception is a partial migration of a (non-guest) remote connection
     * resource; in that case, all actions (even these) will be ordered after
     * the connection's pseudo-start on the migration target, so the target is
     * the router node.
     */
    if (pcmk__strcase_any_of(task, PCMK_ACTION_CANCEL, PCMK_ACTION_STOP,
                             PCMK_ACTION_DEMOTE, PCMK_ACTION_MIGRATE_FROM,
                             PCMK_ACTION_MIGRATE_TO, NULL)
        && !partial_migration) {
        crm_trace("Routing %s for %s through remote connection's "
                  "current node %s (moving)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (began_on? began_on->priv->name : "none"),
                  partial_migration? " (partial migration)" : "");
        return began_on;
    }

    /* Everything else (start, promote, monitor, probe, refresh,
     * clear failcount, delete, ...) must occur after the connection starts on
     * the node it is moving to.
     */
    crm_trace("Routing %s for %s through remote connection's "
              "next node %s (moving)%s",
              action->task, (action->rsc? action->rsc->id : "no resource"),
              (ended_on? ended_on->priv->name : "none"),
              partial_migration? " (partial migration)" : "");
    return ended_on;
}

/*!
 * \internal
 * \brief Replace remote connection's addr="#uname" with actual address
 *
 * REMOTE_CONTAINER_HACK: If a given resource is a remote connection resource
 * with its "addr" parameter set to "#uname", pull the actual value from the
 * parameters evaluated without a node (which was put there earlier in
 * pcmk__create_graph() when the bundle's expand() method was called).
 *
 * \param[in,out] rsc     Resource to check
 * \param[in,out] params  Resource parameters evaluated per node
 */
void
pcmk__substitute_remote_addr(pcmk_resource_t *rsc, GHashTable *params)
{
    const char *remote_addr = g_hash_table_lookup(params, PCMK_REMOTE_RA_ADDR);

    if (pcmk__str_eq(remote_addr, "#uname", pcmk__str_none)) {
        GHashTable *base = pe_rsc_params(rsc, NULL, rsc->priv->scheduler);

        remote_addr = g_hash_table_lookup(base, PCMK_REMOTE_RA_ADDR);
        if (remote_addr != NULL) {
            pcmk__insert_dup(params, PCMK_REMOTE_RA_ADDR, remote_addr);
        }
    }
}

/*!
 * \brief Add special guest node meta-attributes to XML
 *
 * If a given action will be executed on a guest node, add the following as XML
 * attributes (using meta-attribute naming):
 * * The resource's \c PCMK_META_CONTAINER_ATTRIBUTE_TARGET meta-attribute
 *   (usually set only for bundles), as \c PCMK_META_CONTAINER_ATTRIBUTE_TARGET
 * * The guest's physical host (current host for "down" actions, next host for
 *   "up" actions), as \c PCMK__META_PHYSICAL_HOST
 *
 * If the guest node has no physical host, then don't add either attribute.
 *
 * \param[in,out] args_xml  XML to add attributes to
 * \param[in]     action    Action to check
 */
void
pcmk__add_guest_meta_to_xml(xmlNode *args_xml, const pcmk_action_t *action)
{
    const pcmk_node_t *guest = action->node;
    const pcmk_node_t *host = NULL;
    const pcmk_resource_t *launcher = NULL;
    enum pcmk__action_type task;

    if (!pcmk__is_guest_or_bundle_node(guest)) {
        return;
    }
    launcher = guest->priv->remote->priv->launcher;

    task = pcmk__parse_action(action->task);
    if ((task == pcmk__action_notify) || (task == pcmk__action_notified)) {
        task = pcmk__parse_action(g_hash_table_lookup(action->meta,
                                                      "notify_operation"));
    }

    switch (task) {
        case pcmk__action_stop:
        case pcmk__action_stopped:
        case pcmk__action_demote:
        case pcmk__action_demoted:
            // "Down" actions take place on guest's current host
            host = pcmk__current_node(launcher);
            break;

        case pcmk__action_start:
        case pcmk__action_started:
        case pcmk__action_monitor:
        case pcmk__action_promote:
        case pcmk__action_promoted:
            // "Up" actions take place on guest's next host
            host = launcher->priv->assigned_node;
            break;

        default:
            break;
    }

    if (host != NULL) {
        gpointer target =
            g_hash_table_lookup(action->rsc->priv->meta,
                                PCMK_META_CONTAINER_ATTRIBUTE_TARGET);

        hash2metafield((gpointer) PCMK_META_CONTAINER_ATTRIBUTE_TARGET,
                       target,
                       (gpointer) args_xml);
        hash2metafield((gpointer) PCMK__META_PHYSICAL_HOST,
                       (gpointer) host->priv->name,
                       (gpointer) args_xml);
    }
}
