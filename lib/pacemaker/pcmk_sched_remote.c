/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
#include <crm/msg_xml.h>
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

/* We always use pe_order_preserve with these convenience functions to exempt
 * internally generated constraints from the prohibition of user constraints
 * involving remote connection resources.
 *
 * The start ordering additionally uses pe_order_runnable_left so that the
 * specified action is not runnable if the start is not runnable.
 */

static inline void
order_start_then_action(pe_resource_t *first_rsc, pe_action_t *then_action,
                        uint32_t extra)
{
    if ((first_rsc != NULL) && (then_action != NULL)) {
        pcmk__new_ordering(first_rsc, start_key(first_rsc), NULL,
                           then_action->rsc, NULL, then_action,
                           pe_order_preserve|pe_order_runnable_left|extra,
                           first_rsc->cluster);
    }
}

static inline void
order_action_then_stop(pe_action_t *first_action, pe_resource_t *then_rsc,
                       uint32_t extra)
{
    if ((first_action != NULL) && (then_rsc != NULL)) {
        pcmk__new_ordering(first_action->rsc, NULL, first_action,
                           then_rsc, stop_key(then_rsc), NULL,
                           pe_order_preserve|extra, then_rsc->cluster);
    }
}

static enum remote_connection_state
get_remote_node_state(const pe_node_t *node)
{
    const pe_resource_t *remote_rsc = NULL;
    const pe_node_t *cluster_node = NULL;

    CRM_ASSERT(node != NULL);

    remote_rsc = node->details->remote_rsc;
    CRM_ASSERT(remote_rsc != NULL);

    cluster_node = pe__current_node(remote_rsc);

    /* If the cluster node the remote connection resource resides on
     * is unclean or went offline, we can't process any operations
     * on that remote node until after it starts elsewhere.
     */
    if ((remote_rsc->next_role == RSC_ROLE_STOPPED)
        || (remote_rsc->allocated_to == NULL)) {

        // The connection resource is not going to run anywhere

        if ((cluster_node != NULL) && cluster_node->details->unclean) {
            /* The remote connection is failed because its resource is on a
             * failed node and can't be recovered elsewhere, so we must fence.
             */
            return remote_state_failed;
        }

        if (!pcmk_is_set(remote_rsc->flags, pe_rsc_failed)) {
            /* Connection resource is cleanly stopped */
            return remote_state_stopped;
        }

        /* Connection resource is failed */

        if ((remote_rsc->next_role == RSC_ROLE_STOPPED)
            && remote_rsc->remote_reconnect_ms
            && node->details->remote_was_fenced
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

    } else if (cluster_node->details->unclean
               || !(cluster_node->details->online)) {
        // Connection is running on a dead node, see if we can recover it first
        return remote_state_resting;

    } else if (pcmk__list_of_multiple(remote_rsc->running_on)
               && (remote_rsc->partial_migration_source != NULL)
               && (remote_rsc->partial_migration_target != NULL)) {
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
apply_remote_ordering(pe_action_t *action)
{
    pe_resource_t *remote_rsc = NULL;
    enum action_tasks task = text2task(action->task);
    enum remote_connection_state state = get_remote_node_state(action->node);

    uint32_t order_opts = pe_order_none;

    if (action->rsc == NULL) {
        return;
    }

    CRM_ASSERT(pe__is_guest_or_remote_node(action->node));

    remote_rsc = action->node->details->remote_rsc;
    CRM_ASSERT(remote_rsc != NULL);

    crm_trace("Order %s action %s relative to %s%s (state: %s)",
              action->task, action->uuid,
              pcmk_is_set(remote_rsc->flags, pe_rsc_failed)? "failed " : "",
              remote_rsc->id, state2text(state));

    if (pcmk__strcase_any_of(action->task, CRMD_ACTION_MIGRATE,
                             CRMD_ACTION_MIGRATED, NULL)) {
        /* Migration ops map to "no_action", but we need to apply the same
         * ordering as for stop or demote (see get_router_node()).
         */
        task = stop_rsc;
    }

    switch (task) {
        case start_rsc:
        case action_promote:
            order_opts = pe_order_none;

            if (state == remote_state_failed) {
                /* Force recovery, by making this action required */
                pe__set_order_flags(order_opts, pe_order_implies_then);
            }

            /* Ensure connection is up before running this action */
            order_start_then_action(remote_rsc, action, order_opts);
            break;

        case stop_rsc:
            if (state == remote_state_alive) {
                order_action_then_stop(action, remote_rsc,
                                       pe_order_implies_first);

            } else if (state == remote_state_failed) {
                /* The resource is active on the node, but since we don't have a
                 * valid connection, the only way to stop the resource is by
                 * fencing the node. There is no need to order the stop relative
                 * to the remote connection, since the stop will become implied
                 * by the fencing.
                 */
                pe_fence_node(remote_rsc->cluster, action->node,
                              "resources are active but "
                              "connection is unrecoverable",
                              FALSE);

            } else if (remote_rsc->next_role == RSC_ROLE_STOPPED) {
                /* State must be remote_state_unknown or remote_state_stopped.
                 * Since the connection is not coming back up in this
                 * transition, stop this resource first.
                 */
                order_action_then_stop(action, remote_rsc,
                                       pe_order_implies_first);

            } else {
                /* The connection is going to be started somewhere else, so
                 * stop this resource after that completes.
                 */
                order_start_then_action(remote_rsc, action, pe_order_none);
            }
            break;

        case action_demote:
            /* Only order this demote relative to the connection start if the
             * connection isn't being torn down. Otherwise, the demote would be
             * blocked because the connection start would not be allowed.
             */
            if ((state == remote_state_resting)
                || (state == remote_state_unknown)) {

                order_start_then_action(remote_rsc, action, pe_order_none);
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
                                        pe_order_implies_then);

            } else {
                pe_node_t *cluster_node = pe__current_node(remote_rsc);

                if ((task == monitor_rsc) && (state == remote_state_failed)) {
                    /* We would only be here if we do not know the state of the
                     * resource on the remote node. Since we have no way to find
                     * out, it is necessary to fence the node.
                     */
                    pe_fence_node(remote_rsc->cluster, action->node,
                                  "resources are in unknown state "
                                  "and connection is unrecoverable", FALSE);
                }

                if ((cluster_node != NULL) && (state == remote_state_stopped)) {
                    /* The connection is currently up, but is going down
                     * permanently. Make sure we check services are actually
                     * stopped _before_ we let the connection get closed.
                     */
                    order_action_then_stop(action, remote_rsc,
                                           pe_order_runnable_left);

                } else {
                    order_start_then_action(remote_rsc, action, pe_order_none);
                }
            }
            break;
    }
}

static void
apply_container_ordering(pe_action_t *action)
{
    /* VMs are also classified as containers for these purposes... in
     * that they both involve a 'thing' running on a real or remote
     * cluster node.
     *
     * This allows us to be smarter about the type and extent of
     * recovery actions required in various scenarios
     */
    pe_resource_t *remote_rsc = NULL;
    pe_resource_t *container = NULL;
    enum action_tasks task = text2task(action->task);

    CRM_ASSERT(action->rsc != NULL);
    CRM_ASSERT(action->node != NULL);
    CRM_ASSERT(pe__is_guest_or_remote_node(action->node));

    remote_rsc = action->node->details->remote_rsc;
    CRM_ASSERT(remote_rsc != NULL);

    container = remote_rsc->container;
    CRM_ASSERT(container != NULL);

    if (pcmk_is_set(container->flags, pe_rsc_failed)) {
        pe_fence_node(action->rsc->cluster, action->node, "container failed",
                      FALSE);
    }

    crm_trace("Order %s action %s relative to %s%s for %s%s",
              action->task, action->uuid,
              pcmk_is_set(remote_rsc->flags, pe_rsc_failed)? "failed " : "",
              remote_rsc->id,
              pcmk_is_set(container->flags, pe_rsc_failed)? "failed " : "",
              container->id);

    if (pcmk__strcase_any_of(action->task, CRMD_ACTION_MIGRATE,
                             CRMD_ACTION_MIGRATED, NULL)) {
        /* Migration ops map to "no_action", but we need to apply the same
         * ordering as for stop or demote (see get_router_node()).
         */
        task = stop_rsc;
    }

    switch (task) {
        case start_rsc:
        case action_promote:
            // Force resource recovery if the container is recovered
            order_start_then_action(container, action, pe_order_implies_then);

            // Wait for the connection resource to be up, too
            order_start_then_action(remote_rsc, action, pe_order_none);
            break;

        case stop_rsc:
        case action_demote:
            if (pcmk_is_set(container->flags, pe_rsc_failed)) {
                /* When the container representing a guest node fails, any stop
                 * or demote actions for resources running on the guest node
                 * are implied by the container stopping. This is similar to
                 * how fencing operations work for cluster nodes and remote
                 * nodes.
                 */
            } else {
                /* Ensure the operation happens before the connection is brought
                 * down.
                 *
                 * If we really wanted to, we could order these after the
                 * connection start, IFF the container's current role was
                 * stopped (otherwise we re-introduce an ordering loop when the
                 * connection is restarting).
                 */
                order_action_then_stop(action, remote_rsc, pe_order_none);
            }
            break;

        default:
            /* Wait for the connection resource to be up */
            if (pcmk__action_is_recurring(action)) {
                /* In case we ever get the recovery logic wrong, force
                 * recurring monitors to be restarted, even if just
                 * the connection was re-established
                 */
                if (task != no_action) {
                    order_start_then_action(remote_rsc, action,
                                            pe_order_implies_then);
                }
            } else {
                order_start_then_action(remote_rsc, action, pe_order_none);
            }
            break;
    }
}

/*!
 * \internal
 * \brief Order all relevant actions relative to remote connection actions
 *
 * \param[in,out] data_set  Cluster working set
 */
void
pcmk__order_remote_connection_actions(pe_working_set_t *data_set)
{
    if (!pcmk_is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        return;
    }

    crm_trace("Creating remote connection orderings");

    for (GList *iter = data_set->actions; iter != NULL; iter = iter->next) {
        pe_action_t *action = iter->data;
        pe_resource_t *remote = NULL;

        // We are only interested in resource actions
        if (action->rsc == NULL) {
            continue;
        }

        /* Special case: If we are clearing the failcount of an actual
         * remote connection resource, then make sure this happens before
         * any start of the resource in this transition.
         */
        if (action->rsc->is_remote_node &&
            pcmk__str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT,
                         pcmk__str_casei)) {

            pcmk__new_ordering(action->rsc, NULL, action, action->rsc,
                               pcmk__op_key(action->rsc->id, RSC_START, 0),
                               NULL, pe_order_optional, data_set);

            continue;
        }

        // We are only interested in actions assigned to a node
        if (action->node == NULL) {
            continue;
        }

        if (!pe__is_guest_or_remote_node(action->node)) {
            continue;
        }

        /* We are only interested in real actions.
         *
         * @TODO This is probably wrong; pseudo-actions might be converted to
         * real actions and vice versa later in update_actions() at the end of
         * pcmk__apply_orderings().
         */
        if (pcmk_is_set(action->flags, pe_action_pseudo)) {
            continue;
        }

        remote = action->node->details->remote_rsc;
        if (remote == NULL) {
            // Orphaned
            continue;
        }

        /* Another special case: if a resource is moving to a Pacemaker Remote
         * node, order the stop on the original node after any start of the
         * remote connection. This ensures that if the connection fails to
         * start, we leave the resource running on the original node.
         */
        if (pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)) {
            for (GList *item = action->rsc->actions; item != NULL;
                 item = item->next) {
                pe_action_t *rsc_action = item->data;

                if (!pe__same_node(rsc_action->node, action->node)
                    && pcmk__str_eq(rsc_action->task, RSC_STOP,
                                    pcmk__str_casei)) {
                    pcmk__new_ordering(remote, start_key(remote), NULL,
                                       action->rsc, NULL, rsc_action,
                                       pe_order_optional, data_set);
                }
            }
        }

        /* The action occurs across a remote connection, so create
         * ordering constraints that guarantee the action occurs while the node
         * is active (after start, before stop ... things like that).
         *
         * This is somewhat brittle in that we need to make sure the results of
         * this ordering are compatible with the result of get_router_node().
         * It would probably be better to add XML_LRM_ATTR_ROUTER_NODE as part
         * of this logic rather than create_graph_action().
         */
        if (remote->container) {
            crm_trace("Container ordering for %s", action->uuid);
            apply_container_ordering(action);

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
pcmk__is_failed_remote_node(const pe_node_t *node)
{
    return pe__is_remote_node(node) && (node->details->remote_rsc != NULL)
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
pcmk__rsc_corresponds_to_guest(const pe_resource_t *rsc, const pe_node_t *node)
{
    return (rsc != NULL) && (rsc->fillers != NULL) && (node != NULL)
            && (node->details->remote_rsc != NULL)
            && (node->details->remote_rsc->container == rsc);
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
pe_node_t *
pcmk__connection_host_for_action(const pe_action_t *action)
{
    pe_node_t *began_on = NULL;
    pe_node_t *ended_on = NULL;
    bool partial_migration = false;
    const char *task = action->task;

    if (pcmk__str_eq(task, CRM_OP_FENCE, pcmk__str_casei)
        || !pe__is_guest_or_remote_node(action->node)) {
        return NULL;
    }

    CRM_ASSERT(action->node->details->remote_rsc != NULL);

    began_on = pe__current_node(action->node->details->remote_rsc);
    ended_on = action->node->details->remote_rsc->allocated_to;
    if (action->node->details->remote_rsc
        && (action->node->details->remote_rsc->container == NULL)
        && action->node->details->remote_rsc->partial_migration_target) {
        partial_migration = true;
    }

    if (began_on == NULL) {
        crm_trace("Routing %s for %s through remote connection's "
                  "next node %s (starting)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (ended_on? ended_on->details->uname : "none"),
                  partial_migration? " (partial migration)" : "");
        return ended_on;
    }

    if (ended_on == NULL) {
        crm_trace("Routing %s for %s through remote connection's "
                  "current node %s (stopping)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (began_on? began_on->details->uname : "none"),
                  partial_migration? " (partial migration)" : "");
        return began_on;
    }

    if (pe__same_node(began_on, ended_on)) {
        crm_trace("Routing %s for %s through remote connection's "
                  "current node %s (not moving)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (began_on? began_on->details->uname : "none"),
                  partial_migration? " (partial migration)" : "");
        return began_on;
    }

    /* If we get here, the remote connection is moving during this transition.
     * This means some actions for resources behind the connection will get
     * routed through the cluster node the connection resource is currently on,
     * and others are routed through the cluster node the connection will end up
     * on.
     */

    if (pcmk__str_eq(task, "notify", pcmk__str_casei)) {
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
    if (pcmk__strcase_any_of(task, "cancel", "stop", "demote", "migrate_from",
                             "migrate_to", NULL) && !partial_migration) {
        crm_trace("Routing %s for %s through remote connection's "
                  "current node %s (moving)%s",
                  action->task, (action->rsc? action->rsc->id : "no resource"),
                  (began_on? began_on->details->uname : "none"),
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
              (ended_on? ended_on->details->uname : "none"),
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
pcmk__substitute_remote_addr(pe_resource_t *rsc, GHashTable *params)
{
    const char *remote_addr = g_hash_table_lookup(params,
                                                  XML_RSC_ATTR_REMOTE_RA_ADDR);

    if (pcmk__str_eq(remote_addr, "#uname", pcmk__str_none)) {
        GHashTable *base = pe_rsc_params(rsc, NULL, rsc->cluster);

        remote_addr = g_hash_table_lookup(base, XML_RSC_ATTR_REMOTE_RA_ADDR);
        if (remote_addr != NULL) {
            g_hash_table_insert(params, strdup(XML_RSC_ATTR_REMOTE_RA_ADDR),
                                strdup(remote_addr));
        }
    }
}

/*!
 * \brief Add special bundle meta-attributes to XML
 *
 * If a given action will be executed on a guest node (including a bundle),
 * add the special bundle meta-attribute "container-attribute-target" and
 * environment variable "physical_host" as XML attributes (using meta-attribute
 * naming).
 *
 * \param[in,out] args_xml  XML to add attributes to
 * \param[in]     action    Action to check
 */
void
pcmk__add_bundle_meta_to_xml(xmlNode *args_xml, const pe_action_t *action)
{
    const pe_node_t *host = NULL;
    enum action_tasks task;

    if (!pe__is_guest_node(action->node)) {
        return;
    }

    task = text2task(action->task);
    if ((task == action_notify) || (task == action_notified)) {
        task = text2task(g_hash_table_lookup(action->meta, "notify_operation"));
    }

    switch (task) {
        case stop_rsc:
        case stopped_rsc:
        case action_demote:
        case action_demoted:
            // "Down" actions take place on guest's current host
            host = pe__current_node(action->node->details->remote_rsc->container);
            break;

        case start_rsc:
        case started_rsc:
        case monitor_rsc:
        case action_promote:
        case action_promoted:
            // "Up" actions take place on guest's next host
            host = action->node->details->remote_rsc->container->allocated_to;
            break;

        default:
            break;
    }

    if (host != NULL) {
        hash2metafield((gpointer) XML_RSC_ATTR_TARGET,
                       (gpointer) g_hash_table_lookup(action->rsc->meta,
                                                      XML_RSC_ATTR_TARGET),
                       (gpointer) args_xml);
        hash2metafield((gpointer) PCMK__ENV_PHYSICAL_HOST,
                       (gpointer) host->details->uname,
                       (gpointer) args_xml);
    }
}
