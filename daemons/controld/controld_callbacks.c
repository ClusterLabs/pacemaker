/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>           // PRIu32
#include <stdbool.h>            // bool
#include <stdio.h>              // NULL

#include <sys/param.h>
#include <string.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>
#include <crm/cib.h>

#include <pacemaker-controld.h>

/* From join_dc... */
extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

void
crmd_ha_msg_filter(xmlNode * msg)
{
    if (AM_I_DC) {
        const char *sys_from = crm_element_value(msg, PCMK__XA_CRM_SYS_FROM);

        if (pcmk__str_eq(sys_from, CRM_SYSTEM_DC, pcmk__str_casei)) {
            const char *from = crm_element_value(msg, PCMK__XA_SRC);

            if (!controld_is_local_node(from)) {
                int level = LOG_INFO;
                const char *op = crm_element_value(msg, PCMK__XA_CRM_TASK);

                /* make sure the election happens NOW */
                if (controld_globals.fsa_state != S_ELECTION) {
                    ha_msg_input_t new_input;

                    level = LOG_WARNING;
                    new_input.msg = msg;
                    register_fsa_error_adv(C_FSA_INTERNAL, I_ELECTION, NULL, &new_input,
                                           __func__);
                }

                do_crm_log(level, "Another DC detected: %s (op=%s)", from, op);
                goto done;
            }
        }

    } else {
        const char *sys_to = crm_element_value(msg, PCMK__XA_CRM_SYS_TO);

        if (pcmk__str_eq(sys_to, CRM_SYSTEM_DC, pcmk__str_casei)) {
            return;
        }
    }

    /* crm_log_xml_trace(msg, "HA[inbound]"); */
    route_message(C_HA_MESSAGE, msg);

  done:
    controld_trigger_fsa();
}

/*!
 * \internal
 * \brief Check whether a node is online
 *
 * \param[in] node  Node to check
 *
 * \retval -1 if completely dead
 * \retval  0 if partially alive
 * \retval  1 if completely alive
 */
static int
node_alive(const pcmk__node_status_t *node)
{
    if (pcmk_is_set(node->flags, pcmk__node_status_remote)) {
        // Pacemaker Remote nodes can't be partially alive
        if (pcmk__str_eq(node->state, PCMK_VALUE_MEMBER, pcmk__str_none)) {
            return 1;
        }
        return -1;

    } else if (pcmk__cluster_is_node_active(node)) {
        // Completely up cluster node: both cluster member and peer
        return 1;

    } else if (!pcmk_is_set(node->processes, crm_get_cluster_proc())
               && !pcmk__str_eq(node->state, PCMK_VALUE_MEMBER,
                                pcmk__str_none)) {
        // Completely down cluster node: neither cluster member nor peer
        return -1;
    }

    // Partially up cluster node: only cluster member or only peer
    return 0;
}

#define state_text(state) ((state)? (const char *)(state) : "in unknown state")

// @TODO This is insanely long, and some parts should be functionized
void
peer_update_callback(enum pcmk__node_update type, pcmk__node_status_t *node,
                     const void *data)
{
    uint32_t old = 0;
    bool appeared = FALSE;
    bool is_remote = pcmk_is_set(node->flags, pcmk__node_status_remote);

    controld_node_pending_timer(node);

    /* The controller waits to receive some information from the membership
     * layer before declaring itself operational. If this is being called for a
     * cluster node, indicate that we have it.
     */
    if (!is_remote) {
        controld_set_fsa_input_flags(R_PEER_DATA);
    }

    if ((type == pcmk__node_update_processes)
        && pcmk_is_set(node->processes, crm_get_cluster_proc())
        && !AM_I_DC
        && !is_remote) {
        /* relay_message() on the recipient ignores these messages, but
         * libcrmcluster will have cached the node name by then
         */
        xmlNode *query = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_CRMD,
                                           NULL, CRM_SYSTEM_CRMD, CRM_OP_HELLO,
                                           NULL);

        crm_debug("Sending hello to node %" PRIu32 " so that it learns our "
                  "node name",
                  node->cluster_layer_id);
        pcmk__cluster_send_message(node, pcmk_ipc_controld, query);
        pcmk__xml_free(query);
    }

    if (node->name == NULL) {
        return;
    }

    switch (type) {
        case pcmk__node_update_name:
            /* If we've never seen the node, then it also won't be in the status section */
            crm_info("%s node %s is now %s",
                     (is_remote? "Remote" : "Cluster"),
                     node->name, state_text(node->state));
            return;

        case pcmk__node_update_state:
            /* This callback should not be called unless the state actually
             * changed, but here's a failsafe just in case.
             */
            CRM_CHECK(!pcmk__str_eq(data, node->state, pcmk__str_casei),
                      return);

            crm_info("%s node %s is now %s (was %s)",
                     (is_remote? "Remote" : "Cluster"),
                     node->name, state_text(node->state), state_text(data));

            if (pcmk__str_eq(PCMK_VALUE_MEMBER, node->state, pcmk__str_none)) {
                appeared = TRUE;
                if (!is_remote) {
                    remove_stonith_cleanup(node->name);
                }
            } else {
                controld_remove_failed_sync_node(node->name);
                controld_remove_voter(node->name);
            }

            crmd_alert_node_event(node);
            break;

        case pcmk__node_update_processes:
            CRM_CHECK(data != NULL, return);
            old = *(const uint32_t *)data;
            appeared = pcmk_is_set(node->processes, crm_get_cluster_proc());

            {
                const char *dc_s = controld_globals.dc_name;

                if ((dc_s == NULL) && AM_I_DC) {
                    dc_s = PCMK_VALUE_TRUE;
                }

                crm_info("Node %s is %s a peer " QB_XS
                         " DC=%s old=%#07x new=%#07x",
                         node->name, (appeared? "now" : "no longer"),
                         pcmk__s(dc_s, "<none>"), old, node->processes);
            }

            if (!pcmk_is_set((node->processes ^ old), crm_get_cluster_proc())) {
                /* Peer status did not change. This should not be possible,
                 * since we don't track process flags other than peer status.
                 */
                crm_trace("Process flag %#7x did not change from %#7x to %#7x",
                          crm_get_cluster_proc(), old, node->processes);
                return;

            }

            if (!appeared) {
                node->peer_lost = time(NULL);
                controld_remove_failed_sync_node(node->name);
                controld_remove_voter(node->name);
            }

            if (!pcmk_is_set(controld_globals.fsa_input_register,
                             R_CIB_CONNECTED)) {
                crm_trace("Ignoring peer status change because not connected to CIB");
                return;

            } else if (controld_globals.fsa_state == S_STOPPING) {
                crm_trace("Ignoring peer status change because stopping");
                return;
            }

            if (!appeared && controld_is_local_node(node->name)) {
                /* Did we get evicted? */
                crm_notice("Our peer connection failed");
                register_fsa_input(C_CRMD_STATUS_CALLBACK, I_ERROR, NULL);

            } else if (pcmk__str_eq(node->name, controld_globals.dc_name,
                                    pcmk__str_casei)
                       && !pcmk__cluster_is_node_active(node)) {

                // The DC has left, so trigger a new election
                crm_notice("Our peer on the DC (%s) is dead",
                           controld_globals.dc_name);
                register_fsa_input(C_CRMD_STATUS_CALLBACK, I_ELECTION, NULL);
            } else if (AM_I_DC
                       || pcmk_is_set(controld_globals.flags, controld_dc_left)
                       || (controld_globals.dc_name == NULL)) {
                /* This only needs to be done once, so normally the DC should do
                 * it. However if there is no DC, every node must do it, since
                 * there is no other way to ensure some one node does it.
                 */
                if (appeared) {
                    te_trigger_stonith_history_sync(FALSE);
                }
            }
            break;
    }

    if (AM_I_DC) {
        xmlNode *update = NULL;
        int flags = node_update_peer;
        int alive = node_alive(node);
        pcmk__graph_action_t *down = match_down_event(node->xml_id);

        crm_trace("Alive=%d, appeared=%d, down=%d",
                  alive, appeared, (down? down->id : -1));

        if (appeared && (alive > 0) && !is_remote) {
            register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);
        }

        if (down) {
            const char *task = crm_element_value(down->xml, PCMK_XA_OPERATION);

            if (pcmk__str_eq(task, PCMK_ACTION_STONITH, pcmk__str_casei)) {
                const bool confirmed =
                    pcmk_is_set(down->flags, pcmk__graph_action_confirmed);

                /* tengine_stonith_callback() confirms fence actions */
                crm_trace("Updating CIB %s fencer reported fencing of %s complete",
                          (confirmed? "after" : "before"), node->name);

            } else if (!appeared && pcmk__str_eq(task, PCMK_ACTION_DO_SHUTDOWN,
                                                 pcmk__str_casei)) {

                // Shutdown actions are immediately confirmed (i.e. no_wait)
                if (!is_remote) {
                    flags |= node_update_join | node_update_expected;
                    crmd_peer_down(node, FALSE);
                    check_join_state(controld_globals.fsa_state, __func__);
                }
                if (alive >= 0) {
                    crm_info("%s of peer %s is in progress " QB_XS " action=%d",
                             task, node->name, down->id);
                } else {
                    crm_notice("%s of peer %s is complete " QB_XS " action=%d",
                               task, node->name, down->id);
                    pcmk__update_graph(controld_globals.transition_graph, down);
                    trigger_graph();
                }

            } else {
                const char *liveness = "alive";

                if (alive == 0) {
                    liveness = "partially alive";

                } else if (alive < 0) {
                    liveness = "dead";
                }

                crm_trace("Node %s is %s, was expected to %s (op %d)",
                          node->name, liveness, task, down->id);
            }

        } else if (appeared == FALSE) {
            if ((controld_globals.transition_graph == NULL)
                || (controld_globals.transition_graph->id <= 0)) {
                crm_info("Stonith/shutdown of node %s is unknown to the "
                         "current DC", node->name);
            } else {
                crm_warn("Stonith/shutdown of node %s was not expected",
                         node->name);
            }
            if (!is_remote) {
                crm_update_peer_join(__func__, node, controld_join_none);
                check_join_state(controld_globals.fsa_state, __func__);
            }
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Node failure", NULL);
            fail_incompletable_actions(controld_globals.transition_graph,
                                       node->xml_id);

        } else {
            crm_trace("Node %s came up, was not expected to be down",
                      node->name);
        }

        if (is_remote) {
            /* A pacemaker_remote node won't have its cluster status updated
             * in the CIB by membership-layer callbacks, so do it here.
             */
            flags |= node_update_cluster;

            /* Trigger resource placement on newly integrated nodes */
            if (appeared) {
                abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                                 "Pacemaker Remote node integrated", NULL);
            }
        }

        if (!appeared && (type == pcmk__node_update_processes)
            && (node->when_member > 1)) {
            /* The node left CPG but is still a cluster member. Set its
             * membership time to 1 to record it in the cluster state as a
             * boolean, so we don't fence it due to
             * PCMK_OPT_NODE_PENDING_TIMEOUT.
             */
            node->when_member = 1;
            flags |= node_update_cluster;
            controld_node_pending_timer(node);
        }

        /* Update the CIB node state */
        update = create_node_state_update(node, flags, NULL, __func__);
        if (update == NULL) {
            crm_debug("Node state update not yet possible for %s", node->name);
        } else {
            fsa_cib_anon_update(PCMK_XE_STATUS, update);
        }
        pcmk__xml_free(update);
    }

    controld_trigger_fsa();
}

gboolean
crm_fsa_trigger(gpointer user_data)
{
    crm_trace("Invoked (queue len: %d)",
              g_list_length(controld_globals.fsa_message_queue));
    s_crmd_fsa(C_FSA_INTERNAL);
    crm_trace("Exited  (queue len: %d)",
              g_list_length(controld_globals.fsa_message_queue));
    return TRUE;
}
