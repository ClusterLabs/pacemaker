/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <string.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
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
        const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);

        if (pcmk__str_eq(sys_from, CRM_SYSTEM_DC, pcmk__str_casei)) {
            const char *from = crm_element_value(msg, F_ORIG);

            if (!pcmk__str_eq(from, fsa_our_uname, pcmk__str_casei)) {
                int level = LOG_INFO;
                const char *op = crm_element_value(msg, F_CRM_TASK);

                /* make sure the election happens NOW */
                if (fsa_state != S_ELECTION) {
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
        const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);

        if (pcmk__str_eq(sys_to, CRM_SYSTEM_DC, pcmk__str_casei)) {
            return;
        }
    }

    /* crm_log_xml_trace("HA[inbound]", msg); */
    route_message(C_HA_MESSAGE, msg);

  done:
    trigger_fsa();
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
node_alive(const crm_node_t *node)
{
    if (pcmk_is_set(node->flags, crm_remote_node)) {
        // Pacemaker Remote nodes can't be partially alive
        return pcmk__str_eq(node->state, CRM_NODE_MEMBER, pcmk__str_casei) ? 1: -1;

    } else if (crm_is_peer_active(node)) {
        // Completely up cluster node: both cluster member and peer
        return 1;

    } else if (!pcmk_is_set(node->processes, crm_get_cluster_proc())
               && !pcmk__str_eq(node->state, CRM_NODE_MEMBER, pcmk__str_casei)) {
        // Completely down cluster node: neither cluster member nor peer
        return -1;
    }

    // Partially up cluster node: only cluster member or only peer
    return 0;
}

#define state_text(state) ((state)? (const char *)(state) : "in unknown state")

bool controld_dc_left = false;

void
peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    uint32_t old = 0;
    bool appeared = FALSE;
    bool is_remote = pcmk_is_set(node->flags, crm_remote_node);

    /* The controller waits to receive some information from the membership
     * layer before declaring itself operational. If this is being called for a
     * cluster node, indicate that we have it.
     */
    if (!is_remote) {
        controld_set_fsa_input_flags(R_PEER_DATA);
    }

    if (type == crm_status_processes
        && pcmk_is_set(node->processes, crm_get_cluster_proc())
        && !AM_I_DC
        && !is_remote) {
        /*
         * This is a hack until we can send to a nodeid and/or we fix node name lookups
         * These messages are ignored in crmd_ha_msg_filter()
         */
        xmlNode *query = create_request(CRM_OP_HELLO, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

        crm_debug("Sending hello to node %u so that it learns our node name", node->id);
        send_cluster_message(node, crm_msg_crmd, query, FALSE);

        free_xml(query);
    }

    if (node->uname == NULL) {
        return;
    }

    switch (type) {
        case crm_status_uname:
            /* If we've never seen the node, then it also won't be in the status section */
            crm_info("%s node %s is now %s",
                     (is_remote? "Remote" : "Cluster"),
                     node->uname, state_text(node->state));
            return;

        case crm_status_nstate:
            /* This callback should not be called unless the state actually
             * changed, but here's a failsafe just in case.
             */
            CRM_CHECK(!pcmk__str_eq(data, node->state, pcmk__str_casei),
                      return);

            crm_info("%s node %s is now %s (was %s)",
                     (is_remote? "Remote" : "Cluster"),
                     node->uname, state_text(node->state), state_text(data));

            if (pcmk__str_eq(CRM_NODE_MEMBER, node->state, pcmk__str_casei)) {
                appeared = TRUE;
                if (!is_remote) {
                    remove_stonith_cleanup(node->uname);
                }
            } else {
                controld_remove_voter(node->uname);
            }

            crmd_alert_node_event(node);
            break;

        case crm_status_processes:
            CRM_CHECK(data != NULL, return);
            old = *(const uint32_t *)data;
            appeared = pcmk_is_set(node->processes, crm_get_cluster_proc());

            crm_info("Node %s is %s a peer " CRM_XS " DC=%s old=%#07x new=%#07x",
                     node->uname, (appeared? "now" : "no longer"),
                     (AM_I_DC? "true" : (fsa_our_dc? fsa_our_dc : "<none>")),
                     old, node->processes);

            if (!pcmk_is_set((node->processes ^ old), crm_get_cluster_proc())) {
                /* Peer status did not change. This should not be possible,
                 * since we don't track process flags other than peer status.
                 */
                crm_trace("Process flag %#7x did not change from %#7x to %#7x",
                          crm_get_cluster_proc(), old, node->processes);
                return;

            }

            if (!appeared) {
                controld_remove_voter(node->uname);
            }

            if (!pcmk_is_set(fsa_input_register, R_CIB_CONNECTED)) {
                crm_trace("Ignoring peer status change because not connected to CIB");
                return;

            } else if (fsa_state == S_STOPPING) {
                crm_trace("Ignoring peer status change because stopping");
                return;
            }

            if (pcmk__str_eq(node->uname, fsa_our_uname, pcmk__str_casei) && !appeared) {
                /* Did we get evicted? */
                crm_notice("Our peer connection failed");
                register_fsa_input(C_CRMD_STATUS_CALLBACK, I_ERROR, NULL);

            } else if (pcmk__str_eq(node->uname, fsa_our_dc, pcmk__str_casei) && crm_is_peer_active(node) == FALSE) {
                /* Did the DC leave us? */
                crm_notice("Our peer on the DC (%s) is dead", fsa_our_dc);
                register_fsa_input(C_CRMD_STATUS_CALLBACK, I_ELECTION, NULL);

                /* @COMPAT DC < 1.1.13: If a DC shuts down normally, we don't
                 * want to fence it. Newer DCs will send their shutdown request
                 * to all peers, who will update the DC's expected state to
                 * down, thus avoiding fencing. We can safely erase the DC's
                 * transient attributes when it leaves in that case. However,
                 * the only way to avoid fencing older DCs is to leave the
                 * transient attributes intact until it rejoins.
                 */
                if (compare_version(fsa_our_dc_version, "3.0.9") > 0) {
                    controld_delete_node_state(node->uname,
                                               controld_section_attrs,
                                               cib_scope_local);
                }

            } else if (AM_I_DC || controld_dc_left || (fsa_our_dc == NULL)) {
                /* This only needs to be done once, so normally the DC should do
                 * it. However if there is no DC, every node must do it, since
                 * there is no other way to ensure some one node does it.
                 */
                if (appeared) {
                    te_trigger_stonith_history_sync(FALSE);
                } else {
                    controld_delete_node_state(node->uname,
                                               controld_section_attrs,
                                               cib_scope_local);
                }
            }
            break;
    }

    if (AM_I_DC) {
        xmlNode *update = NULL;
        int flags = node_update_peer;
        int alive = node_alive(node);
        crm_action_t *down = match_down_event(node->uuid);

        crm_trace("Alive=%d, appeared=%d, down=%d",
                  alive, appeared, (down? down->id : -1));

        if (appeared && (alive > 0) && !is_remote) {
            register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);
        }

        if (down) {
            const char *task = crm_element_value(down->xml, XML_LRM_ATTR_TASK);

            if (pcmk__str_eq(task, CRM_OP_FENCE, pcmk__str_casei)) {

                /* tengine_stonith_callback() confirms fence actions */
                crm_trace("Updating CIB %s fencer reported fencing of %s complete",
                          (pcmk_is_set(down->flags, pcmk__graph_action_confirmed)? "after" : "before"), node->uname);

            } else if (!appeared && pcmk__str_eq(task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {

                // Shutdown actions are immediately confirmed (i.e. no_wait)
                if (!is_remote) {
                    flags |= node_update_join | node_update_expected;
                    crmd_peer_down(node, FALSE);
                    check_join_state(fsa_state, __func__);
                }
                if (alive >= 0) {
                    crm_info("%s of peer %s is in progress " CRM_XS " action=%d",
                             task, node->uname, down->id);
                } else {
                    crm_notice("%s of peer %s is complete " CRM_XS " action=%d",
                               task, node->uname, down->id);
                    pcmk__update_graph(transition_graph, down);
                    trigger_graph();
                }

            } else {
                crm_trace("Node %s is %s, was expected to %s (op %d)",
                          node->uname,
                          ((alive > 0)? "alive" :
                           ((alive < 0)? "dead" : "partially alive")),
                          task, down->id);
            }

        } else if (appeared == FALSE) {
            crm_warn("Stonith/shutdown of node %s was not expected",
                     node->uname);
            if (!is_remote) {
                crm_update_peer_join(__func__, node, crm_join_none);
                check_join_state(fsa_state, __func__);
            }
            abort_transition(INFINITY, tg_restart, "Node failure", NULL);
            fail_incompletable_actions(transition_graph, node->uuid);

        } else {
            crm_trace("Node %s came up, was not expected to be down",
                      node->uname);
        }

        if (is_remote) {
            /* A pacemaker_remote node won't have its cluster status updated
             * in the CIB by membership-layer callbacks, so do it here.
             */
            flags |= node_update_cluster;

            /* Trigger resource placement on newly integrated nodes */
            if (appeared) {
                abort_transition(INFINITY, tg_restart,
                                 "Pacemaker Remote node integrated", NULL);
            }
        }

        /* Update the CIB node state */
        update = create_node_state_update(node, flags, NULL, __func__);
        if (update == NULL) {
            crm_debug("Node state update not yet possible for %s", node->uname);
        } else {
            fsa_cib_anon_update(XML_CIB_TAG_STATUS, update);
        }
        free_xml(update);
    }

    trigger_fsa();
}

void
crmd_cib_connection_destroy(gpointer user_data)
{
    CRM_CHECK(user_data == fsa_cib_conn,;);

    crm_trace("Invoked");
    trigger_fsa();
    fsa_cib_conn->state = cib_disconnected;

    if (!pcmk_is_set(fsa_input_register, R_CIB_CONNECTED)) {
        crm_info("Connection to the CIB manager terminated");
        return;
    }

    // @TODO This should trigger a reconnect, not a shutdown
    crm_crit("Lost connection to the CIB manager, shutting down");
    register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);
    controld_clear_fsa_input_flags(R_CIB_CONNECTED);

    return;
}

gboolean
crm_fsa_trigger(gpointer user_data)
{
    crm_trace("Invoked (queue len: %d)", g_list_length(fsa_message_queue));
    s_crmd_fsa(C_FSA_INTERNAL);
    crm_trace("Exited  (queue len: %d)", g_list_length(fsa_message_queue));
    return TRUE;
}
