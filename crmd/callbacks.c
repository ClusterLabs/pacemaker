/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <string.h>
#include <crmd_fsa.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/cluster.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>
#include <tengine.h>
#include <membership.h>

void crmd_ha_connection_destroy(gpointer user_data);

/* From join_dc... */
extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

void
crmd_ha_connection_destroy(gpointer user_data)
{
    crm_trace("Invoked");
    if (is_set(fsa_input_register, R_HA_DISCONNECTED)) {
        /* we signed out, so this is expected */
        crm_info("Heartbeat disconnection complete");
        return;
    }

    crm_crit("Lost connection to heartbeat service!");
    register_fsa_input(C_HA_DISCONNECT, I_ERROR, NULL);
    trigger_fsa(fsa_source);
}

void
crmd_ha_msg_filter(xmlNode * msg)
{
    if (AM_I_DC) {
        const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);

        if (safe_str_eq(sys_from, CRM_SYSTEM_DC)) {
            const char *from = crm_element_value(msg, F_ORIG);

            if (safe_str_neq(from, fsa_our_uname)) {
                int level = LOG_INFO;
                const char *op = crm_element_value(msg, F_CRM_TASK);

                /* make sure the election happens NOW */
                if (fsa_state != S_ELECTION) {
                    ha_msg_input_t new_input;

                    level = LOG_WARNING;
                    new_input.msg = msg;
                    register_fsa_error_adv(C_FSA_INTERNAL, I_ELECTION, NULL, &new_input,
                                           __FUNCTION__);
                }

                do_crm_log(level, "Another DC detected: %s (op=%s)", from, op);
                goto done;
            }
        }

    } else {
        const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);

        if (safe_str_eq(sys_to, CRM_SYSTEM_DC)) {
            return;
        }
    }

    /* crm_log_xml_trace("HA[inbound]", msg); */
    route_message(C_HA_MESSAGE, msg);

  done:
    trigger_fsa(fsa_source);
}

#define state_text(state) ((state)? (const char *)(state) : "in unknown state")

void
peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    uint32_t old = 0;
    uint32_t changed = 0;
    bool appeared = FALSE;
    bool is_remote = is_set(node->flags, crm_remote_node);
    const char *status = NULL;

    /* Crmd waits to receive some information from the membership layer before
     * declaring itself operational. If this is being called for a cluster node,
     * indicate that we have it.
     */
    if (!is_remote) {
        set_bit(fsa_input_register, R_PEER_DATA);
    }

    if (node->uname == NULL) {
        return;
    }

    switch (type) {
        case crm_status_uname:
            /* If we've never seen the node, then it also won't be in the status section */
            crm_info("%s is now %s", node->uname, state_text(node->state));
            return;

        case crm_status_rstate:
        case crm_status_nstate:
            /* This callback should not be called unless the state actually
             * changed, but here's a failsafe just in case.
             */
            CRM_CHECK(safe_str_neq(data, node->state), return);

            crm_info("%s node %s is now %s (was %s)",
                     (is_remote? "Remote" : "Cluster"),
                     node->uname, state_text(node->state), state_text(data));

            if (safe_str_eq(CRM_NODE_MEMBER, node->state)) {
                appeared = TRUE;
                if (!is_remote) {
                    remove_stonith_cleanup(node->uname);
                }
            }

            crmd_notify_node_event(node);
            break;

        case crm_status_processes:
            if (data) {
                old = *(const uint32_t *)data;
                changed = node->processes ^ old;
            }

            status = (node->processes & proc_flags) ? ONLINESTATUS : OFFLINESTATUS;
            crm_info("Client %s/%s now has status [%s] (DC=%s, changed=%6x)",
                     node->uname, peer2text(proc_flags), status,
                     AM_I_DC ? "true" : crm_str(fsa_our_dc), changed);

            if ((changed & proc_flags) == 0) {
                /* Peer process did not change */
                crm_trace("No change %6x %6x %6x", old, node->processes, proc_flags);
                return;
            } else if (is_not_set(fsa_input_register, R_CIB_CONNECTED)) {
                crm_trace("Not connected");
                return;
            } else if (fsa_state == S_STOPPING) {
                crm_trace("Stopping");
                return;
            }

            appeared = (node->processes & proc_flags) != 0;
            if (safe_str_eq(node->uname, fsa_our_uname) && (node->processes & proc_flags) == 0) {
                /* Did we get evicted? */
                crm_notice("Our peer connection failed");
                register_fsa_input(C_CRMD_STATUS_CALLBACK, I_ERROR, NULL);

            } else if (safe_str_eq(node->uname, fsa_our_dc) && crm_is_peer_active(node) == FALSE) {
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
                    erase_status_tag(node->uname, XML_TAG_TRANSIENT_NODEATTRS, cib_scope_local);
                }

            } else if(AM_I_DC && appeared == FALSE) {
                crm_info("Peer %s left us", node->uname);
                erase_status_tag(node->uname, XML_TAG_TRANSIENT_NODEATTRS, cib_scope_local);
            }
            break;
    }

    if (AM_I_DC) {
        xmlNode *update = NULL;
        int flags = node_update_peer;
        gboolean alive = is_remote? appeared : crm_is_peer_active(node);
        crm_action_t *down = match_down_event(node->uuid, appeared);

        crm_trace("Alive=%d, appeared=%d, down=%d",
                  alive, appeared, (down? down->id : -1));

        if (alive && type == crm_status_processes) {
            register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);
        }

        if (down) {
            const char *task = crm_element_value(down->xml, XML_LRM_ATTR_TASK);

            if (safe_str_eq(task, CRM_OP_FENCE)) {

                /* tengine_stonith_callback() confirms fence actions */
                crm_trace("Updating CIB %s stonithd reported fencing of %s complete",
                          (down->confirmed? "after" : "before"), node->uname);

            } else if ((alive == FALSE) && safe_str_eq(task, CRM_OP_SHUTDOWN)) {
                crm_notice("%s of peer %s is complete "CRM_XS" op=%d",
                           task, node->uname, down->id);

                /* down->confirmed = TRUE; */
                stop_te_timer(down->timer);

                if (!is_remote) {
                    flags |= node_update_join | node_update_expected;
                    crmd_peer_down(node, FALSE);
                    check_join_state(fsa_state, __FUNCTION__);
                }

                update_graph(transition_graph, down);
                trigger_graph();

            } else {
                crm_trace("Node %s is %salive, was expected to %s (op %d)",
                          node->uname, (alive? "" : "not "), task, down->id);
            }

        } else if (appeared == FALSE) {
            crm_notice("Stonith/shutdown of %s not matched", node->uname);

            if (!is_remote) {
                crm_update_peer_join(__FUNCTION__, node, crm_join_none);
                check_join_state(fsa_state, __FUNCTION__);
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
                                 "pacemaker_remote node integrated", NULL);
            }
        }

        /* Update the CIB node state */
        update = create_node_state_update(node, flags, NULL, __FUNCTION__);
        fsa_cib_anon_update(XML_CIB_TAG_STATUS, update,
                            cib_scope_local | cib_quorum_override | cib_can_create);
        free_xml(update);
    }

    trigger_fsa(fsa_source);
}

void
crmd_cib_connection_destroy(gpointer user_data)
{
    CRM_CHECK(user_data == fsa_cib_conn,;);

    crm_trace("Invoked");
    trigger_fsa(fsa_source);
    fsa_cib_conn->state = cib_disconnected;

    if (is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {
        crm_info("Connection to the CIB terminated...");
        return;
    }

    /* eventually this will trigger a reconnect, not a shutdown */
    crm_err("Connection to the CIB terminated...");
    register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);
    clear_bit(fsa_input_register, R_CIB_CONNECTED);

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
