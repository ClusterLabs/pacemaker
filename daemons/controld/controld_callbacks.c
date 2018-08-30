/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <string.h>
#include <controld_fsa.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/cluster.h>
#include <crm/cib.h>

#include <pacemaker-controld.h>
#include <controld_messages.h>
#include <controld_callbacks.h>
#include <controld_lrm.h>
#include <controld_transition.h>
#include <controld_membership.h>

/* From join_dc... */
extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

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
    if (is_set(node->flags, crm_remote_node)) {
        // Pacemaker Remote nodes can't be partially alive
        return safe_str_eq(node->state, CRM_NODE_MEMBER)? 1: -1;

    } else if (crm_is_peer_active(node)) {
        // Completely up cluster node: both cluster member and peer
        return 1;

    } else if (is_not_set(node->processes, crm_get_cluster_proc())
               && safe_str_neq(node->state, CRM_NODE_MEMBER)) {
        // Completely down cluster node: neither cluster member nor peer
        return -1;
    }

    // Partially up cluster node: only cluster member or only peer
    return 0;
}

#define state_text(state) ((state)? (const char *)(state) : "in unknown state")

void
peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    uint32_t old = 0;
    bool appeared = FALSE;
    bool is_remote = is_set(node->flags, crm_remote_node);

    /* The controller waits to receive some information from the membership
     * layer before declaring itself operational. If this is being called for a
     * cluster node, indicate that we have it.
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
            crm_info("%s node %s is now %s",
                     (is_remote? "Remote" : "Cluster"),
                     node->uname, state_text(node->state));
            return;

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

            crmd_alert_node_event(node);
            break;

        case crm_status_processes:
            CRM_CHECK(data != NULL, return);
            old = *(const uint32_t *)data;
            appeared = is_set(node->processes, crm_get_cluster_proc());

            crm_info("Node %s is %s a peer " CRM_XS " DC=%s old=0x%07x new=0x%07x",
                     node->uname, (appeared? "now" : "no longer"),
                     (AM_I_DC? "true" : (fsa_our_dc? fsa_our_dc : "<none>")),
                     old, node->processes);

            if (is_not_set((node->processes ^ old), crm_get_cluster_proc())) {
                /* Peer status did not change. This should not be possible,
                 * since we don't track process flags other than peer status.
                 */
                crm_trace("Process flag 0x%7x did not change from 0x%7x to 0x%7x",
                          crm_get_cluster_proc(), old, node->processes);
                return;

            } else if (is_not_set(fsa_input_register, R_CIB_CONNECTED)) {
                crm_trace("Ignoring peer status change because not connected to CIB");
                return;

            } else if (fsa_state == S_STOPPING) {
                crm_trace("Ignoring peer status change because stopping");
                return;
            }

            if (safe_str_eq(node->uname, fsa_our_uname) && !appeared) {
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

            } else if(AM_I_DC) {
                if (appeared) {
                    te_trigger_stonith_history_sync();
                } else {
                    erase_status_tag(node->uname, XML_TAG_TRANSIENT_NODEATTRS, cib_scope_local);
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

        if (alive && type == crm_status_processes) {
            register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);
        }

        if (down) {
            const char *task = crm_element_value(down->xml, XML_LRM_ATTR_TASK);

            if (safe_str_eq(task, CRM_OP_FENCE)) {

                /* tengine_stonith_callback() confirms fence actions */
                crm_trace("Updating CIB %s fencer reported fencing of %s complete",
                          (down->confirmed? "after" : "before"), node->uname);

            } else if (!appeared && safe_str_eq(task, CRM_OP_SHUTDOWN)) {

                // Shutdown actions are immediately confirmed (i.e. no_wait)
                if (!is_remote) {
                    flags |= node_update_join | node_update_expected;
                    crmd_peer_down(node, FALSE);
                    check_join_state(fsa_state, __FUNCTION__);
                }
                if (alive >= 0) {
                    crm_info("%s of peer %s is in progress " CRM_XS " action=%d",
                             task, node->uname, down->id);
                } else {
                    crm_notice("%s of peer %s is complete " CRM_XS " action=%d",
                               task, node->uname, down->id);
                    update_graph(transition_graph, down);
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
        if (update == NULL) {
            crm_debug("Node state update not yet possible for %s", node->uname);
        } else {
            fsa_cib_anon_update(XML_CIB_TAG_STATUS, update);
        }
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
        crm_info("Connection to the CIB manager terminated");
        return;
    }

    // @TODO This should trigger a reconnect, not a shutdown
    crm_crit("Lost connection to the CIB manager, shutting down");
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
