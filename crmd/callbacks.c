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
#include <crm/common/msg.h>
#include <crm/common/cluster.h>
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

/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */
gboolean
crmd_ipc_msg_callback(IPC_Channel * client, gpointer user_data)
{
    int lpc = 0;
    xmlNode *msg = NULL;
    crmd_client_t *curr_client = (crmd_client_t *) user_data;
    gboolean stay_connected = TRUE;

    crm_trace("Invoked: %s", curr_client->table_key);

    while (IPC_ISRCONN(client)) {
        if (client->ops->is_message_pending(client) == 0) {
            break;
        }

        msg = xmlfromIPC(client, MAX_IPC_DELAY);
        if (msg == NULL) {
            break;
        }
#if ENABLE_ACL
        determine_request_user(&curr_client->user, client, msg, F_CRM_USER);
#endif

        lpc++;
        crm_trace("Processing msg from %s", curr_client->table_key);
        crm_log_xml_trace(msg, "CRMd[inbound]");

        if (crmd_authorize_message(msg, curr_client)) {
            route_message(C_IPC_MESSAGE, msg);
        }

        free_xml(msg);
        msg = NULL;

        if (client->ch_status != IPC_CONNECT) {
            break;
        }
    }

    crm_trace("Processed %d messages", lpc);

    if (client->ch_status != IPC_CONNECT) {
        stay_connected = FALSE;
        process_client_disconnect(curr_client);
    }

    trigger_fsa(fsa_source);
    return stay_connected;
}

extern GCHSource *lrm_source;

gboolean
lrm_dispatch(IPC_Channel * src_not_used, gpointer user_data)
{
    /* ?? src == lrm_channel ?? */
    ll_lrm_t *lrm = (ll_lrm_t *) user_data;
    IPC_Channel *lrm_channel = lrm->lrm_ops->ipcchan(lrm);

    lrm->lrm_ops->rcvmsg(lrm, FALSE);
    if (lrm_channel->ch_status != IPC_CONNECT) {
        lrm_connection_destroy(NULL);
        return FALSE;
    }
    return TRUE;
}

extern gboolean process_lrm_event(lrm_op_t * op);

void
lrm_op_callback(lrm_op_t * op)
{
    CRM_CHECK(op != NULL, return);
    process_lrm_event(op);
}

static void
crmd_proc_update(crm_node_t * member, enum crm_proc_flag client)
{
    const char *status = NULL;

    CRM_CHECK(member != NULL, return);
    status = (member->processes & client) ? ONLINESTATUS : OFFLINESTATUS;
    crm_notice("Status update: Client %s/%s now has status [%s] (DC=%s)",
               member->uname, peer2text(client), status, AM_I_DC ? "true" : crm_str(fsa_our_dc));

    if (is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {
        return;
    } else if (fsa_state == S_STOPPING) {
        return;
    }

    if (safe_str_eq(member->uname, fsa_our_dc) && crm_is_peer_active(member) == FALSE) {
        /* Did the DC leave us? */
        crm_info("Got client status callback - our DC is dead");
        register_fsa_input(C_CRMD_STATUS_CALLBACK, I_ELECTION, NULL);

    } else if (AM_I_DC) {
        xmlNode *update = NULL;

        update =
            create_node_state(member->uname, NULL, NULL, status, NULL, NULL, FALSE, __FUNCTION__);

        fsa_cib_anon_update(XML_CIB_TAG_STATUS, update,
                            cib_scope_local | cib_quorum_override | cib_can_create);
        free_xml(update);

        if ((member->processes & client) == 0) {
            erase_node_from_join(member->uname);
            check_join_state(fsa_state, __FUNCTION__);
            fail_incompletable_actions(transition_graph, member->uuid);

        } else {
            register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);
        }
    }

    trigger_fsa(fsa_source);
}

void
peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    gboolean reset_status_entry = FALSE;
    uint32_t old = 0;

    set_bit_inplace(fsa_input_register, R_PEER_DATA);
    if (node->uname == NULL) {
        return;
    }

    switch (type) {
        case crm_status_uname:
            crm_info("status: %s is now %s", node->uname, node->state);
            /* reset_status_entry = TRUE; */
            /* If we've never seen the node, then it also wont be in the status section */
            break;
        case crm_status_nstate:
            crm_info("status: %s is now %s (was %s)", node->uname, node->state, (const char *)data);
            reset_status_entry = TRUE;
            break;
        case crm_status_processes:
            if (data) {
                old = *(const uint32_t *)data;
            }

            if ((node->processes ^ old) & proc_flags) {
                crmd_proc_update(node, proc_flags);
            }
            break;
    }

    /* Can this be removed now that do_cl_join_finalize_respond() does the same thing? */
    if (AM_I_DC && reset_status_entry && safe_str_eq(CRMD_STATE_ACTIVE, node->state)) {
        crm_action_t *down = match_down_event(0, node->uname, NULL);

        erase_status_tag(node->uname, XML_CIB_TAG_LRM, cib_scope_local);
        erase_status_tag(node->uname, XML_TAG_TRANSIENT_NODEATTRS, cib_scope_local);
        if (down) {
            const char *task = crm_element_value(down->xml, XML_LRM_ATTR_TASK);

            if (safe_str_eq(task, CRM_OP_FENCE)) {
                crm_info("Node return implies stonith of %s (action %d) completed", node->uname,
                         down->id);
                down->confirmed = TRUE;
            }
        }

        /* TODO: potentially we also want to set XML_CIB_ATTR_JOINSTATE and XML_CIB_ATTR_EXPSTATE here */
    }
}

void
crmd_ipc_connection_destroy(gpointer user_data)
{
    GCHSource *source = NULL;
    crmd_client_t *client = user_data;

/* Calling this function on an _active_ connection results in:
 * crmd_ipc_connection_destroy (callbacks.c:431)
 * -> G_main_del_IPC_Channel (GSource.c:478)
 *  -> g_source_unref
 *   -> G_CH_destroy_int (GSource.c:647)
 *    -> crmd_ipc_connection_destroy (callbacks.c:437)\
 *
 * A better alternative is to call G_main_del_IPC_Channel() directly
 */

    if (client == NULL) {
        crm_trace("No client to delete");
        return;
    }

    crm_trace("Disconnecting client %s (%p)", client->table_key, client);
    source = client->client_source;
    client->client_source = NULL;
    if (source != NULL) {
        crm_trace("Deleting %s (%p) from mainloop", client->table_key, source);
        G_main_del_IPC_Channel(source);
    }
    crm_free(client->table_key);
    crm_free(client->sub_sys);
    crm_free(client->uuid);
    crm_free(client->user);
    crm_free(client);

    return;
}

gboolean
crmd_client_connect(IPC_Channel * client_channel, gpointer user_data)
{
    crm_trace("Invoked");
    if (client_channel == NULL) {
        crm_err("Channel was NULL");

    } else if (client_channel->ch_status == IPC_DISCONNECT) {
        crm_err("Channel was disconnected");

    } else {
        crmd_client_t *blank_client = NULL;

        crm_trace("Channel connected");
        crm_malloc0(blank_client, sizeof(crmd_client_t));
        CRM_ASSERT(blank_client != NULL);

        crm_trace("Created client: %p", blank_client);

        client_channel->ops->set_recv_qlen(client_channel, 1024);
        client_channel->ops->set_send_qlen(client_channel, 1024);

        blank_client->client_channel = client_channel;
        blank_client->sub_sys = NULL;
        blank_client->uuid = NULL;
        blank_client->table_key = NULL;

        blank_client->client_source =
            G_main_add_IPC_Channel(G_PRIORITY_LOW, client_channel,
                                   FALSE, crmd_ipc_msg_callback,
                                   blank_client, crmd_ipc_connection_destroy);
    }

    return TRUE;
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
    clear_bit_inplace(fsa_input_register, R_CIB_CONNECTED);

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
