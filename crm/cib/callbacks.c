/* $Id: callbacks.c,v 1.75 2005/07/11 12:13:07 andrew Exp $ */
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <portability.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/uids.h>
#include <clplumbing/cl_uuid.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ctrl.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <cibio.h>
#include <callbacks.h>
#include <cibmessages.h>
#include <cibprimatives.h>
#include <notify.h>

#include <crm/dmalloc_wrapper.h>

gint cib_GCompareFunc(gconstpointer a, gconstpointer b);
gboolean cib_msg_timeout(gpointer data);
void cib_GHFunc(gpointer key, gpointer value, gpointer user_data);
gboolean ghash_str_clfree(gpointer key, gpointer value, gpointer user_data);
gboolean can_write(int flags);
HA_Message *cib_msg_copy(const HA_Message *msg, gboolean with_data);
gboolean ccm_manual_check(gpointer data);
extern enum cib_errors revision_check(crm_data_t *cib_update, crm_data_t *cib_copy, int flags);
void send_cib_replace(const HA_Message *sync_request, const char *host);
void cib_process_request(const HA_Message *request, gboolean privileged,
			 gboolean from_peer, cib_client_t *cib_client);

gboolean syncd_once = FALSE;

GHashTable *peer_hash = NULL;
int        next_client_id  = 0;
gboolean   cib_is_master   = FALSE;
gboolean   cib_have_quorum = FALSE;
char *     ccm_transition_id = NULL;
GHashTable *client_list    = NULL;
GHashTable *ccm_membership = NULL;
extern const char *cib_our_uname;
extern ll_cluster_t *hb_conn;
extern int set_connected_peers(crm_data_t *xml_obj);

/*
typedef struct cib_operation_s
{
	const char* 	operation;
	gboolean	modifies_cib;
	gboolean	needs_privileges;
	gboolean	needs_quorum;
	gboolean	needs_section;
	gboolean	needs_data;
	enum cib_errors (*fn)(
		const char *, int, const char *,
		crm_data_t*, crm_data_t*, crm_data_t**, crm_data_t**);
} cib_operation_t;
*/
/* technically bump does modify the cib...
 * but we want to split the "bump" from the "sync"
 */
cib_operation_t cib_server_ops[] = {
	{NULL,		   FALSE,FALSE,FALSE,FALSE,FALSE,cib_process_default},
	{CRM_OP_NOOP,	   FALSE,FALSE,FALSE,FALSE,FALSE,cib_process_default},
	{CIB_OP_APPLY_DIFF,TRUE, TRUE, TRUE, TRUE, TRUE, cib_process_diff},
	{CIB_OP_SLAVE,     FALSE,TRUE, FALSE,FALSE,FALSE,cib_process_readwrite},
	{CIB_OP_SLAVEALL,  TRUE, TRUE, FALSE,FALSE,FALSE,cib_process_readwrite},
	{CIB_OP_SYNC_ONE,  FALSE,TRUE, FALSE,TRUE, FALSE,cib_process_sync_one},
	{CIB_OP_MASTER,    FALSE,TRUE, FALSE,FALSE,FALSE,cib_process_readwrite},
	{CIB_OP_ISMASTER,  FALSE,TRUE, FALSE,FALSE,FALSE,cib_process_readwrite},
	{CIB_OP_BUMP,      TRUE, TRUE, TRUE, TRUE, FALSE,cib_process_bump},
	{CIB_OP_REPLACE,   TRUE, TRUE, TRUE, TRUE, TRUE, cib_process_replace},
	{CIB_OP_CREATE,    TRUE, TRUE, TRUE, TRUE, TRUE, cib_process_modify},
	{CIB_OP_UPDATE,    TRUE, TRUE, TRUE, TRUE, TRUE, cib_process_modify},
	{CIB_OP_DELETE,    TRUE, TRUE, TRUE, TRUE, TRUE, cib_process_delete},
	{CIB_OP_DELETE_ALT,TRUE, TRUE, TRUE, TRUE, TRUE, cib_process_modify},
	{CIB_OP_QUERY,     FALSE,FALSE,FALSE,TRUE, FALSE,cib_process_query},
	{CIB_OP_SYNC,      FALSE,TRUE, FALSE,TRUE, FALSE,cib_process_sync},
	{CRM_OP_QUIT,	   FALSE,TRUE, FALSE,FALSE,FALSE,cib_process_quit},
	{CRM_OP_PING,	   FALSE,FALSE,FALSE,FALSE,FALSE,cib_process_ping},
	{CIB_OP_ERASE,     TRUE, TRUE, TRUE, TRUE, FALSE,cib_process_erase}
};

int send_via_callback_channel(HA_Message *msg, const char *token);

enum cib_errors cib_process_command(
	const HA_Message *request, HA_Message **reply,
	crm_data_t **cib_diff, gboolean privileged);

gboolean cib_common_callback(
	IPC_Channel *channel, gpointer user_data, gboolean privileged);

enum cib_errors cib_get_operation_id(const HA_Message * msg, int *operation);

gboolean cib_process_disconnect(IPC_Channel *channel, cib_client_t *cib_client);

gboolean
cib_client_connect(IPC_Channel *channel, gpointer user_data)
{
	gboolean auth_failed = FALSE;
	gboolean can_connect = TRUE;
	gboolean (*client_callback)(IPC_Channel *channel, gpointer user_data) = NULL;

	cib_client_t *new_client = NULL;
	crm_debug_3("Connecting channel");

	if (channel == NULL) {
		crm_err("Channel was NULL");
		can_connect = FALSE;
		
	} else if (channel->ch_status == IPC_DISCONNECT) {
		crm_err("Channel was disconnected");
		can_connect = FALSE;
		
	} else if(user_data == NULL) {
		crm_err("user_data must contain channel name");
		can_connect = FALSE;
		
	} else {
		crm_malloc0(new_client, sizeof(cib_client_t));
		new_client->id          = NULL;
		new_client->callback_id = NULL;
		new_client->source      = NULL;
		new_client->channel     = channel;
		new_client->channel_name = user_data;
		new_client->delegated_calls = NULL;

		crm_debug_3("Created channel %p for channel %s",
			  new_client, new_client->channel_name);
		
		client_callback = NULL;
		
		/* choose callback and do auth based on channel_name */
		if(safe_str_eq(new_client->channel_name, cib_channel_callback)) {
			client_callback = cib_null_callback;

		} else {
			cl_uuid_t client_id;

			cl_uuid_generate(&client_id);
			crm_malloc0(new_client->id, sizeof(char)*36);
			cl_uuid_unparse(&client_id, new_client->id);
			new_client->id[35] = EOS;
			
			cl_uuid_generate(&client_id);
			crm_malloc0(new_client->callback_id, sizeof(char)*36);
			cl_uuid_unparse(&client_id, new_client->callback_id);
			new_client->callback_id[35] = EOS;
			
			client_callback = cib_ro_callback;
			if(safe_str_eq(new_client->channel_name, cib_channel_rw)) {
				client_callback = cib_rw_callback;
			} 
		}
	}

	if(auth_failed) {
		crm_err("Connection to %s channel failed authentication",
			(char *)user_data);
		can_connect = FALSE;
	}

	if(can_connect == FALSE) {
		if(new_client) {
			crm_free(new_client->id);
			crm_free(new_client->callback_id);
		}
		crm_free(new_client);
		return FALSE;
	}

	
	channel->ops->set_recv_qlen(channel, 100);
	if(safe_str_eq(new_client->channel_name, cib_channel_callback)) {
		channel->ops->set_send_qlen(channel, 400);
	} else {
		channel->ops->set_send_qlen(channel, 100);
	}
		
	if(client_callback != NULL) {
		new_client->source = G_main_add_IPC_Channel(
			G_PRIORITY_LOW, channel, FALSE, client_callback,
			new_client, default_ipc_connection_destroy);
	}
	if(client_callback != cib_null_callback) {
		/* send msg to client with uuid to use when signing up for
		 * callback channel
		 */

		HA_Message *reg_msg = ha_msg_new(3);
		ha_msg_add(reg_msg, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(reg_msg, F_CIB_CLIENTID,  new_client->id);
		ha_msg_add(
			reg_msg, F_CIB_CALLBACK_TOKEN, new_client->callback_id);
		
		send_ipc_message(channel, reg_msg);
		
		/* make sure we can find ourselves later for sync calls
		 * redirected to the master instance
		 */
		g_hash_table_insert(client_list, new_client->id, new_client);
	}

	crm_debug_3("Channel %s connected for client %s",
		  new_client->channel_name, new_client->id);
	
	return TRUE;
}

gboolean
cib_rw_callback(IPC_Channel *channel, gpointer user_data)
{
	return cib_common_callback(channel, user_data, TRUE);
}

gboolean
cib_ro_callback(IPC_Channel *channel, gpointer user_data)
{
	return cib_common_callback(channel, user_data, FALSE);
}

gboolean
cib_null_callback(IPC_Channel *channel, gpointer user_data)
{
	gboolean did_disconnect = TRUE;
	HA_Message *op_request = NULL;
	cib_client_t *cib_client = user_data;
	cib_client_t *hash_client = NULL;
	const char *type = NULL;
	const char *uuid_ticket = NULL;
	const char *client_name = NULL;
	gboolean register_failed = FALSE;

	if(cib_client == NULL) {
		crm_err("Discarding IPC message from unknown source"
			" on callback channel.");
		return FALSE;
	}
	
	while(channel->ops->is_message_pending(channel)) {
		if (channel->ch_status != IPC_CONNECT) {
			/* The message which was pending for us is that
			 * the channel is no longer fully connected.
			 *
			 * Dont read requests from disconnected clients
			 */
			break;
		}
		op_request = msgfromIPC_noauth(channel);

		type = cl_get_string(op_request, F_CIB_OPERATION);
		if(safe_str_eq(type, T_CIB_NOTIFY) ) {
			/* Update the notify filters for this client */
			int on_off = 0;
			ha_msg_value_int(
				op_request, F_CIB_NOTIFY_ACTIVATE, &on_off);
			type = cl_get_string(op_request, F_CIB_NOTIFY_TYPE);

			if(safe_str_eq(type, T_CIB_POST_NOTIFY)) {
				cib_client->post_notify = on_off;
				
			} else if(safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
				cib_client->pre_notify = on_off;

			} else if(safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
				cib_client->confirmations = on_off;

			} else if(safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
				cib_client->diffs = on_off;

			}
			continue;
			
		} else if(safe_str_neq(type, CRM_OP_REGISTER) ) {
			crm_warn("Discarding IPC message from %s on callback channel",
				 cib_client->id);
			crm_msg_del(op_request);
			continue;
		}

		uuid_ticket = cl_get_string(op_request, F_CIB_CALLBACK_TOKEN);
		client_name = cl_get_string(op_request, F_CIB_CLIENTNAME);

		CRM_DEV_ASSERT(uuid_ticket != NULL);
		if(crm_assert_failed) {
			register_failed = crm_assert_failed;
		}
		
		CRM_DEV_ASSERT(client_name != NULL);
		if(crm_assert_failed) {
			register_failed = crm_assert_failed;
		}

		if(register_failed == FALSE) {
			hash_client = g_hash_table_lookup(client_list, uuid_ticket);
			if(hash_client != NULL) {
				crm_err("Duplicate registration request..."
					" disconnecting");
				register_failed = TRUE;
			}
		}
		
		if(register_failed) {
			crm_err("Registration request failed... disconnecting");
			crm_msg_del(op_request);
			return FALSE;
		}

		cib_client->id   = crm_strdup(uuid_ticket);
		cib_client->name = crm_strdup(client_name);

		g_hash_table_insert(client_list, cib_client->id, cib_client);
		crm_debug_2("Registered %s on %s channel",
			    cib_client->id, cib_client->channel_name);

		crm_msg_del(op_request);

		op_request = ha_msg_new(2);
		ha_msg_add(op_request, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(op_request, F_CIB_CLIENTID,  cib_client->id);
		
		send_ipc_message(channel, op_request);
	}
	did_disconnect = cib_process_disconnect(channel, cib_client);	
	if(did_disconnect) {
		crm_debug_2("Client disconnected");
	}
	
	return did_disconnect;
}

gboolean
cib_common_callback(
	IPC_Channel *channel, gpointer user_data, gboolean privileged)
{
	int rc = cib_ok;
	int lpc = 0;

	HA_Message *op_request = NULL;
	cib_client_t *cib_client = user_data;

	if(cib_client == NULL) {
		crm_err("Receieved call from unknown source. Discarding.");
		return FALSE;
	}
	
	crm_debug_2("Callback for %s on %s channel",
		    cib_client->id, cib_client->channel_name);

	while(channel->ops->is_message_pending(channel)) {
		if (channel->ch_status != IPC_CONNECT) {
			/* The message which was pending for us is that
			 * the channel is no longer fully connected.
			 *
			 * Dont read requests from disconnected clients
			 */
			break;
		}
		op_request = msgfromIPC(channel, 0);
		if (op_request == NULL) {
			perror("Receive failure:");
			break;
		}

		crm_debug_2("Processing IPC message from %s on %s channel",
			    cib_client->id, cib_client->channel_name);
		crm_log_message_adv(LOG_MSG, "Client[inbound]", op_request);
		
		lpc++;
		rc = cib_ok;
		
		CRM_DEV_ASSERT(
			ha_msg_add(op_request, F_CIB_CLIENTID, cib_client->id) == HA_OK);

		if(crm_assert_failed == FALSE) {
			cib_process_request(
				op_request, privileged, FALSE, cib_client);
		}
		
		crm_debug_3("Cleaning up request");
		crm_msg_del(op_request);
		op_request = NULL;
	}

	crm_debug_2("Processed %d messages", lpc);

	return cib_process_disconnect(channel, cib_client);
}

void
cib_process_request(const HA_Message *request, gboolean privileged,
		    gboolean from_peer, cib_client_t *cib_client) 
{
	int call_type    = 0;
	int call_options = 0;

	gboolean process = TRUE;		
	gboolean needs_reply = TRUE;
	gboolean local_notify = FALSE;
	gboolean needs_forward = FALSE;
	crm_data_t *result_diff = NULL;
	
	enum cib_errors rc = cib_ok;
	HA_Message *op_reply = NULL;
	
	const char *op         = cl_get_string(request, F_CIB_OPERATION);
	const char *originator = cl_get_string(request, F_ORIG);
	const char *host       = cl_get_string(request, F_CIB_HOST);
	const char *reply_to   = cl_get_string(request, F_CIB_ISREPLY);
	const char *update     = cl_get_string(request, F_CIB_GLOBAL_UPDATE);
	const char *delegated  = cl_get_string(request, F_CIB_DELEGATED);
	const char *client_id  = NULL;

	crm_debug_4("%s Processing msg %s",
		  cib_our_uname, cl_get_string(request, F_SEQ));

	if(host != NULL && strlen(host) == 0) {
		host = NULL;
	}
	
	ha_msg_value_int(request, F_CIB_CALLOPTS, &call_options);
	crm_debug_4("Retrieved call options: %d", call_options);
	
	crm_debug_2("Processing %s message (%s) to %s...",
		    from_peer?"peer":"local",originator, host?host:"master");

	rc = cib_get_operation_id(request, &call_type);
	
	if(rc != cib_ok) {
		/* TODO: construct error reply */
		crm_err("Pre-processing of command failed: %s",
			cib_error2string(rc));
		
	} else if(from_peer == FALSE) {

		if(cib_server_ops[call_type].modifies_cib
		   && !(call_options & cib_inhibit_bcast)) {
			/* we need to send an update anyway */
			needs_reply = TRUE;
		} else {
			needs_reply = FALSE;
		}
		
		if(host == NULL && (call_options & cib_scope_local)) {
			crm_debug("Processing locally scoped %s op from %s",
				  op, cib_client->name);
			local_notify = TRUE;

		} else if(host == NULL && cib_is_master) {
			crm_debug("Processing master %s op locally from %s",
				  op, cib_client->name);
			local_notify = TRUE;

		} else if(safe_str_eq(host, cib_our_uname)) {
			crm_debug("Processing locally addressed %s op from %s",
				  op, cib_client->name);
			local_notify = TRUE;
		} else {
			crm_debug("%s op from %s needs to be forwarded to %s",
				  op, cib_client->name,
				  host?host:"the master instance");
			needs_forward = TRUE;
			process = FALSE;
		}
		
	} else if(crm_is_true(update) && safe_str_eq(reply_to, cib_our_uname)) {
		crm_debug("Processing global/peer update from %s"
			  " that originated from us", originator);
		needs_reply = FALSE;
		local_notify = TRUE;
		
	} else if(crm_is_true(update)) {
		crm_debug("Processing global/peer update from %s", originator);
		needs_reply = FALSE;

	} else if(host != NULL && safe_str_eq(host, cib_our_uname)) {
		crm_debug("Processing request sent to us from %s", originator);

	} else if(delegated != NULL && cib_is_master == TRUE) {
		crm_debug("Processing request sent to master instance from %s",
			originator);

	} else if(reply_to != NULL && safe_str_eq(reply_to, cib_our_uname)) {
		crm_debug("Forward reply sent from %s to local clients",
			  originator);
		process = FALSE;
		needs_reply = FALSE;
		local_notify = TRUE;

	} else if(delegated != NULL) {
		crm_debug_2("Ignoring msg for master instance");
		return;

	} else if(host != NULL) {
		/* this is for a specific instance and we're not it */
		crm_debug_2("Ignoring msg for instance on %s", crm_str(host));
		return;
		
	} else if(reply_to == NULL && cib_is_master == FALSE) {
		/* this is for the master instance and we're not it */
		crm_debug_2("Ignoring reply to %s", crm_str(reply_to));
		return;
		
	} else {
		crm_err("Nothing for us to do?");
		crm_log_message_adv(LOG_ERR, "Peer[inbound]", request);
		return;
	}
	crm_debug_3("Finished determining processing actions");

	if(call_options & cib_discard_reply) {
		needs_reply = cib_server_ops[call_type].modifies_cib;
		local_notify = FALSE;
	}
	
	if(needs_forward) {
		HA_Message *forward_msg = cib_msg_copy(request, TRUE);
		ha_msg_add(forward_msg, F_CIB_DELEGATED, cib_our_uname);
		crm_log_message(LOG_MSG, forward_msg);
		
		if(host != NULL) {
			crm_debug("Forwarding %s op to %s", op, host);
			send_ha_message(hb_conn, forward_msg, host, FALSE);
			
		} else {
			crm_debug("Forwarding %s op to master instance", op);
			send_ha_message(hb_conn, forward_msg, NULL, FALSE);
		}
		
		if(call_options & cib_discard_reply) {
			crm_debug_2("Client not interested in reply");
			crm_msg_del(forward_msg);
			
		} else if(call_options & cib_sync_call) {
			/* keep track of the request so we can time it
			 * out if required
			 */
			crm_debug("Registering delegated call from %s",
				  cib_client->id);
			cib_client->delegated_calls = g_list_append(
				cib_client->delegated_calls, forward_msg);
		} else {
			crm_msg_del(forward_msg);
		}
		return;
	}

	if(process) {
		crm_debug_3("Performing local processing:"
			    " op=%s origin=%s/%s,%s (update=%s)",
			    cl_get_string(request, F_CIB_OPERATION), originator,
			    cl_get_string(request, F_CIB_CLIENTID),
			    cl_get_string(request, F_CIB_CALLID), update);
		
		rc = cib_process_command(request, &op_reply, &result_diff, TRUE);
		crm_debug_3("Processing complete");

		if(rc == cib_diff_resync || rc == cib_diff_failed
		   || rc == cib_old_data) {
			crm_warn("%s operation failed: %s",
				crm_str(op), cib_error2string(rc));
			
		} else if(rc != cib_ok) {
			crm_err("%s operation failed: %s",
				crm_str(op), cib_error2string(rc));
			crm_log_message_adv(LOG_DEBUG, "CIB[output]", op_reply);
			crm_debug("Input message");
			crm_log_message(LOG_DEBUG, request);
		}
		

		if(op_reply == NULL && (needs_reply || local_notify)) {
			crm_err("Unexpected NULL reply to message");
			crm_log_message(LOG_ERR, request);
			needs_reply = FALSE;
			local_notify = FALSE;
		}
			
	}

	crm_debug_3("processing response cases");

	if(local_notify) {
		/* send callback to originating child */
		cib_client_t *client_obj = NULL;
		HA_Message *client_reply = NULL;
		enum cib_errors local_rc = cib_ok;
		crm_debug_4("find the client");

		if(process == FALSE) {
			client_reply = cib_msg_copy(request, TRUE);
		} else {
			client_reply = cib_msg_copy(op_reply, TRUE);
		}
		
		client_id = cl_get_string(request, F_CIB_CLIENTID);
		if(client_id != NULL) {
			client_obj = g_hash_table_lookup(
				client_list, client_id);
		} else {
			crm_debug("No client to sent the response to."
				  "  F_CIB_CLIENTID not set.");
		}
		
		crm_debug_3("Sending callback to request originator");
		if(client_obj != NULL) {
			crm_debug_2("Sending %ssync response to %s %s",
				  (call_options & cib_sync_call)?"":"an a-",
				  client_obj->id,
				  from_peer?"(originator of delegated request)":"");

			if(call_options & cib_sync_call) {
				send_via_callback_channel(
					client_reply, client_obj->id);

			} else {
				send_via_callback_channel(
					client_reply, client_obj->callback_id);
			}
			
		} else {
			crm_warn("Client %s may have left us",
				 crm_str(client_id));
			crm_msg_del(client_reply);
		}
		if(local_rc != cib_ok) {
			crm_warn("%sSync reply failed: %s",
				 (call_options & cib_sync_call)?"":"A-",
				 cib_error2string(local_rc));
			crm_log_message(LOG_DEBUG, op_reply);
		}
	}

	if(needs_reply == FALSE) {
		/* nothing more to do...
		 * this was a non-originating slave update
		 */
		crm_debug_3("Completed slave update");
		crm_msg_del(op_reply);
		free_xml(result_diff);
		return;
	}
	
	crm_debug_4("add the originator to message");

	CRM_DEV_ASSERT(op_reply != NULL);
	CRM_DEV_ASSERT(cib_server_ops[call_type].modifies_cib == FALSE
		       || result_diff != NULL || rc != cib_ok);
	
	/* from now on we are the server */ 
	if(rc == cib_ok
	   && result_diff != NULL
	   && cib_server_ops[call_type].modifies_cib
	   && !(call_options & cib_inhibit_bcast)) {
		/* this (successful) call modified the CIB _and_ the
		 * change needs to be broadcast...
		 *   send via HA to other nodes
		 */
		HA_Message *op_bcast = cib_msg_copy(request, FALSE);
		int diff_add_updates = 0;
		int diff_add_epoche  = 0;
		int diff_add_admin_epoche = 0;
		
		int diff_del_updates = 0;
		int diff_del_epoche  = 0;
		int diff_del_admin_epoche = 0;
		
		cib_diff_version_details(
			result_diff,
			&diff_add_admin_epoche, &diff_add_epoche, &diff_add_updates, 
			&diff_del_admin_epoche, &diff_del_epoche, &diff_del_updates);

		crm_debug("Sending update diff %d.%d.%d -> %d.%d.%d",
			diff_del_admin_epoche,diff_del_epoche,diff_del_updates,
			diff_add_admin_epoche,diff_add_epoche,diff_add_updates);

		ha_msg_add(op_bcast, F_CIB_ISREPLY, originator);
		ha_msg_add(op_bcast, F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
		ha_msg_mod(op_bcast, F_CIB_OPERATION, CIB_OP_APPLY_DIFF);

		add_message_xml(op_bcast, F_CIB_UPDATE_DIFF, result_diff);
		crm_log_message(LOG_DEBUG_3, op_bcast);
		send_ha_message(hb_conn, op_bcast, NULL, TRUE);
		crm_msg_del(op_bcast);
		
	} else if((call_options & cib_discard_reply) == 0) {
		if(from_peer && originator != NULL) {
			/* send reply via HA to originating node */
			crm_debug("Sending request result to originator only");
			ha_msg_add(op_reply, F_CIB_ISREPLY, originator);
			send_ha_message(hb_conn, op_reply, originator, FALSE);
		}
		if(call_options & cib_inhibit_bcast ) {
			crm_debug("Request not broadcast: inhibited");
		}
		if(cib_server_ops[call_type].modifies_cib == FALSE) {
			crm_debug_2("Request not broadcast: R/O call");
		}
		if(rc != cib_ok) {
			crm_warn("Request not broadcast: call failed: %s",
				 cib_error2string(rc));
		}
	}
	
	crm_msg_del(op_reply);
	free_xml(result_diff);

	return;	
}

enum cib_errors
cib_process_command(const HA_Message *request, HA_Message **reply,
		    crm_data_t **cib_diff, gboolean privileged)
{
	crm_data_t *output   = NULL;
	crm_data_t *input    = NULL;
	crm_data_t *input_fragment = NULL;

	crm_data_t *current_cib = the_cib;
	crm_data_t *result_cib  = NULL;
	crm_data_t *local_diff  = NULL;
	
	int call_type      = 0;
	int call_options   = 0;
	enum cib_errors rc = cib_ok;

	const char *op = NULL;
	const char *call_id = NULL;
	const char *section = NULL;
	const char *tmp = NULL;
	gboolean global_update = crm_is_true(
		cl_get_string(request, F_CIB_GLOBAL_UPDATE));

	CRM_DEV_ASSERT(reply != NULL);
	if(reply) { *reply = NULL; }
	
	/* Start processing the request... */
	op = cl_get_string(request, F_CIB_OPERATION);
	call_id = cl_get_string(request, F_CIB_CALLID);
	ha_msg_value_int(request, F_CIB_CALLOPTS, &call_options);

	crm_debug_4("Processing call id: %s", call_id);
	
	rc = cib_get_operation_id(request, &call_type);
	
	if(rc == cib_ok &&
	   cib_server_ops[call_type].needs_privileges
	   && privileged == FALSE) {
		/* abort */
		rc = cib_not_authorized;
	}
	
	if(rc == cib_ok
	   && global_update == FALSE
	   && cib_server_ops[call_type].needs_quorum
	   && can_write(call_options) == FALSE) {
		rc = cib_no_quorum;
	}

	/* prevent NUMUPDATES from being incrimented - apply the change as-is */
	if(global_update) {
		call_options |= cib_inhibit_bcast;
	}
	
	if(rc == cib_ok && cib_server_ops[call_type].needs_section) {
		section = cl_get_string(request, F_CIB_SECTION);
	}

	if(rc == cib_ok && safe_str_eq(op, CIB_OP_APPLY_DIFF)) {
		crm_debug_4("Unpacking diff data in %s", F_CIB_UPDATE_DIFF);
		input_fragment = get_message_xml(request, F_CIB_UPDATE_DIFF);
		if(global_update) {
			call_options |= cib_force_diff;
		} else {
			do_id_check(input_fragment);
		}
		
	} else if(rc == cib_ok && safe_str_eq(op, CIB_OP_SYNC)) {
 		input_fragment = ha_msg_copy(request);
		
	} else if(rc == cib_ok && safe_str_eq(op, CIB_OP_SYNC_ONE)) {
 		input_fragment = ha_msg_copy(request);
		
	} else if(rc == cib_ok && cib_server_ops[call_type].needs_data) {
		crm_debug_4("Unpacking data in %s", F_CIB_CALLDATA);
		input_fragment = get_message_xml(request, F_CIB_CALLDATA);
	}

	/* extract the CIB from the fragment */
	if(input_fragment != NULL
	   && safe_str_eq(crm_element_name(input_fragment), XML_TAG_FRAGMENT)) {
		input = find_xml_node(input_fragment, XML_TAG_CIB, TRUE);
		
	} else {
		input = input_fragment;
	}

	/* grab the section specified for the command */
	if(input != NULL && safe_str_eq(crm_element_name(input), XML_TAG_CIB)){
		rc = revision_check(input, current_cib, call_options);
		if(rc == cib_ok) {
			input = get_object_root(section, input);
			do_id_check(input);
		}
	}
	
	if(cib_server_ops[call_type].modifies_cib) {
		cib_pre_notify(
			call_options, op,
			get_object_root(section, current_cib), input);
	}

	if(rc == cib_ok) {
		rc = cib_server_ops[call_type].fn(
			op, call_options, section, input,
			current_cib, &result_cib, &output);
	}
	
	if(cib_server_ops[call_type].modifies_cib) {
		if(safe_str_eq(op, CIB_OP_APPLY_DIFF)) {
			local_diff = copy_xml(input);

		} else if(result_cib != NULL && current_cib != result_cib) {
			local_diff = diff_cib_object(
				current_cib, result_cib, FALSE);
		}
		if(rc != cib_ok) {
			free_xml(result_cib);

		} else if(activateCibXml(result_cib,CIB_FILENAME) < 0){
			crm_warn("Activation failed");
			rc = cib_ACTIVATION;
		}
		cib_post_notify(call_options, op, input, rc, the_cib);
		cib_diff_notify(call_options, op, input, rc, local_diff);

	} else if(result_cib != NULL) {
		crm_err("%s call modified the CIB", op);
		free_xml(result_cib);
	}
	
	
	crm_debug_4("Processing reply cases");
	if((call_options & cib_discard_reply)
	   && cib_server_ops[call_type].modifies_cib == FALSE) {
		crm_debug_3("No reply needed for call %s", call_id);
		return rc;
		
	} else if(reply == NULL) {
		crm_debug("No reply possible for call %s", call_id);
		return rc;
	}

	crm_debug_4("Creating a basic reply");
	*reply = ha_msg_new(8);
	ha_msg_add(*reply, F_TYPE, T_CIB);
	ha_msg_add(*reply, F_CIB_OPERATION, op);
	ha_msg_add(*reply, F_CIB_CALLID, call_id);
	ha_msg_add_int(*reply, F_CIB_RC, rc);

	tmp = cl_get_string(request, F_CIB_CLIENTID);
	ha_msg_add(*reply, F_CIB_CLIENTID, tmp);
	
	tmp = cl_get_string(request, F_CIB_CALLOPTS);
	ha_msg_add(*reply, F_CIB_CALLOPTS, tmp);
	
	crm_debug_4("Attaching output if necessary");
	if(output != NULL) {
		add_message_xml(*reply, F_CIB_CALLDATA, output);
	} else {
		crm_debug_3("No output for call %s", call_id);
	}
	

	crm_debug_4("Cleaning up");
	if(cib_diff != NULL) {
		*cib_diff = local_diff;
	} else {
		free_xml(local_diff);
	}
	free_xml(output);
	free_xml(input_fragment);
	return rc;
}

int
send_via_callback_channel(HA_Message *msg, const char *token) 
{
	cib_client_t *hash_client = NULL;
	GList *list_item = NULL;
	enum cib_errors rc = cib_ok;
	
	crm_debug_3("Delivering msg %p to client %s", msg, token);

	if(token == NULL) {
		crm_err("No client id token, cant send message");
		if(rc == cib_ok) {
			rc = cib_missing;
		}
		
	} else {
		/* A client that left before we could reply is not really
		 * _our_ error.  Warn instead.
		 */
		hash_client = g_hash_table_lookup(client_list, token);
		if(hash_client == NULL) {
			crm_warn("Cannot find client for token %s", token);
			rc = cib_client_gone;
			
		} else if(hash_client->channel == NULL) {
			crm_err("Cannot find channel for client %s", token);
			rc = cib_client_corrupt;

		} else if(hash_client->channel->ops->get_chan_status(
				  hash_client->channel) != IPC_CONNECT) {
			crm_warn("Client %s has disconnected", token);
			rc = cib_client_gone;
		}
	}

	/* this is a more important error so overwriting rc is warrented */
	if(msg == NULL) {
		crm_err("No message to send");
		rc = cib_reply_failed;
	}

	if(rc == cib_ok) {
		list_item = g_list_find_custom(
			hash_client->delegated_calls, msg, cib_GCompareFunc);
	}
	
	if(list_item != NULL) {
		/* remove it - no need to time it out */
		HA_Message *orig_msg = list_item->data;
		crm_debug_3("Removing msg from delegated list");
		hash_client->delegated_calls = g_list_remove(
			hash_client->delegated_calls, orig_msg);
		CRM_DEV_ASSERT(orig_msg != msg);
		crm_msg_del(orig_msg);
	}
	
	if(rc == cib_ok) {
		crm_debug_3("Delivering reply to client %s", token);
		if(send_ipc_message(hash_client->channel, msg) == FALSE) {
			crm_warn("Delivery of reply to client %s/%s failed",
				hash_client->name, token);
			rc = cib_reply_failed;
		}

	} else {
		/* be consistent...
		 * send_ipc_message() will free the message, so we should do
		 *  so manually if we dont try to send it.
		 */
		crm_msg_del(msg);
	}
	
	return rc;
}

gint cib_GCompareFunc(gconstpointer a, gconstpointer b)
{
	const HA_Message *a_msg = a;
	const HA_Message *b_msg = b;

	int msg_a_id = 0;
	int msg_b_id = 0;
	
	ha_msg_value_int(a_msg, F_CIB_CALLID, &msg_a_id);
	ha_msg_value_int(b_msg, F_CIB_CALLID, &msg_b_id);
	
	if(msg_a_id == msg_b_id) {
		return 0;
	} else if(msg_a_id < msg_b_id) {
		return -1;
	}
	return 1;
}


gboolean
cib_msg_timeout(gpointer data)
{
	crm_debug_4("Checking if any clients have timed out messages");
	g_hash_table_foreach(client_list, cib_GHFunc, NULL);
	return TRUE;
}


void
cib_GHFunc(gpointer key, gpointer value, gpointer user_data)
{
	cib_client_t *client = value;

	GListPtr list = client->delegated_calls;
	HA_Message *msg = NULL;


	while(list != NULL) {
		int seen = 0;
		int timeout = 5; /* 1 iteration == 1 seconds */
		HA_Message *reply = NULL;
		const char *host_to = NULL;
		
		msg = list->data;
		ha_msg_value_int(msg, F_CIB_SEENCOUNT, &seen);
		ha_msg_value_int(msg, F_CIB_TIMEOUT, &timeout);
		host_to = cl_get_string(msg, F_CIB_HOST);
		
		crm_debug_4("Timeout %d, seen %d", timeout, seen);
		if(timeout > 0 && seen < timeout) {
			int seen2 = 0;
			crm_debug_4("Updating seen count for msg from client %s",
				  client->id);
			seen++;
			ha_msg_mod_int(msg, F_CIB_SEENCOUNT, seen);
			ha_msg_value_int(msg, F_CIB_SEENCOUNT, &seen2);
			list = list->next;
			continue;
		}
		
		crm_warn("Sending operation timeout msg to client %s",
			 client->id);
		
		reply = ha_msg_new(4);
		ha_msg_add(reply, F_TYPE, T_CIB);
		ha_msg_add(reply, F_CIB_OPERATION,
			   cl_get_string(msg, F_CIB_OPERATION));
		ha_msg_add(reply, F_CIB_CALLID,
			   cl_get_string(msg, F_CIB_CALLID));
		if(host_to == NULL) {
			ha_msg_add_int(reply, F_CIB_RC, cib_master_timeout);
		} else {
			ha_msg_add_int(reply, F_CIB_RC, cib_remote_timeout);
		}
		
		send_ipc_message(client->channel, reply);

		list = list->next;
		client->delegated_calls = g_list_remove(
			client->delegated_calls, msg);

		crm_msg_del(msg);
	}
}


gboolean
cib_process_disconnect(IPC_Channel *channel, cib_client_t *cib_client)
{
	if (channel->ch_status != IPC_CONNECT && cib_client != NULL) {
		crm_info("Cleaning up after %s channel disconnect from client (%p) %s/%s",
			 cib_client->channel_name, cib_client,
			 crm_str(cib_client->id), crm_str(cib_client->name));

		if(cib_client->id != NULL) {
			g_hash_table_remove(client_list, cib_client->id);
		}
		if(cib_client->source != NULL) {
			crm_debug_3("deleting the IPC Channel");
 			G_main_del_IPC_Channel(cib_client->source);
			cib_client->source = NULL;
		}
		
		crm_debug_3("Freeing the cib client %s", crm_str(cib_client->id));
#if 0
		/* todo - put this back in once i recheck its safe */
 		crm_free(cib_client->callback_id);
  		crm_free(cib_client->name);
  		crm_free(cib_client->id);
#endif
  		crm_free(cib_client);
		crm_debug_3("Freed the cib client");

		return FALSE;

	} else if (channel->ch_status != IPC_CONNECT) {
		crm_warn("Unknown client disconnected");
		return FALSE;
	}

	return TRUE;
}


gboolean
cib_ha_dispatch(IPC_Channel *channel, gpointer user_data)
{
	int lpc = 0;
	ll_cluster_t *hb_cluster = (ll_cluster_t*)user_data;

	while(lpc < 2 && hb_cluster->llc_ops->msgready(hb_cluster)) {
 		lpc++; 
		/* invoke the callbacks but dont block */
		hb_cluster->llc_ops->rcvmsg(hb_cluster, 0);
	}

	crm_debug_4("%d HA messages dispatched", lpc);

	if (channel && (channel->ch_status != IPC_CONNECT)) {
		crm_crit("Lost connection to heartbeat service... exiting");
		exit(100);
		return FALSE;
	}
	return TRUE;
}

void
cib_peer_callback(const HA_Message * msg, void* private_data)
{
	int call_type = 0;
	const char *originator = cl_get_string(msg, F_ORIG);

	if(originator == NULL || safe_str_eq(originator, cib_our_uname)) {
 		crm_debug_3("Discarding message %s/%s from ourselves",
			  cl_get_string(msg, F_CIB_CLIENTID), 
			  cl_get_string(msg, F_CIB_CALLID));
		return;

	} else if(ccm_membership == NULL) {
 		crm_debug_3("Discarding message %s/%s: membership not established",
			  originator, cl_get_string(msg, F_SEQ));
		return;
		
	} else if(g_hash_table_lookup(ccm_membership, originator) == NULL) {
 		crm_debug_3("Discarding message %s/%s: not in our membership",
			  originator, cl_get_string(msg, F_CIB_CALLID));
		return;

	} else if(cib_get_operation_id(msg, &call_type) != cib_ok) {
		crm_err("Invalid operation... discarding msg %s",
			cl_get_string(msg, F_SEQ));
		return;
	}

	crm_debug_4("%s Processing msg %s",
		  cib_our_uname, cl_get_string(msg, F_SEQ));

	cib_process_request(msg, TRUE, TRUE, NULL);

	return;
}

HA_Message *
cib_msg_copy(const HA_Message *msg, gboolean with_data) 
{
	int lpc = 0;
	const char *field = NULL;
	const char *value = NULL;
	const HA_Message *value_struct = NULL;

	const char *field_list[] = {
		F_TYPE		,
		F_CIB_CLIENTID  ,
		F_CIB_CALLOPTS  ,
		F_CIB_CALLID    ,
		F_CIB_OPERATION ,
		F_CIB_ISREPLY   ,
		F_CIB_SECTION   ,
		F_CIB_HOST	,
		F_CIB_RC	,
		F_CIB_DELEGATED	,
		F_CIB_OBJID	,
		F_CIB_OBJTYPE	,
		F_CIB_EXISTING	,
		F_CIB_SEENCOUNT	,
		F_CIB_TIMEOUT	,
		F_CIB_CALLBACK_TOKEN	,
		F_CIB_GLOBAL_UPDATE	,
		F_CIB_CLIENTNAME	,
		F_CIB_NOTIFY_TYPE	,
		F_CIB_NOTIFY_ACTIVATE
	};
	
	const char *data_list[] = {
		F_CIB_CALLDATA  ,
		F_CIB_UPDATE	,
		F_CIB_UPDATE_RESULT
	};

	HA_Message *copy = ha_msg_new(10);

	if(copy == NULL) {
		return copy;
	}
	
	for(lpc = 0; lpc < DIMOF(field_list); lpc++) {
		field = field_list[lpc];
		value = cl_get_string(msg, field);
		if(value != NULL) {
			ha_msg_add(copy, field, value);
		}
	}
	for(lpc = 0; with_data && lpc < DIMOF(data_list); lpc++) {
		field = data_list[lpc];
		value_struct = cl_get_struct(msg, field);
		if(value_struct != NULL) {
			ha_msg_addstruct(copy, field, value_struct);
		}
	}
	return copy;
}


enum cib_errors
cib_get_operation_id(const HA_Message * msg, int *operation) 
{
	int lpc = 0;
	int max_msg_types = DIMOF(cib_server_ops);
	const char *op = cl_get_string(msg, F_CIB_OPERATION);

	for (lpc = 0; lpc < max_msg_types; lpc++) {
		if (safe_str_eq(op, cib_server_ops[lpc].operation)) {
			*operation = lpc;
			return cib_ok;
		}
	}
	crm_err("Operation %s is not valid", op);
	*operation = -1;
	return cib_operation;
}

void
cib_client_status_callback(const char * node, const char * client,
			   const char * status, void * private)
{
	if(safe_str_eq(client, CRM_SYSTEM_CIB)) {
		crm_debug_2("Status update: Client %s/%s now has status [%s]",
			    node, client, status);
		g_hash_table_replace(peer_hash, crm_strdup(node), crm_strdup(status));
		set_connected_peers(the_cib);
	}
	return;
}

extern oc_ev_t *cib_ev_token;

gboolean
ccm_manual_check(gpointer data)
{
	int rc = 0;
	oc_ev_t *ccm_token = cib_ev_token;
	
	crm_debug("manual check");	
	rc = oc_ev_handle_event(ccm_token);
	if(0 == rc) {
		return TRUE;

	} else {
		crm_err("CCM connection appears to have failed: rc=%d.", rc);
		return FALSE;
	}
}

gboolean cib_ccm_dispatch(int fd, gpointer user_data)
{
	int rc = 0;
	oc_ev_t *ccm_token = (oc_ev_t*)user_data;
	crm_debug("received callback");	
	rc = oc_ev_handle_event(ccm_token);
	if(0 == rc) {
		return TRUE;

	} else {
		crm_err("CCM connection appears to have failed: rc=%d.", rc);
		return FALSE;
	}
}

void 
cib_ccm_msg_callback(
	oc_ed_t event, void *cookie, size_t size, const void *data)
{
	int instance = -1;
	gboolean update_id = FALSE;
	gboolean update_quorum = FALSE;
	
	const oc_ev_membership_t *membership = data;

	if(membership != NULL) {
		instance = membership->m_instance;
	}

	crm_info("Process CCM event=%s (id=%d)", 
		 ccm_event_name(event), instance);

	switch(event) {
		case OC_EV_MS_NEW_MEMBERSHIP:
		case OC_EV_MS_INVALID:
			update_id = TRUE;
			update_quorum = TRUE;
			break;
		case OC_EV_MS_PRIMARY_RESTORED:
			update_id = TRUE;
			break;
		case OC_EV_MS_NOT_PRIMARY:
			crm_debug("Ignoring transitional CCM event: %s",
				  ccm_event_name(event));
			break;
		case OC_EV_MS_EVICTED:
			crm_err("Evicted from CCM: %s", ccm_event_name(event));
			update_quorum = TRUE;
			break;
		default:
			crm_err("Unknown CCM event: %d", event);
	}
	
	if(update_id) {
		CRM_DEV_ASSERT(membership != NULL);
		if(crm_assert_failed) { return; }
	
		if(ccm_transition_id != NULL) {
			crm_free(ccm_transition_id);
			ccm_transition_id = NULL;
		}
		ccm_transition_id = crm_itoa(instance);
		set_transition(the_cib);
	}
	
	if(update_quorum) {
		unsigned int members = 0;
		int offset = 0;
		unsigned int lpc = 0;

		cib_have_quorum = ccm_have_quorum(event);

		if(cib_have_quorum) {
 			crm_xml_add(
				the_cib,XML_ATTR_HAVE_QUORUM,XML_BOOLEAN_TRUE);
		} else {
 			crm_xml_add(
				the_cib,XML_ATTR_HAVE_QUORUM,XML_BOOLEAN_FALSE);
		}
		
		crm_info("Quorum %s after event=%s (id=%d)", 
			 cib_have_quorum?"(re)attained":"lost",
			 ccm_event_name(event), instance);
		
		if(ccm_membership != NULL) {
			g_hash_table_foreach_remove(
				ccm_membership, ghash_str_clfree, NULL);
		}
		ccm_membership = g_hash_table_new(g_str_hash, g_str_equal);

		if(membership != NULL) {
			members = membership->m_n_member;
			offset = membership->m_memb_idx;
		}
		
		for(lpc = 0; lpc < members; lpc++) {
			oc_node_t a_node = membership->m_array[lpc+offset];
			char *uname = crm_strdup(a_node.node_uname);
			g_hash_table_insert(
				ccm_membership, uname, uname);	
		}
	}
	
	oc_ev_callback_done(cookie);
	
	return;
}

gboolean
ghash_str_clfree(gpointer key, gpointer value, gpointer user_data)
{
	if(key != NULL) {
		crm_free(key);
	}
	return TRUE;
}

gboolean
can_write(int flags)
{
	const char *value = NULL;

	if(cib_have_quorum) {
		return TRUE;
	}
	value = get_crm_option(the_cib, "no_quorum_policy", TRUE);
	if(safe_str_eq(value, "ignore")) {
		return TRUE;		
	}
	if((flags & cib_quorum_override) != 0) {
		crm_debug_2("Overriding \"no quorum\" condition");
		return TRUE;
	}
	return FALSE;
}


