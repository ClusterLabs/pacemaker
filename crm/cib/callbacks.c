/* $Id: callbacks.c,v 1.37 2005/04/01 10:13:34 andrew Exp $ */
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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/uids.h>

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

#include <crm/dmalloc_wrapper.h>

gint cib_GCompareFunc(gconstpointer a, gconstpointer b);
gboolean cib_msg_timeout(gpointer data);
void cib_GHFunc(gpointer key, gpointer value, gpointer user_data);
gboolean ghash_str_clfree(gpointer key, gpointer value, gpointer user_data);

GHashTable *peer_hash = NULL;
int        next_client_id  = 0;
gboolean   cib_is_master   = FALSE;
gboolean   cib_have_quorum = FALSE;
GHashTable *client_list    = NULL;
GHashTable *ccm_membership = NULL;
extern const char *cib_our_uname;
extern ll_cluster_t *hb_conn;

/* technically bump does modify the cib...
 * but we want to split the "bump" from the "sync"
 */
cib_operation_t cib_server_ops[] = {
	{NULL,		     FALSE, FALSE, FALSE, FALSE, cib_process_default},
	{CRM_OP_NOOP,	     FALSE, FALSE, FALSE, FALSE, cib_process_default},
	{CRM_OP_RETRIVE_CIB, FALSE, FALSE, FALSE, FALSE, cib_process_query},
	{CRM_OP_CIB_SLAVE,   FALSE, TRUE,  FALSE, FALSE, cib_process_readwrite},
	{CRM_OP_CIB_SLAVEALL,TRUE,  TRUE,  FALSE, FALSE, cib_process_readwrite},
	{CRM_OP_CIB_MASTER,  FALSE, TRUE,  FALSE, FALSE, cib_process_readwrite},
	{CRM_OP_CIB_ISMASTER,FALSE, TRUE,  FALSE, FALSE, cib_process_readwrite},
	{CRM_OP_CIB_BUMP,    FALSE, TRUE,  TRUE,  FALSE, cib_process_bump},
	{CRM_OP_CIB_REPLACE, TRUE,  TRUE,  TRUE,  TRUE,  cib_process_replace},
	{CRM_OP_CIB_CREATE,  TRUE,  TRUE,  TRUE,  TRUE,  cib_process_modify},
	{CRM_OP_CIB_UPDATE,  TRUE,  TRUE,  TRUE,  TRUE,  cib_process_modify},
	{CRM_OP_JOINACK,     TRUE,  TRUE,  TRUE,  TRUE,  cib_process_modify},
	{CRM_OP_SHUTDOWN_REQ,TRUE,  TRUE,  TRUE,  TRUE,  cib_process_modify},
	{CRM_OP_CIB_DELETE,  TRUE,  TRUE,  TRUE,  TRUE,  cib_process_modify},
	{CRM_OP_CIB_QUERY,   FALSE, FALSE, TRUE,  FALSE, cib_process_query},
	{CRM_OP_QUIT,	     FALSE, TRUE,  FALSE, FALSE, cib_process_quit},
	{CRM_OP_PING,	     FALSE, FALSE, FALSE, FALSE, cib_process_ping},
	{CRM_OP_CIB_ERASE,   TRUE,  TRUE,  TRUE,  FALSE, cib_process_erase}
};

int send_via_callback_channel(HA_Message *msg, const char *token);

enum cib_errors cib_process_command(
	const HA_Message *request, HA_Message **reply, gboolean privileged);

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
	crm_devel("Connecting channel");

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
		crm_malloc(new_client, sizeof(cib_client_t));
		new_client->id          = NULL;
		new_client->callback_id = NULL;
		new_client->source      = NULL;
		new_client->channel     = channel;
		new_client->channel_name = user_data;
		new_client->delegated_calls = NULL;

		crm_devel("Created channel %p for channel %s",
			  new_client, new_client->channel_name);
		
		client_callback = NULL;
		
		/* choose callback and do auth based on channel_name */
		if(safe_str_eq(new_client->channel_name, cib_channel_callback)) {
			client_callback = cib_null_callback;

		} else {
			uuid_t client_id;

			uuid_generate(client_id);
			crm_malloc(new_client->id, sizeof(char)*36);
			uuid_unparse(client_id, new_client->id);
			new_client->id[35] = EOS;
			
			uuid_generate(client_id);
			crm_malloc(new_client->callback_id, sizeof(char)*36);
			uuid_unparse(client_id, new_client->callback_id);
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

	crm_devel("Channel %s connected for client %s",
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
		crm_verbose("Registered %s on %s channel",
			    cib_client->id, cib_client->channel_name);

		crm_msg_del(op_request);

		op_request = ha_msg_new(2);
		ha_msg_add(op_request, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(op_request, F_CIB_CLIENTID,  cib_client->id);
		
		send_ipc_message(channel, op_request);
	}
	did_disconnect = cib_process_disconnect(channel, cib_client);	
	if(did_disconnect) {
		crm_debug("Client disconnected");
	}
	
	return did_disconnect;
}

gboolean
cib_common_callback(
	IPC_Channel *channel, gpointer user_data, gboolean privileged)
{
	int rc = cib_ok;
	int lpc = 0;
	int call_type = 0;
	int call_options = 0;

	const char *op = NULL;
	const char *host = NULL;
	
	HA_Message *op_request = NULL;
	HA_Message *op_reply   = NULL;

	gboolean needs_processing = FALSE;
	cib_client_t *cib_client = user_data;

	if(cib_client == NULL) {
		crm_err("Receieved call from unknown source. Discarding.");
		return FALSE;
	}
	
	crm_verbose("Callback for %s on %s channel",
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

		crm_verbose("Processing IPC message from %s on %s channel",
			    cib_client->id, cib_client->channel_name);
 		crm_log_message(LOG_MSG, op_request);
		crm_log_message_adv(LOG_DEV, "Client[inbound]", op_request);
		
		lpc++;
		rc = cib_ok;
		
		if(HA_OK != ha_msg_add(
			   op_request, F_CIB_CLIENTID, cib_client->id)) {
			crm_err("Couldnt add F_CIB_CLIENTID to message");
			rc = cib_msg_field_add;
		}

		if(rc == cib_ok) {
			ha_msg_value_int(
				op_request, F_CIB_CALLOPTS, &call_options);
			crm_devel("Call options: %.8lx", (long)call_options);
			
			host = cl_get_string(op_request, F_CIB_HOST);
			op = cl_get_string(op_request, F_CIB_OPERATION);
			rc = cib_get_operation_id(op_request, &call_type);
		}
		
		if(rc == cib_ok
		   && cib_server_ops[call_type].needs_privileges
		   && privileged == FALSE) {
			rc = cib_not_authorized;
		}

		needs_processing = FALSE;
		if(rc != cib_ok) {
			/* TODO: construct error reply */
			crm_err("Pre-processing of command failed: %s",
				cib_error2string(rc));
			
		} else if(host == NULL && cib_is_master
			&& !(call_options & cib_scope_local)) {
 			crm_devel("Processing master %s op locally", op);
			needs_processing = TRUE;

		} else if(
			(host == NULL && (call_options & cib_scope_local))
			  || safe_str_eq(host, cib_our_uname)) {
 			crm_devel("Processing %s op locally", op);
			needs_processing = TRUE;

		} else {
			/* send via HA to other nodes */
			ha_msg_add(op_request, F_CIB_DELEGATED, cib_our_uname);
			crm_log_message(LOG_MSG, op_request);

			if(host != NULL) {
				crm_devel("Forwarding %s op to %s", op, host);
				send_ha_message(hb_conn, op_request, host);

			} else {
				crm_info("Forwarding %s op to master instance",
					 op);
				send_ha_message(hb_conn, op_request, NULL);
			}

			if(call_options & cib_discard_reply) {
				crm_trace("Client not interested in reply");

			} else if(call_options & cib_sync_call) {
				/* keep track of the request so we can time it
				 * out if required
				 */
				HA_Message *saved = ha_msg_copy(op_request);
				crm_devel("Registering delegated call from %s",
					  cib_client->id);
				cib_client->delegated_calls = g_list_append(
					cib_client->delegated_calls, saved);
			}
			crm_msg_del(op_request);
			op_request = NULL;
			continue;
		}

		if(needs_processing) {
 			crm_verbose("Processing %s op", op);
			rc = cib_process_command(
				op_request, &op_reply, privileged);
			crm_devel("Performing local processing: op=%s origin=%s/%s,%s (update=%s)",
				  op, cib_our_uname, cib_client->id,
				  cl_get_string(op_request, F_CIB_CALLID),
				  (rc==cib_ok && cib_server_ops[call_type].modifies_cib)?"true":"false");
 			crm_devel("Processing complete");
		}
		
		crm_devel("processing response cases");
		if(rc != cib_ok) {
			crm_err("Input message");
			crm_log_message(LOG_ERR, op_request);
			crm_err("Output message");
			crm_log_message_adv(LOG_ERR, "CIB[output]", op_reply);
		}
		
		if(op_reply == NULL) {
			crm_trace("No reply is required for op %s", crm_str(op));
			
		} else if(call_options & cib_sync_call) {
 			crm_devel("Sending sync reply to %s op", crm_str(op));
			crm_log_message(LOG_MSG, op_reply);
			if(send_ipc_message(channel, op_reply) == FALSE) {
				crm_err("Sync reply failed: %s",
					 cib_error2string(cib_reply_failed));
			}
			
		} else {
			enum cib_errors local_rc = cib_ok;
			/* send reply via client's callback channel */
 			crm_devel("Sending async reply %p to %s op",
				  op_reply, crm_str(op));
			crm_log_message(LOG_MSG, op_reply);
			local_rc = send_via_callback_channel(
				op_reply, cib_client->callback_id);
			if(local_rc != cib_ok) {
				crm_warn("ASync reply failed: %s",
					 cib_error2string(local_rc));
			}
		}

		op_reply = NULL;

		crm_devel("Processing forward cases");
		if(rc == cib_ok
		   && cib_server_ops[call_type].modifies_cib
		   && !(call_options & cib_scope_local)) {
			/* send via HA to other nodes */
 			crm_debug("Forwarding %s op to all instances", op);
			ha_msg_add(op_request,
				   F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
			send_ha_message(hb_conn, op_request, NULL);
			
		} else {
			if(call_options & cib_scope_local ) {
				crm_devel("Request not broadcast : local scope");
			}
			if(cib_server_ops[call_type].modifies_cib == FALSE) {
				crm_devel("Request not broadcast : R/O call");
			}
			if(rc != cib_ok) {
				crm_devel("Request not broadcast : call failed : %s",
					  cib_error2string(rc));
			}
		}

		crm_devel("Cleaning up request");
		crm_msg_del(op_request);
		op_request = NULL;
	}

	crm_verbose("Processed %d messages", lpc);
    
	return cib_process_disconnect(channel, cib_client);
}

enum cib_errors
cib_process_command(
	const HA_Message *request, HA_Message **reply, gboolean privileged)
{
	crm_data_t *output   = NULL;
	crm_data_t *input    = NULL;

	int call_type      = 0;
	int call_options   = 0;
	enum cib_errors rc = cib_ok;

	const char *op = NULL;
	const char *call_id = NULL;
	const char *section = NULL;
	const char *tmp = NULL;

	CRM_DEV_ASSERT(reply != NULL);
	if(reply) { *reply = NULL; }
	
	/* Start processing the request... */
	op = cl_get_string(request, F_CIB_OPERATION);
	call_id = cl_get_string(request, F_CIB_CALLID);
	ha_msg_value_int(request, F_CIB_CALLOPTS, &call_options);

	crm_trace("Processing call id: %s", call_id);
	
	rc = cib_get_operation_id(request, &call_type);
	
	if(rc == cib_ok &&
	   cib_server_ops[call_type].needs_privileges
	   && privileged == FALSE) {
		/* abort */
		rc = cib_not_authorized;
	}
	
	if(rc == cib_ok && cib_server_ops[call_type].needs_section) {
		section = cl_get_string(request, F_CIB_SECTION);
		crm_trace("Unpacked section as: %s", section);
	}

	if(rc == cib_ok && cib_server_ops[call_type].needs_data) {
		crm_trace("Unpacking data in %s", F_CIB_CALLDATA);
		input = get_message_xml(request, F_CIB_CALLDATA);
	}		

	if(rc == cib_ok) {
		rc = cib_server_ops[call_type].fn(
			op, call_options, section, input, &output);
	}

	crm_trace("Processing reply cases");
	if(call_options & cib_discard_reply) {
		crm_devel("No reply needed for call %s", call_id);
		return rc;
		
	} else if(reply == NULL) {
		crm_debug("No reply possible for call %s", call_id);
		return rc;
	}

	crm_trace("Creating a basic reply");
	*reply = ha_msg_new(8);
	ha_msg_add(*reply, F_TYPE, T_CIB);
	ha_msg_add(*reply, F_CIB_OPERATION, op);
	ha_msg_add(*reply, F_CIB_CALLID, call_id);
	ha_msg_add_int(*reply, F_CIB_RC, rc);

	tmp = cl_get_string(request, F_CIB_CLIENTID);
	ha_msg_add(*reply, F_CIB_CLIENTID, tmp);
	
	tmp = cl_get_string(request, F_CIB_CALLOPTS);
	ha_msg_add(*reply, F_CIB_CALLOPTS, tmp);
	
	crm_trace("Attaching output if necessary");
	if(output != NULL) {
		add_message_xml(*reply, F_CIB_CALLDATA, output);
	} else {
		crm_devel("No output for call %s", call_id);
	}
	

	crm_trace("Cleaning up");
	free_xml(output);
	free_xml(input);
	return rc;
}

int
send_via_callback_channel(HA_Message *msg, const char *token) 
{
	cib_client_t *hash_client = NULL;
	GList *list_item = NULL;
	enum cib_errors rc = cib_ok;
	
	crm_devel("Delivering msg %p to client %s", msg, token);

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
		crm_devel("Removing msg from delegated list");
		hash_client->delegated_calls = g_list_remove(
			hash_client->delegated_calls, orig_msg);
		CRM_DEV_ASSERT(orig_msg != msg);
		crm_msg_del(orig_msg);
	}
	
	if(rc == cib_ok) {
		crm_devel("Delivering reply to client %s", token);
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
	crm_trace("Checking if any clients have timed out messages");
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
		
		crm_trace("Timeout %d, seen %d", timeout, seen);
		if(timeout > 0 && seen < timeout) {
			int seen2 = 0;
			crm_trace("Updating seen count for msg from client %s",
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
			crm_devel("deleting the IPC Channel");
 			G_main_del_IPC_Channel(cib_client->source);
			cib_client->source = NULL;
		}
		
		crm_devel("Freeing the cib client %s", crm_str(cib_client->id));
#if 0
		/* todo - put this back in once i recheck its safe */
 		crm_free(cib_client->callback_id);
  		crm_free(cib_client->name);
  		crm_free(cib_client->id);
#endif
  		crm_free(cib_client);
		crm_devel("Freed the cib client");

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

	while(hb_cluster->llc_ops->msgready(hb_cluster)) {
 		lpc++; 
		/* invoke the callbacks but dont block */
		hb_cluster->llc_ops->rcvmsg(hb_cluster, 0);
	}

	crm_trace("%d HA messages dispatched", lpc);

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
	int is_done      = 1;
	int call_type    = 0;
	int call_options = 0;

	gboolean process = TRUE;		
	gboolean needs_reply = TRUE;
	gboolean local_notify = FALSE;

	enum cib_errors rc = cib_ok;
	HA_Message *op_reply = NULL;
	
	const char *originator = cl_get_string(msg, F_ORIG);
	const char *request_to = cl_get_string(msg, F_CIB_HOST);
	const char *reply_to   = cl_get_string(msg, F_CIB_ISREPLY);
	const char *update     = cl_get_string(msg, F_CIB_GLOBAL_UPDATE);
	const char *delegated  = cl_get_string(msg, F_CIB_DELEGATED);
	const char *client_id  = NULL;

	if(safe_str_eq(originator, cib_our_uname)) {
 		crm_devel("Discarding message %s/%s from ourselves",
			  cl_get_string(msg, F_CIB_CLIENTID), 
			  cl_get_string(msg, F_CIB_CALLID));
		return;

	} else if(ccm_membership == NULL) {
 		crm_devel("Discarding message %s/%s: membership not established",
			  originator, cl_get_string(msg, F_SEQ));
		return;
		
	} else if(g_hash_table_lookup(ccm_membership, originator) == NULL) {
 		crm_devel("Discarding message %s/%s: not in our membership",
			  originator, cl_get_string(msg, F_CIB_CALLID));
		return;

	} else if(cib_get_operation_id(msg, &call_type) != cib_ok) {
		crm_err("Invalid operation... discarding msg %s",
			cl_get_string(msg, F_SEQ));
		return;
	}

	crm_trace("%s Processing msg %s",
		  cib_our_uname, cl_get_string(msg, F_SEQ));

	if(request_to != NULL && strlen(request_to) == 0) {
		request_to = NULL;
	}
	
	if(cib_server_ops[call_type].modifies_cib
	   || (reply_to == NULL && cib_is_master)
	   || request_to != NULL) {
		is_done = 0;
	}

	crm_debug("Processing message from peer to %s...",
		  request_to?request_to:"master");
	crm_log_message_adv(LOG_DEV, "Peer[inbound]", msg);

	if(crm_is_true(update) && safe_str_eq(reply_to, cib_our_uname)) {
		crm_devel("Processing global update that originated from us");
		needs_reply = FALSE;
		local_notify = TRUE;
		
	} else if(crm_is_true(update)) {
		crm_devel("Processing global update");
		needs_reply = FALSE;

	} else if(request_to != NULL
		  && safe_str_eq(request_to, cib_our_uname)) {
		crm_devel("Processing request sent to us");

	} else if(delegated != NULL && cib_is_master == TRUE) {
		crm_devel("Processing request sent to master instance");

	} else if(reply_to != NULL && safe_str_eq(reply_to, cib_our_uname)) {
		crm_devel("Forward reply sent from %s to local clients",
			  originator);
		process = FALSE;
		needs_reply = FALSE;
		local_notify = TRUE;

	} else if(delegated != NULL) {
		crm_devel("Ignoring msg for master instance");
		return;

	} else if(request_to != NULL) {
		/* this is for a specific instance and we're not it */
		crm_devel("Ignoring msg for instance on %s",
			  crm_str(request_to));
		return;
		
	} else if(reply_to == NULL && cib_is_master == FALSE) {
		/* this is for the master instance and we're not it */
		crm_devel("Ignoring reply to %s", crm_str(reply_to));
		return;
		
	} else {
		crm_warn("Nothing for us to do?");
		return;
	}
	crm_devel("Finished determining processing actions");

	ha_msg_value_int(msg, F_CIB_CALLOPTS, &call_options);
	crm_trace("Retrieved call options: %d", call_options);

	if(process) {
		crm_devel("Performing local processing: op=%s origin=%s/%s,%s (update=%s)",
			  cl_get_string(msg, F_CIB_OPERATION),
			  originator,
			  cl_get_string(msg, F_CIB_CLIENTID),
			  cl_get_string(msg, F_CIB_CALLID),
			  update);
		rc = cib_process_command(msg, &op_reply, TRUE);
	}
	
	if(local_notify) {
		/* send callback to originating child */
		cib_client_t *client_obj = NULL;
		HA_Message *client_reply = NULL;
		crm_trace("find the client");

		if(process == FALSE) {
			client_reply = ha_msg_copy(msg);
		} else {
			client_reply = ha_msg_copy(op_reply);
		}
		
		client_id = cl_get_string(msg, F_CIB_CLIENTID);
		if(client_id != NULL) {
			client_obj = g_hash_table_lookup(
				client_list, client_id);
		} else {
			crm_err("No client to sent the response to."
				"  F_CIB_CLIENTID not set.");
		}
		
		crm_devel("Sending callback to originator of delegated request");
		if(client_obj != NULL) {
			if(is_done == 0) {
				crm_devel("Sending local modify response");

			} else {
				crm_devel("Sending master response");
			}
			if(call_options & cib_sync_call) {
				crm_devel("Sending sync response: %d",
					  call_options);

				send_via_callback_channel(
					client_reply, client_obj->id);

			} else {
				crm_devel("Sending async response");
				send_via_callback_channel(
					client_reply, client_obj->callback_id);
			}
			
		} else {
			crm_warn("Client %s may have left us",
				 crm_str(client_id));
			crm_msg_del(client_reply);
		}
	}

	if(needs_reply == FALSE) {
		/* nothing more to do...
		 * this was a non-originating slave update
		 */
		crm_devel("Completed slave update");
		crm_msg_del(op_reply);
		return;
	}
	
	crm_trace("add the originator to message");

	/* from now on we are the server */ 
	if(rc == cib_ok && cib_server_ops[call_type].modifies_cib
	   && !(call_options & cib_scope_local)) {
		/* this (successful) call modified the CIB _and_ the
		 * change needs to be broadcast...
		 *   send via HA to other nodes
		 */
		HA_Message *op_bcast = ha_msg_copy(msg);
		crm_devel("Sending update request to everyone");
		ha_msg_add(op_bcast, F_CIB_ISREPLY, originator);
		ha_msg_add(op_bcast, F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
		crm_log_message(LOG_DEV, op_bcast);
		send_ha_message(hb_conn, op_bcast, NULL);
		crm_msg_del(op_bcast);
		
	} else {
		/* send reply via HA to originating node */
		crm_devel("Sending request result to originator only");
		ha_msg_add(op_reply, F_CIB_ISREPLY, originator);
		send_ha_message(hb_conn, op_reply, originator);
	}
	crm_msg_del(op_reply);

	return;
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
		crm_verbose("Status update: Client %s/%s now has status [%s]",
			    node, client, status);
		g_hash_table_replace(peer_hash, crm_strdup(node), crm_strdup(status));
	}
	return;
}

gboolean cib_ccm_dispatch(int fd, gpointer user_data)
{
	int rc = 0;
	oc_ev_t *ccm_token = (oc_ev_t*)user_data;
	crm_devel("received callback");	
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
	unsigned lpc = 0;
	int offset = 0;
	const oc_ev_membership_t *membership = data;
	crm_devel("received callback");	

	if(event==OC_EV_MS_NEW_MEMBERSHIP 
	   || event==OC_EV_MS_NOT_PRIMARY
	   || event==OC_EV_MS_PRIMARY_RESTORED) {
		cib_have_quorum = TRUE;
	} else {
		cib_have_quorum = FALSE;
	}

	crm_info("Quorum %s after event=%s", 
		 cib_have_quorum?"(re)attained":"lost",
		 event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
		 event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
		 event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
		 event==OC_EV_MS_EVICTED?"EVICTED":
		 "NO QUORUM MEMBERSHIP");
	
	if(data == NULL) {
		return;
	}
	
	if(ccm_membership != NULL) {
		g_hash_table_foreach_remove(
			ccm_membership, ghash_str_clfree, NULL);
	}
	ccm_membership = g_hash_table_new(g_str_hash, g_str_equal);

	offset = membership->m_memb_idx;
	
	for(lpc = 0; lpc < membership->m_n_member; lpc++) {
		oc_node_t a_node = membership->m_array[lpc+offset];
		char *uname = crm_strdup(a_node.node_uname);
		crm_devel("Copying ccm member node %d:%s", lpc, uname);
		g_hash_table_insert(ccm_membership, uname, uname);	
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
