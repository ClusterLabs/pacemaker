/* $Id: callbacks.c,v 1.6 2004/12/16 14:34:18 andrew Exp $ */
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


int        next_client_id = 0;
gboolean   cib_is_master  = FALSE;
GHashTable *client_list   = NULL;
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

int send_via_callback_channel(struct ha_msg *msg, const char *token);

enum cib_errors cib_process_command(
	const struct ha_msg *request, struct ha_msg **reply, gboolean privileged);

gboolean cib_common_callback(
	IPC_Channel *channel, gpointer user_data, gboolean privileged);

enum cib_errors cib_get_operation_id(const struct ha_msg* msg, int *operation);

gboolean cib_process_disconnect(IPC_Channel *channel, cib_client_t *cib_client);

gboolean
cib_client_connect(IPC_Channel *channel, gpointer user_data)
{
	gboolean auth_failed = FALSE;
	gboolean can_connect = TRUE;
	gboolean (*client_callback)(IPC_Channel *channel, gpointer user_data) = NULL;

	cib_client_t *new_client = NULL;
	crm_debug("Connecting channel");

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

		crm_debug("Created channel %p for channel %s",
			  new_client, new_client->channel_name);
		
		client_callback = NULL;
		
		/* choose callback and do auth based on channel_name */
		if(safe_str_eq(new_client->channel_name, "cib_callback")) {
			client_callback = cib_null_callback;

		} else {
			uuid_t client_id;

			uuid_generate(client_id);
			crm_malloc(new_client->id, sizeof(char)*36);
			uuid_unparse(client_id, new_client->id);
			new_client->id[35] = EOS;
			
			uuid_generate(client_id);
			crm_malloc(new_client->callback_id, sizeof(char)*30);
			uuid_unparse(client_id, new_client->callback_id);
			new_client->callback_id[35] = EOS;
			
			client_callback = cib_ro_callback;
			if(safe_str_eq(new_client->channel_name, "cib_rw")) {
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
	channel->ops->set_send_qlen(channel, 100);

	if(client_callback != NULL) {
		new_client->source = G_main_add_IPC_Channel(
			G_PRIORITY_LOW, channel, FALSE, client_callback,
			new_client, default_ipc_connection_destroy);
	}
	if(client_callback != cib_null_callback) {
		/* send msg to client with uuid to use when signing up for
		 * callback channel
		 */

		struct ha_msg *reg_msg = ha_msg_new(3);
		ha_msg_add(reg_msg, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(reg_msg, F_CIB_CLIENTID,  new_client->id);
		ha_msg_add(
			reg_msg, F_CIB_CALLBACK_TOKEN, new_client->callback_id);
		
		msg2ipcchan(reg_msg, channel);
		ha_msg_del(reg_msg);
		
		/* make sure we can find ourselves later for sync calls
		 * redirected to the master instance
		 */
		g_hash_table_insert(client_list, new_client->id, new_client);
	}

	crm_info("Channel %s connected for client %s",
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
	struct ha_msg *op_request = NULL;
	cib_client_t *cib_client = user_data;
	cib_client_t *hash_client = NULL;
	const char *type = NULL;
	const char *uuid_ticket = NULL;

	if(cib_client == NULL) {
		crm_err("Discarding IPC message from unknown source"
			" on callback channel.");
		return FALSE;
	}
	
	while(channel->ops->is_message_pending(channel)) {
		if (channel->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT
			 */
			break;
		}
		op_request = msgfromIPC_noauth(channel);

		type = cl_get_string(op_request, F_CIB_OPERATION);
		if(safe_str_neq(type, CRM_OP_REGISTER) ) {
			crm_warn("Discarding IPC message from %s on callback channel",
				 cib_client->id);
			ha_msg_del(op_request);
			continue;
		}
		
		uuid_ticket = cl_get_string(op_request, F_CIB_CALLBACK_TOKEN);
		hash_client = g_hash_table_lookup(client_list, uuid_ticket);

		if(hash_client != NULL) {
			crm_err("Duplicate registration request... disconnecting");
			ha_msg_del(op_request);
			return FALSE;
		}


		cib_client->id = crm_strdup(uuid_ticket);
		g_hash_table_insert(client_list, cib_client->id, cib_client);
		crm_info("Registered %s on %s channel",
			    cib_client->id, cib_client->channel_name);

		ha_msg_del(op_request);

		op_request = ha_msg_new(2);
		ha_msg_add(op_request, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(op_request, F_CIB_CLIENTID,  cib_client->id);
		
		msg2ipcchan(op_request, channel);
		ha_msg_del(op_request);

	}
	return cib_process_disconnect(channel, cib_client);	
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
	
	struct ha_msg *op_request = NULL;
	struct ha_msg *op_reply   = NULL;

	cib_client_t *cib_client = user_data;

	if(cib_client == NULL) {
		crm_err("Receieved call from unknown source. Discarding.");
		return FALSE;
	}
	
	crm_verbose("Callback for %s on %s channel",
		    cib_client->id, cib_client->channel_name);

	while(channel->ops->is_message_pending(channel)) {
		if (channel->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		op_request = msgfromIPC(channel);
		if (op_request == NULL) {
			perror("Receive failure:");
			break;
		}

		crm_verbose("Processing IPC message from %s on %s channel",
			    cib_client->id, cib_client->channel_name);
		cl_log_message(op_request);
		
		lpc++;

		if(ha_msg_add(op_request, F_CIB_CLIENTID, cib_client->id) != HA_OK) {
			crm_err("Couldnt add F_CIB_CLIENTID to message");
			rc = cib_msg_field_add;
		}

		if(rc == cib_ok) {
			ha_msg_value_int(
				op_request, F_CIB_CALLOPTS, &call_options);
			crm_trace("Call options: %.8lx", (long)call_options);
			
			host = cl_get_string(op_request, F_CIB_HOST);
			crm_trace("Destination host: %s", host);

			op = cl_get_string(op_request, F_CIB_OPERATION);
			crm_trace("Retrieved command: %s", op);

			rc = cib_get_operation_id(op_request, &call_type);
			crm_trace("Command offset: %d", call_type);
		}
		
		if(rc == cib_ok
		   && cib_server_ops[call_type].needs_privileges
		   && privileged == FALSE) {
			rc = cib_not_authorized;
		}

		if(rc != cib_ok) {
			/* TODO: construct error reply */
			crm_err("Pre-processing of command failed: %s",
				cib_error2string(rc));
			
		} else if(host == NULL && cib_is_master
			&& !(call_options & cib_scope_local)) {
 			crm_info("Processing master %s op locally", op);
			rc = cib_process_command(
				op_request, &op_reply, privileged);

		} else if((host == NULL && (call_options & cib_scope_local))
			  || safe_str_eq(host, cib_our_uname)) {
 			crm_info("Processing %s op locally", op);
			rc = cib_process_command(
				op_request, &op_reply, privileged);

		} else if(host != NULL) {
 			crm_info("Forwarding %s op to %s", op, host);
			ha_msg_add(op_request, F_CIB_DELEGATED, cib_our_uname);
			hb_conn->llc_ops->send_ordered_nodemsg(
				hb_conn, op_request, host);

			if(call_options & cib_discard_reply) {
				ha_msg_del(op_request);

			} else if(call_options & cib_sync_call) {
				/* keep track of the request so we can time it
				 * out if required
				 */
				crm_debug("Registering call from %s as delegated", cib_client->id);
				cib_client->delegated_calls = g_list_append(
					cib_client->delegated_calls,
					op_request);
			} else {
				ha_msg_del(op_request);
			}
			continue;

		} else {
			/* send via HA to other nodes */
 			crm_info("Forwarding %s op to master instance", op);
			ha_msg_add(op_request, F_CIB_DELEGATED, cib_our_uname);
			
			hb_conn->llc_ops->sendclustermsg(hb_conn, op_request);
			if(call_options & cib_discard_reply) {
				ha_msg_del(op_request);

			} else if(call_options & cib_sync_call) {
				/* keep track of the request so we can time it
				 * out if required
				 */
				crm_debug("Registering call from %s as delegated", cib_client->id);
				cib_client->delegated_calls = g_list_append(
					cib_client->delegated_calls,
					op_request);
			} else {
				ha_msg_del(op_request);
			}
			continue;
		}

		if(op_reply == NULL) {
			crm_trace("No reply is required for op %s", op);
			
		} else if(call_options & cib_sync_call) {
 			crm_info("Sending sync reply %p to %s op", op_reply,op);
			if(msg2ipcchan(op_reply, channel) != HA_OK) {
				rc = cib_reply_failed;
			}

		} else {
			/* send reply via client's callback channel */
 			crm_info("Sending async reply %p to %s op", op_reply, op);
			rc = send_via_callback_channel(
				op_reply, cib_client->callback_id);
		}
		
		if(rc == cib_ok
		   && cib_server_ops[call_type].modifies_cib
		   && !(call_options & cib_scope_local)) {
			/* send via HA to other nodes */
 			crm_info("Forwarding %s op to all instances", op);
			ha_msg_add(op_request, F_CIB_GLOBAL_UPDATE, "true");
			hb_conn->llc_ops->sendclustermsg(hb_conn, op_request);

		} else {
			if(call_options & cib_scope_local ) {
				crm_debug("Request not broadcast : local scope");
			}
			if(cib_server_ops[call_type].modifies_cib == FALSE) {
				crm_debug("Request not broadcast : R/O call");
			}
			if(rc != cib_ok) {
				crm_debug("Request not broadcast : call failed : %s",
					  cib_error2string(rc));
			}
		}

		ha_msg_del(op_request);
		ha_msg_del(op_reply);
	}

	crm_verbose("Processed %d messages", lpc);
    
	return cib_process_disconnect(channel, cib_client);
}

enum cib_errors
cib_process_command(const struct ha_msg *request, struct ha_msg **reply,
		    gboolean privileged)
{
	xmlNodePtr input    = NULL;
	const char *input_s = NULL;

	char *output_s    = NULL;
	xmlNodePtr output = NULL;

	int call_type      = 0;
	int call_options   = 0;
	enum cib_errors rc = cib_ok;

	const char *op = NULL;
	const char *call_id = NULL;
	const char *section = NULL;

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
		crm_trace("Unpacking section");
		section = cl_get_string(request, F_CIB_SECTION);
	}

	if(rc == cib_ok && cib_server_ops[call_type].needs_data) {
		crm_trace("Unpacking data in %s", F_CIB_CALLDATA);
		input_s = cl_get_string(request, F_CIB_CALLDATA);
		if(input_s != NULL) {
			crm_trace("Converting to xmlNodePtr");			
			input = string2xml(input_s);
			if(input == NULL) {
				crm_err("Invalid XML input");
				rc = CIBRES_CORRUPT;
			}
		}
	}		

	if(rc == cib_ok) {
		rc = cib_server_ops[call_type].fn(
			op, call_options, section, input, &output);
	}
	
	if(call_options & cib_discard_reply || reply == NULL) {
		if(reply) *reply = NULL;
		return rc;
	}

	/* make the basic reply */
	*reply = ha_msg_new(8);
	ha_msg_add(*reply, F_TYPE, "cib");
	ha_msg_add(*reply, F_CIB_OPERATION, op);
	ha_msg_add(*reply, F_CIB_CALLID, call_id);
	ha_msg_add_int(*reply, F_CIB_RC, rc);

	{
		const char *tmp = cl_get_string(request, F_CIB_CLIENTID);
		ha_msg_add(*reply, F_CIB_CLIENTID, tmp);

		tmp = cl_get_string(request, F_CIB_CALLOPTS);
		ha_msg_add(*reply, F_CIB_CALLOPTS, tmp);

		tmp = cl_get_string(request, F_CIB_CALLID);
		ha_msg_add(*reply, F_CIB_CALLID, tmp);
	}
	
	/* attach the output if necessary */
	output_s = dump_xml_unformatted(output);
	if(output != NULL && output_s == NULL) {
		crm_err("Currupt output in reply to \"%s\" op",op);
		rc = cib_output_data;

	} else if(output_s != NULL
		  && ha_msg_add(*reply, F_CIB_CALLDATA, output_s) != HA_OK) {
		rc = cib_msg_field_add;
	}

	crm_free(output_s);
	free_xml(output);
	free_xml(input);
	return rc;
}

int
send_via_callback_channel(struct ha_msg *msg, const char *token) 
{
	cib_client_t *hash_client = NULL;
	GList *list_item = NULL;
	
	crm_debug("Delivering msg %p to client %s", msg, token);

	if(msg == NULL) {
		crm_err("No message to send");
		return cib_reply_failed;

	} else if(token == NULL) {
		crm_err("No client id token, cant send message");
		return cib_missing;
	}
	
	hash_client = g_hash_table_lookup(client_list, token);

	if(hash_client == NULL) {
		crm_err("Cannot find client for token %s", token);
		return cib_client_gone;

	} else if(hash_client->channel == NULL) {
		crm_err("Cannot find channel for client %s", token);
		return cib_client_corrupt;
	}

	list_item = g_list_find_custom(
		hash_client->delegated_calls, msg, cib_GCompareFunc);

	if(list_item != NULL) {
		/* remove it - no need to time it out */
		struct ha_msg *orig_msg = list_item->data;
		crm_debug("Removing msg from delegated list");
		hash_client->delegated_calls = g_list_remove(
			hash_client->delegated_calls, orig_msg);
		ha_msg_del(orig_msg);
	}
	
	crm_debug("Delivering reply to client %s", token);
	if(msg2ipcchan(msg, hash_client->channel) != HA_OK) {
		crm_err("Delivery of reply to client %s failed", token);
		return cib_reply_failed;
	}
	return cib_ok;
}

gint cib_GCompareFunc(gconstpointer a, gconstpointer b)
{
	const struct ha_msg *a_msg = a;
	const struct ha_msg *b_msg = b;

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
	struct ha_msg *msg = NULL;


	while(list != NULL) {
		struct ha_msg *reply = ha_msg_new(4);
		int seen = 0;
		int timeout = 5; /* 1 iteration == 1 seconds */

		msg = list->data;
		ha_msg_value_int(msg, F_CIB_SEENCOUNT, &seen);
		ha_msg_value_int(msg, F_CIB_TIMEOUT, &timeout);

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
		
		ha_msg_add(reply, F_TYPE, "cib");
		ha_msg_add(reply, F_CIB_OPERATION,
			   cl_get_string(msg, F_CIB_OPERATION));
		ha_msg_add(reply, F_CIB_CALLID,
			   cl_get_string(msg, F_CIB_CALLID));
		ha_msg_add_int(reply, F_CIB_RC, cib_master_timeout);

		msg2ipcchan(reply, client->channel);

		list = list->next;
		client->delegated_calls = g_list_remove(
			client->delegated_calls, msg);

		ha_msg_del(reply);
		ha_msg_del(msg);
	}
}


gboolean
cib_process_disconnect(IPC_Channel *channel, cib_client_t *cib_client)
{
	if (channel->ch_status == IPC_DISCONNECT && cib_client != NULL) {
		crm_info("Cleaning up after %s channel disconnect from client (%p) %s",
			 cib_client->channel_name, cib_client, cib_client->id);

		g_hash_table_remove(client_list, cib_client->id);
		
		if(cib_client->source != NULL) {
			crm_debug("deleting the IPC Channel");
 			G_main_del_IPC_Channel(cib_client->source);
			cib_client->source = NULL;
		}
		
		crm_debug("Freeing the cib client");
		crm_debug("Freeing the cib client %s", cib_client->id);
/* 		crm_free(cib_client->callback_id); */
 		crm_free(cib_client->id);
  		crm_free(cib_client);
		crm_debug("Freed the cib client");

		return FALSE;

	} else if (channel->ch_status == IPC_DISCONNECT) {
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

	if (channel && (channel->ch_status == IPC_DISCONNECT)) {
		crm_crit("Lost connection to heartbeat service... exiting");
		exit(100);
		return FALSE;
	}
	return TRUE;
}

void
cib_peer_callback(const struct ha_msg* msg, void* private_data)
{
	int is_done      = 1;
	int call_type    = 0;
	int call_options = 0;

	gboolean process = TRUE;		
	gboolean needs_reply = TRUE;
	gboolean local_notify = FALSE;

	enum cib_errors rc = cib_ok;
	struct ha_msg *op_reply = NULL;
	
	const char *originator = cl_get_string(msg, F_ORIG);
	const char *request_to = cl_get_string(msg, F_CIB_HOST);
	const char *reply_to   = cl_get_string(msg, F_CIB_ISREPLY);
	const char *update     = cl_get_string(msg, F_CIB_GLOBAL_UPDATE);
	const char *delegated  = cl_get_string(msg, F_CIB_DELEGATED);
	const char *client_id  = NULL;

	if(safe_str_eq(originator, cib_our_uname)) {
		crm_debug("Discarding message %s from ourselves",
			  cl_get_string(msg, F_SEQ));
		return;
	}
	
	if(cib_get_operation_id(msg, &call_type) != cib_ok) {
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

	crm_info("Processing message from peer to %s...", request_to);
	cl_log_message(msg);

	if(safe_str_eq(update, "true")
	   && safe_str_eq(reply_to, cib_our_uname)) {
		crm_debug("Processing global update that originated from us");
		needs_reply = FALSE;
		local_notify = TRUE;
		
	} else if(safe_str_eq(update, "true")) {
		crm_debug("Processing global update");
		needs_reply = FALSE;

	} else if(request_to != NULL
		  && safe_str_eq(request_to, cib_our_uname)) {
		crm_debug("Processing request sent to us");

	} else if(delegated != NULL && cib_is_master == TRUE) {
		crm_debug("Processing request sent to master instance");

	} else if(reply_to != NULL && safe_str_eq(reply_to, cib_our_uname)) {
		crm_debug("Forward reply sent from %s to local clients",
			  originator);
		process = FALSE;
		needs_reply = FALSE;
		local_notify = TRUE;

	} else if(delegated != NULL) {
		crm_debug("Ignoring msg for master instance");
		return;

	} else if(request_to != NULL) {
		/* this is for a specific instance and we're not it */
		crm_debug("Ignoring msg for instance on %s", request_to);
		return;
		
	} else if(reply_to == NULL && cib_is_master == FALSE) {
		/* this is for the master instance and we're not it */
		crm_debug("Ignoring reply to %s", reply_to);
		return;
		
	} else {
		crm_warn("Nothing for us to do?");
		return;
	}

	ha_msg_value_int(msg, F_CIB_CALLOPTS, &call_options);
	crm_trace("Retrieved call options: %d", call_options);

	if(process) {
		crm_debug("Performing local processing");
		rc = cib_process_command(msg, &op_reply, TRUE);
	}
	
	if(local_notify) {
		/* send callback to originating child */
		cib_client_t *client_obj = NULL;
		crm_trace("find the client");

		if(process == FALSE) {
			op_reply = ha_msg_copy(msg);
		}
		
		client_id = cl_get_string(msg, F_CIB_CLIENTID);
		if(client_id != NULL) {
			client_obj = g_hash_table_lookup(
				client_list, client_id);
		} else {
			crm_err("No client to sent the response to."
				"  F_CIB_CLIENTID not set.");
		}
		
		crm_debug("Sending callback to originator of delegated request");
		if(client_obj != NULL) {
			if(is_done == 0) {
				crm_debug("Sending local modify response");

			} else {
				crm_debug("Sending master response");
			}
			if(call_options & cib_sync_call) {
				crm_debug("Sending sync response: %d",
					  call_options);

				send_via_callback_channel(
					op_reply, client_obj->id);
/* 				msg2ipcchan(op_reply, client_obj->channel); */
				
			} else {
				crm_debug("Sending async response");
				send_via_callback_channel(
					op_reply, client_obj->callback_id);
			}
			
		} else {
			crm_warn("Client %s may have left us", client_id);
		}
		if(process == FALSE) {
			ha_msg_del(op_reply);
		}
	}

	if(needs_reply == FALSE) {
		/* nothing more to do...
		 * this was a non-originating slave update
		 */
		crm_debug("Completed slave update");
		return;
	}
	
	crm_trace("add the originator to message");
	ha_msg_add(op_reply, F_CIB_ISREPLY, originator);

	/* from now on we are the server */ 
	if(rc == cib_ok && cib_server_ops[call_type].modifies_cib
	   && !(call_options & cib_scope_local)) {
		/* this (successful) call modified the CIB _and_ the
		 * change needs to be broadcast...
		 *   send via HA to other nodes
		 */
		crm_debug("Sending update request to everyone");
		hb_conn->llc_ops->sendclustermsg(hb_conn, op_reply);
		
	} else {
		/* send reply via HA to originating node */
		crm_debug("Sending request result to originator only");
		hb_conn->llc_ops->send_ordered_nodemsg(
			hb_conn, op_reply, originator);
	}

	return;
}

enum cib_errors
cib_get_operation_id(const struct ha_msg* msg, int *operation) 
{
	int lpc = 0;
	int max_msg_types = DIMOF(cib_server_ops);
	const char *op    = cl_get_string(msg, F_CIB_OPERATION);

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
