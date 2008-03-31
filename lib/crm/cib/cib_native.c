/*
 * Copyright (c) 2004 International Business Machines
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <crm_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <heartbeat.h>
#include <clplumbing/ipc.h>
#include <ha_msg.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <cib_private.h>

typedef struct cib_native_opaque_s 
{
		IPC_Channel	*command_channel;
		IPC_Channel	*callback_channel;
 		GCHSource	*callback_source; 
		
} cib_native_opaque_t;

int cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	crm_data_t *data, crm_data_t **output_data, int call_options);

int cib_native_signon(cib_t* cib, const char *name, enum cib_conn_type type);
int cib_native_signoff(cib_t* cib);
int cib_native_free(cib_t* cib);

IPC_Channel *cib_native_channel(cib_t* cib);
int cib_native_inputfd(cib_t* cib);

gboolean cib_native_msgready(cib_t* cib);
int cib_native_rcvmsg(cib_t* cib, int blocking);
gboolean cib_native_dispatch(IPC_Channel *channel, gpointer user_data);
cib_t *cib_native_new (cib_t *cib);
void cib_native_delete(cib_t *cib);
int cib_native_set_connection_dnotify(
	cib_t *cib, void (*dnotify)(gpointer user_data));

void cib_native_notify(gpointer data, gpointer user_data);

void cib_native_callback(cib_t *cib, struct ha_msg *msg);

int cib_native_register_callback(cib_t* cib, const char *callback, int enabled);

cib_t*
cib_native_new (cib_t *cib)
{
	cib_native_opaque_t *native = NULL;
	crm_malloc0(cib->variant_opaque, sizeof(cib_native_opaque_t));
	
	native = cib->variant_opaque;
	native->command_channel   = NULL;
	native->callback_channel  = NULL;

	/* assign variant specific ops*/
	cib->cmds->variant_op = cib_native_perform_op;
	cib->cmds->signon     = cib_native_signon;
	cib->cmds->signoff    = cib_native_signoff;
	cib->cmds->free       = cib_native_free;
	cib->cmds->channel    = cib_native_channel;
	cib->cmds->inputfd    = cib_native_inputfd;
	cib->cmds->msgready   = cib_native_msgready;
	cib->cmds->rcvmsg     = cib_native_rcvmsg;
	cib->cmds->dispatch   = cib_native_dispatch;

	cib->cmds->register_callback = cib_native_register_callback;
	cib->cmds->set_connection_dnotify = cib_native_set_connection_dnotify;
	
	return cib;
}

void
cib_native_delete(cib_t *cib)
{
	crm_free(cib->variant_opaque);
}

int
cib_native_signon(cib_t* cib, const char *name, enum cib_conn_type type)
{
	int rc = cib_ok;
	char *uuid_ticket = NULL;
	struct ha_msg *reg_msg = NULL;
	cib_native_opaque_t *native = cib->variant_opaque;
	
	crm_debug_4("Connecting command channel");
	if(type == cib_command) {
		cib->state = cib_connected_command;
		native->command_channel = init_client_ipc_comms_nodispatch(
			cib_channel_rw);
		
	} else if(type == cib_query) {
		cib->state = cib_connected_query;
		native->command_channel = init_client_ipc_comms_nodispatch(
			cib_channel_ro);
		
	} else if(type == cib_query_synchronous) {
		cib->state = cib_connected_query;
		native->command_channel = init_client_ipc_comms_nodispatch(
			cib_channel_ro_synchronous);
		
	} else if(type == cib_command_synchronous) {
		cib->state = cib_connected_query;
		native->command_channel = init_client_ipc_comms_nodispatch(
			cib_channel_rw_synchronous);
		
	} else {
		return cib_not_connected;		
	}
	
	if(native->command_channel == NULL) {
		crm_debug("Connection to command channel failed");
		rc = cib_connection;
		
	} else if(native->command_channel->ch_status != IPC_CONNECT) {
		crm_err("Connection may have succeeded,"
			" but authentication to command channel failed");
		rc = cib_authentication;
	}
	
	if(type == cib_query_synchronous || type == cib_command_synchronous) {
		return rc;
	}

	if(rc == cib_ok) {
		crm_debug_4("Connecting callback channel");
		native->callback_source = init_client_ipc_comms(
			cib_channel_callback, cib_native_dispatch,
			cib, &(native->callback_channel));
		
		if(native->callback_channel == NULL) {
			crm_debug("Connection to callback channel failed");
			rc = cib_connection;

		} else if(native->callback_channel->ch_status != IPC_CONNECT) {
			crm_err("Connection may have succeeded,"
				" but authentication to callback channel failed");
			rc = cib_authentication;
			
		} else if(native->callback_source == NULL) {
			crm_err("Callback source not recorded");
			rc = cib_connection;
		} else {
			native->callback_channel->send_queue->max_qlen = 500;
		}		
	}
	
	if(rc == cib_ok) {
		crm_debug_4("Waiting for msg on command channel");
		
		reg_msg = msgfromIPC(native->command_channel, MSG_ALLOWINTR);
		
		if(native->command_channel->ops->get_chan_status(
			   native->command_channel) != IPC_CONNECT) {
			crm_err("No reply message - disconnected - %d", rc);
			rc = cib_not_connected;
		
		} else if(rc != IPC_OK) {
			crm_err("No reply message - failed - %d", rc);
			rc = cib_reply_failed;
			
		} else if(reg_msg == NULL) {
			crm_err("No reply message - empty - %d", rc);
			rc = cib_reply_failed;
		}
	}
	
	if(rc == cib_ok) {
		const char *msg_type = NULL;
		msg_type = cl_get_string(reg_msg, F_CIB_OPERATION);
		if(safe_str_neq(msg_type, CRM_OP_REGISTER) ) {
			crm_err("Invalid registration message: %s", msg_type);
			rc = cib_registration_msg;

		} else {
			const char *tmp_ticket = NULL;
			crm_debug_4("Retrieving callback channel ticket");
			tmp_ticket = cl_get_string(
				reg_msg, F_CIB_CALLBACK_TOKEN);

			if(tmp_ticket == NULL) {
				rc = cib_callback_token;
			} else {
				uuid_ticket = crm_strdup(tmp_ticket);
			}
		}

	}

	if(reg_msg != NULL) {
		crm_msg_del(reg_msg);
		reg_msg = NULL;		
	}
	
	if(rc == cib_ok) {
		crm_debug_4("Registering callback channel with ticket %s",
			  crm_str(uuid_ticket));
		reg_msg = ha_msg_new(2);
		ha_msg_add(reg_msg, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(reg_msg, F_CIB_CALLBACK_TOKEN, uuid_ticket);
		ha_msg_add(reg_msg, F_CIB_CLIENTNAME, name);

		if(send_ipc_message(
			   native->callback_channel, reg_msg) == FALSE) {
			rc = cib_callback_register;
		}

		crm_msg_del(reg_msg);
		crm_free(uuid_ticket);
	}
	if(rc == cib_ok) {
		/* In theory IPC_INTR could trip us up here */
		crm_debug_4("wait for the callback channel setup to complete");
		reg_msg = msgfromIPC(native->callback_channel, MSG_ALLOWINTR);

		if(native->callback_channel->ops->get_chan_status(
			   native->callback_channel) != IPC_CONNECT) {
			crm_err("No reply message - disconnected - %d", rc);
			rc = cib_not_connected;
			
		} else if(reg_msg == NULL) {
			crm_err("No reply message - empty - %d", rc);
			rc = cib_reply_failed;
		}
		crm_msg_del(reg_msg);
	}
	
	if(rc == cib_ok) {
		crm_debug("Connection to CIB successful");
		return cib_ok;
	}
	crm_debug("Connection to CIB failed: %s", cib_error2string(rc));
	cib_native_signoff(cib);
	return rc;
}
	
int
cib_native_signoff(cib_t* cib)
{
	cib_native_opaque_t *native = cib->variant_opaque;

	crm_debug("Signing out of the CIB Service");
	
	/* close channels */
	if (native->command_channel != NULL) {
 		native->command_channel->ops->destroy(
			native->command_channel);
		native->command_channel = NULL;
	}

	if (native->callback_source != NULL) {
		G_main_del_IPC_Channel(native->callback_source);
		native->callback_source = NULL;
	}

	if (native->callback_channel != NULL) {
#ifdef BUG
 		native->callback_channel->ops->destroy(
			native->callback_channel);
#endif
		native->callback_channel = NULL;
	}

	cib->state = cib_disconnected;
	cib->type  = cib_none;

	return cib_ok;
}

int
cib_native_free (cib_t* cib)
{
	int rc = cib_ok;

	crm_warn("Freeing CIB");
	if(cib->state != cib_disconnected) {
		rc = cib_native_signoff(cib);
		if(rc == cib_ok) {
			crm_free(cib);
		}
	}
	
	return rc;
}

IPC_Channel *
cib_native_channel(cib_t* cib)
{
	cib_native_opaque_t *native = NULL;
	if(cib == NULL) {
		crm_err("Missing cib object");
		return NULL;
	}
	
	native = cib->variant_opaque;

	if(native != NULL) {
		return native->callback_channel;
	}

	crm_err("couldnt find variant specific data in %p", cib);
	return NULL;
}

int
cib_native_inputfd(cib_t* cib)
{
	IPC_Channel *ch = cib_native_channel(cib);
	return ch->ops->get_recv_select_fd(ch);
}

static HA_Message *
cib_create_op(
	int call_id, const char *op, const char *host, const char *section,
	crm_data_t *data, int call_options) 
{
	int  rc = HA_OK;
	HA_Message *op_msg = NULL;
	op_msg = ha_msg_new(9);
	CRM_CHECK(op_msg != NULL, return NULL);

	rc = ha_msg_add(op_msg, F_XML_TAGNAME, "cib_command");
	
	if(rc == HA_OK) {
		rc = ha_msg_add(op_msg, F_TYPE, T_CIB);
	}
	if(rc == HA_OK) {
		rc = ha_msg_add(op_msg, F_CIB_OPERATION, op);
	}
	if(rc == HA_OK && host != NULL) {
		rc = ha_msg_add(op_msg, F_CIB_HOST, host);
	}
	if(rc == HA_OK && section != NULL) {
		rc = ha_msg_add(op_msg, F_CIB_SECTION, section);
	}
	if(rc == HA_OK) {
		rc = ha_msg_add_int(op_msg, F_CIB_CALLID, call_id);
	}
	if(rc == HA_OK) {
		crm_debug_4("Sending call options: %.8lx, %d",
			  (long)call_options, call_options);
		rc = ha_msg_add_int(op_msg, F_CIB_CALLOPTS, call_options);
	}
#if 0
	if(rc == HA_OK && cib->call_timeout > 0) {
		rc = ha_msg_add_int(op_msg, F_CIB_TIMEOUT, cib->call_timeout);
	}
#endif
	if(rc == HA_OK && data != NULL) {
#if 0		
		const char *tag = crm_element_name(data);
		crm_data_t *cib = data;
		if(safe_str_neq(tag, XML_TAG_CIB)) {
			cib = find_xml_node(data, XML_TAG_CIB, FALSE);
			if(cib != NULL) {
				tag = XML_TAG_CIB;
			}
		}
		if(safe_str_eq(tag, XML_TAG_CIB)) {
			const char *version = feature_set(cib);
			crm_xml_add(cib, XML_ATTR_CIB_REVISION, version);
		} else {
			crm_info("Skipping feature check for %s tag", tag);
		}
#endif

		add_message_xml(op_msg, F_CIB_CALLDATA, data);
	}
	
	if (rc != HA_OK) {
		crm_err("Failed to create CIB operation message");
		crm_log_message(LOG_ERR, op_msg);
		crm_msg_del(op_msg);
		return NULL;
	}

	if(call_options & cib_inhibit_bcast) {
		CRM_CHECK((call_options & cib_scope_local), return NULL);
	}
	return op_msg;
}

int
cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	crm_data_t *data, crm_data_t **output_data, int call_options) 
{
	int  rc = HA_OK;
	
	struct ha_msg *op_msg   = NULL;
	struct ha_msg *op_reply = NULL;

 	cib_native_opaque_t *native = cib->variant_opaque;

	if(cib->state == cib_disconnected) {
		return cib_not_connected;
	}

	if(output_data != NULL) {
		*output_data = NULL;
	}
	
	if(op == NULL) {
		crm_err("No operation specified");
		return cib_operation;
	}

	cib->call_id++;
	/* prevent call_id from being negative (or zero) and conflicting
	 *    with the cib_errors enum
	 * use 2 because we use it as (cib->call_id - 1) below
	 */
	if(cib->call_id < 1) {
		cib->call_id = 1;
	}
	
	op_msg = cib_create_op(
		cib->call_id, op, host, section, data, call_options);
	if(op_msg == NULL) {
		return cib_create_msg;
	}
	
	crm_debug_3("Sending %s message to CIB service", op);
	if(send_ipc_message(native->command_channel, op_msg) == FALSE) {
		crm_err("Sending message to CIB service FAILED");
		crm_msg_del(op_msg);
		return cib_send_failed;

	} else {
		crm_debug_3("Message sent");
	}

	crm_msg_del(op_msg);

	if((call_options & cib_discard_reply)) {
		crm_debug_3("Discarding reply");
		return cib_ok;

	} else if(!(call_options & cib_sync_call)) {
		crm_debug_3("Async call, returning");
		CRM_CHECK(cib->call_id != 0, return cib_reply_failed);
		return cib->call_id;
	}

	rc = IPC_OK;
	crm_debug_3("Waiting for a syncronous reply");
	while(IPC_ISRCONN(native->command_channel)) {
		int reply_id = -1;
		int msg_id = cib->call_id;

		op_reply = msgfromIPC(native->command_channel, MSG_ALLOWINTR);
		if(op_reply == NULL) {
			break;
		}
		CRM_CHECK(ha_msg_value_int(
				  op_reply, F_CIB_CALLID, &reply_id) == HA_OK,
			  crm_msg_del(op_reply);
			  return cib_reply_failed);

		if(reply_id == msg_id) {
			break;
			
		} else if(reply_id < msg_id) {
			crm_debug("Recieved old reply: %d (wanted %d)",
				  reply_id, msg_id);
			crm_log_message_adv(
				LOG_MSG, "Old reply", op_reply);

		} else if((reply_id - 10000) > msg_id) {
			/* wrap-around case */
			crm_debug("Recieved old reply: %d (wanted %d)",
				  reply_id, msg_id);
			crm_log_message_adv(
				LOG_MSG, "Old reply", op_reply);
		} else {
			crm_err("Received a __future__ reply:"
				" %d (wanted %d)", reply_id, msg_id);
		}
		crm_msg_del(op_reply);
		op_reply = NULL;
	}

	if(op_reply == NULL) {
		if(IPC_ISRCONN(native->command_channel) == FALSE) {
			crm_err("No reply message - disconnected - %d",
				native->command_channel->ch_status);
			cib->state = cib_disconnected;
			return cib_not_connected;
		}
		crm_err("No reply message - empty - %d", rc);
		return cib_reply_failed;
	}
	
	if(IPC_ISRCONN(native->command_channel) == FALSE) {
		crm_err("CIB disconnected: %d", 
			native->command_channel->ch_status);
		cib->state = cib_disconnected;
	}
	
	crm_debug_3("Syncronous reply recieved");
	rc = cib_ok;
	
	/* Start processing the reply... */
	if(ha_msg_value_int(op_reply, F_CIB_RC, &rc) != HA_OK) {
		rc = cib_return_code;
	}	

	if(rc == cib_diff_resync) {
	    /* This is an internal value that clients do not and should not care about */
	    rc = cib_ok;
	}
	
	if(rc == cib_ok || rc == cib_not_master || rc == cib_master_timeout) {
		crm_log_message(LOG_MSG, op_reply);

	} else {
/* 	} else if(rc == cib_remote_timeout) { */
		crm_err("Call failed: %s", cib_error2string(rc));
		crm_log_message(LOG_WARNING, op_reply);
	}
	
	if(output_data == NULL) {
		/* do nothing more */
		
	} else if(!(call_options & cib_discard_reply)) {
		*output_data = get_message_xml(op_reply, F_CIB_CALLDATA);
		if(*output_data == NULL) {
			crm_debug_3("No output in reply to \"%s\" command %d",
				  op, cib->call_id - 1);
		}
	}
	
	crm_msg_del(op_reply);

	return rc;
}

gboolean
cib_native_msgready(cib_t* cib)
{
	cib_native_opaque_t *native = NULL;
	
	if (cib == NULL) {
		crm_err("No CIB!");
		return FALSE;
	}

	native = cib->variant_opaque;

	if(native->command_channel != NULL) {
		/* drain the channel */
		IPC_Channel *cmd_ch = native->command_channel;
		HA_Message *cmd_msg = NULL;
		while(cmd_ch->ch_status != IPC_DISCONNECT
		      && cmd_ch->ops->is_message_pending(cmd_ch)) {
		    /* this will happen when the CIB exited from beneath us */
		    cmd_msg = msgfromIPC_noauth(cmd_ch);
		    crm_msg_del(cmd_msg);
		}

	} else {
		crm_err("No command channel");
	}	

	if(native->callback_channel == NULL) {
		crm_err("No callback channel");
		return FALSE;

	} else if(native->callback_channel->ch_status == IPC_DISCONNECT) {
		crm_info("Lost connection to the CIB service [%d].",
			 native->callback_channel->farside_pid);
		return FALSE;

	} else if(native->callback_channel->ops->is_message_pending(
			  native->callback_channel)) {
		crm_debug_4("Message pending on command channel [%d]",
			    native->callback_channel->farside_pid);
		return TRUE;
	}

	crm_debug_3("No message pending");
	return FALSE;
}

int
cib_native_rcvmsg(cib_t* cib, int blocking)
{
	const char *type = NULL;
	struct ha_msg* msg = NULL;
	cib_native_opaque_t *native = NULL;
	
	if (cib == NULL) {
		crm_err("No CIB!");
		return FALSE;
	}

	native = cib->variant_opaque;
	
	/* if it is not blocking mode and no message in the channel, return */
	if (blocking == 0 && cib_native_msgready(cib) == FALSE) {
		crm_debug_3("No message ready and non-blocking...");
		return 0;

	} else if (cib_native_msgready(cib) == FALSE) {
		crm_debug("Waiting for message from CIB service...");
		if(native->callback_channel == NULL) {
			return 0;
			
		} else if(native->callback_channel->ch_status != IPC_CONNECT) {
			return 0;
			
		} else if(native->command_channel
			  && native->command_channel->ch_status != IPC_CONNECT){
			return 0;
		}
		native->callback_channel->ops->waitin(native->callback_channel);
	}

	/* IPC_INTR is not a factor here */
	msg = msgfromIPC_noauth(native->callback_channel);
	if (msg == NULL) {
		crm_warn("Received a NULL msg from CIB service.");
		return 0;
	}

	/* do callbacks */
	type = cl_get_string(msg, F_TYPE);
	crm_debug_4("Activating %s callbacks...", type);

	if(safe_str_eq(type, T_CIB)) {
		cib_native_callback(cib, msg);
		
	} else if(safe_str_eq(type, T_CIB_NOTIFY)) {
		g_list_foreach(cib->notify_list, cib_native_notify, msg);

	} else {
		crm_err("Unknown message type: %s", type);
	}
	
	crm_msg_del(msg);

	return 1;
}

void
cib_native_callback(cib_t *cib, struct ha_msg *msg)
{
	int rc = 0;
	int call_id = 0;
	crm_data_t *output = NULL;

	cib_callback_client_t *blob = NULL;

	cib_callback_client_t local_blob;

	/* gcc4 had a point... make sure (at least) local_blob.callback
	 *   is initialized before use
	 */
	local_blob.callback = NULL;
	local_blob.user_data = NULL;
	local_blob.only_success = FALSE;

	ha_msg_value_int(msg, F_CIB_CALLID, &call_id);

	blob = g_hash_table_lookup(
		cib_op_callback_table, GINT_TO_POINTER(call_id));
	
	if(blob != NULL) {
		crm_debug_3("Callback found for call %d", call_id);
/* 		local_blob.callback = blob->callback; */
/* 		local_blob.user_data = blob->user_data; */
/* 		local_blob.only_success = blob->only_success; */
		local_blob = *blob;
		blob = NULL;
		
		g_hash_table_remove(
			cib_op_callback_table, GINT_TO_POINTER(call_id));
	} else {
		crm_debug_3("No callback found for call %d", call_id);
		local_blob.callback = NULL;
	}

	ha_msg_value_int(msg, F_CIB_RC, &rc);
	if(rc == cib_diff_resync) {
	    /* This is an internal value that clients do not and should not care about */
	    rc = cib_ok;
	}

	output = get_message_xml(msg, F_CIB_CALLDATA);
	
	if(local_blob.callback != NULL
	   && (rc == cib_ok || local_blob.only_success == FALSE)) {
		local_blob.callback(
			msg, call_id, rc, output, local_blob.user_data);
		
	} else if(cib->op_callback == NULL && rc != cib_ok) {
		crm_warn("CIB command failed: %s", cib_error2string(rc));
		crm_log_message_adv(LOG_DEBUG, "Failed CIB Update", msg);
	}
	
	if(cib->op_callback == NULL) {
		crm_debug_3("No OP callback set, ignoring reply");
	} else {
		cib->op_callback(msg, call_id, rc, output);
	}
	free_xml(output);
	
	crm_debug_4("OP callback activated.");
}


void
cib_native_notify(gpointer data, gpointer user_data)
{
	struct ha_msg *msg = user_data;
	cib_notify_client_t *entry = data;
	const char *event = NULL;

	if(msg == NULL) {
		crm_warn("Skipping callback - NULL message");
		return;
	}

	event = cl_get_string(msg, F_SUBTYPE);
	
	if(entry == NULL) {
		crm_warn("Skipping callback - NULL callback client");
		return;

	} else if(entry->callback == NULL) {
		crm_warn("Skipping callback - NULL callback");
		return;

	} else if(safe_str_neq(entry->event, event)) {
		crm_debug_4("Skipping callback - event mismatch %p/%s vs. %s",
			  entry, entry->event, event);
		return;
	}
	
	crm_debug_4("Invoking callback for %p/%s event...", entry, event);
	entry->callback(event, msg);
	crm_debug_4("Callback invoked...");
}

gboolean
cib_native_dispatch(IPC_Channel *channel, gpointer user_data)
{
	int lpc = 0;
	cib_t *cib = user_data;
	cib_native_opaque_t *native = NULL;

	crm_debug_3("Received callback");

	if(user_data == NULL){
		crm_err("user_data field must contain the CIB struct");
		return FALSE;
	}

	native = cib->variant_opaque;
	
	while(cib_native_msgready(cib)) {
 		lpc++; 
		/* invoke the callbacks but dont block */
		if(cib_native_rcvmsg(cib, 0) < 1) {
			break;
		}
	}

	crm_debug_3("%d CIB messages dispatched", lpc);

	if(native->callback_channel
	   && native->callback_channel->ch_status != IPC_CONNECT) {
		crm_crit("Lost connection to the CIB service [%d/callback].",
			channel->farside_pid);

		if(native->callback_source != NULL) {
		    G_main_del_IPC_Channel(native->callback_source);
		    native->callback_source = NULL;
		}

		return FALSE;

	} else if(native->command_channel
		  && native->command_channel->ch_status != IPC_CONNECT) {
		crm_crit("Lost connection to the CIB service [%d/command].",
			channel->farside_pid);

		return FALSE;
	}

	return TRUE;
}

int cib_native_set_connection_dnotify(
	cib_t *cib, void (*dnotify)(gpointer user_data))
{
	cib_native_opaque_t *native = NULL;
	
	if (cib == NULL) {
		crm_err("No CIB!");
		return FALSE;
	}

	native = cib->variant_opaque;

	if(dnotify == NULL) {
		crm_warn("Setting dnotify back to default value");
		set_IPC_Channel_dnotify(native->callback_source,
					default_ipc_connection_destroy);

	} else {
		crm_debug_3("Setting dnotify");
		set_IPC_Channel_dnotify(native->callback_source, dnotify);
	}
	return cib_ok;
}


int
cib_native_register_callback(cib_t* cib, const char *callback, int enabled) 
{
	HA_Message *notify_msg = ha_msg_new(3);
	cib_native_opaque_t *native = cib->variant_opaque;

	/* short term hack - should make this generic somehow */
	ha_msg_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
	ha_msg_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
	ha_msg_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
	send_ipc_message(native->callback_channel, notify_msg);
	crm_msg_del(notify_msg);
	return cib_ok;
}

