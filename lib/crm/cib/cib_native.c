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
#include <portability.h>
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
#include <crm/common/ipc.h>

typedef struct cib_native_opaque_s 
{
		IPC_Channel	*command_channel;
		IPC_Channel	*callback_channel;
 		GCHSource	*callback_source; 
		
} cib_native_opaque_t;

int cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	xmlNodePtr data, xmlNodePtr *output_data, int call_options);

int cib_native_signon(cib_t* cib, enum cib_conn_type type);
int cib_native_signoff(cib_t* cib);
int cib_native_free(cib_t* cib);

IPC_Channel *cib_native_channel(cib_t* cib);
int cib_native_inputfd(cib_t* cib);

gboolean cib_native_msgready(cib_t* cib);
int cib_native_rcvmsg(cib_t* cib, int blocking);
gboolean cib_native_dispatch(IPC_Channel *channel, gpointer user_data);
cib_t *cib_native_new (cib_t *cib);
int cib_native_set_connection_dnotify(
	cib_t *cib, void (*dnotify)(gpointer user_data));

void cib_native_notify(gpointer data, gpointer user_data);

void cib_native_callback(cib_t *cib, struct ha_msg *msg);


cib_t*
cib_native_new (cib_t *cib)
{
	cib_native_opaque_t *native = NULL;
	crm_malloc(cib->variant_opaque, sizeof(cib_native_opaque_t));
	
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

	cib->cmds->set_connection_dnotify = cib_native_set_connection_dnotify;
	
	return cib;
}

int
cib_native_signon(cib_t* cib, enum cib_conn_type type)
{
	int rc = cib_ok;
	char *uuid_ticket = NULL;
	struct ha_msg *reg_msg = NULL;
	cib_native_opaque_t *native = cib->variant_opaque;

	crm_trace("Connecting command channel");
	if(type == cib_command) {
		cib->state = cib_connected_command;
		native->command_channel = init_client_ipc_comms_nodispatch(
			cib_channel_rw);

	} else {
		cib->state = cib_connected_query;
		native->command_channel = init_client_ipc_comms_nodispatch(
			cib_channel_ro);
	}

	if(native->command_channel == NULL) {
		crm_err("Connection to command channel failed");
		rc = cib_connection;
		
	} else if(native->command_channel->ch_status != IPC_CONNECT) {
		crm_err("Connection may have succeeded,"
			" but authentication to command channel failed");
		rc = cib_authentication;
	}

	if(rc == cib_ok) {
		crm_trace("Connecting callback channel");
		native->callback_source = init_client_ipc_comms(
			cib_channel_callback, cib_native_dispatch, cib, &(native->callback_channel));
		
		if(native->callback_channel == NULL) {
			crm_err("Connection to callback channel failed");
			rc = cib_connection;
		}
		
	} else if(rc == cib_ok
		  && native->callback_channel->ch_status != IPC_CONNECT) {
		crm_err("Connection may have succeeded,"
			" but authentication to callback channel failed");
		rc = cib_authentication;
	}

	if(rc == cib_ok) {
		const char *msg_type = NULL;
		crm_trace("Waiting for msg on command channel");
		reg_msg = msgfromIPC_noauth(native->command_channel);

		msg_type = cl_get_string(reg_msg, F_CIB_OPERATION);
		if(safe_str_neq(msg_type, CRM_OP_REGISTER) ) {
			crm_err("Invalid registration message: %s", msg_type);
			rc = cib_registration_msg;

		} else {
			const char *tmp_ticket = NULL;
			crm_trace("Retrieving callback channel ticket");
			tmp_ticket = cl_get_string(
				reg_msg, F_CIB_CALLBACK_TOKEN);

			if(tmp_ticket == NULL) {
				rc = cib_callback_token;
			} else {
				uuid_ticket = crm_strdup(tmp_ticket);
			}
		}

		ha_msg_del(reg_msg);
		reg_msg = NULL;		
	}

	if(rc == cib_ok) {
		crm_trace("Registering callback channel with ticket %s",
			uuid_ticket);
		reg_msg = ha_msg_new(2);
		ha_msg_add(reg_msg, F_CIB_OPERATION, CRM_OP_REGISTER);
		ha_msg_add(reg_msg, F_CIB_CALLBACK_TOKEN, uuid_ticket);
		if(msg2ipcchan(reg_msg, native->callback_channel) != HA_OK) {
			rc = cib_callback_register;
		}
		crm_free(uuid_ticket);
		ha_msg_del(reg_msg);

	}
	if(rc == cib_ok) {
		crm_trace("wait for the callback channel setup to complete");
		reg_msg = msgfromIPC_noauth(native->callback_channel);

		if(reg_msg == NULL) {
			crm_err("Connection to callback channel not maintined");
			rc = cib_connection;
		}
		ha_msg_del(reg_msg);
	}
	
	if(rc == cib_ok) {
		crm_info("Connection to CIB successful");
		return cib_ok;
	}
	crm_err("Connection to CIB failed: %s", cib_error2string(rc));
	cib_native_signoff(cib);
	return rc;
}

int
cib_native_signoff(cib_t* cib)
{
	cib_native_opaque_t *native = cib->variant_opaque;

	crm_info("Signing out of the CIB Service");
	
	/* close channels */
	if (native->command_channel != NULL) {
 		native->command_channel->ops->destroy(
			native->command_channel);
		native->command_channel = NULL;
	}
	if (native->callback_channel != NULL) {
 		native->callback_channel->ops->destroy(
			native->callback_channel);
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

int
cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	xmlNodePtr data, xmlNodePtr *output_data, int call_options) 
{
	int  rc = HA_OK;

	const char *output = NULL;
	
	struct ha_msg *op_msg   = NULL;
	struct ha_msg *op_reply = NULL;

 	cib_native_opaque_t *native = cib->variant_opaque;

	if(cib->state ==  cib_disconnected) {
		return cib_not_connected;
	}

	if(output_data != NULL) {
		*output_data = NULL;
	}
	
	op_msg = ha_msg_new(7);
	if(op == NULL) {
		crm_err("No operation specified");
		rc = cib_operation;
	}
	
	if(rc == HA_OK) {
		rc = ha_msg_add(op_msg, F_TYPE, "cib");
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
		char *tmp = crm_itoa(cib->call_id);
		rc = ha_msg_add(op_msg, F_CIB_CALLID, tmp);
		crm_free(tmp);
	}
	if(rc == HA_OK) {
		char *tmp = crm_itoa(call_options);
		crm_trace("Sending call options: %.8lx, %d, %s",
			  (long)call_options, call_options, tmp);
		rc = ha_msg_add(op_msg, F_CIB_CALLOPTS, tmp);
		crm_free(tmp);
	}
	if(rc == HA_OK) {
		char *calldata = dump_xml_unformatted(data);
		if(calldata != NULL) {
			rc = ha_msg_add(op_msg, F_CIB_CALLDATA, calldata);
		} else {
			crm_debug("Calldata string was NULL (xml=%p)", data);
		}

		crm_free(calldata);
	}
	
	if (rc != HA_OK) {
		ha_msg_del(op_msg);
		crm_err("Failed to create CIB operation message");
		return cib_create_msg;
	}

	cib->call_id++;

	crm_debug("Sending message to CIB service");
/* 	cl_log_message(op_msg); */
	rc = msg2ipcchan(op_msg, native->command_channel);
	ha_msg_del(op_msg);
	
	if (rc != HA_OK) {
		return cib_send_failed;
	}

	if((call_options & cib_discard_reply)) {
		return cib_ok;

	} else if(!(call_options & cib_sync_call)) {
		return cib->call_id - 1;
	}

	op_reply = msgfromIPC_noauth(native->command_channel);
	if (op_reply == NULL) {
		crm_err("No reply message");
		return cib_reply_failed;
	}

	rc = cib_ok;
	
	/* Start processing the reply... */
	if(ha_msg_value_int(op_reply, F_CIB_RC, &rc) != HA_OK) {
		rc = cib_return_code;
	}	
	
	if(!(call_options & cib_discard_reply)) {
		output = cl_get_string(op_msg, F_CIB_CALLDATA);
	}

	if(output_data == NULL) {
		/* do nothing more */
		
	} else if(output != NULL) {
		*output_data = string2xml(output);
		if(*output_data == NULL) {
			rc = cib_output_data;
		}
	} else {
		crm_debug("No output in reply to \"%s\" command %d",
			  op, cib->call_id - 1);
	}
	
	ha_msg_del(op_reply);

	return rc;
}

gboolean
cib_native_msgready(cib_t* cib)
{
	IPC_Channel *ch = NULL;
	cib_native_opaque_t *native = NULL;
	
	if (cib == NULL) {
		crm_err("No CIB!");
		return FALSE;
	}

	native = cib->variant_opaque;

	ch = cib_native_channel(cib);
	if (ch == NULL) {
		crm_err("No channel");
		return FALSE;
	}

	if(native->command_channel->ops->is_message_pending(
		   native->command_channel)) {
		crm_verbose("Message pending on command channel");
	}
	if(native->callback_channel->ops->is_message_pending(
		   native->callback_channel)) {
		crm_trace("Message pending on callback channel");
		return TRUE;
	} 
	crm_verbose("No message pending");
	return FALSE;
}

int
cib_native_rcvmsg(cib_t* cib, int blocking)
{
	const char *type = NULL;
	struct ha_msg* msg = NULL;
	IPC_Channel *ch = cib_native_channel(cib);

	/* if it is not blocking mode and no message in the channel, return */
	if (blocking == 0 && cib_native_msgready(cib) == FALSE) {
		crm_debug("No message ready and non-blocking...");
		return 0;

	} else if (cib_native_msgready(cib) == FALSE) {
		crm_debug("Waiting for message from CIB service...");
		ch->ops->waitin(ch);
	}
	
	/* get the message */
	msg = msgfromIPC_noauth(ch);
	if (msg == NULL) {
		crm_warn("Received a NULL msg from CIB service.");
		return 0;
	}

	/* do callbacks */
	type = cl_get_string(msg, F_TYPE);
	crm_trace("Activating %s callbacks...", type);

	if(safe_str_eq(type, T_CIB)) {
		cib_native_callback(cib, msg);
		
	} else if(safe_str_eq(type, T_CIB_NOTIFY)) {
		g_list_foreach(cib->notify_list, cib_native_notify, msg);

	} else {
		crm_err("Unknown message type: %s", type);
	}
	
	ha_msg_del(msg);

	return 1;
}

void
cib_native_callback(cib_t *cib, struct ha_msg *msg)
{
	int rc = 0;
	int call_id = 0;
	xmlNodePtr output = NULL;
	const char *output_s = NULL;

	if(cib->op_callback == NULL) {
		crm_debug("No OP callback set, ignoring reply");
		return;
	}
	
	ha_msg_value_int(msg, F_CIB_CALLID, &call_id);
	ha_msg_value_int(msg, F_CIB_RC, &rc);
	output_s = cl_get_string(msg, F_CIB_CALLDATA);
	if(output_s != NULL) {
		output = string2xml(output_s);
	}
	
	cib->op_callback(msg, call_id, rc, output);
	
	crm_trace("OP callback activated.");
}


void
cib_native_notify(gpointer data, gpointer user_data)
{
	struct ha_msg *msg = user_data;
	cib_notify_client_t *entry = data;
	const char *event = cl_get_string(msg, F_SUBTYPE);

	if(entry == NULL) {
		crm_warn("Skipping callback - NULL callback client");
		return;

	} else if(entry->callback == NULL) {
		crm_warn("Skipping callback - NULL callback");
		return;

	} else if(safe_str_neq(entry->event, event)) {
		crm_trace("Skipping callback - event mismatch %p/%s vs. %s",
			  entry, entry->event, event);
		return;
	}
	
	crm_trace("Invoking callback for %p/%s event...", entry, event);
	entry->callback(event, msg);
}

gboolean
cib_native_dispatch(IPC_Channel *channel, gpointer user_data)
{
	int lpc = 0;
	cib_t *cib = user_data;

	crm_debug("Received callback");

	if(user_data == NULL){
		crm_err("user_data field must contain the CIB struct");
		return FALSE;
	}
	
	while(cib_native_msgready(cib)) {
 		lpc++; 
		/* invoke the callbacks but dont block */
		if(cib_native_rcvmsg(cib, 0) < 1) {
			break;
		}
	}

	crm_debug("%d CIB messages dispatched", lpc);

	if (channel && (channel->ch_status == IPC_DISCONNECT)) {
		crm_crit("Lost connection to the CIB service.");
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
		crm_debug("Setting dnotify");
		set_IPC_Channel_dnotify(native->callback_source, dnotify);
	}
	return cib_ok;
}


