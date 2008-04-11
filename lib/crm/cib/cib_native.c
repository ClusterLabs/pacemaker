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
#include <clplumbing/Gmain_timeout.h>

typedef struct cib_native_opaque_s 
{
		IPC_Channel	*command_channel;
		IPC_Channel	*callback_channel;
 		GCHSource	*callback_source; 
		
} cib_native_opaque_t;

int cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	xmlNode *data, xmlNode **output_data, int call_options);

int cib_native_signon(cib_t* cib, const char *name, enum cib_conn_type type);
int cib_native_signoff(cib_t* cib);
int cib_native_free(cib_t* cib);

IPC_Channel *cib_native_channel(cib_t* cib);
int cib_native_inputfd(cib_t* cib);

gboolean cib_native_msgready(cib_t* cib);
int cib_native_rcvmsg(cib_t* cib, int blocking);
gboolean cib_native_dispatch(IPC_Channel *channel, gpointer user_data);
int cib_native_set_connection_dnotify(
	cib_t *cib, void (*dnotify)(gpointer user_data));

void cib_native_notify(gpointer data, gpointer user_data);

void cib_native_callback(cib_t *cib, xmlNode *msg);

int cib_native_register_callback(cib_t* cib, const char *callback, int enabled);

cib_t*
cib_native_new (void)
{
	cib_native_opaque_t *native = NULL;
	cib_t *cib = cib_new_variant();
	
	crm_malloc0(native, sizeof(cib_native_opaque_t));
	
	cib->variant = cib_native;
	cib->variant_opaque = native;

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

int
cib_native_signon(cib_t* cib, const char *name, enum cib_conn_type type)
{
	int rc = cib_ok;
	char *uuid_ticket = NULL;
	xmlNode *reg_msg = NULL;
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
		
		reg_msg = xmlfromIPC(native->command_channel, 0);
		
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
		msg_type = crm_element_value(reg_msg, F_CIB_OPERATION);
		if(safe_str_neq(msg_type, CRM_OP_REGISTER) ) {
			crm_err("Invalid registration message: %s", msg_type);
			rc = cib_registration_msg;

		} else {
			const char *tmp_ticket = NULL;
			crm_debug_4("Retrieving callback channel ticket");
			tmp_ticket = crm_element_value(
				reg_msg, F_CIB_CALLBACK_TOKEN);

			if(tmp_ticket == NULL) {
				rc = cib_callback_token;
			} else {
				uuid_ticket = crm_strdup(tmp_ticket);
			}
		}

	}

	if(reg_msg != NULL) {
	    free_xml(reg_msg);
	    reg_msg = NULL;		
	}
	
	if(rc == cib_ok) {
		crm_debug_4("Registering callback channel with ticket %s",
			  crm_str(uuid_ticket));
		reg_msg = create_xml_node(NULL, __FUNCTION__);
		crm_xml_add(reg_msg, F_CIB_OPERATION, CRM_OP_REGISTER);
		crm_xml_add(reg_msg, F_CIB_CALLBACK_TOKEN, uuid_ticket);
		crm_xml_add(reg_msg, F_CIB_CLIENTNAME, name);

		if(send_ipc_message(
			   native->callback_channel, reg_msg) == FALSE) {
			rc = cib_callback_register;
		}

		free_xml(reg_msg);
		crm_free(uuid_ticket);
	}
	if(rc == cib_ok) {
		/* In theory IPC_INTR could trip us up here */
		crm_debug_4("wait for the callback channel setup to complete");
		reg_msg = xmlfromIPC(native->callback_channel, 0);

		if(native->callback_channel->ops->get_chan_status(
			   native->callback_channel) != IPC_CONNECT) {
			crm_err("No reply message - disconnected - %d", rc);
			rc = cib_not_connected;
			
		} else if(reg_msg == NULL) {
			crm_err("No reply message - empty - %d", rc);
			rc = cib_reply_failed;
		}
		free_xml(reg_msg);
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
			crm_free(cib->variant_opaque);
			crm_free(cib->cmds);
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

static xmlNode *
cib_create_op(
	int call_id, const char *op, const char *host, const char *section,
	xmlNode *data, int call_options) 
{
	int  rc = HA_OK;
	xmlNode *op_msg = create_xml_node(NULL, "cib-op");
	CRM_CHECK(op_msg != NULL, return NULL);

	crm_xml_add(op_msg, F_XML_TAGNAME, "cib_command");
	
	crm_xml_add(op_msg, F_TYPE, T_CIB);
	crm_xml_add(op_msg, F_CIB_OPERATION, op);
	crm_xml_add(op_msg, F_CIB_HOST, host);
	crm_xml_add(op_msg, F_CIB_SECTION, section);
	crm_xml_add_int(op_msg, F_CIB_CALLID, call_id);
	crm_debug_4("Sending call options: %.8lx, %d",
		    (long)call_options, call_options);
	crm_xml_add_int(op_msg, F_CIB_CALLOPTS, call_options);

	if(data != NULL) {
#if 0		
		const char *tag = crm_element_name(data);
		xmlNode *cib = data;
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
		crm_log_xml(LOG_ERR, "op", op_msg);
		free_xml(op_msg);
		return NULL;
	}

	if(call_options & cib_inhibit_bcast) {
		CRM_CHECK((call_options & cib_scope_local), return NULL);
	}
	return op_msg;
}

static gboolean timer_expired = FALSE;
static struct timer_rec_s *sync_timer = NULL;
static gboolean cib_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;
    timer_expired = TRUE;
    crm_err("Call %d timed out after %ds", timer->call_id, timer->timeout);

    /* Always return TRUE, never remove the handler
     * We do that after the while-loop in cib_native_perform_op()
     */
    return TRUE;
}

int
cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	xmlNode *data, xmlNode **output_data, int call_options) 
{
	int  rc = HA_OK;
	
	xmlNode *op_msg   = NULL;
	xmlNode *op_reply = NULL;

 	cib_native_opaque_t *native = cib->variant_opaque;
	if(sync_timer == NULL) {
	    crm_malloc0(sync_timer, sizeof(struct timer_rec_s));
	}
	
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
		free_xml(op_msg);
		return cib_send_failed;

	} else {
		crm_debug_3("Message sent");
	}

	free_xml(op_msg);

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

	if(cib->call_timeout > 0) {
	    /* We need this, even with msgfromIPC_timeout(), because we might
	     * get other/older replies that don't match the active request
	     */
	    timer_expired = FALSE;
	    sync_timer->call_id = cib->call_id;
	    sync_timer->timeout = cib->call_timeout*1000;
	    sync_timer->ref = Gmain_timeout_add(
		sync_timer->timeout, cib_timeout_handler, sync_timer);
	}

	while(timer_expired == FALSE && IPC_ISRCONN(native->command_channel)) {
		int reply_id = -1;
		int msg_id = cib->call_id;

		op_reply = xmlfromIPC(native->command_channel, cib->call_timeout);
		if(op_reply == NULL) {
			break;
		}

		crm_element_value_int(op_reply, F_CIB_CALLID, &reply_id);
		CRM_CHECK(reply_id > 0,
			  free_xml(op_reply);
			  if(sync_timer->ref > 0) {
			      g_source_remove(sync_timer->ref);
			      sync_timer->ref = 0;
			  }
			  return cib_reply_failed);

		if(reply_id == msg_id) {
			break;
			
		} else if(reply_id < msg_id) {
			crm_debug("Recieved old reply: %d (wanted %d)",
				  reply_id, msg_id);
			crm_log_xml(
				LOG_MSG, "Old reply", op_reply);

		} else if((reply_id - 10000) > msg_id) {
			/* wrap-around case */
			crm_debug("Recieved old reply: %d (wanted %d)",
				  reply_id, msg_id);
			crm_log_xml(
				LOG_MSG, "Old reply", op_reply);
		} else {
			crm_err("Received a __future__ reply:"
				" %d (wanted %d)", reply_id, msg_id);
		}
		free_xml(op_reply);
		op_reply = NULL;
	}

	if(sync_timer->ref > 0) {
	    g_source_remove(sync_timer->ref);
	    sync_timer->ref = 0;
	}
	
	if(timer_expired) {
	    return cib_remote_timeout;
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
	if(crm_element_value_int(op_reply, F_CIB_RC, &rc) != 0) {
		rc = cib_return_code;
	}	

	if(rc == cib_diff_resync) {
	    /* This is an internal value that clients do not and should not care about */
	    rc = cib_ok;
	}
	
	if(rc == cib_ok || rc == cib_not_master || rc == cib_master_timeout) {
	    crm_log_xml(LOG_MSG, "passed", op_reply);

	} else {
/* 	} else if(rc == cib_remote_timeout) { */
		crm_err("Call failed: %s", cib_error2string(rc));
		crm_log_xml(LOG_WARNING, "failed", op_reply);
	}
	
	if(output_data == NULL) {
		/* do nothing more */
		
	} else if(!(call_options & cib_discard_reply)) {
		xmlNode *tmp = get_message_xml(op_reply, F_CIB_CALLDATA);
		if(tmp == NULL) {
			crm_debug_3("No output in reply to \"%s\" command %d",
				  op, cib->call_id - 1);
		} else {
		    *output_data = copy_xml(tmp);
		}
	}
	
	free_xml(op_reply);

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
		xmlNode *cmd_msg = NULL;
		while(cmd_ch->ch_status != IPC_DISCONNECT
		      && cmd_ch->ops->is_message_pending(cmd_ch)) {
		    /* this will happen when the CIB exited from beneath us */
		    cmd_msg = xmlfromIPC(cmd_ch, 0);
		    free_xml(cmd_msg);
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
	xmlNode* msg = NULL;
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
	msg = xmlfromIPC(native->callback_channel, 0);
	if (msg == NULL) {
		crm_warn("Received a NULL msg from CIB service.");
		return 0;
	}

	/* do callbacks */
	type = crm_element_value(msg, F_TYPE);
	crm_debug_4("Activating %s callbacks...", type);

	if(safe_str_eq(type, T_CIB)) {
		cib_native_callback(cib, msg);
		
	} else if(safe_str_eq(type, T_CIB_NOTIFY)) {
		g_list_foreach(cib->notify_list, cib_native_notify, msg);

	} else {
		crm_err("Unknown message type: %s", type);
	}
	
	free_xml(msg);

	return 1;
}

void
cib_native_callback(cib_t *cib, xmlNode *msg)
{
	int rc = 0;
	int call_id = 0;
	xmlNode *output = NULL;

	cib_callback_client_t *blob = NULL;

	cib_callback_client_t local_blob;

	/* gcc4 had a point... make sure (at least) local_blob.callback
	 *   is initialized before use
	 */
	local_blob.callback = NULL;
	local_blob.user_data = NULL;
	local_blob.only_success = FALSE;

	crm_element_value_int(msg, F_CIB_CALLID, &call_id);
	blob = g_hash_table_lookup(
		cib_op_callback_table, GINT_TO_POINTER(call_id));
	
	if(blob != NULL) {
		crm_debug_3("Callback found for call %d", call_id);
/* 		local_blob.callback = blob->callback; */
/* 		local_blob.user_data = blob->user_data; */
/* 		local_blob.only_success = blob->only_success; */
		local_blob = *blob;
		blob = NULL;
		
		remove_cib_op_callback(call_id, FALSE);

	} else {
		crm_debug_3("No callback found for call %d", call_id);
		local_blob.callback = NULL;
	}

	crm_element_value_int(msg, F_CIB_RC, &rc);
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
		crm_log_xml(LOG_DEBUG, "Failed CIB Update", msg);
	}
	
	if(cib->op_callback == NULL) {
		crm_debug_3("No OP callback set, ignoring reply");
	} else {
		cib->op_callback(msg, call_id, rc, output);
	}
	crm_debug_4("OP callback activated.");
}


void
cib_native_notify(gpointer data, gpointer user_data)
{
	xmlNode *msg = user_data;
	cib_notify_client_t *entry = data;
	const char *event = NULL;

	if(msg == NULL) {
		crm_warn("Skipping callback - NULL message");
		return;
	}

	event = crm_element_value(msg, F_SUBTYPE);
	
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
	xmlNode *notify_msg = create_xml_node(NULL, "cib-callback");
	cib_native_opaque_t *native = cib->variant_opaque;

	/* short term hack - should make this generic somehow */
	crm_xml_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
	crm_xml_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
	crm_xml_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
	send_ipc_message(native->callback_channel, notify_msg);
	free_xml(notify_msg);
	return cib_ok;
}

