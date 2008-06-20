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
		char *token;
		
} cib_native_opaque_t;

int cib_native_perform_op(
	cib_t *cib, const char *op, const char *host, const char *section,
	xmlNode *data, xmlNode **output_data, int call_options);

int cib_native_free(cib_t* cib);
int cib_native_signoff(cib_t* cib);
int cib_native_signon(cib_t* cib, const char *name, enum cib_conn_type type);

IPC_Channel *cib_native_channel(cib_t* cib);
gboolean     cib_native_msgready(cib_t* cib);
gboolean     cib_native_dispatch(IPC_Channel *channel, gpointer user_data);

int cib_native_inputfd(cib_t* cib);
int cib_native_rcvmsg(cib_t* cib, int blocking);
int cib_native_set_connection_dnotify(cib_t *cib, void (*dnotify)(gpointer user_data));

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
	cib->cmds->inputfd    = cib_native_inputfd;

	cib->cmds->register_notification = cib_native_register_notification;
	cib->cmds->set_connection_dnotify = cib_native_set_connection_dnotify;

	return cib;
}


int
cib_native_signon(cib_t* cib, const char *name, enum cib_conn_type type)
{
	int rc = cib_ok;
	xmlNode *hello = NULL;
	char *uuid_ticket = NULL;
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

	if(rc == cib_ok) {
	    if(rc == cib_ok) {
		rc = get_channel_token(native->command_channel, &uuid_ticket);
		native->token = uuid_ticket;
	    }
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
	    rc = get_channel_token(native->callback_channel, &uuid_ticket);
	    if(rc == cib_ok) {
		crm_free(native->token);
		native->token = uuid_ticket;
	    }
	}
	
	if(rc == cib_ok) {
	    CRM_CHECK(native->token != NULL, ;);
	    hello = cib_create_op(0, native->token, CRM_OP_REGISTER, NULL, NULL, NULL, 0);
	    crm_xml_add(hello, F_CIB_CLIENTNAME, name);
	    
	    if(send_ipc_message(native->command_channel, hello) == FALSE) {
		rc = cib_callback_register;
	    }

	    free_xml(hello);
	}
	
	if(rc == cib_ok) {
		cib->call_timeout = 30; /* Default to 30s */
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
	
	CRM_CHECK(native->token != NULL, ;);
	op_msg = cib_create_op(
	    cib->call_id, native->token, op, host, section, data, call_options);
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
			  crm_log_xml(LOG_ERR, "Invalid call id", op_reply);
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
			crm_log_xml(LOG_MSG, "Old reply", op_reply);

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

	if(IPC_ISRCONN(native->command_channel) == FALSE) {
		crm_err("CIB disconnected: %d", 
			native->command_channel->ch_status);
		cib->state = cib_disconnected;
	}
	
	if(op_reply == NULL) {
		crm_err("No reply message - empty - %d", rc);
		return cib_reply_failed;
	}
	
	crm_debug_3("Syncronous reply recieved");
	rc = cib_ok;
	
	/* Start processing the reply... */
	if(crm_element_value_int(op_reply, F_CIB_RC, &rc) != 0) {
		rc = cib_return_code;
	}	

	switch(rc) {
	    case cib_ok:
	    case cib_diff_resync:
		/* This is an internal value that clients do not and should not care about */
		rc = cib_ok;
		/* fall through */
	    case cib_not_master:
	    case cib_master_timeout:
		crm_log_xml(LOG_MSG, "passed", op_reply);
		break;
	    default:
		if(safe_str_neq(op, CIB_OP_QUERY)) {
		    crm_warn("Call failed: %s", cib_error2string(rc));
		    crm_log_xml(LOG_DEBUG_2, "failed", op_reply);
		}
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
	    cib_native_callback(cib, msg, 0, 0);
		
	} else if(safe_str_eq(type, T_CIB_NOTIFY)) {
		g_list_foreach(cib->notify_list, cib_native_notify, msg);

	} else {
		crm_err("Unknown message type: %s", type);
	}
	
	free_xml(msg);

	return 1;
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

static void
default_cib_connection_destroy(gpointer user_data)
{
    cib_t *cib = user_data;
    cib->state = cib_disconnected;
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
		set_IPC_Channel_dnotify(
		    native->callback_source, default_cib_connection_destroy);

	} else {
		crm_debug_3("Setting dnotify");
		set_IPC_Channel_dnotify(native->callback_source, dnotify);
	}
	return cib_ok;
}

int
cib_native_register_notification(cib_t* cib, const char *callback, int enabled) 
{
	xmlNode *notify_msg = create_xml_node(NULL, "cib-callback");
	cib_native_opaque_t *native = cib->variant_opaque;

	if(cib->state != cib_disconnected) {
	    crm_xml_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
	    crm_xml_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
	    crm_xml_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
	    send_ipc_message(native->callback_channel, notify_msg);
	}

	free_xml(notify_msg);
	return cib_ok;
}

