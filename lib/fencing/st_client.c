/*
 * Copyright (c) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

GHashTable *stonith_op_callback_table = NULL;

typedef struct stonith_private_s 
{
	char *token;
	IPC_Channel	*command_channel;
	IPC_Channel	*callback_channel;
	GCHSource	*callback_source;

	void (*op_callback)(const xmlNode *msg, int call_id,
			    int rc, xmlNode *output, void *data);
		
} stonith_private_t;

typedef struct stonith_notify_client_s 
{
	const char *event;
	const char *obj_id;   /* implement one day */
	const char *obj_type; /* implement one day */
	void (*callback)(const char *event, xmlNode *msg);
	
} stonith_notify_client_t;

typedef struct stonith_callback_client_s 
{
	void (*callback)(const xmlNode*, int, int, xmlNode*, void*);
	const char *id;
	void *user_data;
	gboolean only_success;
	struct timer_rec_s *timer;
	
} stonith_callback_client_t;

struct timer_rec_s 
{
	int call_id;
	int timeout;
	guint ref;	
	stonith_t *stonith;
};

typedef enum stonith_errors (*stonith_op_t)(
    const char *, int, const char *, xmlNode *,
    xmlNode*, xmlNode*, xmlNode**, xmlNode**);

gboolean stonith_dispatch(IPC_Channel *channel, gpointer user_data);
void stonith_perform_callback(stonith_t *stonith, xmlNode *msg, int call_id, int rc);
xmlNode *stonith_create_op(
    int call_id, const char *token, const char *op, xmlNode *data, int call_options);
int stonith_send_command(
	stonith_t *stonith, const char *op, xmlNode *data, xmlNode **output_data, int call_options);

static void stonith_connection_destroy(gpointer user_data);
static void stonith_send_notification(gpointer data, gpointer user_data);

static void stonith_connection_destroy(gpointer user_data)
{
    stonith_t *stonith = user_data;
    xmlNode *notify = create_xml_node(NULL, "notify");;

    stonith->state = stonith_disconnected;
    crm_xml_add(notify, F_TYPE, T_STONITH_NOTIFY);
    crm_xml_add(notify, F_SUBTYPE, T_STONITH_NOTIFY_DISCONNECT);

    g_list_foreach(stonith->notify_list, stonith_send_notification, notify);
    free_xml(notify);
}

static int stonith_api_register_device(
    stonith_t *stonith, int call_options,
    const char *id, const char *namespace, const char *agent, GHashTable *params)
{
    int rc = 0;
    xmlNode *data = create_xml_node(NULL, F_STONITH_DEVICE);
    xmlNode *args = create_xml_node(data, XML_TAG_ATTRS);

    crm_xml_add(data, XML_ATTR_ID, id);
    crm_xml_add(data, "agent", agent);
    crm_xml_add(data, "namespace", namespace);

    g_hash_table_foreach(params, hash2field, args);
    
    rc = stonith_send_command(stonith, STONITH_OP_DEVICE_ADD, data, NULL, call_options);
    free_xml(data);
    
    return rc;
}

static int stonith_api_remove_device(
    stonith_t *stonith, int call_options, const char *name)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, F_STONITH_DEVICE);
    crm_xml_add(data, XML_ATTR_ID, name);
    rc = stonith_send_command(stonith, STONITH_OP_DEVICE_DEL, data, NULL, call_options);
    free_xml(data);
    
    return rc;
}

static int stonith_api_query(
    stonith_t *stonith, int call_options, const char *target, GListPtr *devices, int timeout)
{
    int rc = 0, lpc = 0, max = 0;

    xmlNode *data = NULL;
    xmlNode *output = NULL;
    xmlXPathObjectPtr xpathObj = NULL;

    CRM_CHECK(devices != NULL, return -1);

    data = create_xml_node(NULL, F_STONITH_DEVICE);
    crm_xml_add(data, F_STONITH_TARGET, target);
    rc = stonith_send_command(stonith, STONITH_OP_QUERY, data, &output, call_options);

    if(rc < 0) {
	return rc;
    }
    
    xpathObj = xpath_search(output, "//@agent");
    max = xpathObj->nodesetval->nodeNr;

    for(lpc = 0; lpc < max; lpc++) {
	xmlNode *match = getXpathResult(xpathObj, lpc);
	CRM_CHECK(match != NULL, continue);
	
	crm_info("%s[%d] = %s", "//@agent", lpc, xmlGetNodePath(match));
	*devices = g_list_append(*devices, crm_element_value_copy(match, XML_ATTR_ID));
    }

    free_xml(output);
    free_xml(data);
    return max;
}

static int stonith_api_call(
    stonith_t *stonith, int call_options, const char *id, const char *action, const char *port, int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(data, F_STONITH_DEVICE, id);
    crm_xml_add(data, F_STONITH_ACTION, action);
    crm_xml_add(data, F_STONITH_PORT,   port);
    crm_xml_add_int(data, "timeout", timeout);

    rc = stonith_send_command(stonith, STONITH_OP_EXEC, data, NULL, call_options);
    free_xml(data);
    
    return rc;
}

static int stonith_api_fence(
    stonith_t *stonith, int call_options, const char *node, int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(data, F_STONITH_TARGET, node);
    crm_xml_add_int(data, "timeout", timeout);

    rc = stonith_send_command(stonith, STONITH_OP_FENCE, data, NULL, call_options);
    free_xml(data);
    
    return rc;
}

static int stonith_api_unfence(
    stonith_t *stonith, int call_options, const char *node, int timeout)
{
    int rc = 0;
    xmlNode *data = NULL;

    data = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(data, F_STONITH_TARGET, node);
    crm_xml_add_int(data, "timeout", timeout);

    rc = stonith_send_command(stonith, STONITH_OP_UNFENCE, data, NULL, call_options);
    free_xml(data);
    
    return rc;
}

const char *
stonith_error2string(enum stonith_errors return_code)
{
    const char *error_msg = NULL;
    switch(return_code) {
	case stonith_ok:
	    error_msg = "";
	    break;
	case stonith_not_supported:
	    error_msg = "";
	    break;
	case stonith_connection:
	    error_msg = "";
	    break;
	case stonith_authentication:
	    error_msg = "";
	    break;
	case stonith_callback_register:
	    error_msg = "";
	    break;
	case stonith_missing:
	    error_msg = "";
	    break;
	case stonith_exists:
	    error_msg = "";
	    break;
	case stonith_timeout:
	    error_msg = "";
	    break;
	case stonith_ipc:
	    error_msg = "";
	    break;
	case stonith_peer:
	    error_msg = "";
	    break;
    }
			
    if(error_msg == NULL) {
	crm_err("Unknown Stonith error code: %d", return_code);
	error_msg = "<unknown error>";
    }
	
    return error_msg;
}

static gint stonithlib_GCompareFunc(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    const stonith_notify_client_t *a_client = a;
    const stonith_notify_client_t *b_client = b;
	
    CRM_CHECK(a_client->event != NULL && b_client->event != NULL, return 0);
    rc = strcmp(a_client->event, b_client->event);
    if(rc == 0) {
	if(a_client->callback == b_client->callback) {
	    return 0;
	} else if(((long)a_client->callback) < ((long)b_client->callback)) {
	    crm_err("callbacks for %s are not equal: %p vs. %p",
		    a_client->event, a_client->callback, b_client->callback);
	    return -1;
	} 
	crm_err("callbacks for %s are not equal: %p vs. %p",
		a_client->event, a_client->callback, b_client->callback);
	return 1;
    }
    return rc;
}

static int get_stonith_token(IPC_Channel *ch, char **token) 
{
    int rc = stonith_ok;
    xmlNode *reg_msg = NULL;
    const char *msg_type = NULL;
    const char *tmp_ticket = NULL;
    
    CRM_CHECK(ch != NULL, return stonith_missing);
    CRM_CHECK(token != NULL, return stonith_missing);
    
    crm_debug_4("Waiting for msg on command channel");
    
    reg_msg = xmlfromIPC(ch, MAX_IPC_DELAY);
    
    if(ch->ops->get_chan_status(ch) != IPC_CONNECT) {
	crm_err("No reply message - disconnected");
	free_xml(reg_msg);
	return stonith_connection;
	
    } else if(reg_msg == NULL) {
	crm_err("No reply message - empty");
	return stonith_ipc;
    }
    
    msg_type = crm_element_value(reg_msg, F_STONITH_OPERATION);
    tmp_ticket = crm_element_value(reg_msg, F_STONITH_CLIENTID);
    
    if(safe_str_neq(msg_type, CRM_OP_REGISTER) ) {
	crm_err("Invalid registration message: %s", msg_type);
	rc = stonith_callback_register;
	
    } else if(tmp_ticket == NULL) {
	crm_err("No registration token provided");
	crm_log_xml_warn(reg_msg, "Bad reply")
	rc = stonith_peer;

    } else {
	crm_debug("Obtained registration token: %s", tmp_ticket);
	*token = crm_strdup(tmp_ticket);
    }

    free_xml(reg_msg);
    return rc;
}

xmlNode *stonith_create_op(
    int call_id, const char *token, const char *op, xmlNode *data, int call_options) 
{
    int  rc = HA_OK;
    xmlNode *op_msg = create_xml_node(NULL, "stonith_command");
    CRM_CHECK(op_msg != NULL, return NULL);
    CRM_CHECK(token != NULL, return NULL);

    crm_xml_add(op_msg, F_XML_TAGNAME, "stonith_command");
	
    crm_xml_add(op_msg, F_TYPE, T_STONITH);
    crm_xml_add(op_msg, F_STONITH_CALLBACK_TOKEN, token);
    crm_xml_add(op_msg, F_STONITH_OPERATION, op);
    crm_xml_add_int(op_msg, F_STONITH_CALLID, call_id);
    crm_debug_4("Sending call options: %.8lx, %d",
		(long)call_options, call_options);
    crm_xml_add_int(op_msg, F_STONITH_CALLOPTS, call_options);

    if(data != NULL) {
	add_message_xml(op_msg, F_STONITH_CALLDATA, data);
    }
	
    if (rc != HA_OK) {
	crm_err("Failed to create STONITH operation message");
	crm_log_xml(LOG_ERR, "op", op_msg);
	free_xml(op_msg);
	return NULL;
    }

    return op_msg;
}

static void stonith_destroy_op_callback(gpointer data)
{
    stonith_callback_client_t *blob = data;
    if(blob->timer && blob->timer->ref > 0) {
	g_source_remove(blob->timer->ref);
    }
    crm_free(blob->timer);
    crm_free(blob);
}

static int stonith_api_signoff(stonith_t* stonith)
{
    stonith_private_t *native = stonith->private;

    crm_debug("Signing out of the STONITH Service");
	
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

    stonith->state = stonith_disconnected;
    return stonith_ok;
}

static int stonith_api_signon(
    stonith_t* stonith, const char *name, int *async_fd, int *sync_fd)
{
    int rc = stonith_ok;
    xmlNode *hello = NULL;
    char *uuid_ticket = NULL;
    stonith_private_t *native = stonith->private;
	
    crm_debug_4("Connecting command channel");

    stonith->state = stonith_connected_command;
    native->command_channel = init_client_ipc_comms_nodispatch(stonith_channel);
	
    if(native->command_channel == NULL) {
	crm_debug("Connection to command channel failed");
	rc = stonith_connection;
		
    } else if(native->command_channel->ch_status != IPC_CONNECT) {
	crm_err("Connection may have succeeded,"
		" but authentication to command channel failed");
	rc = stonith_authentication;
    }

    if(rc == stonith_ok) {
	rc = get_stonith_token(native->command_channel, &uuid_ticket);
	if(rc == stonith_ok) {
	    native->token = uuid_ticket;
	    uuid_ticket = NULL;

	} else {
	    stonith->state = stonith_disconnected;
	    native->command_channel->ops->disconnect(native->command_channel);
	    return rc;
	}
    }

    native->callback_channel = init_client_ipc_comms_nodispatch(
	stonith_channel_callback);
    
    if(native->callback_channel == NULL) {
	crm_debug("Connection to callback channel failed");
	rc = stonith_connection;
		
    } else if(native->callback_channel->ch_status != IPC_CONNECT) {
	crm_err("Connection may have succeeded,"
		" but authentication to command channel failed");
	rc = stonith_authentication;
    }
	
    if(rc == stonith_ok) {
	native->callback_channel->send_queue->max_qlen = 500;
	rc = get_stonith_token(native->callback_channel, &uuid_ticket);
	if(rc == stonith_ok) {
	    crm_free(native->token);
	    native->token = uuid_ticket;
	}
    }
	
    if(rc == stonith_ok) {
	CRM_CHECK(native->token != NULL, ;);
	hello = stonith_create_op(0, native->token, CRM_OP_REGISTER, NULL, 0);
	crm_xml_add(hello, F_STONITH_CLIENTNAME, name);
	    
	if(send_ipc_message(native->command_channel, hello) == FALSE) {
	    rc = stonith_callback_register;
	}

	free_xml(hello);
    }
	
    if(rc == stonith_ok) {
	gboolean do_mainloop = TRUE;
	if(async_fd != NULL) {
	    do_mainloop = FALSE;
	    *async_fd = native->callback_channel->ops->get_recv_select_fd(native->callback_channel);
	}

	if(sync_fd != NULL) {
	    do_mainloop = FALSE;
	    *sync_fd = native->callback_channel->ops->get_send_select_fd(native->callback_channel);
	}

	if(do_mainloop) {
	    crm_debug_4("Connecting callback channel");
	    native->callback_source = G_main_add_IPC_Channel(
		G_PRIORITY_HIGH, native->callback_channel, FALSE, stonith_dispatch,
		stonith, default_ipc_connection_destroy);
		
	    if(native->callback_source == NULL) {
		crm_err("Callback source not recorded");
		rc = stonith_connection;

	    } else {
		set_IPC_Channel_dnotify(
		    native->callback_source, stonith_connection_destroy);
	    }
	}
    } 

    if(rc == stonith_ok) {
#if HAVE_MSGFROMIPC_TIMEOUT
	stonith->call_timeout = MAX_IPC_DELAY;
#endif
	crm_debug("Connection to STONITH successful");
	return stonith_ok;
    }

    crm_debug("Connection to STONITH failed: %s", stonith_error2string(rc));
    stonith->cmds->disconnect(stonith);
    return rc;
}

static int stonith_set_notification(stonith_t* stonith, const char *callback, int enabled) 
{
    xmlNode *notify_msg = create_xml_node(NULL, __FUNCTION__);
    stonith_private_t *native = stonith->private;

    if(stonith->state != stonith_disconnected) {
	crm_xml_add(notify_msg, F_STONITH_OPERATION, T_STONITH_NOTIFY);
	if(enabled) {
	    crm_xml_add(notify_msg, F_STONITH_NOTIFY_ACTIVATE, callback);
	} else {
	    crm_xml_add(notify_msg, F_STONITH_NOTIFY_DEACTIVATE, callback);
	}	
	send_ipc_message(native->callback_channel, notify_msg);
    }

    free_xml(notify_msg);
    return stonith_ok;
}

static int stonith_api_add_notification(
    stonith_t *stonith, const char *event, void (*callback)(
	const char *event, xmlNode *msg))
{
    GList *list_item = NULL;
    stonith_notify_client_t *new_client = NULL;

    crm_debug_2("Adding callback for %s events (%d)",
		event, g_list_length(stonith->notify_list));

    crm_malloc0(new_client, sizeof(stonith_notify_client_t));
    new_client->event = event;
    new_client->callback = callback;

    list_item = g_list_find_custom(
	stonith->notify_list, new_client, stonithlib_GCompareFunc);
	
    if(list_item != NULL) {
	crm_warn("Callback already present");
	crm_free(new_client);
	return stonith_exists;
		
    } else {
	stonith->notify_list = g_list_append(
	    stonith->notify_list, new_client);

	stonith_set_notification(stonith, event, 1);
		
	crm_debug_3("Callback added (%d)", g_list_length(stonith->notify_list));
    }
    return stonith_ok;
}


static int stonith_api_del_notification(
    stonith_t *stonith, const char *event, void (*callback)(
	const char *event, xmlNode *msg))
{
    GList *list_item = NULL;
    stonith_notify_client_t *new_client = NULL;

    crm_debug("Removing callback for %s events", event);

    crm_malloc0(new_client, sizeof(stonith_notify_client_t));
    new_client->event = event;
    new_client->callback = callback;

    list_item = g_list_find_custom(
	stonith->notify_list, new_client, stonithlib_GCompareFunc);
	
    stonith_set_notification(stonith, event, 0);

    if(list_item != NULL) {
	stonith_notify_client_t *list_client = list_item->data;
	stonith->notify_list =
	    g_list_remove(stonith->notify_list, list_client);
	crm_free(list_client);

	crm_debug_3("Removed callback");

    } else {
	crm_debug_3("Callback not present");
    }
    crm_free(new_client);
    return stonith_ok;
}

static gboolean stonith_async_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;
    crm_debug("Async call %d timed out after %ds", timer->call_id, timer->timeout);
    stonith_perform_callback(timer->stonith, NULL, timer->call_id, stonith_timeout);

    /* Always return TRUE, never remove the handler
     * We do that in stonith_del_callback()
     */
    return TRUE;
}

static int stonith_api_add_callback(
    stonith_t *stonith, int call_id, int timeout, gboolean only_success, void *user_data,
    const char *callback_name, void (*callback)(const xmlNode*, int, int, xmlNode*,void*)) 
{
    stonith_callback_client_t *blob = NULL;
    CRM_CHECK(stonith != NULL, return stonith_missing);
    CRM_CHECK(stonith->private != NULL, return stonith_missing);

    if(call_id == 0) {
	stonith_private_t *private = stonith->private;
	private->op_callback = callback;

    } else if(call_id < 0) {
	if(only_success == FALSE) {
	    callback(NULL, call_id, call_id, NULL, user_data);
	} else {
	    crm_warn("STONITH call failed: %s", stonith_error2string(call_id));
	}
	return FALSE;
    }
	
    crm_malloc0(blob, sizeof(stonith_callback_client_t));
    blob->id = callback_name;
    blob->only_success = only_success;
    blob->user_data = user_data;
    blob->callback = callback;

    if(timeout > 0) {
	struct timer_rec_s *async_timer = NULL;
	    
	crm_malloc0(async_timer, sizeof(struct timer_rec_s));
	blob->timer = async_timer;

	async_timer->stonith = stonith;
	async_timer->call_id = call_id;
	async_timer->timeout = timeout*1000;
	async_timer->ref = g_timeout_add(
	    async_timer->timeout, stonith_async_timeout_handler, async_timer);
    }
	
    g_hash_table_insert(stonith_op_callback_table, GINT_TO_POINTER(call_id), blob);
	
    return TRUE;
}

static int stonith_api_del_callback(stonith_t *stonith, int call_id, gboolean all_callbacks) 
{
    stonith_private_t *private = stonith->private;
    
    if(all_callbacks) {
	private->op_callback = NULL;
	if(stonith_op_callback_table != NULL) {
	    g_hash_table_destroy(stonith_op_callback_table);
	}

	stonith_op_callback_table = g_hash_table_new_full(
	    g_direct_hash, g_direct_equal,
	    NULL, stonith_destroy_op_callback);

    } else if(call_id == 0) {
	private->op_callback = NULL;

    } else {
	g_hash_table_remove(stonith_op_callback_table, GINT_TO_POINTER(call_id));
    }
    return stonith_ok;
}

static void stonith_dump_pending_op(
    gpointer key, gpointer value, gpointer user_data) 
{
    int call = GPOINTER_TO_INT(key);
    stonith_callback_client_t *blob = value;

    crm_debug("Call %d (%s): pending", call, crm_str(blob->id));
}

void stonith_dump_pending_callbacks(void)
{
    if(stonith_op_callback_table == NULL) {
	return;
    }
    return g_hash_table_foreach(
	stonith_op_callback_table, stonith_dump_pending_op, NULL);
}

void stonith_perform_callback(stonith_t *stonith, xmlNode *msg, int call_id, int rc)
{
    xmlNode *output = NULL;
    stonith_private_t *private = NULL;
    stonith_callback_client_t *blob = NULL;
    stonith_callback_client_t local_blob;
    CRM_CHECK(stonith != NULL, return);
    CRM_CHECK(stonith->private != NULL, return);

    private = stonith->private;

    local_blob.id = NULL;
    local_blob.callback = NULL;
    local_blob.user_data = NULL;
    local_blob.only_success = FALSE;

    if(msg != NULL) {
	crm_element_value_int(msg, F_STONITH_RC, &rc);
	crm_element_value_int(msg, F_STONITH_CALLID, &call_id);
	output = get_message_xml(msg, F_STONITH_CALLDATA);
    }

    blob = g_hash_table_lookup(
	stonith_op_callback_table, GINT_TO_POINTER(call_id));
	
    if(blob != NULL) {
	local_blob = *blob;
	blob = NULL;
		
	stonith_api_del_callback(stonith, call_id, FALSE);

    } else {
	crm_debug_2("No callback found for call %d", call_id);
	local_blob.callback = NULL;
    }

    if(stonith == NULL) {
	crm_debug("No stonith object supplied");
    }
	
    if(local_blob.callback != NULL
       && (rc == stonith_ok || local_blob.only_success == FALSE)) {
	crm_debug_2("Invoking callback %s for call %d", crm_str(local_blob.id), call_id);
	local_blob.callback(msg, call_id, rc, output, local_blob.user_data);
		
    } else if(private->op_callback == NULL && rc != stonith_ok) {
	crm_warn("STONITH command failed: %s", stonith_error2string(rc));
	crm_log_xml(LOG_DEBUG, "Failed STONITH Update", msg);
    }
	
    if(private->op_callback != NULL) {
	crm_debug_2("Invoking global callback for call %d", call_id);
	private->op_callback(msg, call_id, rc, output, stonith);
    }
    crm_debug_4("OP callback activated.");
}

static void stonith_send_notification(gpointer data, gpointer user_data)
{
    xmlNode *msg = user_data;
    stonith_notify_client_t *entry = data;
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

static gboolean timer_expired = FALSE;

int stonith_send_command(
    stonith_t *stonith, const char *op, xmlNode *data, xmlNode **output_data, int call_options) 
{
    int  rc = HA_OK;
	
    xmlNode *op_msg   = NULL;
    xmlNode *op_reply = NULL;

    stonith_private_t *native = stonith->private;
	
    if(stonith->state == stonith_disconnected) {
	return stonith_connection;
    }

    if(output_data != NULL) {
	*output_data = NULL;
    }
	
    if(op == NULL) {
	crm_err("No operation specified");
	return stonith_missing;
    }

    stonith->call_id++;
    /* prevent call_id from being negative (or zero) and conflicting
     *    with the stonith_errors enum
     * use 2 because we use it as (stonith->call_id - 1) below
     */
    if(stonith->call_id < 1) {
	stonith->call_id = 1;
    }
	
    CRM_CHECK(native->token != NULL, ;);
    op_msg = stonith_create_op(stonith->call_id, native->token, op, data, call_options);
    if(op_msg == NULL) {
	return stonith_missing;
    }
	
    crm_debug_3("Sending %s message to STONITH service", op);
    if(send_ipc_message(native->command_channel, op_msg) == FALSE) {
	crm_err("Sending message to STONITH service FAILED");
	free_xml(op_msg);
	return stonith_ipc;

    } else {
	crm_debug_3("Message sent");
    }

    free_xml(op_msg);

    if((call_options & stonith_discard_reply)) {
	crm_debug_3("Discarding reply");
	return stonith_ok;

    } else if(!(call_options & stonith_sync_call)) {
	crm_debug_3("Async call, returning");
	CRM_CHECK(stonith->call_id != 0, return stonith_ipc);

	return stonith->call_id;
    }
	
    rc = IPC_OK;
    crm_debug_3("Waiting for a syncronous reply");

#ifndef HAVE_MSGFROMIPC_TIMEOUT
    sync_timer.ref = 0;
    if(stonith->call_timeout > 0) {
	timer_expired = FALSE;
	sync_timer.call_id = stonith->call_id;
	sync_timer.timeout = stonith->call_timeout*1000;
	sync_timer.ref = g_timeout_add(
	    sync_timer.timeout, stonith_timeout_handler, &sync_timer);
    }
#endif
    rc = stonith_ok;
    while(timer_expired == FALSE && IPC_ISRCONN(native->command_channel)) {
	int reply_id = -1;
	int msg_id = stonith->call_id;

	op_reply = xmlfromIPC(native->command_channel, stonith->call_timeout);
	if(op_reply == NULL) {
	    rc = stonith_peer;
	    break;
	}

	crm_element_value_int(op_reply, F_STONITH_CALLID, &reply_id);
	if(reply_id <= 0) {
	    rc = stonith_peer;
	    break;

	} else if(reply_id == msg_id) {
	    crm_debug_3("Syncronous reply received");
	    crm_log_xml(LOG_MSG, "Reply", op_reply);
	    if(crm_element_value_int(op_reply, F_STONITH_RC, &rc) != 0) {
		rc = stonith_peer;
	    }
		    
	    if(output_data != NULL && is_not_set(call_options, stonith_discard_reply)) {
		xmlNode *tmp = get_message_xml(op_reply, F_STONITH_CALLDATA);
		if(tmp != NULL) {
		    *output_data = copy_xml(tmp);
		}
	    }

	    break;
			
	} else if(reply_id < msg_id) {
	    crm_debug("Recieved old reply: %d (wanted %d)", reply_id, msg_id);
	    crm_log_xml(LOG_MSG, "Old reply", op_reply);

	} else if((reply_id - 10000) > msg_id) {
	    /* wrap-around case */
	    crm_debug("Recieved old reply: %d (wanted %d)", reply_id, msg_id);
	    crm_log_xml(LOG_MSG, "Old reply", op_reply);

	} else {
	    crm_err("Received a __future__ reply:"
		    " %d (wanted %d)", reply_id, msg_id);
	}
	free_xml(op_reply);
	op_reply = NULL;
    }
	
    if(IPC_ISRCONN(native->command_channel) == FALSE) {
	crm_err("STONITH disconnected: %d", native->command_channel->ch_status);
	stonith->state = stonith_disconnected;
    }

    if(op_reply == NULL && stonith->state == stonith_disconnected) {
	rc = stonith_connection;

    } else if(rc == stonith_ok && op_reply == NULL) {
	rc = stonith_peer;
    }
	
#ifndef HAVE_MSGFROMIPC_TIMEOUT
    if(sync_timer.ref > 0) {
	g_source_remove(sync_timer.ref);
	sync_timer.ref = 0;
    }
#endif
	
    free_xml(op_reply);
    return rc;
}

static gboolean stonith_msgready(stonith_t* stonith)
{
    stonith_private_t *private = NULL;
	
    if (stonith == NULL) {
	crm_err("No STONITH!");
	return FALSE;
    }

    private = stonith->private;

    if(private->command_channel != NULL) {
	/* drain the channel */
	IPC_Channel *cmd_ch = private->command_channel;
	xmlNode *cmd_msg = NULL;
	while(cmd_ch->ch_status != IPC_DISCONNECT
	      && cmd_ch->ops->is_message_pending(cmd_ch)) {
	    /* this will happen when the STONITH exited from beneath us */
	    cmd_msg = xmlfromIPC(cmd_ch, MAX_IPC_DELAY);
	    free_xml(cmd_msg);
	}

    } else {
	crm_err("No command channel");
    }	

    if(private->callback_channel == NULL) {
	crm_err("No callback channel");
	return FALSE;

    } else if(private->callback_channel->ch_status == IPC_DISCONNECT) {
	crm_info("Lost connection to the STONITH service [%d].",
		 private->callback_channel->farside_pid);
	return FALSE;

    } else if(private->callback_channel->ops->is_message_pending(
		  private->callback_channel)) {
	crm_debug_4("Message pending on command channel [%d]",
		    private->callback_channel->farside_pid);
	return TRUE;
    }

    crm_debug_3("No message pending");
    return FALSE;
}

static int stonith_rcvmsg(stonith_t* stonith)
{
    const char *type = NULL;
    xmlNode* msg = NULL;
    stonith_private_t *private = NULL;
	
    if (stonith == NULL) {
	crm_err("No STONITH!");
	return FALSE;
    }

    private = stonith->private;
	
    /* if it is not blocking mode and no message in the channel, return */
    if (stonith_msgready(stonith) == FALSE) {
	crm_debug_3("No message ready and non-blocking...");
	return 0;
    }

    /* IPC_INTR is not a factor here */
    msg = xmlfromIPC(private->callback_channel, MAX_IPC_DELAY);
    if (msg == NULL) {
	crm_warn("Received a NULL msg from STONITH service.");
	return 0;
    }

    /* do callbacks */
    type = crm_element_value(msg, F_TYPE);
    crm_debug_4("Activating %s callbacks...", type);

    if(safe_str_eq(type, T_STONITH_NG)) {
	stonith_perform_callback(stonith, msg, 0, 0);
		
    } else if(safe_str_eq(type, T_STONITH_NOTIFY)) {
	g_list_foreach(stonith->notify_list, stonith_send_notification, msg);

    } else {
	crm_err("Unknown message type: %s", type);
    }
	
    free_xml(msg);

    return 1;
}

gboolean stonith_dispatch(IPC_Channel *channel, gpointer user_data)
{
    stonith_t *stonith = user_data;
    stonith_private_t *private = NULL;
    gboolean stay_connected = TRUE;
    
    CRM_CHECK(stonith != NULL, return FALSE);
    
    private = stonith->private;
    CRM_CHECK(private->callback_channel == channel, return FALSE);
    
    while(stonith_msgready(stonith)) {
	/* invoke the callbacks but dont block */
	int rc = stonith_rcvmsg(stonith);
	if( rc < 0) {
	    crm_err("Message acquisition failed: %d", rc);
	    break;

	} else if(rc == 0) {
	    break;
	}
    }
    
    if(private->callback_channel
       && private->callback_channel->ch_status != IPC_CONNECT) {
	crm_crit("Lost connection to the STONITH service [%d/callback].",
		 channel->farside_pid);
	private->callback_source = NULL;
	stay_connected = FALSE;
    }
    
    if(private->command_channel
       && private->command_channel->ch_status != IPC_CONNECT) {
	crm_crit("Lost connection to the STONITH service [%d/command].",
		 channel->farside_pid);
	private->callback_source = NULL;
	stay_connected = FALSE;
    }

    return stay_connected;
}

static int stonith_api_free (stonith_t* stonith)
{
    int rc = stonith_ok;

    if(stonith->state != stonith_disconnected) {
	rc = stonith->cmds->disconnect(stonith);
    }

    if(stonith->state == stonith_disconnected) {
	stonith_private_t *private = stonith->private;
	crm_free(private->token);
	crm_free(stonith->private);
	crm_free(stonith->cmds);
	crm_free(stonith);
    }
	
    return rc;
}

void stonith_api_delete(stonith_t *stonith)
{
    GList *list = stonith->notify_list;
    while(list != NULL) {
	stonith_notify_client_t *client = g_list_nth_data(list, 0);
	list = g_list_remove(list, client);
	crm_free(client);
    }
	
    g_hash_table_destroy(stonith_op_callback_table);
    stonith->cmds->free(stonith);
    stonith = NULL;
}

stonith_t *stonith_api_new(void) 
{
    stonith_t* new_stonith = NULL;
    stonith_private_t* private = NULL;
    crm_malloc0(new_stonith, sizeof(stonith_t));
    crm_malloc0(private, sizeof(stonith_private_t));
    new_stonith->private = private;
    
    if(stonith_op_callback_table != NULL) {
	g_hash_table_destroy(stonith_op_callback_table);
	stonith_op_callback_table = NULL;
    }
    if(stonith_op_callback_table == NULL) {
	stonith_op_callback_table = g_hash_table_new_full(
	    g_direct_hash, g_direct_equal,
	    NULL, stonith_destroy_op_callback);
    }

    new_stonith->call_id = 1;
    new_stonith->notify_list = NULL;
    new_stonith->state = stonith_disconnected;
    
    crm_malloc0(new_stonith->cmds, sizeof(stonith_api_operations_t));

    new_stonith->cmds->free       = stonith_api_free;
    new_stonith->cmds->connect    = stonith_api_signon;
    new_stonith->cmds->disconnect = stonith_api_signoff;
    
    new_stonith->cmds->call       = stonith_api_call;
    new_stonith->cmds->fence      = stonith_api_fence;
    new_stonith->cmds->unfence    = stonith_api_unfence;

    new_stonith->cmds->query           = stonith_api_query;
    new_stonith->cmds->remove_device   = stonith_api_remove_device;
    new_stonith->cmds->register_device = stonith_api_register_device;
    
    new_stonith->cmds->remove_callback       = stonith_api_del_callback;	
    new_stonith->cmds->register_callback     = stonith_api_add_callback;	
    new_stonith->cmds->remove_notification   = stonith_api_del_notification;
    new_stonith->cmds->register_notification = stonith_api_add_notification;

    return new_stonith;
}

