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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <cib_private.h>

/* short term hack to reduce callback messages */
typedef struct cib_native_opaque_s 
{
		IPC_Channel	*command_channel;
		IPC_Channel	*callback_channel;
 		GCHSource	*callback_source; 
		
} cib_native_opaque_t;

GHashTable *cib_op_callback_table = NULL;

gboolean verify_cib_cmds(cib_t *cib);

int cib_client_set_op_callback(
	cib_t *cib, void (*callback)(const struct ha_msg *msg, int call_id,
				     int rc, crm_data_t *output));
int cib_client_noop(cib_t *cib, int call_options);
int cib_client_ping(cib_t *cib, crm_data_t **output_data, int call_options);

int cib_client_query(cib_t *cib, const char *section,
	     crm_data_t **output_data, int call_options);
int cib_client_query_from(cib_t *cib, const char *host, const char *section,
			  crm_data_t **output_data, int call_options);

int cib_client_sync(cib_t *cib, const char *section, int call_options);
int cib_client_sync_from(
	cib_t *cib, const char *host, const char *section, int call_options);

int cib_client_is_master(cib_t *cib);
int cib_client_set_slave(cib_t *cib, int call_options);
int cib_client_set_slave_all(cib_t *cib, int call_options);
int cib_client_set_master(cib_t *cib, int call_options);

int cib_client_bump_epoch(cib_t *cib, int call_options);
int cib_client_create(cib_t *cib, const char *section, crm_data_t *data,
		      crm_data_t **output_data, int call_options);
int cib_client_modify(cib_t *cib, const char *section, crm_data_t *data,
		      crm_data_t **output_data, int call_options);
int cib_client_update(cib_t *cib, const char *section, crm_data_t *data,
		      crm_data_t **output_data, int call_options);
int cib_client_replace(cib_t *cib, const char *section, crm_data_t *data,
		       crm_data_t **output_data, int call_options);
int cib_client_delete(cib_t *cib, const char *section, crm_data_t *data,
		      crm_data_t **output_data, int call_options);
int cib_client_delete_absolute(
	cib_t *cib, const char *section, crm_data_t *data,
	crm_data_t **output_data, int call_options);
int cib_client_erase(
	cib_t *cib, crm_data_t **output_data, int call_options);
int cib_client_quit(cib_t *cib,   int call_options);

int cib_client_add_notify_callback(
	cib_t *cib, const char *event, void (*callback)(
		const char *event, struct ha_msg *msg));

int cib_client_del_notify_callback(
	cib_t *cib, const char *event, void (*callback)(
		const char *event, struct ha_msg *msg));

gint ciblib_GCompareFunc(gconstpointer a, gconstpointer b);

extern cib_t *cib_native_new(cib_t *cib);
extern void cib_native_delete(cib_t *cib);

static enum cib_variant configured_variant = cib_native;

/* define of the api functions*/
cib_t*
cib_new(void)
{
	cib_t* new_cib = NULL;

	if(configured_variant != cib_native) {
		crm_err("Only the native CIB type is currently implemented");
		return NULL;
	}

	if(cib_op_callback_table != NULL) {
		g_hash_table_destroy(cib_op_callback_table);
		cib_op_callback_table = NULL;
	}
	if(cib_op_callback_table == NULL) {
		cib_op_callback_table = g_hash_table_new_full(
			g_direct_hash, g_direct_equal,
			NULL, g_hash_destroy_str);
	}

	crm_malloc0(new_cib, sizeof(cib_t));

	new_cib->call_id = 1;

	new_cib->type  = cib_none;
	new_cib->state = cib_disconnected;

	new_cib->op_callback	= NULL;
	new_cib->variant_opaque = NULL;
	new_cib->notify_list    = NULL;

	/* the rest will get filled in by the variant constructor */
	crm_malloc0(new_cib->cmds, sizeof(cib_api_operations_t));

	new_cib->cmds->set_op_callback     = cib_client_set_op_callback;
	new_cib->cmds->add_notify_callback = cib_client_add_notify_callback;
	new_cib->cmds->del_notify_callback = cib_client_del_notify_callback;
	
	new_cib->cmds->noop    = cib_client_noop;
	new_cib->cmds->ping    = cib_client_ping;
	new_cib->cmds->query   = cib_client_query;
	new_cib->cmds->sync    = cib_client_sync;

	new_cib->cmds->query_from = cib_client_query_from;
	new_cib->cmds->sync_from  = cib_client_sync_from;
	
	new_cib->cmds->is_master  = cib_client_is_master;
	new_cib->cmds->set_master = cib_client_set_master;
	new_cib->cmds->set_slave  = cib_client_set_slave;
	new_cib->cmds->set_slave_all = cib_client_set_slave_all;

	new_cib->cmds->bump_epoch = cib_client_bump_epoch;

	new_cib->cmds->create  = cib_client_create;
	new_cib->cmds->modify  = cib_client_modify;
	new_cib->cmds->update  = cib_client_update;
	new_cib->cmds->replace = cib_client_replace;
	new_cib->cmds->delete  = cib_client_delete;
	new_cib->cmds->erase   = cib_client_erase;
	new_cib->cmds->quit    = cib_client_quit;

	new_cib->cmds->delete_absolute  = cib_client_delete_absolute;
	
	cib_native_new(new_cib);
	if(verify_cib_cmds(new_cib) == FALSE) {
		cib_delete(new_cib);
		return NULL;
	}
	
	return new_cib;
}

void
cib_delete(cib_t *cib)
{
	GList *list = cib->notify_list;
	while(list != NULL) {
		cib_notify_client_t *client = g_list_nth_data(list, 0);
		list = g_list_remove(list, client);
		crm_free(client);
	}
	
	cib_native_delete(cib);
	g_hash_table_destroy(cib_op_callback_table);
	crm_free(cib->cmds);
	crm_free(cib);
}


int
cib_client_set_op_callback(
	cib_t *cib, void (*callback)(const struct ha_msg *msg, int call_id,
				     int rc, crm_data_t *output)) 
{
	if(callback == NULL) {
		crm_info("Un-Setting operation callback");
		
	} else {
		crm_debug_3("Setting operation callback");
	}
	cib->op_callback = callback;
	return cib_ok;
}
	
int cib_client_noop(cib_t *cib, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	}
	
	return cib->cmds->variant_op(
		cib, CRM_OP_NOOP, NULL, NULL, NULL, NULL, call_options);
}

int cib_client_ping(cib_t *cib, crm_data_t **output_data, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	}
	
	return cib->cmds->variant_op(
		cib, CRM_OP_PING, NULL,NULL,NULL, output_data, call_options);
}


int cib_client_query(cib_t *cib, const char *section,
		     crm_data_t **output_data, int call_options)
{
	return cib->cmds->query_from(
		cib, NULL, section, output_data, call_options);
}

int cib_client_query_from(cib_t *cib, const char *host, const char *section,
			  crm_data_t **output_data, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	}
	
	return cib->cmds->variant_op(cib, CIB_OP_QUERY, host, section,
				     NULL, output_data, call_options);
}


int cib_client_is_master(cib_t *cib)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 
	return cib->cmds->variant_op(
		cib, CIB_OP_ISMASTER, NULL, NULL,NULL,NULL,
		cib_scope_local|cib_sync_call);
}

int cib_client_set_slave(cib_t *cib, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(
		cib, CIB_OP_SLAVE, NULL,NULL,NULL,NULL, call_options);
}

int cib_client_set_slave_all(cib_t *cib, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(
		cib, CIB_OP_SLAVEALL, NULL,NULL,NULL,NULL, call_options);
}

int cib_client_set_master(cib_t *cib, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	crm_debug_3("Adding cib_scope_local to options");
	return cib->cmds->variant_op(
		cib, CIB_OP_MASTER, NULL,NULL,NULL,NULL,
		call_options|cib_scope_local);
}



int cib_client_bump_epoch(cib_t *cib, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(
		cib, CIB_OP_BUMP, NULL, NULL, NULL, NULL, call_options);
}

int cib_client_sync(cib_t *cib, const char *section, int call_options)
{
	return cib->cmds->sync_from(cib, NULL, section, call_options);
}

int cib_client_sync_from(
	cib_t *cib, const char *host, const char *section, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	}

	return cib->cmds->variant_op(
		cib, CIB_OP_SYNC, host, section, NULL, NULL, call_options);
}

int cib_client_create(cib_t *cib, const char *section, crm_data_t *data,
		      crm_data_t **output_data, int call_options) 
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(cib, CIB_OP_CREATE, NULL, section,
				     data, output_data, call_options);
}


int cib_client_modify(cib_t *cib, const char *section, crm_data_t *data,
	   crm_data_t **output_data, int call_options) 
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(cib, CIB_OP_MODIFY, NULL, section,
				     data, output_data, call_options);
}

int cib_client_update(cib_t *cib, const char *section, crm_data_t *data,
		      crm_data_t **output_data, int call_options) 
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(cib, CIB_OP_UPDATE, NULL, section,
				     data, output_data, call_options);
}


int cib_client_replace(cib_t *cib, const char *section, crm_data_t *data,
	    crm_data_t **output_data, int call_options) 
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} else if(data == NULL) {
		return cib_missing_data;
	}
	
	return cib->cmds->variant_op(cib, CIB_OP_REPLACE, NULL, section,
				     data, output_data, call_options);
}


int cib_client_delete(cib_t *cib, const char *section, crm_data_t *data,
	   crm_data_t **output_data, int call_options) 
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	}
	
	return cib->cmds->variant_op(cib, CIB_OP_DELETE, NULL, section,
				     data, output_data, call_options);
}

int cib_client_delete_absolute(
	cib_t *cib, const char *section, crm_data_t *data,
	crm_data_t **output_data, int call_options) 
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	}
	
	return cib->cmds->variant_op(cib, CIB_OP_DELETE_ALT, NULL, section,
				     data, output_data, call_options);
}

int cib_client_erase(
	cib_t *cib, crm_data_t **output_data, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(cib, CIB_OP_ERASE, NULL, NULL, NULL,
				     output_data, call_options);
}


int cib_client_quit(cib_t *cib, int call_options)
{
	if(cib == NULL) {
		return cib_missing;
	} else if(cib->state == cib_disconnected) {
		return cib_not_connected;
	} else if(cib->cmds->variant_op == NULL) {
		return cib_variant;
	} 

	return cib->cmds->variant_op(
		cib, CRM_OP_QUIT, NULL, NULL, NULL, NULL, call_options);
}

int cib_client_add_notify_callback(
	cib_t *cib, const char *event, void (*callback)(
		const char *event, struct ha_msg *msg))
{
	GList *list_item = NULL;
	cib_notify_client_t *new_client = NULL;
	
	crm_debug_2("Adding callback for %s events (%d)",
		    event, g_list_length(cib->notify_list));

	crm_malloc0(new_client, sizeof(cib_notify_client_t));
	new_client->event = event;
	new_client->callback = callback;

	list_item = g_list_find_custom(
		cib->notify_list, new_client, ciblib_GCompareFunc);
	
	if(list_item != NULL) {
		crm_warn("Callback already present");
		crm_free(new_client);
		
	} else {
		cib->notify_list = g_list_append(
			cib->notify_list, new_client);

		cib->cmds->register_callback(cib, event, 1);
		
		crm_debug_3("Callback added (%d)", g_list_length(cib->notify_list));
	}
	return cib_ok;
}


int cib_client_del_notify_callback(
	cib_t *cib, const char *event, void (*callback)(
		const char *event, struct ha_msg *msg))
{
	GList *list_item = NULL;
	cib_notify_client_t *new_client = NULL;

	crm_debug("Removing callback for %s events", event);

	crm_malloc0(new_client, sizeof(cib_notify_client_t));
	new_client->event = event;
	new_client->callback = callback;

	list_item = g_list_find_custom(
		cib->notify_list, new_client, ciblib_GCompareFunc);
	
	cib->cmds->register_callback(cib, event, 0);

	if(list_item != NULL) {
		cib_notify_client_t *list_client = list_item->data;
		cib->notify_list =
			g_list_remove(cib->notify_list, list_client);
		crm_free(list_client);

		crm_debug_3("Removed callback");

	} else {
		crm_debug_3("Callback not present");
	}
	crm_free(new_client);
	return cib_ok;
}

gint ciblib_GCompareFunc(gconstpointer a, gconstpointer b)
{
	const cib_notify_client_t *a_client = a;
	const cib_notify_client_t *b_client = b;
	if(a_client->callback == b_client->callback
	   && safe_str_neq(a_client->event, b_client->event)) {
		return 0;
	} else if(((long)a_client->callback) < ((long)b_client->callback)) {
		return -1;
	}
	return 1;
}



gboolean
add_cib_op_callback(
	int call_id, gboolean only_success, void *user_data,
	void (*callback)(const HA_Message*, int, int, crm_data_t*,void*)) 
{
	cib_callback_client_t *blob = NULL;

	if(call_id < 0) {
		crm_warn("CIB call failed: %s", cib_error2string(call_id));
		if(only_success == FALSE) {
			callback(NULL, call_id, call_id, NULL, user_data);
		}
		return FALSE;
	}
	
	crm_malloc0(blob, sizeof(cib_callback_client_t));
	blob->only_success = only_success;
	blob->user_data = user_data;
	blob->callback = callback;
	
	g_hash_table_insert(
		cib_op_callback_table, GINT_TO_POINTER(call_id), blob);
	return TRUE;
}

void
remove_cib_op_callback(int call_id, gboolean all_callbacks) 
{
	if(all_callbacks) {
		if(cib_op_callback_table != NULL) {
			g_hash_table_destroy(cib_op_callback_table);
		}
		cib_op_callback_table = g_hash_table_new_full(
			g_direct_hash, g_direct_equal,
			NULL, g_hash_destroy_str);
	} else {
		g_hash_table_remove(
			cib_op_callback_table,
			GINT_TO_POINTER(call_id));
	}
}

int
num_cib_op_callbacks(void)
{
	if(cib_op_callback_table == NULL) {
		return 0;
	}
	return g_hash_table_size(cib_op_callback_table);
}



char *
cib_pluralSection(const char *a_section)
{
	char *a_section_parent = NULL;
	if (a_section == NULL) {
		a_section_parent = crm_strdup("all");

	} else if(strcasecmp(a_section, XML_TAG_CIB) == 0) {
		a_section_parent = crm_strdup("all");

	} else if(strcasecmp(a_section, XML_CIB_TAG_NODE) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_NODES);

	} else if(strcasecmp(a_section, XML_CIB_TAG_STATE) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_STATUS);

	} else if(strcasecmp(a_section, XML_CIB_TAG_CONSTRAINT) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcasecmp(a_section, XML_CONS_TAG_RSC_LOCATION) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcasecmp(a_section, XML_CONS_TAG_RSC_DEPEND) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcasecmp(a_section, XML_CONS_TAG_RSC_ORDER) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CONSTRAINTS);
		
	} else if(strcasecmp(a_section, "resource") == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_RESOURCES);

	} else if(strcasecmp(a_section, XML_CIB_TAG_RESOURCE) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_RESOURCES);

	} else if(strcasecmp(a_section, XML_CIB_TAG_GROUP) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_RESOURCES);

	} else if(strcasecmp(a_section, XML_CIB_TAG_INCARNATION) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_RESOURCES);
		
	} else if(strcasecmp(a_section, XML_CIB_TAG_NVPAIR) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CRMCONFIG);

	} else if(strcasecmp(a_section, XML_TAG_ATTR_SETS) == 0) {
		a_section_parent = crm_strdup(XML_CIB_TAG_CRMCONFIG);

	} else {
		crm_err("Unknown section %s", a_section);
		a_section_parent = crm_strdup("all");
	}
	
	crm_debug_2("Plural of %s is %s", crm_str(a_section), a_section_parent);

	return a_section_parent;
}

const char *
cib_error2string(enum cib_errors return_code)
{
	const char *error_msg = NULL;
	switch(return_code) {
		case cib_bad_permissions:
			error_msg = "bad permissions for the on-disk configuration. shutdown heartbeat and repair.";
			break;
		case cib_bad_digest:
			error_msg = "the on-disk configuration was manually altered. shutdown heartbeat and repair.";
			break;
		case cib_bad_config:
			error_msg = "the on-disk configuration is not valid";
			break;
		case cib_msg_field_add:
			error_msg = "failed adding field to cib message";
			break;			
		case cib_id_check:
			error_msg = "missing id or id-collision detected";
			break;			
		case cib_operation:
			error_msg = "invalid operation";
			break;
		case cib_create_msg:
			error_msg = "couldnt create cib message";
			break;
		case cib_client_gone:
			error_msg = "client left before we could send reply";
			break;
		case cib_not_connected:
			error_msg = "not connected";
			break;
		case cib_not_authorized:
			error_msg = "not authorized";
			break;
		case cib_send_failed:
			error_msg = "send failed";
			break;
		case cib_reply_failed:
			error_msg = "reply failed";
			break;
		case cib_return_code:
			error_msg = "no return code";
			break;
		case cib_output_ptr:
			error_msg = "nowhere to store output";
			break;
		case cib_output_data:
			error_msg = "corrupt output data";
			break;
		case cib_connection:
			error_msg = "connection failed";
			break;
		case cib_callback_register:
			error_msg = "couldnt register callback channel";
			break;
		case cib_authentication:
			error_msg = "";
			break;
		case cib_registration_msg:
			error_msg = "invalid registration msg";
			break;
		case cib_callback_token:
			error_msg = "callback token not found";
			break;
		case cib_missing:
			error_msg = "cib object missing";
			break;
		case cib_variant:
			error_msg = "unknown/corrupt cib variant";
			break;
		case CIBRES_MISSING_ID:
			error_msg = "The id field is missing";
			break;
		case CIBRES_MISSING_TYPE:
			error_msg = "The type field is missing";
			break;
		case CIBRES_MISSING_FIELD:
			error_msg = "A required field is missing";
			break;
		case CIBRES_OBJTYPE_MISMATCH:
			error_msg = "CIBRES_OBJTYPE_MISMATCH";
			break;
		case cib_EXISTS:
			error_msg = "The object already exists";
			break;
		case cib_NOTEXISTS:
			error_msg = "The object/attribute does not exist";
			break;
		case CIBRES_CORRUPT:
			error_msg = "The CIB is corrupt";
			break;
		case cib_NOOBJECT:
			error_msg = "The update was empty";
			break;
		case cib_NOPARENT:
			error_msg = "The parent object does not exist";
			break;
		case cib_NODECOPY:
			error_msg = "Failed while copying update";
			break;
		case CIBRES_OTHER:
			error_msg = "CIBRES_OTHER";
			break;
		case cib_ok:
			error_msg = "ok";
			break;
		case cib_unknown:
			error_msg = "Unknown error";
			break;
		case cib_STALE:
			error_msg = "Discarded old update";
			break;
		case cib_ACTIVATION:
			error_msg = "Activation Failed";
			break;
		case cib_NOSECTION:
			error_msg = "Required section was missing";
			break;
		case cib_NOTSUPPORTED:
			error_msg = "Supplied information is not supported";
			break;
		case cib_not_master:
			error_msg = "Local service is not the master instance";
			break;
		case cib_client_corrupt:
			error_msg = "Service client not valid";
			break;
		case cib_remote_timeout:
			error_msg = "Remote node did not respond";
			break;
		case cib_master_timeout:
			error_msg = "No master service is currently active";
			break;
		case cib_revision_unsupported:
			error_msg = "The required CIB revision number is not supported";
			break;
		case cib_revision_unknown:
			error_msg = "The CIB revision number could not be determined";
			break;
		case cib_missing_data:
			error_msg = "Required data for this CIB API call not found";
			break;
		case cib_no_quorum:
			error_msg = "Write requires quorum";
			break;
		case cib_diff_failed:
			error_msg = "Application of an update diff failed";
			break;
		case cib_diff_resync:
			error_msg = "Application of an update diff failed, requesting a full refresh";
			break;
		case cib_bad_section:
			error_msg = "Invalid CIB section specified";
			break;
		case cib_old_data:
			error_msg = "Update was older than existing configuration";
			break;
		case cib_dtd_validation:
			error_msg = "Update does not conform to the DTD in "HA_NOARCHDATAHBDIR"/crm.dtd";
			break;
		case cib_invalid_argument:
			error_msg = "Invalid argument";
			break;
	}
			
	if(error_msg == NULL) {
		crm_err("Unknown CIB Error Code: %d", return_code);
		error_msg = "<unknown error>";
	}
	
	return error_msg;
}

const char *
cib_op2string(enum cib_update_op operation)
{
	const char *operation_msg = NULL;
	switch(operation) {
		case 0:
			operation_msg = "none";
			break;
		case 1:
			operation_msg = "add";
			break;
		case 2:
			operation_msg = "modify";
			break;
		case 3:
			operation_msg = "delete";
			break;
		case CIB_UPDATE_OP_MAX:
			operation_msg = "invalid operation";
			break;
			
	}

	if(operation_msg == NULL) {
		crm_err("Unknown CIB operation %d", operation);
		operation_msg = "<unknown operation>";
	}
	
	return operation_msg;
}




int
cib_section2enum(const char *a_section) 
{
	if(a_section == NULL || strcasecmp(a_section, "all") == 0) {
		return cib_section_all;

	} else if(strcasecmp(a_section, XML_CIB_TAG_NODES) == 0) {
		return cib_section_nodes;

	} else if(strcasecmp(a_section, XML_CIB_TAG_STATUS) == 0) {
		return cib_section_status;

	} else if(strcasecmp(a_section, XML_CIB_TAG_CONSTRAINTS) == 0) {
		return cib_section_constraints;
		
	} else if(strcasecmp(a_section, XML_CIB_TAG_RESOURCES) == 0) {
		return cib_section_resources;

	} else if(strcasecmp(a_section, XML_CIB_TAG_CRMCONFIG) == 0) {
		return cib_section_crmconfig;

	}
	crm_err("Unknown CIB section: %s", a_section);
	return cib_section_none;
}


int
cib_compare_generation(crm_data_t *left, crm_data_t *right)
{
	int lpc = 0;
	const char *attributes[] = {
		XML_ATTR_GENERATION_ADMIN,
		XML_ATTR_GENERATION,
		XML_ATTR_NUMUPDATES,
		XML_ATTR_NUMPEERS
	};

	crm_log_xml_debug_3(left, "left");
	crm_log_xml_debug_3(right, "right");
	
	for(lpc = 0; lpc < DIMOF(attributes); lpc++) {
		int int_elem_l = -1;
		int int_elem_r = -1;
		const char *elem_r = NULL;
		const char *elem_l = crm_element_value(left, attributes[lpc]);

		if(right != NULL) {
			elem_r = crm_element_value(right, attributes[lpc]);
		}
	
		if(elem_l != NULL) { int_elem_l = crm_parse_int(elem_l, NULL); }
		if(elem_r != NULL) { int_elem_r = crm_parse_int(elem_r, NULL); }

		if(int_elem_l < int_elem_r) {
			crm_debug_2("%s (%s < %s)", attributes[lpc],
				    crm_str(elem_l), crm_str(elem_r));
			return -1;
			
		} else if(int_elem_l > int_elem_r) {
			crm_debug_2("%s (%s > %s)", attributes[lpc],
				    crm_str(elem_l), crm_str(elem_r));
			return 1;
		}
	}
	
	return 0;
}

crm_data_t*
get_cib_copy(cib_t *cib)
{
	crm_data_t *xml_cib;
#if CRM_DEPRECATED_SINCE_2_0_4
	crm_data_t *xml_cib_copy;
#endif
	int options = cib_scope_local|cib_sync_call;
	if(cib->cmds->query(cib, NULL, &xml_cib, options) != cib_ok) {
		crm_err("Couldnt retrieve the CIB");
		return NULL;
	} else if(xml_cib == NULL) {
		crm_err("The CIB result was empty");
		return NULL;
	}

	if(safe_str_eq(crm_element_name(xml_cib), XML_TAG_CIB)) {
		return xml_cib;
		
#if CRM_DEPRECATED_SINCE_2_0_4
	} else {
		xml_cib_copy = copy_xml(
			find_xml_node(xml_cib, XML_TAG_CIB, TRUE));
		free_xml(xml_cib);
		return xml_cib_copy;
#endif
	}
	free_xml(xml_cib);
	return NULL;
}

crm_data_t*
cib_get_generation(cib_t *cib)
{
	crm_data_t *the_cib = get_cib_copy(cib);
	crm_data_t *generation = create_xml_node(
		NULL, XML_CIB_TAG_GENERATION_TUPPLE);

	if(the_cib != NULL) {
		copy_in_properties(generation, the_cib);
		free_xml(the_cib);
	}
	
	return generation;
}

gboolean
apply_cib_diff(crm_data_t *old, crm_data_t *diff, crm_data_t **new)
{
	gboolean result = TRUE;
	const char *value = NULL;

	int this_updates = 0;
	int this_epoch  = 0;
	int this_admin_epoch = 0;

	int diff_add_updates = 0;
	int diff_add_epoch  = 0;
	int diff_add_admin_epoch = 0;

	int diff_del_updates = 0;
	int diff_del_epoch  = 0;
	int diff_del_admin_epoch = 0;

	CRM_CHECK(diff != NULL, return FALSE);
	CRM_CHECK(old != NULL, return FALSE);
	
	value = crm_element_value(old, XML_ATTR_GENERATION_ADMIN);
	this_admin_epoch = crm_parse_int(value, "0");
	crm_debug_3("%s=%d (%s)", XML_ATTR_GENERATION_ADMIN,
		  this_admin_epoch, value);
	
	value = crm_element_value(old, XML_ATTR_GENERATION);
	this_epoch = crm_parse_int(value, "0");
	crm_debug_3("%s=%d (%s)", XML_ATTR_GENERATION, this_epoch, value);
	
	value = crm_element_value(old, XML_ATTR_NUMUPDATES);
	this_updates = crm_parse_int(value, "0");
	crm_debug_3("%s=%d (%s)", XML_ATTR_NUMUPDATES, this_updates, value);
	
	cib_diff_version_details(
		diff,
		&diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
		&diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

	value = NULL;
	if(result && diff_del_admin_epoch != this_admin_epoch) {
		value = XML_ATTR_GENERATION_ADMIN;
		result = FALSE;
		crm_debug_3("%s=%d", value, diff_del_admin_epoch);

	} else if(result && diff_del_epoch != this_epoch) {
		value = XML_ATTR_GENERATION;
		result = FALSE;
		crm_debug_3("%s=%d", value, diff_del_epoch);

	} else if(result && diff_del_updates != this_updates) {
		value = XML_ATTR_NUMUPDATES;
		result = FALSE;
		crm_debug_3("%s=%d", value, diff_del_updates);
	}

	if(result) {
		int len = 0;
		crm_data_t *tmp = NULL;
		crm_data_t *diff_copy = copy_xml(diff);
		
		tmp = find_xml_node(diff_copy, "diff-removed", TRUE);
		if(tmp != NULL) {
			len = tmp->nfields;
			cl_msg_remove(tmp, XML_ATTR_GENERATION_ADMIN);
			cl_msg_remove(tmp, XML_ATTR_GENERATION);
			cl_msg_remove(tmp, XML_ATTR_NUMUPDATES);
		}
		
		tmp = find_xml_node(diff_copy, "diff-added", TRUE);
		if(tmp != NULL) {
			len = tmp->nfields;
			cl_msg_remove(tmp, XML_ATTR_GENERATION_ADMIN);
			cl_msg_remove(tmp, XML_ATTR_GENERATION);
			cl_msg_remove(tmp, XML_ATTR_NUMUPDATES);
		}
		
		result = apply_xml_diff(old, diff_copy, new);
		free_xml(diff_copy);
		
	} else {
		crm_err("target and diff %s values didnt match", value);
	}
	
	
	return result;
}

gboolean xml_has_child(crm_data_t *data, const char *name);

gboolean
xml_has_child(crm_data_t *data, const char *name) 
{
	xml_child_iter_filter(data, child, name,
		return TRUE;
		);
	return FALSE;
}

gboolean
cib_config_changed(crm_data_t *old_cib, crm_data_t *new_cib, crm_data_t **result)
{
	gboolean config_changes = FALSE;
	const char *tag = NULL;
	crm_data_t *diff = NULL;
	crm_data_t *dest = NULL;

	if(result) {
		*result = NULL;
	}

	diff = diff_xml_object(old_cib, new_cib, FALSE);
	if(diff == NULL) {
		return FALSE;
	}

	tag = "diff-removed";
	dest = find_xml_node(diff, tag, FALSE);
	if(dest) {
		dest = find_xml_node(dest, "cib", FALSE);
		
	}

	if(dest) {
		if(xml_has_child(dest, "status")) {
			cl_msg_remove(dest, "status");
		}
		if(xml_has_children(dest)) {
			config_changes = TRUE;
		}
	}

	tag = "diff-added";
	dest = find_xml_node(diff, tag, FALSE);
	if(dest) {
		dest = find_xml_node(dest, "cib", FALSE);
	}

	if(dest) {
		if(xml_has_child(dest, "status")) {
			cl_msg_remove(dest, "status");
		}
		if(xml_has_children(dest)) {
			config_changes = TRUE;
		}
	}

	/* TODO: Check cib attributes */
	
	if(result) {
		*result = diff;
	} else {
		free_xml(diff);
	}
	
	return config_changes;
}

crm_data_t *
diff_cib_object(crm_data_t *old_cib, crm_data_t *new_cib, gboolean suppress)
{
	crm_data_t *dest = NULL;
	crm_data_t *src = NULL;
	const char *name = NULL;
	const char *value = NULL;

	crm_data_t *diff = diff_xml_object(old_cib, new_cib, suppress);
	
	/* add complete version information */
	src = old_cib;
	dest = find_xml_node(diff, "diff-removed", FALSE);
	if(src != NULL && dest != NULL) {
		name = XML_ATTR_GENERATION_ADMIN;
		value = crm_element_value(src, name);
		if(value == NULL) {
			value = "0";
		}
		crm_xml_add(dest, name, value);

		name = XML_ATTR_GENERATION;
		value = crm_element_value(src, name);
		if(value == NULL) {
			value = "0";
		}
		crm_xml_add(dest, name, value);

		name = XML_ATTR_NUMUPDATES;
		value = crm_element_value(src, name);
		if(value == NULL) {
			value = "0";
		}
		crm_xml_add(dest, name, value);
	}
	
	src = new_cib;
	dest = find_xml_node(diff, "diff-added", FALSE);
	if(src != NULL && dest != NULL) {
		name = XML_ATTR_GENERATION_ADMIN;
		value = crm_element_value(src, name);
		if(value == NULL) {
			value = "0";
		}
		crm_xml_add(dest, name, value);

		name = XML_ATTR_GENERATION;
		value = crm_element_value(src, name);
		if(value == NULL) {
			value = "0";
		}
		crm_xml_add(dest, name, value);

		name = XML_ATTR_NUMUPDATES;
		value = crm_element_value(src, name);
		if(value == NULL) {
			value = "0";
		}
		crm_xml_add(dest, name, value);
	}
	return diff;
}

void
log_cib_diff(int log_level, crm_data_t *diff, const char *function)
{
	int add_updates = 0;
	int add_epoch  = 0;
	int add_admin_epoch = 0;

	int del_updates = 0;
	int del_epoch  = 0;
	int del_admin_epoch = 0;

	if(diff == NULL) {
		return;
	}
	
	cib_diff_version_details(
		diff, &add_admin_epoch, &add_epoch, &add_updates, 
		&del_admin_epoch, &del_epoch, &del_updates);

	if(add_updates != del_updates) {
		do_crm_log(log_level, "%s: Diff: --- %d.%d.%d", function,
			   del_admin_epoch, del_epoch, del_updates);
		do_crm_log(log_level, "%s: Diff: +++ %d.%d.%d", function,
			   add_admin_epoch, add_epoch, add_updates);
	} else if(diff != NULL) {
		do_crm_log(log_level,
			   "%s: Local-only Change: %d.%d.%d", function,
			   add_admin_epoch, add_epoch, add_updates);
	}
	
	log_xml_diff(log_level, diff, function);
}

gboolean
cib_version_details(
	crm_data_t *cib, int *admin_epoch, int *epoch, int *updates)
{
	const char *value = NULL;
	if(cib == NULL) {
		*admin_epoch = -1;
		*epoch  = -1;
		*updates = -1;
		return FALSE;
		
	} else {
		value = crm_element_value(cib, XML_ATTR_GENERATION_ADMIN);
		*admin_epoch = crm_parse_int(value, "-1");

		value  = crm_element_value(cib, XML_ATTR_GENERATION);
		*epoch = crm_parse_int(value, "-1");

		value = crm_element_value(cib, XML_ATTR_NUMUPDATES);
		*updates = crm_parse_int(value, "-1");
	}
	return TRUE;	
}

gboolean
cib_diff_version_details(
	crm_data_t *diff, int *admin_epoch, int *epoch, int *updates, 
	int *_admin_epoch, int *_epoch, int *_updates)
{
	crm_data_t *tmp = NULL;

	tmp = find_xml_node(diff, "diff-added", FALSE);
	cib_version_details(tmp, admin_epoch, epoch, updates);

	tmp = find_xml_node(diff, "diff-removed", FALSE);
	cib_version_details(tmp, _admin_epoch, _epoch, _updates);
	return TRUE;
}

/*
 * The caller should never free the return value
 */
crm_data_t*
get_object_root(const char *object_type, crm_data_t *the_root)
{
	const char *node_stack[2];
	crm_data_t *tmp_node = NULL;
	
	if(the_root == NULL) {
		crm_err("CIB root object was NULL");
		return NULL;
	}
	
	node_stack[0] = XML_CIB_TAG_CONFIGURATION;
	node_stack[1] = object_type;

	if(object_type == NULL
	   || strlen(object_type) == 0
	   || safe_str_eq(XML_CIB_TAG_SECTION_ALL, object_type)
	   || safe_str_eq(XML_TAG_CIB, object_type)) {
		/* get the whole cib */
		return the_root;

	} else if(strcasecmp(object_type, XML_CIB_TAG_STATUS) == 0) {
		/* these live in a different place */
		tmp_node = find_xml_node(the_root, XML_CIB_TAG_STATUS, FALSE);

		node_stack[0] = object_type;
		node_stack[1] = NULL;

	} else {
		tmp_node = find_xml_node_nested(the_root, node_stack, 2);
	}

	if (tmp_node == NULL) {
		crm_debug_2("Section [%s [%s]] not present in %s",
			    node_stack[0],
			    node_stack[1]?node_stack[1]:"",
			    crm_element_name(the_root));
	}
	return tmp_node;
}

const char *
get_crm_option(crm_data_t *cib, const char *name, gboolean do_warn) 
{
	const char * value = NULL;
	crm_data_t * a_default = NULL;
	crm_data_t * config = get_object_root(XML_CIB_TAG_CRMCONFIG, cib);
	
	if(config != NULL) {
		a_default = find_entity(config, XML_CIB_TAG_NVPAIR, name);
	}
	
	if(a_default == NULL) {
		if(do_warn) {
			crm_warn("Option %s not set", name);
		}
		return NULL;
	}
	
	value = crm_element_value(a_default, XML_NVPAIR_ATTR_VALUE);
	if(safe_str_eq(value, "")) {
		value = NULL;
	}
	
	return value;
}

crm_data_t*
create_cib_fragment_adv(
	crm_data_t *update, const char *update_section, const char *source)
{
	crm_data_t *cib = NULL;
	gboolean whole_cib = FALSE;
	crm_data_t *object_root  = NULL;
	const char *update_name = NULL;
	char *local_section = NULL;

/* 	crm_debug("Creating a blank fragment: %s", update_section); */
	
	if(update == NULL && update_section == NULL) {
		crm_debug_3("Creating a blank fragment");
		update = createEmptyCib();
		crm_xml_add(cib, XML_ATTR_ORIGIN, source);
		return update;

	} else if(update == NULL) {
		crm_err("No update to create a fragment for");
		return NULL;
		
	} else if(update_section == NULL) {
		local_section = cib_pluralSection(update_name);
		update_section = local_section;
	}

	if(safe_str_eq(crm_element_name(update), XML_TAG_CIB)) {
		whole_cib = TRUE;
	}
	
	if(whole_cib == FALSE) {
		cib = createEmptyCib();
		crm_xml_add(cib, XML_ATTR_ORIGIN, source);
		object_root = get_object_root(update_section, cib);
		add_node_copy(object_root, update);

	} else {
		cib = copy_xml(update);
		crm_xml_add(cib, XML_ATTR_ORIGIN, source);
	}

	crm_free(local_section);
	crm_debug_3("Verifying created fragment");
	if(verifyCibXml(cib) == FALSE) {
		crm_err("Fragment creation failed");
		crm_log_xml_err(cib, "[src]");		
		free_xml(cib);
		cib = NULL;
	}
	
	return cib;
}

/*
 * It is the callers responsibility to free both the new CIB (output)
 *     and the new CIB (input)
 */
crm_data_t*
createEmptyCib(void)
{
	crm_data_t *cib_root = NULL, *config = NULL, *status = NULL;
	
	cib_root = create_xml_node(NULL, XML_TAG_CIB);

	config = create_xml_node(cib_root, XML_CIB_TAG_CONFIGURATION);
	status = create_xml_node(cib_root, XML_CIB_TAG_STATUS);

/* 	crm_xml_add(cib_root, "version", "1"); */
	crm_xml_add(cib_root, "generated", XML_BOOLEAN_TRUE);

	create_xml_node(config, XML_CIB_TAG_CRMCONFIG);
	create_xml_node(config, XML_CIB_TAG_NODES);
	create_xml_node(config, XML_CIB_TAG_RESOURCES);
	create_xml_node(config, XML_CIB_TAG_CONSTRAINTS);
	
	if (verifyCibXml(cib_root)) {
		return cib_root;
	}

	free_xml(cib_root);
	crm_crit("The generated CIB did not pass integrity testing!!"
		 "  All hope is lost.");
	return NULL;
}


gboolean
verifyCibXml(crm_data_t *cib)
{
	int lpc = 0;
	gboolean is_valid = TRUE;
	crm_data_t *tmp_node = NULL;

	const char *sections[] = {
		XML_CIB_TAG_NODES,
		XML_CIB_TAG_RESOURCES,
		XML_CIB_TAG_CONSTRAINTS,
		XML_CIB_TAG_STATUS,
		XML_CIB_TAG_CRMCONFIG
	};
	
	if (cib == NULL) {
		crm_warn("CIB was empty.");
		return FALSE;
	}

	/* basic tests... are the standard section all there */
	for(lpc = 0; lpc < DIMOF(sections); lpc++) {
		tmp_node = get_object_root(sections[lpc], cib);
		if (tmp_node == NULL) {
			crm_warn("Section %s is not present in the CIB",
				 sections[lpc]);
			is_valid = FALSE;
		}
	}

	/* more integrity tests */

	return is_valid;
}


gboolean verify_cib_cmds(cib_t *cib) 
{
	gboolean valid = TRUE;
	if(cib->cmds->variant_op == NULL) {
		crm_err("Operation variant_op not set");
		valid = FALSE;
	}	
	if(cib->cmds->signon == NULL) {
		crm_err("Operation signon not set");
		valid = FALSE;
	}
	if(cib->cmds->signoff == NULL) {
		crm_err("Operation signoff not set");
		valid = FALSE;
	}
	if(cib->cmds->free == NULL) {
		crm_err("Operation free not set");
		valid = FALSE;
	}
	if(cib->cmds->set_op_callback == NULL) {
		crm_err("Operation set_op_callback not set");
		valid = FALSE;
	}
	if(cib->cmds->add_notify_callback == NULL) {
		crm_err("Operation add_notify_callback not set");
		valid = FALSE;
	}
	if(cib->cmds->del_notify_callback == NULL) {
		crm_err("Operation del_notify_callback not set");
		valid = FALSE;
	}
	if(cib->cmds->set_connection_dnotify == NULL) {
		crm_err("Operation set_connection_dnotify not set");
		valid = FALSE;
	}
	if(cib->cmds->channel == NULL) {
		crm_err("Operation channel not set");
		valid = FALSE;
	}
	if(cib->cmds->inputfd == NULL) {
		crm_err("Operation inputfd not set");
		valid = FALSE;
	}
	if(cib->cmds->noop == NULL) {
		crm_err("Operation noop not set");
		valid = FALSE;
	}
	if(cib->cmds->ping == NULL) {
		crm_err("Operation ping not set");
		valid = FALSE;
	}
	if(cib->cmds->query == NULL) {
		crm_err("Operation query not set");
		valid = FALSE;
	}
	if(cib->cmds->query_from == NULL) {
		crm_err("Operation query_from not set");
		valid = FALSE;
	}
	if(cib->cmds->is_master == NULL) {
		crm_err("Operation is_master not set");
		valid = FALSE;
	}
	if(cib->cmds->set_master == NULL) {
		crm_err("Operation set_master not set");
		valid = FALSE;
	}
	if(cib->cmds->set_slave == NULL) {
		crm_err("Operation set_slave not set");
		valid = FALSE;
	}		
	if(cib->cmds->set_slave_all == NULL) {
		crm_err("Operation set_slave_all not set");
		valid = FALSE;
	}		
	if(cib->cmds->sync == NULL) {
		crm_err("Operation sync not set");
		valid = FALSE;
	}		if(cib->cmds->sync_from == NULL) {
		crm_err("Operation sync_from not set");
		valid = FALSE;
	}
	if(cib->cmds->bump_epoch == NULL) {
		crm_err("Operation bump_epoch not set");
		valid = FALSE;
	}		
	if(cib->cmds->create == NULL) {
		crm_err("Operation create not set");
		valid = FALSE;
	}
	if(cib->cmds->modify == NULL) {
		crm_err("Operation modify not set");
		valid = FALSE;
	}
	if(cib->cmds->replace == NULL) {
		crm_err("Operation replace not set");
		valid = FALSE;
	}
	if(cib->cmds->delete == NULL) {
		crm_err("Operation delete not set");
		valid = FALSE;
	}
	if(cib->cmds->erase == NULL) {
		crm_err("Operation erase not set");
		valid = FALSE;
	}
	if(cib->cmds->quit == NULL) {
		crm_err("Operation quit not set");
		valid = FALSE;
	}
	
	if(cib->cmds->msgready == NULL) {
		crm_err("Operation msgready not set");
		valid = FALSE;
	}
	if(cib->cmds->rcvmsg == NULL) {
		crm_err("Operation rcvmsg not set");
		valid = FALSE;
	}
	if(cib->cmds->dispatch == NULL) {
		crm_err("Operation dispatch not set");
		valid = FALSE;
	}

	return valid;
}
