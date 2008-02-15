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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/cl_log.h>

#include <time.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <cibio.h>
#include <callbacks.h>
#include <notify.h>


extern GHashTable *client_list;
int pending_updates = 0;

void cib_notify_client(gpointer key, gpointer value, gpointer user_data);
void attach_cib_generation(xmlNode *msg, const char *field, xmlNode *a_cib);

void do_cib_notify(
	int options, const char *op, xmlNode *update,
	enum cib_errors result, xmlNode *result_data, const char *msg_type);


void
cib_notify_client(gpointer key, gpointer value, gpointer user_data)
{

	IPC_Channel *ipc_client = NULL;
	xmlNode *update_msg = user_data;
	cib_client_t *client = value;
	const char *type = NULL;
	gboolean is_pre = FALSE;
	gboolean is_post = FALSE;	
	gboolean is_confirm = FALSE;
	gboolean is_replace = FALSE;
	gboolean is_diff = FALSE;
	gboolean do_send = FALSE;

	int qlen = 0;
	int max_qlen = 0;
	
	CRM_DEV_ASSERT(client != NULL);
	CRM_DEV_ASSERT(update_msg != NULL);

	type = crm_element_value(update_msg, F_SUBTYPE);
	CRM_DEV_ASSERT(type != NULL);

	if(client == NULL) {
		crm_warn("Skipping NULL client");
		return;

	} else if(client->channel == NULL) {
		crm_warn("Skipping client with NULL channel");
		return;

	} else if(client->name == NULL) {
		crm_debug_2("Skipping unnammed client / comamnd channel");
		return;
	}
	
	if(safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
		is_pre = TRUE;
		
	} else if(safe_str_eq(type, T_CIB_POST_NOTIFY)) {
		is_post = TRUE;

	} else if(safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
		is_confirm = TRUE;

	} else if(safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
		is_diff = TRUE;

	} else if(safe_str_eq(type, T_CIB_REPLACE_NOTIFY)) {
		is_replace = TRUE;
	}

	ipc_client = client->channel;
	qlen = ipc_client->send_queue->current_qlen;
	max_qlen = ipc_client->send_queue->max_qlen;

#if 1
	/* get_chan_status() causes memory to be allocated that isnt free'd
	 *   until the message is read (which messes up the memory stats) 
	 */
	if(ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
		crm_debug_2("Skipping notification to disconnected"
			    " client %s/%s", client->name, client->id);
		
	} else if(client->pre_notify && is_pre) {
		if(qlen < (int)(0.4 * max_qlen)) {
			do_send = TRUE;
		} else {
			crm_warn("Throttling pre-notifications due to"
				 " high load: queue=%d (max=%d)",
				 qlen, max_qlen);
		}
		 
	} else if(client->post_notify && is_post) {
		if(qlen < (int)(0.7 * max_qlen)) {
			do_send = TRUE;
		} else {
			crm_warn("Throttling post-notifications due to"
				 " extreme load: queue=%d (max=%d)",
				 qlen, max_qlen);
		}

		/* these are critical */
	} else
#endif
		if(client->diffs && is_diff) {
		do_send = TRUE;

	} else if(client->confirmations && is_confirm) {
		do_send = TRUE;

	} else if(client->replace && is_replace) {
		do_send = TRUE;
	}

	if(do_send) {
		crm_debug_2("Notifying client %s/%s of %s update (queue=%d)",
			    client->name, client->channel_name, type, qlen);

		if(ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
			/* We never want the CIB to exit because our client is slow */
			crm_crit("%s-notification of client %s/%s failed - queue saturated",
				 is_confirm?"Confirmation":is_post?"Post":"Pre",
				 client->name, client->id);
			
		} else if(send_ipc_message(ipc_client, update_msg) == FALSE) {
			crm_warn("Notification of client %s/%s failed",
				 client->name, client->id);
		}
		
	} else {
		crm_debug_3("Client %s/%s not interested in %s notifications",
			    client->name, client->channel_name, type);	
	}
}

void
cib_pre_notify(
	int options, const char *op, xmlNode *existing, xmlNode *update) 
{
	xmlNode *update_msg = NULL;
	const char *type = NULL;
	const char *id = NULL;

	update_msg = create_xml_node(NULL, "pre-notify");

	if(update != NULL) {
		id = crm_element_value(update, XML_ATTR_ID);
	}
	
	crm_xml_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	crm_xml_add(update_msg, F_SUBTYPE, T_CIB_PRE_NOTIFY);
	crm_xml_add(update_msg, F_CIB_OPERATION, op);

	if(id != NULL) {
		crm_xml_add(update_msg, F_CIB_OBJID, id);
	}

	if(update != NULL) {
		crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));
	} else if(existing != NULL) {
		crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(existing));
	}

	type = crm_element_value(update_msg, F_CIB_OBJTYPE);	
	attach_cib_generation(update_msg, "cib_generation", the_cib);
	
	if(existing != NULL) {
		add_message_xml(update_msg, F_CIB_EXISTING, existing);
	}
	if(update != NULL) {
		add_message_xml(update_msg, F_CIB_UPDATE, update);
	}

	g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	
	if(update == NULL) {
		crm_debug_2("Performing operation %s (on section=%s)",
			    op, type);

	} else {
		crm_debug_2("Performing %s on <%s%s%s>",
			    op, type, id?" id=":"", id?id:"");
	}
		
	free_xml(update_msg);
}

void
cib_post_notify(int options, const char *op, xmlNode *update,
		enum cib_errors result, xmlNode *new_obj) 
{
	do_cib_notify(
		options, op, update, result, new_obj, T_CIB_UPDATE_CONFIRM);
}

void
cib_diff_notify(
	int options, const char *client, const char *call_id, const char *op,
	xmlNode *update, enum cib_errors result, xmlNode *diff) 
{
	int add_updates = 0;
	int add_epoch  = 0;
	int add_admin_epoch = 0;

	int del_updates = 0;
	int del_epoch  = 0;
	int del_admin_epoch = 0;

	int log_level = LOG_DEBUG_2;
	
	if(diff == NULL) {
		return;
	}

	if(result != cib_ok) {
		log_level = LOG_WARNING;
	}
	
	cib_diff_version_details(
		diff, &add_admin_epoch, &add_epoch, &add_updates, 
		&del_admin_epoch, &del_epoch, &del_updates);

	if(add_updates != del_updates) {
		do_crm_log(log_level,
			      "Update (client: %s%s%s): %d.%d.%d -> %d.%d.%d (%s)",
			      client, call_id?", call:":"", call_id?call_id:"",
			      del_admin_epoch, del_epoch, del_updates,
			      add_admin_epoch, add_epoch, add_updates,
			      cib_error2string(result));

	} else if(diff != NULL) {
		do_crm_log(log_level,
			      "Local-only Change (client:%s%s%s): %d.%d.%d (%s)",
			      client, call_id?", call: ":"", call_id?call_id:"",
			      add_admin_epoch, add_epoch, add_updates,
			      cib_error2string(result));
	}
	
	do_cib_notify(options, op, update, result, diff, T_CIB_DIFF_NOTIFY);
}

void
do_cib_notify(
	int options, const char *op, xmlNode *update,
	enum cib_errors result, xmlNode *result_data, const char *msg_type) 
{
	xmlNode *update_msg = NULL;
	const char *type = NULL;
	const char *id = NULL;

	update_msg = create_xml_node(NULL, "notify");

	if(result_data != NULL) {
		id = crm_element_value(result_data, XML_ATTR_ID);
	}
	
	crm_xml_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	crm_xml_add(update_msg, F_SUBTYPE, msg_type);
	crm_xml_add(update_msg, F_CIB_OPERATION, op);
	crm_xml_add_int(update_msg, F_CIB_RC, result);
	
	if(id != NULL) {
		crm_xml_add(update_msg, F_CIB_OBJID, id);
	}

	if(update != NULL) {
		crm_debug_4("Setting type to update->name: %s",
			    crm_element_name(update));
		crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));
		type = crm_element_name(update);

	} else if(result_data != NULL) {
		crm_debug_4("Setting type to new_obj->name: %s",
			    crm_element_name(result_data));
		crm_xml_add(update_msg, F_CIB_OBJTYPE, crm_element_name(result_data));
		type = crm_element_name(result_data);
		
	} else {
		crm_debug_4("Not Setting type");
	}

	attach_cib_generation(update_msg, "cib_generation", the_cib);
	if(update != NULL) {
		add_message_xml(update_msg, F_CIB_UPDATE, update);
	}
	if(result_data != NULL) {
		add_message_xml(update_msg, F_CIB_UPDATE_RESULT, result_data);
	}

	crm_debug_3("Notifying clients");
	g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	free_xml(update_msg);

	if(update == NULL) {
		if(result == cib_ok) {
			crm_debug_2("Operation %s (on section=%s) completed",
				    op, crm_str(type));
			
		} else {
			crm_warn("Operation %s (on section=%s) FAILED: (%d) %s",
				 op, crm_str(type), result,
				 cib_error2string(result));
		}
		
	} else {
		if(result == cib_ok) {
			crm_debug_2("Completed %s of <%s %s%s>",
				    op, crm_str(type), id?"id=":"", id?id:"");
			
		} else {
			crm_warn("%s of <%s %s%s> FAILED: %s", op,crm_str(type),
				 id?"id=":"", id?id:"", cib_error2string(result));
		}
	}

	crm_debug_3("Notify complete");
}


void
attach_cib_generation(xmlNode *msg, const char *field, xmlNode *a_cib) 
{
	xmlNode *generation = create_xml_node(
		NULL, XML_CIB_TAG_GENERATION_TUPPLE);

	if(a_cib != NULL) {
		copy_in_properties(generation, a_cib);
	}
	add_message_xml(msg, field, generation);
	free_xml(generation);
}

void
cib_replace_notify(xmlNode *update, enum cib_errors result, xmlNode *diff) 
{
	const char *origin = NULL;
	xmlNode *replace_msg = NULL;
	
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

	origin = crm_element_value(update, F_CRM_ORIGIN);
	
	if(add_updates != del_updates) {
		crm_info("Replaced: %d.%d.%d -> %d.%d.%d from %s",
			 del_admin_epoch, del_epoch, del_updates,
			 add_admin_epoch, add_epoch, add_updates,
			 crm_str(origin));
	} else if(diff != NULL) {
		crm_info("Local-only Replace: %d.%d.%d from %s",
			 add_admin_epoch, add_epoch, add_updates,
			 crm_str(origin));
	}
	
	replace_msg = create_xml_node(NULL, "notify-replace");
	crm_xml_add(replace_msg, F_TYPE, T_CIB_NOTIFY);
	crm_xml_add(replace_msg, F_SUBTYPE, T_CIB_REPLACE_NOTIFY);
	crm_xml_add(replace_msg, F_CIB_OPERATION, CIB_OP_REPLACE);
	crm_xml_add_int(replace_msg, F_CIB_RC, result);
	attach_cib_generation(replace_msg, "cib-replace-generation", update);

	crm_log_xml(LOG_DEBUG_2,"CIB Replaced", replace_msg);
	
	g_hash_table_foreach(client_list, cib_notify_client, replace_msg);
	free_xml(replace_msg);
}
