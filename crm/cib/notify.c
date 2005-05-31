/* $Id: notify.c,v 1.25 2005/05/31 11:32:39 andrew Exp $ */
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

#include <crm/dmalloc_wrapper.h>

extern GHashTable *client_list;
int pending_updates = 0;

void cib_notify_client(gpointer key, gpointer value, gpointer user_data);
void attach_cib_generation(HA_Message *msg, const char *field, crm_data_t *a_cib);

void do_cib_notify(
	int options, const char *op, crm_data_t *update,
	enum cib_errors result, crm_data_t *result_data, const char *msg_type);


void
cib_notify_client(gpointer key, gpointer value, gpointer user_data)
{

	IPC_Channel *ipc_client = NULL;
	HA_Message *update_msg = user_data;
	cib_client_t *client = value;
	const char *type = NULL;
	gboolean is_pre = FALSE;
	gboolean is_post = FALSE;	
	gboolean is_confirm = FALSE;
	gboolean is_diff = FALSE;
	gboolean do_send = FALSE;

	int qlen = 0;
	int max_qlen = 0;
	
	CRM_DEV_ASSERT(client != NULL);
	CRM_DEV_ASSERT(update_msg != NULL);

	type = cl_get_string(update_msg, F_SUBTYPE);
	CRM_DEV_ASSERT(type != NULL);

	if(safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
		is_pre = TRUE;
		
	} else if(safe_str_eq(type, T_CIB_POST_NOTIFY)) {
		is_post = TRUE;

	} else if(safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
		is_confirm = TRUE;

	} else if(safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
		is_diff = TRUE;
	}

	if(client == NULL) {
		crm_warn("Skipping NULL client");
		return;

	} else if(client->channel == NULL) {
		crm_warn("Skipping client with NULL channel");
		return;
	}

	ipc_client = client->channel;
	qlen = ipc_client->send_queue->current_qlen;
	max_qlen = ipc_client->send_queue->max_qlen;
	
	if(ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
		crm_debug("Skipping notification to disconnected"
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

	} else if(client->diffs && is_diff) {
		if(qlen < (int)(0.8 * max_qlen)) {
			do_send = TRUE;
		} else {
			crm_warn("Throttling post-notifications due to"
				 " extreme load: queue=%d (max=%d)",
				 qlen, max_qlen);
		}

		/* these are critical */
	} else if(client->confirmations && is_confirm) {
		do_send = TRUE;
	}

	if(do_send) {

		crm_debug_3("Notifying client %s/%s of update (queue=%d)",
			  client->name, client->channel_name, qlen);

		if(ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
			/* We never want the CIB to exit because our client is slow */
			crm_crit("%s-notification of client %s/%s failed - queue saturated",
				 is_confirm?"Confirmation":is_post?"Post":"Pre",
				 client->name, client->id);
			
		} else {
			HA_Message *msg_copy = ha_msg_copy(update_msg);

			if(crm_send_ipc_message(
				   ipc_client, msg_copy, TRUE) == FALSE) {
				crm_warn("Notification of client %s/%s failed",
					 client->name, client->id);
			}
		}
		
	} else {
		crm_debug_4("Client %s/%s not interested in %s notifications",
			  client->name, client->channel_name, type);	
	}
}

void
cib_pre_notify(
	int options, const char *op, crm_data_t *existing, crm_data_t *update) 
{
	HA_Message *update_msg = ha_msg_new(6);
	const char *type = NULL;
	const char *id = NULL;
	if(options & cib_inhibit_notify) {
		crm_debug_2("Inhibiting notify.");
		return;
	}	

	if(update != NULL) {
		id = crm_element_value(update, XML_ATTR_ID);
	}
	
	ha_msg_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	ha_msg_add(update_msg, F_SUBTYPE, T_CIB_PRE_NOTIFY);
	ha_msg_add(update_msg, F_CIB_OPERATION, op);

	if(id != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJID, id);
	}

	if(update != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));
	} else if(existing != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJTYPE, crm_element_name(existing));
	}

	type = cl_get_string(update_msg, F_CIB_OBJTYPE);	
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
		
	crm_msg_del(update_msg);
}

void
cib_post_notify(int options, const char *op, crm_data_t *update,
		enum cib_errors result, crm_data_t *new_obj) 
{
	if(options & cib_inhibit_notify) {
		crm_debug_2("Inhibiting notify.");
		return;
	}
	do_cib_notify(
		options, op, update, result, new_obj, T_CIB_UPDATE_CONFIRM);
}

void
cib_diff_notify(int options, const char *op, crm_data_t *update,
		enum cib_errors result, crm_data_t *diff) 
{
	do_cib_notify(options, op, update, result, diff, T_CIB_DIFF_NOTIFY);
}

void
do_cib_notify(
	int options, const char *op, crm_data_t *update,
	enum cib_errors result, crm_data_t *result_data, const char *msg_type) 
{
	HA_Message *update_msg = ha_msg_new(8);
	char *type = NULL;
	char *id = NULL;

	if(options & cib_inhibit_notify) {
		crm_debug_2("Inhibiting notify.");
		return;
	}
	if(update != NULL && crm_element_value(result_data, XML_ATTR_ID) != NULL){
		id = crm_element_value_copy(result_data, XML_ATTR_ID);
	}
	
	ha_msg_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	ha_msg_add(update_msg, F_SUBTYPE, msg_type);
	ha_msg_add(update_msg, F_CIB_OPERATION, op);
	ha_msg_add_int(update_msg, F_CIB_RC, result);
	
	if(id != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJID, id);
	}

	if(update != NULL) {
		crm_debug_4("Setting type to update->name: %s",
			    crm_element_name(update));
		ha_msg_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));
		type = crm_strdup(crm_element_name(update));

	} else if(result_data != NULL) {
		crm_debug_4("Setting type to new_obj->name: %s",
			    crm_element_name(result_data));
		ha_msg_add(update_msg, F_CIB_OBJTYPE, crm_element_name(result_data));
		type = crm_strdup(crm_element_name(result_data));
		
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

	crm_free(id);
	crm_free(type);
	crm_msg_del(update_msg);

	crm_debug_3("Notify complete");
}


void
attach_cib_generation(HA_Message *msg, const char *field, crm_data_t *a_cib) 
{
	crm_data_t *generation = create_xml_node(
		NULL, XML_CIB_TAG_GENERATION_TUPPLE);

	if(a_cib != NULL) {
		copy_in_properties(generation, a_cib);
	}
	add_message_xml(msg, field, generation);
	free_xml(generation);
}
