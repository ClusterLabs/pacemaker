/* $Id: notify.c,v 1.9 2005/02/10 11:02:20 andrew Exp $ */
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

void
cib_notify_client(gpointer key, gpointer value, gpointer user_data)
{

	HA_Message *update_msg = user_data;
	cib_client_t *client = value;

	if(safe_str_eq(client->channel_name, cib_channel_callback)) {
		crm_trace("Notifying client %s of update", client->id);
		if(msg2ipcchan(update_msg, client->channel) != HA_OK) {
			crm_err("Notification of client %s failed", client->id);
		}
	}
}

void
cib_pre_notify(
	const char *op, crm_data_t *existing, crm_data_t *update) 
{
	HA_Message *update_msg = ha_msg_new(6);
	const char *type = NULL;
	const char *id = NULL;
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
	
	if(existing != NULL) {
		add_message_xml(update_msg, F_CIB_EXISTING, existing);
	}
	if(update != NULL) {
		add_message_xml(update_msg, F_CIB_UPDATE, update);
	}

	g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	
	pending_updates++;
	
	if(update == NULL) {
		crm_verbose("Performing operation %s (on section=%s)",
			    op, type);

	} else {
		crm_verbose("Performing %s on <%s%s%s>",
			    op, type, id?" id=":"", id?id:"");
	}
		
	crm_msg_del(update_msg);
}

void
cib_post_notify(
	const char *op, crm_data_t *update, enum cib_errors result, crm_data_t *new_obj) 
{
	HA_Message *update_msg = ha_msg_new(8);
	char *type = NULL;
	char *id = NULL;
	if(update != NULL && crm_element_value(new_obj, XML_ATTR_ID) != NULL){
		id = crm_element_value_copy(new_obj, XML_ATTR_ID);
	}
	
	ha_msg_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	ha_msg_add(update_msg, F_SUBTYPE, T_CIB_POST_NOTIFY);
	ha_msg_add(update_msg, F_CIB_OPERATION, op);
	ha_msg_add_int(update_msg, F_CIB_RC, result);
	
	if(id != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJID, id);
	}
	crm_debug("beekhof");
	if(update != NULL) {
		crm_trace("Setting type to update->name: %s",
			    crm_element_name(update));
		ha_msg_add(update_msg, F_CIB_OBJTYPE, crm_element_name(update));
		type = crm_strdup(crm_element_name(update));

	} else if(new_obj != NULL) {
		crm_trace("Setting type to new_obj->name: %s",
			    crm_element_name(new_obj));
		ha_msg_add(update_msg, F_CIB_OBJTYPE, crm_element_name(new_obj));
		type = crm_strdup(crm_element_name(new_obj));
		
	} else {
		crm_trace("Not Setting type");
	}

	
	if(update != NULL) {
		add_message_xml(update_msg, F_CIB_UPDATE, update);

	} else if(new_obj != NULL) {
		add_message_xml(update_msg, F_CIB_UPDATE_RESULT, new_obj);
	}

	crm_debug("Notifying clients");
	g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	
	pending_updates--;

	if(pending_updates == 0) {
		ha_msg_mod(update_msg, F_SUBTYPE, T_CIB_UPDATE_CONFIRM);
		crm_debug("Sending confirmation to clients");
		g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	}

	if(update == NULL) {
		if(result == cib_ok) {
			crm_verbose("Operation %s (on section=%s) completed",
				    op, type);
			
		} else {
			crm_warn("Operation %s (on section=%s) FAILED: (%d) %s",
				 op, type, result, cib_error2string(result));
		}
		
	} else {
		if(result == cib_ok) {
			crm_verbose("Completed %s of <%s %s%s>",
				    op, type, id?"id=":"", id?id:"");
			
		} else {
			crm_warn("%s of <%s %s%s> FAILED: %s", op, type,
				 id?"id=":"", id?id:"", cib_error2string(result));
		}
	}

	crm_free(id);
	crm_free(type);
	crm_msg_del(update_msg);

	crm_debug("Notify complete");
}
