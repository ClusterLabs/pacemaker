/* $Id: notify.c,v 1.3 2004/12/14 14:43:02 andrew Exp $ */
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

	struct ha_msg *update_msg = user_data;
	cib_client_t *client = value;

	if(safe_str_eq(client->channel_name, "cib_callback")) {
		crm_trace("Notifying client %s of update", client->id);
		if(msg2ipcchan(update_msg, client->channel) != HA_OK) {
			crm_err("Notification of client %s failed", client->id);
		}
	}
}

void
cib_pre_notify(
	const char *op, xmlNodePtr existing, xmlNodePtr update) 
{
	struct ha_msg *update_msg = ha_msg_new(6);
	const char *id = xmlGetProp(update, XML_ATTR_ID);
	const char *type = NULL;

	ha_msg_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	ha_msg_add(update_msg, F_SUBTYPE, T_CIB_PRE_NOTIFY);
	ha_msg_add(update_msg, F_CIB_OPERATION, op);

	if(id != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJID, id);
	}

	if(update != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJTYPE, update->name);
	} else if(existing != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJTYPE, existing->name);
	}

	type = cl_get_string(update_msg, F_CIB_OBJTYPE);	
	
	if(existing != NULL) {
		char *existing_s = dump_xml_unformatted(existing);
		if(existing_s != NULL) {
			ha_msg_add(update_msg, F_CIB_EXISTING, existing_s);
		} else {
			crm_debug("Update string was NULL (xml=%p)", update);
		}
		crm_free(existing_s);
	}
	if(update != NULL) {
		char *update_s = dump_xml_unformatted(update);
		if(update_s != NULL) {
			ha_msg_add(update_msg, F_CIB_UPDATE, update_s);
		} else {
			crm_debug("Update string was NULL (xml=%p)", update);
		}
		crm_free(update_s);
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
		
	ha_msg_del(update_msg);
}

void
cib_post_notify(
	const char *op, xmlNodePtr update, enum cib_errors result, xmlNodePtr new_obj) 
{
	struct ha_msg *update_msg = ha_msg_new(8);
	const char *id = xmlGetProp(new_obj, XML_ATTR_ID);
	const char *type = NULL;
	
	ha_msg_add(update_msg, F_TYPE, T_CIB_NOTIFY);
	ha_msg_add(update_msg, F_SUBTYPE, T_CIB_POST_NOTIFY);
	ha_msg_add(update_msg, F_CIB_OPERATION, op);
	ha_msg_add_int(update_msg, F_CIB_RC, result);
	
	if(id != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJID, id);
	}
	if(update != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJTYPE, update->name);
	} else if(new_obj != NULL) {
		ha_msg_add(update_msg, F_CIB_OBJTYPE, new_obj->name);
	}

	type = cl_get_string(update_msg, F_CIB_OBJTYPE);
	
	if(update != NULL) {
		char *update_s = dump_xml_unformatted(update);
		if(update_s != NULL) {
			ha_msg_add(update_msg, F_CIB_UPDATE, update_s);
		} else {
			crm_debug("Update string was NULL (xml=%p)", update);
		}
		crm_free(update_s);
	}
	if(new_obj != NULL) {
		char *new_obj_s = dump_xml_unformatted(new_obj);
		if(new_obj_s != NULL) {
			ha_msg_add(update_msg, F_CIB_UPDATE_RESULT, new_obj_s);
		} else {
			crm_debug("Update string was NULL (xml=%p)", new_obj);
		}
		crm_free(new_obj_s);
	}
	
	g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	
	pending_updates--;

	if(pending_updates == 0) {
		ha_msg_mod(update_msg, F_SUBTYPE, T_CIB_UPDATE_CONFIRM);
		g_hash_table_foreach(client_list, cib_notify_client, update_msg);
	}

	ha_msg_del(update_msg);

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
				    op, type, id?"id=":"", id);
			
		} else {
			crm_warn("%s of <%s %s%s> FAILED: %s", op, type,
				 id?"id=":"", id, cib_error2string(result));
		}
	}
}
