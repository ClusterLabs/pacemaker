/* $Id: complex.c,v 1.4 2004/11/09 16:52:57 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>
#include <crm/msg_xml.h>

gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);
gboolean is_active(rsc_to_node_t *cons);
gboolean constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_dependancy_t *constraint);
void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);


resource_object_functions_t resource_class_functions[] = {
	{
		native_unpack,
		native_color,
		native_create_actions,
		native_internal_constraints,
		native_agent_constraints,
		native_rsc_dependancy_lh,
		native_rsc_dependancy_rh,
		native_rsc_order_lh,
		native_rsc_order_rh,
		native_rsc_location,
		native_expand,
		native_dump,
		native_free
	},
	{
		group_unpack,
		group_color,
		group_create_actions,
		group_internal_constraints,
		group_agent_constraints,
		group_rsc_dependancy_lh,
		group_rsc_dependancy_rh,
		group_rsc_order_lh,
		group_rsc_order_rh,
		group_rsc_location,
		group_expand,
		group_dump,
		group_free
	},
/* 	{ */
/* 		incarnation_expand, */
/* 		incarnation_n_colors, */
/* 		incarnation_assign, */
/* 		incarnation_expand, */
/* 		incarnation_internal_constraints, */
/* 		incarnation_rsc_dependancy, */
/* 		incarnation_rsc_order, */
/* 		incarnation_rsc_location, */
/* 		incarnation_dump */
/* 	}, */

};

/* resource_object_functions_t resource_variants[] = resource_class_functions; */


int get_resource_type(const char *name)
{
	if(safe_str_eq(name, "resource")) {
		return pe_native;

	} else if(safe_str_eq(name, "resource_group")) {
		return pe_group;
	}
	
	return pe_unknown;
}

gboolean
is_active(rsc_to_node_t *cons)
{
	/* todo: check constraint lifetime */
	return TRUE;
}

gboolean	
common_unpack(xmlNodePtr xml_obj, resource_t **rsc)
{
	const char *id       = xmlGetProp(xml_obj, XML_ATTR_ID);
	const char *stopfail = xmlGetProp(xml_obj, "on_stopfail");
	const char *restart  = xmlGetProp(xml_obj, "restart_type");
	const char *timeout  = xmlGetProp(xml_obj, "timeout");
	const char *priority = xmlGetProp(xml_obj, XML_CIB_ATTR_PRIORITY);	
	
	crm_verbose("Processing resource...");
	
	if(id == NULL) {
		crm_err("Must specify id tag in <resource>");
		return FALSE;
		
	} else if(rsc == NULL) {
		crm_err("Nowhere to unpack resource into");
		return FALSE;
		
	}
	crm_malloc(*rsc, sizeof(resource_t));
	
	if(*rsc == NULL) {
		return FALSE;
	}
	
	(*rsc)->id  = id;
	(*rsc)->xml = xml_obj;
	(*rsc)->variant = get_resource_type(xml_obj->name);
	
	if((*rsc)->variant == pe_unknown) {
		crm_err("Unknown resource type: %s", xml_obj->name);
		crm_free(*rsc);
		return FALSE;
	}
	
	(*rsc)->fns = &resource_class_functions[(*rsc)->variant];
	(*rsc)->fns->unpack(*rsc);

	crm_verbose("Processing resource...");
	
	(*rsc)->priority	   = atoi(priority?priority:"0"); 
	(*rsc)->effective_priority = (*rsc)->priority;
	(*rsc)->recovery_type      = recovery_stop_start;
	(*rsc)->runnable	   = TRUE; 
	(*rsc)->provisional	   = TRUE; 
	(*rsc)->timeout		   = timeout;
	(*rsc)->candidate_colors   = NULL;
	(*rsc)->rsc_cons	   = NULL; 
	(*rsc)->actions            = NULL;
	
	if(safe_str_eq(stopfail, "ignore")) {
		(*rsc)->stopfail_type = pesf_ignore;
	} else if(safe_str_eq(stopfail, "stonith")) {
		(*rsc)->stopfail_type = pesf_stonith;
	} else {
		(*rsc)->stopfail_type = pesf_block;
	}
	
	if(safe_str_eq(restart, "restart")) {
		(*rsc)->restart_type = pe_restart_restart;
	} else if(safe_str_eq(restart, "recover")) {
		(*rsc)->restart_type = pe_restart_recover;
	} else {
		(*rsc)->restart_type = pe_restart_ignore;
	}

	return TRUE;
}


void
order_actions(action_t *lh_action, action_t *rh_action, order_constraint_t *order) 
{
	action_wrapper_t *wrapper = NULL;
	GListPtr list = NULL;
	
	crm_verbose("%d Processing %d -> %d",
		    order->id, lh_action->id, rh_action->id);
	
	crm_debug_action(
		print_action("LH (order_actions)", lh_action, FALSE));

	crm_debug_action(
		print_action("RH (order_actions)", rh_action, FALSE));
	
	crm_malloc(wrapper, sizeof(action_wrapper_t));
	if(wrapper != NULL) {
		wrapper->action = rh_action;
		wrapper->strength = order->strength;
		
		list = lh_action->actions_after;
		list = g_list_append(list, wrapper);
		lh_action->actions_after = list;
	}
	
	crm_malloc(wrapper, sizeof(action_wrapper_t));
	if(wrapper != NULL) {
		wrapper->action = lh_action;
		wrapper->strength = order->strength;
		
		list = rh_action->actions_before;
		list = g_list_append(list, wrapper);
		rh_action->actions_before = list;
	}
}

void common_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	crm_debug("%s%s%s%sResource %s: (variant=%s, priority=%f)",
		  pre_text==NULL?"":pre_text,
		  pre_text==NULL?"":": ",
		  rsc->provisional?"Provisional ":"",
		  rsc->runnable?"":"(Non-Startable) ",
		  rsc->id,
		  rsc->xml->name,
		  (double)rsc->priority);
}

void common_free(resource_t *rsc)
{
	if(rsc == NULL) {
		return;
	}
	
	crm_trace("Freeing %s", rsc->id);

	while(rsc->rsc_cons) {
 		pe_free_rsc_dependancy(
			(rsc_dependancy_t*)rsc->rsc_cons->data);
		rsc->rsc_cons = rsc->rsc_cons->next;
	}
	crm_trace("Freeing constraint list");
	if(rsc->rsc_cons != NULL) {
		g_list_free(rsc->rsc_cons);
	}

	crm_trace("Freeing opaque data");
	crm_free(rsc->variant_opaque);
	crm_trace("Freeing resource");
	crm_free(rsc);
	crm_trace("Resource freed");
}
