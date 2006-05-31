/* $Id: complex.c,v 1.1 2006/05/31 15:00:38 andrew Exp $ */
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

#include <portability.h>

#include <crm/cib.h>
#include <pengine.h>
#include <utils.h>
#include <lib/crm/pengine/rules.h>
#include <crm/msg_xml.h>
#include <clplumbing/cl_misc.h>

gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);
gboolean is_active(rsc_to_node_t *cons);
gboolean constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint);

extern gboolean rsc_colocation_new(const char *id, enum con_strength strength,
				   resource_t *rsc_lh, resource_t *rsc_rh);
rsc_to_node_t *generate_location_rule(
	resource_t *rsc, crm_data_t *location_rule, pe_working_set_t *data_set);

void populate_hash(crm_data_t *nvpair_list, GHashTable *hash,
		   const char **attrs, int attrs_length);

resource_object_functions_t resource_class_functions[] = {
	{
		native_unpack,
		native_find_child,
		native_children,
		native_parameter,
		native_print,
		native_active,
		native_resource_state,
		native_free
	},
	{
		group_unpack,
		group_find_child,
		group_children,
		native_parameter,
		group_print,
		group_active,
		group_resource_state,
		group_free
	},
	{
		clone_unpack,
		clone_find_child,
		clone_children,
		native_parameter,
		clone_print,
		clone_active,
		clone_resource_state,
		clone_free
	},
	{
		master_unpack,
		clone_find_child,
		clone_children,
		native_parameter,
		clone_print,
		clone_active,
		clone_resource_state,
		clone_free
	}
};

int get_resource_type(const char *name)
{
	if(safe_str_eq(name, XML_CIB_TAG_RESOURCE)) {
		return pe_native;

	} else if(safe_str_eq(name, XML_CIB_TAG_GROUP)) {
		return pe_group;

	} else if(safe_str_eq(name, XML_CIB_TAG_INCARNATION)) {
		return pe_clone;

	} else if(safe_str_eq(name, XML_CIB_TAG_MASTER)) {
		return pe_master;
	}
	
	return pe_unknown;
}

gboolean
is_active(rsc_to_node_t *cons)
{
	/* todo: check constraint lifetime */
	return TRUE;
}

static void dup_attr(gpointer key, gpointer value, gpointer user_data)
{
	add_hash_param(user_data, key, value);
}

gboolean	
common_unpack(crm_data_t * xml_obj, resource_t **rsc,
	      resource_t *parent, pe_working_set_t *data_set)
{
	const char *value = NULL;
	const char *id    = crm_element_value(xml_obj, XML_ATTR_ID);

	crm_log_xml_debug_3(xml_obj, "Processing resource input...");
	
	if(id == NULL) {
		pe_err("Must specify id tag in <resource>");
		return FALSE;
		
	} else if(rsc == NULL) {
		pe_err("Nowhere to unpack resource into");
		return FALSE;
		
	}
	crm_malloc0(*rsc, sizeof(resource_t));
	
	if(*rsc == NULL) {
		return FALSE;
	}
	
	(*rsc)->xml  = xml_obj;
	(*rsc)->parent  = parent;
	(*rsc)->ops_xml = find_xml_node(xml_obj, "operations", FALSE);
	(*rsc)->variant = get_resource_type(crm_element_name(xml_obj));
	if((*rsc)->variant == pe_unknown) {
		pe_err("Unknown resource type: %s", crm_element_name(xml_obj));
		crm_free(*rsc);
		return FALSE;
	}
	
	(*rsc)->parameters = g_hash_table_new_full(
		g_str_hash,g_str_equal, g_hash_destroy_str,g_hash_destroy_str);
	
	(*rsc)->meta = g_hash_table_new_full(
		g_str_hash,g_str_equal, g_hash_destroy_str,g_hash_destroy_str);
	
	value = crm_element_value(xml_obj, XML_RSC_ATTR_INCARNATION);
	if(value) {
		(*rsc)->id = crm_concat(id, value, ':');
		add_hash_param((*rsc)->meta, XML_RSC_ATTR_INCARNATION, value);
		
	} else {
		(*rsc)->id = crm_strdup(id);
	}

	if(parent) {
		(*rsc)->long_name = crm_concat(parent->long_name, (*rsc)->id, ':');
	} else {
		(*rsc)->long_name = crm_strdup((*rsc)->id);
	}
	
	(*rsc)->fns = &resource_class_functions[(*rsc)->variant];
	crm_debug_3("Unpacking resource...");

	/* meta attributes */
	xml_prop_iter(
		xml_obj, prop_name, prop_value,
		add_hash_param((*rsc)->meta, prop_name, prop_value);
		);
	
	unpack_instance_attributes(
		xml_obj, XML_TAG_META_SETS, NULL, (*rsc)->meta,
		NULL, data_set->now);

	if(parent != NULL) {
		g_hash_table_foreach(parent->meta, dup_attr, (*rsc)->meta);
	}	

	/* populate from the regular attributes until the GUI can create
	 * meta attributes
	 */
	unpack_instance_attributes(
		xml_obj, XML_TAG_ATTR_SETS, NULL, (*rsc)->meta,
		NULL, data_set->now);

	if(parent != NULL) {
		g_hash_table_foreach(
			parent->parameters, dup_attr, (*rsc)->parameters);
	}	

	if((*rsc)->fns->unpack(*rsc, data_set) == FALSE) {
		return FALSE;
	}
	(*rsc)->runnable	   = TRUE; 
	(*rsc)->provisional	   = TRUE; 
	(*rsc)->starting	   = FALSE; 
	(*rsc)->stopping	   = FALSE; 

	(*rsc)->candidate_colors   = NULL;
	(*rsc)->rsc_cons	   = NULL; 
	(*rsc)->actions            = NULL;
	(*rsc)->failed		   = FALSE;
	(*rsc)->start_pending	   = FALSE;	
	(*rsc)->globally_unique    = TRUE;
	(*rsc)->role		   = RSC_ROLE_STOPPED;
	(*rsc)->next_role	   = RSC_ROLE_UNKNOWN;
	(*rsc)->is_managed	   = data_set->is_managed_default;

	(*rsc)->recovery_type      = recovery_stop_start;
	(*rsc)->stickiness         = data_set->default_resource_stickiness;
	(*rsc)->fail_stickiness    = data_set->default_resource_fail_stickiness;

	value = g_hash_table_lookup((*rsc)->meta, XML_CIB_ATTR_PRIORITY);
	(*rsc)->priority	   = crm_parse_int(value, "0"); 
	(*rsc)->effective_priority = (*rsc)->priority;

	value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_NOTIFY);
	(*rsc)->notify		   = crm_is_true(value); 
	
	value = g_hash_table_lookup((*rsc)->meta, "is_managed");
	if(value != NULL && safe_str_neq("default", value)) {
		cl_str_to_boolean(value, &((*rsc)->is_managed));
	}

	crm_debug_2("Options for %s", (*rsc)->id);
	value = g_hash_table_lookup((*rsc)->meta, "globally_unique");
	if(value != NULL) {
		cl_str_to_boolean(value, &((*rsc)->globally_unique));
	}
	
	value = g_hash_table_lookup((*rsc)->meta, XML_RSC_ATTR_RESTART);
	if(safe_str_eq(value, "restart")) {
		(*rsc)->restart_type = pe_restart_restart;
		crm_debug_2("\tDependancy restart handling: restart");

	} else {
		(*rsc)->restart_type = pe_restart_ignore;
		crm_debug_2("\tDependancy restart handling: ignore");
	}

	value = g_hash_table_lookup((*rsc)->meta, "multiple_active");
	if(safe_str_eq(value, "stop_only")) {
		(*rsc)->recovery_type = recovery_stop_only;
		crm_debug_2("\tMultiple running resource recovery: stop only");

	} else if(safe_str_eq(value, "block")) {
		(*rsc)->recovery_type = recovery_block;
		crm_debug_2("\tMultiple running resource recovery: block");

	} else {		
		(*rsc)->recovery_type = recovery_stop_start;
		crm_debug_2("\tMultiple running resource recovery: stop/start");
	}

	value = g_hash_table_lookup((*rsc)->meta, "resource_stickiness");
	if(value != NULL && safe_str_neq("default", value)) {
		(*rsc)->stickiness = char2score(value);
	}
	if((*rsc)->stickiness > 0) {
		crm_debug_2("\tPlacement: prefer current location%s",
			    value == NULL?" (default)":"");
	} else if((*rsc)->stickiness < 0) {
		crm_warn("\tPlacement: always move from the current location%s",
			 value == NULL?" (default)":"");
	} else {
		crm_debug_2("\tPlacement: optimal%s",
			    value == NULL?" (default)":"");
	}

	value = g_hash_table_lookup(
		(*rsc)->meta, XML_RSC_ATTR_FAIL_STICKINESS);
	if(value != NULL) {
		(*rsc)->fail_stickiness = char2score(value);
	}
	crm_debug_2("\tNode score per failure: %d%s",
		    (*rsc)->fail_stickiness, value == NULL?" (default)":"");
	
	value = g_hash_table_lookup(
		(*rsc)->meta, XML_RSC_ATTR_TARGET_ROLE);
	
	if(value != NULL && safe_str_neq("default", value)) {
		(*rsc)->is_managed = TRUE;
		(*rsc)->next_role = text2role(value);
		if((*rsc)->next_role == RSC_ROLE_UNKNOWN) {
			pe_config_err("%s: Unknown value for "
				      XML_RSC_ATTR_TARGET_ROLE": %s",
				      (*rsc)->id, value);
		}
	}

	crm_debug_2("\tDesired next state: %s",
		    (*rsc)->next_role!=RSC_ROLE_UNKNOWN?role2text((*rsc)->next_role):"default");

	if((*rsc)->is_managed == FALSE) {
		crm_warn("Resource %s is currently not managed", (*rsc)->id);

	} else if(data_set->symmetric_cluster) {
		rsc_to_node_t *new_con = rsc2node_new(
			"symmetric_default", *rsc, 0, NULL, data_set);
		new_con->node_list_rh = node_list_dup(data_set->nodes, TRUE, FALSE);
	}
	
	crm_debug_2("\tAction notification: %s",
		    (*rsc)->notify?"required":"not required");
	
/* 	data_set->resources = g_list_append(data_set->resources, (*rsc)); */
	return TRUE;
}

void
order_actions(
	action_t *lh_action, action_t *rh_action, enum pe_ordering order) 
{
	action_wrapper_t *wrapper = NULL;
	GListPtr list = NULL;
	
	crm_debug_2("Ordering Action %s before %s",
		  lh_action->uuid, rh_action->uuid);

	log_action(LOG_DEBUG_4, "LH (order_actions)", lh_action, FALSE);
	log_action(LOG_DEBUG_4, "RH (order_actions)", rh_action, FALSE);

	
	crm_malloc0(wrapper, sizeof(action_wrapper_t));
	if(wrapper != NULL) {
		wrapper->action = rh_action;
		wrapper->type = order;
		
		list = lh_action->actions_after;
		list = g_list_append(list, wrapper);
		lh_action->actions_after = list;
		wrapper = NULL;
	}
	if(order != pe_ordering_recover) {
		crm_malloc0(wrapper, sizeof(action_wrapper_t));
		if(wrapper != NULL) {
			wrapper->action = lh_action;
			wrapper->type = order;
			list = rh_action->actions_before;
			list = g_list_append(list, wrapper);
			rh_action->actions_before = list;
		}
	}
}


void common_free(resource_t *rsc)
{
	if(rsc == NULL) {
		return;
	}
	
	crm_debug_5("Freeing %s", rsc->id);

	while(rsc->rsc_cons) {
 		pe_free_rsc_colocation(
			(rsc_colocation_t*)rsc->rsc_cons->data);
		rsc->rsc_cons = rsc->rsc_cons->next;
	}
	if(rsc->rsc_cons != NULL) {
		g_list_free(rsc->rsc_cons);
	}
	if(rsc->parameters != NULL) {
		g_hash_table_destroy(rsc->parameters);
	}
	if(rsc->meta != NULL) {
		g_hash_table_destroy(rsc->meta);
	}
	if(rsc->orphan) {
		free_xml(rsc->xml);
	}
	pe_free_shallow_adv(rsc->running_on, FALSE);
	pe_free_shallow_adv(rsc->known_on, FALSE);
	pe_free_shallow_adv(rsc->candidate_colors, TRUE);
	pe_free_shallow_adv(rsc->rsc_location, FALSE);
	pe_free_shallow_adv(rsc->allowed_nodes, TRUE);
	crm_free(rsc->id);
	crm_free(rsc->long_name);
	crm_free(rsc->variant_opaque);
	crm_free(rsc);
	crm_debug_5("Resource freed");
}

