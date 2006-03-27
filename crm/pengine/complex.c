/* $Id: complex.c,v 1.76 2006/03/27 05:44:24 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>
#include <pe_rules.h>
#include <crm/msg_xml.h>
#include <clplumbing/cl_misc.h>

gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);
gboolean is_active(rsc_to_node_t *cons);
gboolean constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint);
void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);

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
		native_num_allowed_nodes,
		native_color,
		native_create_actions,
		native_create_probe,
		native_internal_constraints,
		native_agent_constraints,
		native_rsc_colocation_lh,
		native_rsc_colocation_rh,
		native_rsc_order_lh,
		native_rsc_order_rh,
		native_rsc_location,
		native_expand,
		native_children,
		native_parameter,
		native_print,
		native_active,
		native_resource_state,
		native_create_notify_element,
		native_free
	},
	{
		group_unpack,
		group_find_child,
		group_num_allowed_nodes,
		group_color,
		group_create_actions,
		group_create_probe,
		group_internal_constraints,
		group_agent_constraints,
		group_rsc_colocation_lh,
		group_rsc_colocation_rh,
		group_rsc_order_lh,
		group_rsc_order_rh,
		group_rsc_location,
		group_expand,
		group_children,
		native_parameter,
		group_print,
		group_active,
		group_resource_state,
		group_create_notify_element,
		group_free
	},
	{
		clone_unpack,
		clone_find_child,
		clone_num_allowed_nodes,
		clone_color,
		clone_create_actions,
		clone_create_probe,
		clone_internal_constraints,
		clone_agent_constraints,
		clone_rsc_colocation_lh,
		clone_rsc_colocation_rh,
		clone_rsc_order_lh,
		clone_rsc_order_rh,
		clone_rsc_location,
		clone_expand,
		clone_children,
		native_parameter,
		clone_print,
		clone_active,
		clone_resource_state,
		clone_create_notify_element,
		clone_free
	},
	{
		master_unpack,
		clone_find_child,
		clone_num_allowed_nodes,
		clone_color,
		master_create_actions,
		clone_create_probe,
		master_internal_constraints,
		clone_agent_constraints,
		clone_rsc_colocation_lh,
		clone_rsc_colocation_rh,
		clone_rsc_order_lh,
		clone_rsc_order_rh,
		clone_rsc_location,
		clone_expand,
		clone_children,
		native_parameter,
		clone_print,
		clone_active,
		clone_resource_state,
		clone_create_notify_element,
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
	      GHashTable *defaults, pe_working_set_t *data_set)
{
	int lpc = 0;
	const char *id    = crm_element_value(xml_obj, XML_ATTR_ID);
	const char *value = NULL;

	const char *allowed_attrs[] = {
		XML_CIB_ATTR_PRIORITY,
		XML_RSC_ATTR_INCARNATION_MAX,
		XML_RSC_ATTR_INCARNATION_NODEMAX,
		XML_RSC_ATTR_MASTER_MAX,
		XML_RSC_ATTR_MASTER_NODEMAX,
		XML_RSC_ATTR_STICKINESS,
		XML_RSC_ATTR_FAIL_STICKINESS,
	};

	const char *rsc_attrs[] = {
		XML_RSC_ATTR_STOPFAIL,
		XML_RSC_ATTR_RESTART,
		XML_RSC_ATTR_MANAGED,
		XML_RSC_ATTR_UNIQUE,
		XML_RSC_ATTR_NOTIFY,
		XML_RSC_ATTR_MULTIPLE,
		XML_RSC_ATTR_START,
#if CRM_DEPRECATED_SINCE_2_0_4
		XML_RSC_ATTR_STICKINESS,
#endif
	};

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
	
	(*rsc)->id   = id;
	(*rsc)->graph_name = crm_strdup(id);
	(*rsc)->xml  = xml_obj;
	(*rsc)->ops_xml = find_xml_node(xml_obj, "operations", FALSE);
	(*rsc)->variant = get_resource_type(crm_element_name(xml_obj));
	
	if((*rsc)->variant == pe_unknown) {
		pe_err("Unknown resource type: %s", crm_element_name(xml_obj));
		crm_free(*rsc);
		return FALSE;
	}
	
	(*rsc)->fns = &resource_class_functions[(*rsc)->variant];
	crm_debug_3("Unpacking resource...");
	
	(*rsc)->parameters = g_hash_table_new_full(
		g_str_hash,g_str_equal, g_hash_destroy_str,g_hash_destroy_str);

	for(lpc = 0; lpc < DIMOF(rsc_attrs); lpc++) {
		value = crm_element_value(xml_obj, rsc_attrs[lpc]);
		if(value != NULL) {
			add_hash_param(
				(*rsc)->parameters, rsc_attrs[lpc], value);
		}
	}
	
	unpack_instance_attributes(
		xml_obj, XML_TAG_ATTR_SETS, NULL, (*rsc)->parameters,
		allowed_attrs, DIMOF(allowed_attrs), data_set);

	if(defaults != NULL) {
		g_hash_table_foreach(defaults, dup_attr, (*rsc)->parameters);
	}
	
	(*rsc)->runnable	   = TRUE; 
	(*rsc)->provisional	   = TRUE; 
	(*rsc)->starting	   = FALSE; 
	(*rsc)->stopping	   = FALSE; 

	(*rsc)->parent		   = NULL;
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

	value = g_hash_table_lookup((*rsc)->parameters, XML_CIB_ATTR_PRIORITY);
	(*rsc)->priority	   = crm_parse_int(value, "0"); 
	(*rsc)->effective_priority = (*rsc)->priority;

	value = g_hash_table_lookup((*rsc)->parameters, "notify");
	(*rsc)->notify		   = crm_is_true(value); 
	
	value = g_hash_table_lookup((*rsc)->parameters, "is_managed");
	if(value != NULL) {
		cl_str_to_boolean(value, &((*rsc)->is_managed));
	}
	if((*rsc)->is_managed == FALSE) {
		crm_warn("Resource %s is currently not managed", (*rsc)->id);

	} else if(data_set->symmetric_cluster) {
		rsc_to_node_t *new_con = rsc2node_new(
			"symmetric_default", *rsc, 0, NULL, data_set);
		new_con->node_list_rh = node_list_dup(data_set->nodes, FALSE);
	}
	
	crm_debug_2("Options for %s", id);
	value = g_hash_table_lookup((*rsc)->parameters, "globally_unique");
	if(value != NULL) {
		cl_str_to_boolean(value, &((*rsc)->globally_unique));
	}
	
	value = g_hash_table_lookup((*rsc)->parameters, XML_RSC_ATTR_RESTART);
	if(safe_str_eq(value, "restart")) {
		(*rsc)->restart_type = pe_restart_restart;
		crm_debug_2("\tDependancy restart handling: restart");

	} else {
		(*rsc)->restart_type = pe_restart_ignore;
		crm_debug_2("\tDependancy restart handling: ignore");
	}

	value = g_hash_table_lookup((*rsc)->parameters, "multiple_active");
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

	value = g_hash_table_lookup((*rsc)->parameters, "resource_stickiness");
	if(value != NULL) {
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
		(*rsc)->parameters, "resource_failure_stickiness");
	if(value != NULL) {
		(*rsc)->fail_stickiness = char2score(value);
	}
	crm_debug_2("\tNode score per failure: %d%s",
		    (*rsc)->fail_stickiness, value == NULL?" (default)":"");


	crm_debug_2("\tNotification of start/stop actions: %s",
		    (*rsc)->notify?"required":"not required");
	
/* 	data_set->resources = g_list_append(data_set->resources, (*rsc)); */
	(*rsc)->fns->unpack(*rsc, data_set);

	return TRUE;
}

void
order_actions(action_t *lh_action, action_t *rh_action, order_constraint_t *order) 
{
	action_wrapper_t *wrapper = NULL;
	GListPtr list = NULL;
	
	crm_debug_2("Ordering %d: Action %d before %d",
		  order?order->id:-1, lh_action->id, rh_action->id);

	log_action(LOG_DEBUG_4, "LH (order_actions)", lh_action, FALSE);
	log_action(LOG_DEBUG_4, "RH (order_actions)", rh_action, FALSE);

	
	crm_malloc0(wrapper, sizeof(action_wrapper_t));
	if(wrapper != NULL) {
		wrapper->action = rh_action;
		wrapper->type = order->type;
		
		list = lh_action->actions_after;
		list = g_list_append(list, wrapper);
		lh_action->actions_after = list;
		wrapper = NULL;
	}
	if(order->type != pe_ordering_recover) {
		crm_malloc0(wrapper, sizeof(action_wrapper_t));
		if(wrapper != NULL) {
			wrapper->action = lh_action;
			wrapper->type = order->type;
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
	if(rsc->orphan) {
		free_xml(rsc->xml);
	}
	pe_free_shallow_adv(rsc->running_on, FALSE);
	pe_free_shallow_adv(rsc->known_on, FALSE);
	pe_free_shallow_adv(rsc->candidate_colors, TRUE);
	pe_free_shallow_adv(rsc->rsc_location, FALSE);
	pe_free_shallow_adv(rsc->allowed_nodes, TRUE);
	crm_free(rsc->graph_name);
	crm_free(rsc->variant_opaque);
	crm_free(rsc);
	crm_debug_5("Resource freed");
}

void
unpack_instance_attributes(
	crm_data_t *xml_obj, const char *set_name, node_t *node,
	GHashTable *hash, const char **attrs, int attrs_length,
	pe_working_set_t *data_set)
{
	crm_data_t *attributes = NULL;
	
	if(xml_obj == NULL) {
		crm_debug_4("No instance attributes");
		return;
	}

	if(attrs != NULL && attrs[0] == NULL) {
		/* none allowed */
		crm_debug_2("No instance attributes allowed");
		return;
	}
	
	crm_debug_2("Checking for attributes");
	xml_child_iter_filter(
		xml_obj, attr_set, set_name,

		/* check any rules */
		if(test_ruleset(attr_set, node, data_set) == FALSE) {
			continue;
		}
		
		crm_debug_2("Adding attributes");
		attributes = cl_get_struct(attr_set, XML_TAG_ATTRS);
		if(attributes == NULL) {
			pe_err("%s with no %s child", set_name, XML_TAG_ATTRS);
		} else {
			populate_hash(attributes, hash, attrs, attrs_length);
		}
		
		);
}

void
populate_hash(crm_data_t *nvpair_list, GHashTable *hash,
	      const char **attrs, int attrs_length) 
{
	int lpc = 0;
	gboolean set_attr = FALSE;
	const char *name = NULL;
	const char *value = NULL;
	xml_child_iter_filter(
		nvpair_list, an_attr, XML_CIB_TAG_NVPAIR,
		
		name  = crm_element_value(an_attr, XML_NVPAIR_ATTR_NAME);
		
		set_attr = TRUE;

		if(attrs != NULL) {
			set_attr = FALSE;
		}
		
		for(lpc = 0; set_attr == FALSE && lpc < attrs_length
			    && attrs[lpc] != NULL; lpc++) {
			if(safe_str_eq(name, attrs[lpc])) {
				set_attr = TRUE;
			}
		}
		
		if(set_attr) {
			crm_debug_4("Setting attribute: %s", name);
			value = crm_element_value(
				an_attr, XML_NVPAIR_ATTR_VALUE);
			
			add_hash_param(hash, name, value);
			
		} else {
			crm_debug_4("Skipping attribute: %s", name);
		}
		
		);
}



void
add_rsc_param(resource_t *rsc, const char *name, const char *value)
{
	CRM_CHECK(rsc != NULL, return);
	add_hash_param(rsc->parameters, name, value);
}

void
add_hash_param(GHashTable *hash, const char *name, const char *value)
{
	CRM_CHECK(hash != NULL, return);

	crm_debug_3("adding: name=%s value=%s", crm_str(name), crm_str(value));
	if(name == NULL || value == NULL) {
		return;
		
	} else if(g_hash_table_lookup(hash, name) == NULL) {
		g_hash_table_insert(hash, crm_strdup(name), crm_strdup(value));
	}
}

