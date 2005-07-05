/* $Id: complex.c,v 1.44 2005/07/05 13:56:46 andrew Exp $ */
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
#include <crm/msg_xml.h>

gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);
gboolean is_active(rsc_to_node_t *cons);
gboolean constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint);
void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);

gboolean has_agent(node_t *a_node, lrm_agent_t *an_agent);

extern gboolean rsc_colocation_new(const char *id, enum con_strength strength,
				   resource_t *rsc_lh, resource_t *rsc_rh);
extern rsc_to_node_t *rsc2node_new(
	const char *id, resource_t *rsc, double weight, node_t *node,
	pe_working_set_t *data_set);

resource_object_functions_t resource_class_functions[] = {
	{
		native_unpack,
		native_find_child,
		native_num_allowed_nodes,
		native_color,
		native_create_actions,
		native_internal_constraints,
		native_agent_constraints,
		native_rsc_colocation_lh,
		native_rsc_colocation_rh,
		native_rsc_order_lh,
		native_rsc_order_rh,
		native_rsc_location,
		native_expand,
		native_dump,
		native_printw,
		native_free
	},
	{
		group_unpack,
		group_find_child,
		group_num_allowed_nodes,
		group_color,
		group_create_actions,
		group_internal_constraints,
		group_agent_constraints,
		group_rsc_colocation_lh,
		group_rsc_colocation_rh,
		group_rsc_order_lh,
		group_rsc_order_rh,
		group_rsc_location,
		group_expand,
		group_dump,
		group_printw,
		group_free
	},
	{
		incarnation_unpack,
		incarnation_find_child,
		incarnation_num_allowed_nodes,
		incarnation_color,
		incarnation_create_actions,
		incarnation_internal_constraints,
		incarnation_agent_constraints,
		incarnation_rsc_colocation_lh,
		incarnation_rsc_colocation_rh,
		incarnation_rsc_order_lh,
		incarnation_rsc_order_rh,
		incarnation_rsc_location,
		incarnation_expand,
		incarnation_dump,
		incarnation_printw,
		incarnation_free
	}
};

/* resource_object_functions_t resource_variants[] = resource_class_functions; */


int get_resource_type(const char *name)
{
	if(safe_str_eq(name, XML_CIB_TAG_RESOURCE)) {
		return pe_native;

	} else if(safe_str_eq(name, XML_CIB_TAG_GROUP)) {
		return pe_group;

	} else if(safe_str_eq(name, XML_CIB_TAG_INCARNATION)) {
		return pe_incarnation;
	}
	
	return pe_unknown;
}

gboolean
is_active(rsc_to_node_t *cons)
{
	/* todo: check constraint lifetime */
	return TRUE;
}


void
inherit_parent_attributes(
	crm_data_t *parent, crm_data_t *child, gboolean overwrite)
{
	int lpc = 0;
	const char *attributes[] = {
		XML_RSC_ATTR_STOPFAIL,
		XML_RSC_ATTR_RESTART,
		"multiple_active",
		"start_prereq",
		"resource_stickiness",
		"is_managed"
	};

	for(lpc = 0; lpc < DIMOF(attributes); lpc++) {
		const char *attr_p = crm_element_value(parent, attributes[lpc]);
		const char *attr_c = crm_element_value(child, attributes[lpc]);

		if(attr_c != NULL && safe_str_neq(attr_p, attr_c)) {
			if(overwrite == FALSE) {
			crm_debug_2("Resource %s: ignoring parent value for %s",
				ID(child), attributes[lpc]);
				continue;
			}
			pe_warn("Resource %s: Overwriting attribute %s: %s->%s",
				ID(child), attributes[lpc], attr_c, attr_p);
		}
		if(attr_p != NULL) {
			crm_xml_add(child, attributes[lpc], attr_p);
		}
	}
}

gboolean	
common_unpack(
	crm_data_t * xml_obj, resource_t **rsc, pe_working_set_t *data_set)
{
	const char *id       = crm_element_value(xml_obj, XML_ATTR_ID);
	const char *restart  = crm_element_value(xml_obj, XML_RSC_ATTR_RESTART);
	const char *multiple = crm_element_value(xml_obj, "multiple_active");
	const char *placement= crm_element_value(xml_obj, "resource_stickiness");
	const char *priority = NULL;
	const char *is_managed = NULL;

	crm_log_xml_debug_2(xml_obj, "Processing resource input...");
	
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
	
	(*rsc)->id  = id;
	(*rsc)->xml = xml_obj;
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

	unpack_instance_attributes(xml_obj, (*rsc)->parameters);

	priority = get_rsc_param(*rsc, XML_CIB_ATTR_PRIORITY);

	(*rsc)->priority	   = atoi(priority?priority:"0"); 
	(*rsc)->effective_priority = (*rsc)->priority;
	(*rsc)->recovery_type      = recovery_stop_start;
	(*rsc)->runnable	   = TRUE; 
	(*rsc)->provisional	   = TRUE; 
	(*rsc)->start_pending	   = FALSE; 
	(*rsc)->starting	   = FALSE; 
	(*rsc)->stopping	   = FALSE; 
	(*rsc)->candidate_colors   = NULL;
	(*rsc)->rsc_cons	   = NULL; 
	(*rsc)->actions            = NULL;
	(*rsc)->is_managed	   = TRUE;
	(*rsc)->stickiness         = data_set->default_resource_stickiness;

	is_managed = crm_element_value((*rsc)->xml, "is_managed");
	if(is_managed != NULL && crm_is_true(is_managed) == FALSE) {
		(*rsc)->is_managed = FALSE;
		crm_warn("Resource %s is currently not managed", (*rsc)->id);
#if 0		
		rsc_to_node_t *new_con = NULL;
		/* prevent this resource from running anywhere */
		new_con = rsc2node_new(
			"is_managed_default", *rsc, -INFINITY, NULL, data_set);
		new_con->node_list_rh = node_list_dup(data_set->nodes, FALSE);
#endif	
	} else if((*rsc)->is_managed && data_set->symmetric_cluster) {
		rsc_to_node_t *new_con = rsc2node_new(
			"symmetric_default", *rsc, 0, NULL, data_set);
		new_con->node_list_rh = node_list_dup(data_set->nodes, FALSE);
	}
	
	crm_debug_2("Options for %s", id);
	
	if(safe_str_eq(restart, "restart")) {
		(*rsc)->restart_type = pe_restart_restart;
		crm_debug_2("\tDependancy restart handling: restart");

	} else {
		(*rsc)->restart_type = pe_restart_ignore;
		crm_debug_2("\tDependancy restart handling: ignore");
	}

	if(safe_str_eq(multiple, "stop_only")) {
		(*rsc)->recovery_type = recovery_stop_only;
		crm_debug_2("\tMultiple running resource recovery: stop only");

	} else if(safe_str_eq(multiple, "block")) {
		(*rsc)->recovery_type = recovery_block;
		crm_debug_2("\tMultiple running resource recovery: block");

	} else {		
		(*rsc)->recovery_type = recovery_stop_start;
		crm_debug_2("\tMultiple running resource recovery: stop/start");
		
	}

	if(placement != NULL) {
		if(safe_str_eq(placement, "INFINITY")) {
			(*rsc)->stickiness = INFINITY;

		} else if(safe_str_eq(placement, "-INFINITY")) {
			(*rsc)->stickiness = -INFINITY;

		} else {
			(*rsc)->stickiness = atoi(placement);
		}
	}
	if((*rsc)->stickiness > 0) {
		crm_debug_2("\tPlacement: prefer current location%s",
			    placement == NULL?" (default)":"");
	} else if((*rsc)->stickiness < 0) {
		crm_warn("\tPlacement: always move from the current location%s",
			    placement == NULL?" (default)":"");
	} else {
		crm_debug_2("\tPlacement: optimal%s",
			    placement == NULL?" (default)":"");
	}
	
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

void common_printw(resource_t *rsc, const char *pre_text, int *index)
{
#if CURSES_ENABLED
	const char *prov = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
	
	move(*index, 0);
	printw("%s%s %s (%s%s%s:%s):\t",
	       pre_text?pre_text:"", crm_element_name(rsc->xml), rsc->id,
	       prov?prov:"", prov?"::":"",
	       crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS),
	       crm_element_value(rsc->xml, XML_ATTR_TYPE));
#else
	crm_err("printw support requires ncurses to be available during configure");
#endif
}

void common_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	crm_debug_4("%s%s%s%sResource %s: (variant=%s, priority=%f)",
		  pre_text==NULL?"":pre_text,
		  pre_text==NULL?"":": ",
		  rsc->provisional?"Provisional ":"",
		  rsc->runnable?"":"(Non-Startable) ",
		  rsc->id,
		  crm_element_name(rsc->xml),
		  (double)rsc->priority);
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
	pe_free_shallow_adv(rsc->candidate_colors, TRUE);
	crm_free(rsc->variant_opaque);
	crm_free(rsc);
	crm_debug_5("Resource freed");
}

void
common_agent_constraints(
	GListPtr node_list, lrm_agent_t *agent, const char *id) 
{
#if 0
	slist_iter(
		node, node_t, node_list, lpc,
		
		crm_debug_5("Checking if %s supports %s/%s (%s)",
			  node->details->uname,
			  agent->class, agent->type, agent->version);
		
		if(has_agent(node, agent) == FALSE) {
			/* remove node from contention */
			crm_debug_5("Marking node %s unavailable for %s",
				  node->details->uname, id);
			node->weight = -1.0;
			node->fixed = TRUE;
		}
		);
#endif
}


void
unpack_instance_attributes(crm_data_t *xml_obj, GHashTable *hash)
{
	const char *name = NULL;
	const char *value = NULL;
	
	if(xml_obj == NULL) {
		crm_debug_4("No instance attributes");
		return;
	}
	
	xml_child_iter(
		xml_obj, attr_set, XML_TAG_ATTR_SETS,

		xml_child_iter(
			attr_set, attrs, XML_TAG_ATTRS,

			/* todo: check any rules */
			
			xml_child_iter(
				attrs, an_attr, XML_CIB_TAG_NVPAIR,
				
				name  = crm_element_value(
					an_attr, XML_NVPAIR_ATTR_NAME);
				value = crm_element_value(
					an_attr, XML_NVPAIR_ATTR_VALUE);

				add_hash_param(hash, name, value);
				);
			);
		);
}

void
add_rsc_param(resource_t *rsc, const char *name, const char *value)
{
	CRM_DEV_ASSERT(rsc != NULL);
	if(crm_assert_failed) {
		return;
	}
	add_hash_param(rsc->parameters, name, value);
}

void
add_hash_param(GHashTable *hash, const char *name, const char *value)
{
	CRM_DEV_ASSERT(hash != NULL);
	if(crm_assert_failed) {
		return;
	}

	crm_debug_3("adding: name=%s value=%s", crm_str(name), crm_str(value));
	if(name == NULL || value == NULL) {
		return;
		
	} else if(g_hash_table_lookup(hash, name) == NULL) {
		g_hash_table_insert(hash, crm_strdup(name), crm_strdup(value));
	}
}
	
const char *
get_rsc_param(resource_t *rsc, const char *name)
{
	CRM_DEV_ASSERT(rsc != NULL);
	if(crm_assert_failed) {
		return NULL;
	}
	return g_hash_table_lookup(rsc->parameters, name);
}

void
hash2nvpair(gpointer key, gpointer value, gpointer user_data) 
{
	const char *name    = key;
	const char *s_value = value;

	crm_data_t *xml_node  = user_data;
	crm_data_t *xml_child = create_xml_node(xml_node, XML_CIB_TAG_NVPAIR);

	crm_xml_add(xml_child, XML_NVPAIR_ATTR_NAME, name);
	crm_xml_add(xml_child, XML_NVPAIR_ATTR_VALUE, s_value);

	crm_debug_3("dumped: name=%s value=%s", name, s_value);
}
