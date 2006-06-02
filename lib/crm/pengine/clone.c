/* $Id: clone.c,v 1.2 2006/06/02 15:34:18 andrew Exp $ */
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

#include <lib/crm/pengine/status.h>
#include <utils.h>
#include <crm/msg_xml.h>

void clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set);

extern gboolean rsc_colocation_new(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh,
	const char *state_lh, const char *state_rh);

typedef struct clone_variant_data_s
{
		resource_t *self;

		int clone_max;
		int clone_node_max;

		int active_clones;
		int max_nodes;
		
		gboolean interleave;
		gboolean ordered;

		crm_data_t *xml_obj_child;
		
		gboolean notify_confirm;
		
		GListPtr child_list; /* resource_t* */
		
} clone_variant_data_t;

void child_stopping_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);

void child_starting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);


#define get_clone_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_clone || rsc->variant == pe_master); \
	data = (clone_variant_data_t *)rsc->variant_opaque;


static gboolean
create_child_clone(resource_t *rsc, int sub_id, pe_working_set_t *data_set) 
{
	char *inc_num = NULL;
	char *inc_max = NULL;
	resource_t *child_rsc = NULL;
	crm_data_t * child_copy = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	CRM_CHECK(clone_data->xml_obj_child != NULL, return FALSE);

	inc_num = crm_itoa(sub_id);
	inc_max = crm_itoa(clone_data->clone_max);	

	child_copy = copy_xml(clone_data->xml_obj_child);

	crm_xml_add(child_copy, XML_RSC_ATTR_INCARNATION, inc_num);

	if(common_unpack(child_copy, &child_rsc,
			 rsc, data_set) == FALSE) {
		pe_err("Failed unpacking resource %s",
		       crm_element_value(child_copy, XML_ATTR_ID));
		return FALSE;
	}
/* 	child_rsc->parent = clone_data->self; */
	
	crm_debug_3("Setting clone attributes for: %s", child_rsc->id);
	clone_data->child_list = g_list_append(
		clone_data->child_list, child_rsc);
	
	add_hash_param(child_rsc->meta, XML_RSC_ATTR_INCARNATION_MAX, inc_max);
	
	print_resource(LOG_DEBUG_3, "Added", child_rsc, FALSE);
	
	crm_free(inc_num);
	crm_free(inc_max);
	
	return TRUE;
}

gboolean master_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
  	add_hash_param(rsc->parameters, crm_meta_name("stateful"),
		       XML_BOOLEAN_TRUE);
	return clone_unpack(rsc, data_set);
}

gboolean clone_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0;
	crm_data_t *xml_tmp = NULL;
	crm_data_t *xml_self = NULL;
	crm_data_t *xml_obj = rsc->xml;
	clone_variant_data_t *clone_data = NULL;
	resource_t *self = NULL;

	const char *ordered = g_hash_table_lookup(
		rsc->meta, XML_RSC_ATTR_ORDERED);
	const char *interleave = g_hash_table_lookup(
		rsc->meta, XML_RSC_ATTR_INTERLEAVE);
	const char *max_clones = g_hash_table_lookup(
		rsc->meta, XML_RSC_ATTR_INCARNATION_MAX);
	const char *max_clones_node = g_hash_table_lookup(
		rsc->meta, XML_RSC_ATTR_INCARNATION_NODEMAX);

	crm_debug_3("Processing resource %s...", rsc->id);
	
	crm_malloc0(clone_data, sizeof(clone_variant_data_t));
	rsc->variant_opaque = clone_data;
	clone_data->child_list  = NULL;
	clone_data->interleave  = FALSE;
	clone_data->ordered     = FALSE;
	
	clone_data->active_clones  = 0;
	clone_data->xml_obj_child  = NULL;
	clone_data->clone_node_max = crm_parse_int(max_clones_node,"1");

	clone_data->clone_max = crm_parse_int(max_clones, "-1");
	if(clone_data->clone_max < 0) {
		clone_data->clone_max = g_list_length(data_set->nodes);
	}
	if(crm_is_true(interleave)) {
		clone_data->interleave = TRUE;
	}
	if(crm_is_true(ordered)) {
		clone_data->ordered = TRUE;
	}
	
	crm_debug("Options for %s", rsc->id);
	crm_debug("\tClone max: %d", clone_data->clone_max);
	crm_debug("\tClone node max: %d", clone_data->clone_node_max);
	
	clone_data->xml_obj_child = find_xml_node(
		xml_obj, XML_CIB_TAG_GROUP, FALSE);

	if(clone_data->xml_obj_child == NULL) {
		clone_data->xml_obj_child = find_xml_node(
			xml_obj, XML_CIB_TAG_RESOURCE, TRUE);
	}

	if(clone_data->xml_obj_child == NULL) {
		pe_config_err("%s has nothing to clone", rsc->id);
		return FALSE;
	}
	
	xml_self = copy_xml(rsc->xml);
	/* this is a bit of a hack - but simplifies everything else */
	ha_msg_mod(xml_self, F_XML_TAGNAME, XML_CIB_TAG_RESOURCE);
/* 	set_id(xml_self, "self", -1); */
	xml_tmp = find_xml_node(xml_obj, "operations", FALSE);
	if(xml_tmp != NULL) {
		add_node_copy(xml_self, xml_tmp);
	}

	if(common_unpack(xml_self, &self, NULL, data_set)) {
		clone_data->self = self;

	} else {
		crm_log_xml_err(xml_self, "Couldnt unpack dummy child");
		clone_data->self = self;
		return FALSE;
	}
	
	clone_data->notify_confirm = clone_data->self->notify;

	for(lpc = 0; lpc < clone_data->clone_max; lpc++) {
		create_child_clone(rsc, lpc, data_set);
	}
	
	crm_debug_3("Added %d children to resource %s...",
		    clone_data->clone_max, rsc->id);
	return TRUE;
}

resource_t *
clone_find_child(resource_t *rsc, const char *id)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	return pe_find_resource(clone_data->child_list, id);
}

GListPtr clone_children(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	return clone_data->child_list;
}

gboolean clone_active(resource_t *rsc, gboolean all)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		gboolean child_active = child_rsc->fns->active(child_rsc, all);
		if(all == FALSE && child_active) {
			return TRUE;
		} else if(all && child_active == FALSE) {
			return FALSE;
		}
		);
	if(all) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void clone_print(
	resource_t *rsc, const char *pre_text, long options, void *print_data)
{
	const char *child_text = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	if(pre_text != NULL) {
		child_text = "        ";
	} else {
		child_text = "    ";
	}

	if(rsc->variant == pe_master) {
		status_print("%sMaster/Slave Set: %s",
			     pre_text?pre_text:"", clone_data->self->id);

	} else {
		status_print("%sClone Set: %s",
			     pre_text?pre_text:"", clone_data->self->id);
	}
	
	if(options & pe_print_html) {
		status_print("\n<ul>\n");

	} else if((options & pe_print_log) == 0) {
		status_print("\n");
	}
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		if(options & pe_print_html) {
			status_print("<li>\n");
		}
		child_rsc->fns->print(
			child_rsc, child_text, options, print_data);
		if(options & pe_print_html) {
			status_print("</li>\n");
		}
		);

	if(options & pe_print_html) {
		status_print("</ul>\n");
	}
}

void clone_free(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Freeing %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		crm_debug_3("Freeing child %s", child_rsc->id);
		free_xml(child_rsc->xml);
		child_rsc->fns->free(child_rsc);
		);

	crm_debug_3("Freeing child list");
	pe_free_shallow_adv(clone_data->child_list, FALSE);

	if(clone_data->self) {
		free_xml(clone_data->self->xml);
		clone_data->self->fns->free(clone_data->self);
	}
	common_free(rsc);
}

enum rsc_role_e
clone_resource_state(resource_t *rsc)
{
	return RSC_ROLE_UNKNOWN;
}
