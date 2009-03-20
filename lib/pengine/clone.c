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

#include <crm/pengine/rules.h>
#include <crm/pengine/status.h>
#include <unpack.h>
#include <utils.h>
#include <crm/msg_xml.h>

#define VARIANT_CLONE 1
#include "./variant.h"

void clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set);
void force_non_unique_clone(resource_t *rsc, const char *rid, pe_working_set_t *data_set);
resource_t *create_child_clone(resource_t *rsc, int sub_id, pe_working_set_t *data_set);

static void mark_as_orphan(resource_t *rsc) 
{
    set_bit(rsc->flags, pe_rsc_orphan);
    slist_iter(
	child, resource_t, rsc->children, lpc,
	mark_as_orphan(child);
	);
}

static void clear_bit_recursive(resource_t *rsc, unsigned long long flag) 
{
    clear_bit_inplace(rsc->flags, flag);
    if(rsc->children) {
	slist_iter(
	    child_rsc, resource_t, rsc->children, lpc,
	    clear_bit_recursive(child_rsc, flag);
	    );
    }
}

void force_non_unique_clone(resource_t *rsc, const char *rid, pe_working_set_t *data_set) 
{
    if(rsc->variant == pe_clone || rsc->variant == pe_master) {
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	
	crm_config_warn("Clones %s contains non-OCF resource %s and so "
			"can only be used as an anonymous clone. "
			"Set the "XML_RSC_ATTR_UNIQUE" meta attribute to false",
			rsc->id, rid);
	
	clone_data->clone_node_max = 1;
	clone_data->clone_max = g_list_length(data_set->nodes);
	clear_bit_recursive(rsc, pe_rsc_unique);
    }
}

resource_t *
create_child_clone(resource_t *rsc, int sub_id, pe_working_set_t *data_set) 
{
	gboolean as_orphan = FALSE;
	char *inc_num = NULL;
	char *inc_max = NULL;
	resource_t *child_rsc = NULL;
	xmlNode * child_copy = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	CRM_CHECK(clone_data->xml_obj_child != NULL, return FALSE);

	if(sub_id < 0) {
	    as_orphan = TRUE;
	    sub_id = clone_data->total_clones;
	}
	inc_num = crm_itoa(sub_id);
	inc_max = crm_itoa(clone_data->clone_max);	

	child_copy = copy_xml(clone_data->xml_obj_child);

	crm_xml_add(child_copy, XML_RSC_ATTR_INCARNATION, inc_num);

	if(common_unpack(child_copy, &child_rsc,
			 rsc, data_set) == FALSE) {
		pe_err("Failed unpacking resource %s",
		       crm_element_value(child_copy, XML_ATTR_ID));
		child_rsc = NULL;
		goto bail;
	}
/* 	child_rsc->globally_unique = rsc->globally_unique; */

	clone_data->total_clones += 1;
	crm_debug_2("Setting clone attributes for: %s", child_rsc->id);
	rsc->children = g_list_append(rsc->children, child_rsc);
	if(as_orphan) {
	    mark_as_orphan(child_rsc);
	}
	
	add_hash_param(child_rsc->meta, XML_RSC_ATTR_INCARNATION_MAX, inc_max);
	
	print_resource(LOG_DEBUG_3, "Added", child_rsc, FALSE);

  bail:
	crm_free(inc_num);
	crm_free(inc_max);
	
	return child_rsc;
}

gboolean master_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	const char *master_max = g_hash_table_lookup(
		rsc->meta, XML_RSC_ATTR_MASTER_MAX);
	const char *master_node_max = g_hash_table_lookup(
		rsc->meta, XML_RSC_ATTR_MASTER_NODEMAX);

	g_hash_table_replace(rsc->meta, crm_strdup("stateful"), crm_strdup(XML_BOOLEAN_TRUE));
	if(clone_unpack(rsc, data_set)) {
		clone_variant_data_t *clone_data = NULL;
		get_clone_variant_data(clone_data, rsc);
		clone_data->master_max = crm_parse_int(master_max, "1");
		clone_data->master_node_max = crm_parse_int(master_node_max, "1");
		return TRUE;
	}
	return FALSE;
}

gboolean clone_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0;
	const char *type = NULL;
	resource_t *self = NULL;
	int num_xml_children = 0;	
	xmlNode *xml_tmp = NULL;
	xmlNode *xml_self = NULL;
	xmlNode *xml_obj = rsc->xml;
	clone_variant_data_t *clone_data = NULL;

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
	clone_data->interleave  = FALSE;
	clone_data->ordered     = FALSE;
	
	clone_data->active_clones  = 0;
	clone_data->xml_obj_child  = NULL;
	clone_data->clone_node_max = crm_parse_int(max_clones_node, "1");

	if(max_clones) {
	    clone_data->clone_max = crm_parse_int(max_clones, "1");

	} else if(g_list_length(data_set->nodes) > 0) {
	    clone_data->clone_max = g_list_length(data_set->nodes);

	} else {
	    clone_data->clone_max = 1; /* Handy during crm_verify */
	}
	
	if(crm_is_true(interleave)) {
		clone_data->interleave = TRUE;
	}
	if(crm_is_true(ordered)) {
		clone_data->ordered = TRUE;
	}
	if((rsc->flags & pe_rsc_unique) == 0 && clone_data->clone_node_max > 1) {
	    crm_config_err("Anonymous clones (%s) may only support one copy"
			   " per node", rsc->id);
	    clone_data->clone_node_max = 1;
	}

	crm_debug_2("Options for %s", rsc->id);
	crm_debug_2("\tClone max: %d", clone_data->clone_max);
	crm_debug_2("\tClone node max: %d", clone_data->clone_node_max);
	crm_debug_2("\tClone is unique: %s", is_set(rsc->flags, pe_rsc_unique)?"true":"false");

	clone_data->xml_obj_child = find_xml_node(
		xml_obj, XML_CIB_TAG_GROUP, FALSE);

	if(clone_data->xml_obj_child == NULL) {
	    clone_data->xml_obj_child = find_xml_node(
		xml_obj, XML_CIB_TAG_RESOURCE, TRUE);
	} else {
	    xml_child_iter_filter(xml_obj, a_child, XML_CIB_TAG_RESOURCE, num_xml_children++);
	}

	if(clone_data->xml_obj_child == NULL) {
		crm_config_err("%s has nothing to clone", rsc->id);
		return FALSE;
	}

	type = crm_element_name(clone_data->xml_obj_child);
	xml_child_iter_filter(xml_obj, a_child, type, num_xml_children++);

	if(num_xml_children > 1) {
	    crm_config_err("%s has too many children.  Only the first (%s) will be cloned.",
			   rsc->id, ID(clone_data->xml_obj_child));
	}
	
	xml_self = copy_xml(rsc->xml);
	/* this is a bit of a hack - but simplifies everything else */
	xmlNodeSetName(xml_self, ((const xmlChar*)XML_CIB_TAG_RESOURCE));
/* 	set_id(xml_self, "self", -1); */
	xml_tmp = find_xml_node(xml_obj, "operations", FALSE);
	if(xml_tmp != NULL) {
		add_node_copy(xml_self, xml_tmp);
	}

	/* Make clones ever so slightly sticky by default
	 * This is the only way to ensure clone instances are not
	 *  shuffled around the cluster for no benefit
	 */
  	add_hash_param(rsc->meta, XML_RSC_ATTR_STICKINESS, "1");
	
	if(common_unpack(xml_self, &self, rsc, data_set)) {
		clone_data->self = self;

	} else {
		crm_log_xml_err(xml_self, "Couldnt unpack dummy child");
		clone_data->self = self;
		return FALSE;
	}
	
	crm_debug_2("\tClone is unique (fixed): %s", is_set(rsc->flags, pe_rsc_unique)?"true":"false");
	clone_data->notify_confirm = is_set(rsc->flags, pe_rsc_notify);
	add_hash_param(rsc->meta, XML_RSC_ATTR_UNIQUE,
		       is_set(rsc->flags, pe_rsc_unique)?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	for(lpc = 0; lpc < clone_data->clone_max; lpc++) {
		create_child_clone(rsc, lpc, data_set);
	}

	if(clone_data->clone_max == 0) {
	    /* create one so that unpack_find_resource() will hook up
	     * any orphans up to the parent correctly
	     */
	    create_child_clone(rsc, -1, data_set);
	}
	
	crm_debug_3("Added %d children to resource %s...",
		    clone_data->clone_max, rsc->id);
	return TRUE;
}

gboolean clone_active(resource_t *rsc, gboolean all)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
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

static char *
add_list_element(char *list, const char *value) 
{
    int len = 0;
    int last = 0;

    if(value == NULL) {
	return list;
    }
    if(list) {
	last = strlen(list);
    }
    len = last + 2;  /* +1 space, +1 EOS */
    len += strlen(value);
    crm_realloc(list, len);
    sprintf(list + last, " %s", value);
    return list;
}

static void
print_list(char *list, const char *prefix, long options, void *print_data) 
{
    if(list) {
	if(options & pe_print_html) {
	    status_print("<li>\n");
	}
	status_print("\t%s: [%s ]\n", prefix, list);
	if(options & pe_print_html) {
	    status_print("</li>\n");
	}
    }
}


void clone_print(
	resource_t *rsc, const char *pre_text, long options, void *print_data)
{
    char *master_list = NULL;
    char *started_list = NULL;
    char *stopped_list = NULL;
    const char *type = "Clone";
    const char *child_text = NULL;
    clone_variant_data_t *clone_data = NULL;
    get_clone_variant_data(clone_data, rsc);
    if(pre_text != NULL) {
	child_text = "        ";
    } else {
	child_text = "    ";
    }

    if(rsc->variant == pe_master) {
	type = "Master/Slave";
    }

    status_print("%s%s Set: %s%s",
		 pre_text?pre_text:"", type, rsc->id,
		 is_set(rsc->flags, pe_rsc_unique)?" (unique)":"");
	
    if(options & pe_print_html) {
	status_print("\n<ul>\n");

    } else if((options & pe_print_log) == 0) {
	status_print("\n");
    }

    slist_iter(
	child_rsc, resource_t, rsc->children, lpc,

	gboolean print_full = FALSE;
	if(child_rsc->fns->active(child_rsc, FALSE) == FALSE) {
	    /* Inactive clone */
	    if(is_set(child_rsc->flags, pe_rsc_orphan)) {
		continue;

	    } else if(is_set(rsc->flags, pe_rsc_unique)) {
		print_full = TRUE;
	    } else {
		stopped_list = add_list_element(stopped_list, child_rsc->id);
	    }
		
	} else if(is_set(rsc->flags, pe_rsc_unique)
		  || is_set(child_rsc->flags, pe_rsc_managed) == FALSE
		  || is_set(child_rsc->flags, pe_rsc_failed)) {

	    /* Unique, unmanaged or failed clone */
	    print_full = TRUE;
		
	} else if(child_rsc->fns->active(child_rsc, TRUE)) {
	    /* Fully active anonymous clone */
	    node_t *location = child_rsc->fns->location(child_rsc, NULL, TRUE);

	    if(location) {
		const char *host = location->details->uname;
		enum rsc_role_e a_role = child_rsc->fns->state(child_rsc, TRUE);

		if(a_role > RSC_ROLE_SLAVE) {
		    /* And active on a single node as master */
		    master_list = add_list_element(master_list, host);
		    
		} else {
		    /* And active on a single node as started/slave */
		    started_list = add_list_element(started_list, host);
		}
	    
	    } else {
		print_full = TRUE;
	    }
		
	} else {
	    /* Partially active anonymous clone */
	    print_full = TRUE;
	}
	    
	if(print_full) {
	    if(options & pe_print_html) {
		status_print("<li>\n");
	    }
	    child_rsc->fns->print(
		child_rsc, child_text, options, print_data);
	    if(options & pe_print_html) {
		status_print("</li>\n");
	    }
	}
	    
	);
	
    print_list(master_list, "Masters", options, print_data);
    print_list(started_list, rsc->variant==pe_master?"Slaves":"Started", options, print_data);
    print_list(stopped_list, "Stopped", options, print_data);

    crm_free(master_list);
    crm_free(started_list);
    crm_free(stopped_list);    
    
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
		child_rsc, resource_t, rsc->children, lpc,

		crm_debug_3("Freeing child %s", child_rsc->id);
		free_xml(child_rsc->xml);
		child_rsc->fns->free(child_rsc);
		);

	crm_debug_3("Freeing child list");
	pe_free_shallow_adv(rsc->children, FALSE);

	if(clone_data->self) {
		free_xml(clone_data->self->xml);
		clone_data->self->fns->free(clone_data->self);
	}
	common_free(rsc);
}

enum rsc_role_e
clone_resource_state(const resource_t *rsc, gboolean current)
{
	enum rsc_role_e clone_role = RSC_ROLE_UNKNOWN;

	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		enum rsc_role_e a_role = child_rsc->fns->state(child_rsc, current);
		if(a_role > clone_role) {
			clone_role = a_role;
		}
		);

	crm_debug_3("%s role: %s", rsc->id, role2text(clone_role));
	return clone_role;
}
