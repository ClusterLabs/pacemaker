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

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <clplumbing/cl_misc.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <utils.h>
#include <unpack.h>

crm_data_t * do_calculations(
	pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now);

extern crm_data_t*get_object_root(
    const char *object_type, crm_data_t *the_root);

#define PE_WORKING_DIR	HA_VARLIBDIR"/heartbeat/pengine"

#define MEMCHECK_STAGE_0 0

#define check_and_exit(stage) 	cleanup_calculations(data_set);		\
	crm_mem_stats(NULL);						\
	crm_err("Exiting: stage %d", stage);				\
	exit(1);


/*
 * Unpack everything
 * At the end you'll have:
 *  - A list of nodes
 *  - A list of resources (each with any dependencies on other resources)
 *  - A list of constraints between resources and nodes
 *  - A list of constraints between start/stop actions
 *  - A list of nodes that need to be stonith'd
 *  - A list of nodes that need to be shutdown
 *  - A list of the possible stop/start actions (without dependencies)
 */
gboolean
cluster_status(pe_working_set_t *data_set)
{
	crm_data_t * config          = get_object_root(
		XML_CIB_TAG_CRMCONFIG,   data_set->input);
	crm_data_t * cib_nodes       = get_object_root(
		XML_CIB_TAG_NODES,       data_set->input);
	crm_data_t * cib_resources   = get_object_root(
		XML_CIB_TAG_RESOURCES,   data_set->input);
	crm_data_t * cib_status      = get_object_root(
		XML_CIB_TAG_STATUS,      data_set->input);
 	const char *value = crm_element_value(
		data_set->input, XML_ATTR_HAVE_QUORUM);
	
	crm_debug_3("Beginning unpack");
	
	/* reset remaining global variables */
	
	if(data_set->input == NULL) {
		return FALSE;
	}

	if(data_set->now == NULL) {
	    data_set->now = new_ha_date(TRUE);
	}
	
	if(data_set->input != NULL
	   && crm_element_value(data_set->input, XML_ATTR_DC_UUID) != NULL) {
		/* this should always be present */
		data_set->dc_uuid = crm_element_value_copy(
			data_set->input, XML_ATTR_DC_UUID);
	}	
	
 	unpack_config(config, data_set);

	if(value != NULL) {
		cl_str_to_boolean(value, &data_set->have_quorum);
	}
	
	if(data_set->have_quorum == FALSE
	   && data_set->no_quorum_policy != no_quorum_ignore) {
		crm_warn("We do not have quorum"
			 " - fencing and resource management disabled");
	}
	
 	unpack_nodes(cib_nodes, data_set);
 	unpack_resources(cib_resources, data_set);
 	unpack_status(cib_status, data_set);
	
	return TRUE;
}

static void
pe_free_resources(GListPtr resources)
{ 
	resource_t *rsc = NULL;
	GListPtr iterator = resources;
	while(iterator != NULL) {
		iterator = iterator;
		rsc = (resource_t *)iterator->data;
		iterator = iterator->next;
		rsc->fns->free(rsc);
	}
	if(resources != NULL) {
		g_list_free(resources);
	}
}

static void
pe_free_actions(GListPtr actions) 
{
	GListPtr iterator = actions;
	while(iterator != NULL) {
		pe_free_action(iterator->data);
		iterator = iterator->next;
	}
	if(actions != NULL) {
		g_list_free(actions);
	}
}

static void
pe_free_nodes(GListPtr nodes)
{
	GListPtr iterator = nodes;
	while(iterator != NULL) {
		node_t *node = (node_t*)iterator->data;
		struct node_shared_s *details = node->details;
		iterator = iterator->next;

		crm_debug_5("deleting node");
		crm_debug_5("%s is being deleted", details->uname);
		print_node("delete", node, FALSE);
		
		if(details != NULL) {
			if(details->attrs != NULL) {
				g_hash_table_destroy(details->attrs);
			}
			pe_free_shallow_adv(details->running_rsc, FALSE);
			pe_free_shallow_adv(details->allocated_rsc, FALSE);
			crm_free(details);
		}
		crm_free(node);
	}
	if(nodes != NULL) {
		g_list_free(nodes);
	}
}

void
cleanup_calculations(pe_working_set_t *data_set)
{
	if(data_set == NULL) {
		return;
	}

	if(data_set->config_hash != NULL) {
		g_hash_table_destroy(data_set->config_hash);
	}
	
	crm_free(data_set->dc_uuid);
	crm_free(data_set->transition_idle_timeout);
	
	crm_debug_3("deleting resources");
	pe_free_resources(data_set->resources); 
	
	crm_debug_3("deleting actions");
	pe_free_actions(data_set->actions);

	crm_debug_3("deleting nodes");
	pe_free_nodes(data_set->nodes);
	
	free_xml(data_set->graph);
	free_ha_date(data_set->now);
	free_xml(data_set->input);
	free_xml(data_set->failed);
	data_set->stonith_action = NULL;

	CRM_CHECK(data_set->ordering_constraints == NULL, ;);
	CRM_CHECK(data_set->placement_constraints == NULL, ;);
}


void
set_working_set_defaults(pe_working_set_t *data_set) 
{
	data_set->input = NULL;
	data_set->now = NULL;
	data_set->graph = NULL;
	data_set->failed = create_xml_node(NULL, "failed-ops");
	
	data_set->transition_idle_timeout = NULL;
	data_set->dc_uuid            = NULL;
	data_set->dc_node            = NULL;
	data_set->have_quorum        = FALSE;
	data_set->stonith_enabled    = FALSE;
	data_set->stonith_action     = NULL;
	data_set->symmetric_cluster  = TRUE;
	data_set->is_managed_default = TRUE;
	data_set->no_quorum_policy   = no_quorum_freeze;
	
	data_set->remove_after_stop   = FALSE;
	data_set->stop_action_orphans = TRUE;
	data_set->stop_rsc_orphans    = TRUE;
	
	data_set->config_hash = NULL;
	data_set->nodes       = NULL;
	data_set->resources   = NULL;
	data_set->ordering_constraints  = NULL;
	data_set->placement_constraints = NULL;
	data_set->colocation_constraints = NULL;

	data_set->actions  = NULL;	

	data_set->num_synapse     = 0;
	data_set->max_valid_nodes = 0;
	data_set->order_id        = 1;
	data_set->action_id       = 1;

	data_set->default_resource_stickiness = 0;
	data_set->default_resource_fail_stickiness = 0;	
}


resource_t *
pe_find_resource(GListPtr rsc_list, const char *id)
{
	unsigned lpc = 0;
	resource_t *rsc = NULL;
	resource_t *child_rsc = NULL;

	if(id == NULL) {
		return NULL;
	}
	
	crm_debug_4("Looking for %s in %d objects", id, g_list_length(rsc_list));
	for(lpc = 0; lpc < g_list_length(rsc_list); lpc++) {
		rsc = g_list_nth_data(rsc_list, lpc);
		if(rsc == NULL) {
		} else if(rsc->id && strcmp(rsc->id, id) == 0){
			crm_debug_4("Found a match for %s", id);
			return rsc;
			
		} else if(rsc->long_name && strcmp(rsc->long_name, id) == 0) {
			crm_debug_4("Found a match for %s", id);
			return rsc;

		} else if(rsc->clone_name && strcmp(rsc->clone_name, id) == 0) {
			crm_debug_4("Found a match for %s", id);
			return rsc;
		}
	}
	for(lpc = 0; lpc < g_list_length(rsc_list); lpc++) {
		rsc = g_list_nth_data(rsc_list, lpc);

		child_rsc = rsc->fns->find_child(rsc, id);
		if(child_rsc != NULL) {
			return child_rsc;
		}
	}
	crm_debug_2("No match for %s", id);
	return NULL;
}

node_t *
pe_find_node_id(GListPtr nodes, const char *id)
{
	unsigned lpc = 0;
	node_t *node = NULL;
  
	for(lpc = 0; lpc < g_list_length(nodes); lpc++) {
		node = g_list_nth_data(nodes, lpc);
		if(safe_str_eq(node->details->id, id)) {
			return node;
		}
	}
	/* error */
	return NULL;
}

node_t *
pe_find_node(GListPtr nodes, const char *uname)
{
	unsigned lpc = 0;
	node_t *node = NULL;
  
	for(lpc = 0; lpc < g_list_length(nodes); lpc++) {
		node = g_list_nth_data(nodes, lpc);
		if(safe_str_eq(node->details->uname, uname)) {
			return node;
		}
	}
	/* error */
	return NULL;
}
