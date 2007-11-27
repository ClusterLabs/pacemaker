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

#include <lha_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <crm/transition.h>
#include <heartbeat.h>
/* #include <lrm/lrm_api.h> */
#include <sys/stat.h>
#include <clplumbing/cl_misc.h>

static crm_action_t*
unpack_action(synapse_t *parent, crm_data_t *xml_action) 
{
	crm_action_t   *action = NULL;
	crm_data_t *action_copy = NULL;
	const char *value = crm_element_value(xml_action, XML_ATTR_ID);

	if(value == NULL) {
		crm_err("Actions must have an id!");
		crm_log_xml_debug_3(xml_action, "Action with missing id");
		return NULL;
	}
	
	action_copy = copy_xml(xml_action);
	crm_malloc0(action, sizeof(crm_action_t));
	if(action == NULL) {
		return NULL;
	}
	
	action->id   = crm_parse_int(value, NULL);
	action->type = action_type_rsc;
	action->xml  = action_copy;
	action->synapse = parent;
	
	if(safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_RSC_OP)) {
		action->type = action_type_rsc;

	} else if(safe_str_eq(crm_element_name(action_copy),
			      XML_GRAPH_TAG_PSEUDO_EVENT)) {
		action->type = action_type_pseudo;

	} else if(safe_str_eq(crm_element_name(action_copy),
			      XML_GRAPH_TAG_CRM_EVENT)) {
		action->type = action_type_crm;
	}

	action->params = xml2list(action_copy);

	value = g_hash_table_lookup(action->params, "CRM_meta_timeout");
	if(value != NULL) {
		action->timeout = crm_parse_int(value, NULL);
	}

	value = g_hash_table_lookup(action->params, "CRM_meta_interval");
	if(value != NULL) {
		action->interval = crm_parse_int(value, NULL);
	}

	value = g_hash_table_lookup(action->params, "CRM_meta_can_fail");
	if(value != NULL) {	
		cl_str_to_boolean(value, &(action->can_fail));
	}
	
	crm_debug_3("Action %d has timer set to %dms",
		  action->id, action->timeout);

	return action;
}

static synapse_t *
unpack_synapse(crm_graph_t *new_graph, crm_data_t *xml_synapse) 
{
	const char *value = NULL;
	synapse_t *new_synapse = NULL;
	CRM_CHECK(xml_synapse != NULL, return NULL);
	crm_debug_3("looking in synapse %s", ID(xml_synapse));
	
	crm_malloc0(new_synapse, sizeof(synapse_t));
	new_synapse->id = crm_parse_int(ID(xml_synapse), NULL);

	value = crm_element_value(xml_synapse, XML_CIB_ATTR_PRIORITY);
	if(value != NULL) {
		new_synapse->priority = crm_parse_int(value, NULL);
	}
	
	new_graph->num_synapses++;
	CRM_CHECK(new_synapse->id >= 0, crm_free(new_synapse); return NULL);
	
	crm_debug_3("look for actions in synapse %s",
		    crm_element_value(xml_synapse, XML_ATTR_ID));
	
	xml_child_iter_filter(
		xml_synapse, action_set, "action_set",
		
		xml_child_iter(
			action_set, action, 
			
			crm_action_t *new_action = unpack_action(
				new_synapse, action);
			new_graph->num_actions++;
			
			if(new_action == NULL) {
				continue;
			}
			crm_debug_3("Adding action %d to synapse %d",
				    new_action->id, new_synapse->id);
			
			new_synapse->actions = g_list_append(
				new_synapse->actions, new_action);
			);
		
		);

	crm_debug_3("look for inputs in synapse %s", ID(xml_synapse));
	
	xml_child_iter_filter(
		xml_synapse, inputs, "inputs",
		
		xml_child_iter(
			inputs, trigger, 
			
			xml_child_iter(
				trigger, input, 
				
				crm_action_t *new_input = unpack_action(
					new_synapse, input);

				if(new_input == NULL) {
					continue;
				}

				crm_debug_3("Adding input %d to synapse %d",
					    new_input->id, new_synapse->id);
				
				new_synapse->inputs = g_list_append(
					new_synapse->inputs, new_input);
				);
			);
		);
	return new_synapse;
}

crm_graph_t *
unpack_graph(crm_data_t *xml_graph)
{
/*
<transition_graph>
  <synapse>
    <action_set>
      <rsc_op id="2"
	... 
    <inputs>
      <rsc_op id="2"
	... 
*/
	crm_graph_t *new_graph = NULL;
	const char *t_id = NULL;
	const char *time = NULL;
	
	crm_malloc0(new_graph, sizeof(crm_graph_t));
	
	new_graph->id = -1;
	new_graph->abort_priority = 0;
	new_graph->network_delay = -1;
	new_graph->transition_timeout = -1;

	if(xml_graph != NULL) {
		t_id = crm_element_value(xml_graph, "transition_id");
		CRM_CHECK(t_id != NULL, crm_free(new_graph); return NULL);
		new_graph->id = crm_parse_int(t_id, "-1");

		time = crm_element_value(xml_graph, "cluster-delay");
		CRM_CHECK(time != NULL, crm_free(new_graph); return NULL);
		new_graph->network_delay = crm_get_msec(time);
		new_graph->transition_timeout = new_graph->network_delay;

		t_id = crm_element_value(xml_graph, "batch-limit");
		new_graph->batch_limit = crm_parse_int(t_id, "0");


	}
	
	xml_child_iter_filter(
		xml_graph, synapse, "synapse",
		
		synapse_t *new_synapse = unpack_synapse(new_graph, synapse);
		if(new_synapse != NULL) {
			new_graph->synapses = g_list_append(
				new_graph->synapses, new_synapse);
		}
		);

	crm_info("Unpacked transition %d: %d actions in %d synapses",
		 new_graph->id, new_graph->num_actions,new_graph->num_synapses);

	return new_graph;
}

static void
destroy_action(crm_action_t *action)
{
	if(action->timer) {
		CRM_CHECK(action->timer->source_id == 0, ;);
/*  		Gmain_timeout_remove(action->timer->source_id); */
	}
	g_hash_table_destroy(action->params);
	free_xml(action->xml);
	crm_free(action->timer);
	crm_free(action);
}

static void
destroy_synapse(synapse_t *synapse)
{
	while(g_list_length(synapse->actions) > 0) {
		crm_action_t *action = g_list_nth_data(synapse->actions, 0);
		synapse->actions = g_list_remove(synapse->actions, action);
		destroy_action(action);
	}
	
	while(g_list_length(synapse->inputs) > 0) {
		crm_action_t *action = g_list_nth_data(synapse->inputs, 0);
		synapse->inputs = g_list_remove(synapse->inputs, action);
		destroy_action(action);
	}
	crm_free(synapse);
}

void
destroy_graph(crm_graph_t *graph)
{
	if(graph == NULL) {
		return;
	}
	while(g_list_length(graph->synapses) > 0) {
		synapse_t *synapse = g_list_nth_data(graph->synapses, 0);
		graph->synapses = g_list_remove(graph->synapses, synapse);
		destroy_synapse(synapse);
	}
	crm_free(graph);
}


