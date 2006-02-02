/* $Id: unpack.c,v 1.54 2006/02/02 16:48:26 andrew Exp $ */
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

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>
#include <tengine.h>
#include <heartbeat.h>
#include <clplumbing/Gmain_timeout.h>
#include <lrm/lrm_api.h>
#include <sys/stat.h>
#include <clplumbing/cl_misc.h>

cib_t *te_cib_conn = NULL;
action_t* unpack_action(crm_data_t *xml_action);
void set_timer_value(te_timer_t *timer, const char *time, int time_default);
extern int transition_counter;

void
set_timer_value(te_timer_t *timer, const char *time, int time_default)
{
	int tmp_time;

	if(timer == NULL) {
		return;
	}
	
	timer->timeout = time_default;
	tmp_time = crm_get_msec(time);
	if(tmp_time > 0) {
		timer->timeout = tmp_time;
	}
}

gboolean
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
	int num_synapses = 0;
	int num_actions = 0;

	const char *t_id = crm_element_value(xml_graph, "transition_id");
	const char *time = crm_element_value(xml_graph, "global_timeout");
	CRM_DEV_ASSERT(t_id != NULL);
	CRM_DEV_ASSERT(time != NULL);

	transition_timer->timeout = crm_get_msec(time);
	transition_idle_timeout = transition_timer->timeout;		

	transition_counter = crm_parse_int(t_id, "-1");

	crm_info("Beginning transition %d : timeout set to %dms",
		 transition_counter, transition_timer->timeout);

	xml_child_iter_filter(
		xml_graph, synapse, "synapse",

		synapse_t *new_synapse = NULL;

		crm_debug_3("looking in synapse %s",
			  crm_element_value(synapse, XML_ATTR_ID));
		
		crm_malloc0(new_synapse, sizeof(synapse_t));
		new_synapse->id        = num_synapses++;
		new_synapse->complete  = FALSE;
		new_synapse->confirmed = FALSE;
		new_synapse->actions   = NULL;
		new_synapse->inputs    = NULL;
		
		graph = g_list_append(graph, new_synapse);

		crm_debug_3("look for actions in synapse %s",
			  crm_element_value(synapse, XML_ATTR_ID));

		xml_child_iter_filter(
			synapse, actions, "action_set",

			xml_child_iter(
				actions, action, 
				
				action_t *new_action = unpack_action(action);
				num_actions++;
				
				if(new_action == NULL) {
					continue;
				}
				crm_debug_3("Adding action %d to synapse %d",
					  new_action->id, new_synapse->id);

				new_synapse->actions = g_list_append(
					new_synapse->actions,
					new_action);
				);
			
			);

		crm_debug_3("look for inputs in synapse %s",
			  crm_element_value(synapse, XML_ATTR_ID));

		xml_child_iter_filter(
			synapse, inputs, "inputs",

			xml_child_iter(
				inputs, trigger, 

				xml_child_iter(
					trigger, input, 

					action_t *new_input =
						unpack_action(input);

					if(new_input == NULL) {
						continue;
					}

					crm_debug_3("Adding input %d to synapse %d",
						 new_input->id, new_synapse->id);
					
					new_synapse->inputs = g_list_append(
						new_synapse->inputs,
						new_input);
					);
				);
			);
		);

	crm_info("Unpacked %d actions in %d synapses",
		 num_actions, num_synapses);

	print_state(LOG_DEBUG);

	if(num_actions > 0) {
		return TRUE;
	} else {
		/* indicate to caller that there's nothing to do */
		return FALSE;
	}
	
}

action_t*
unpack_action(crm_data_t *xml_action) 
{
	action_t   *action = NULL;
	crm_data_t *action_copy = NULL;
	const char *value = crm_element_value(xml_action, XML_ATTR_ID);

	if(value == NULL) {
		crm_err("Actions must have an id!");
		crm_log_xml_debug_3(xml_action, "Action with missing id");
		return NULL;
	}
	
	action_copy = copy_xml(xml_action);
	crm_malloc0(action, sizeof(action_t));
	if(action == NULL) {
		return NULL;
	}
	
	action->id       = crm_parse_int(value, NULL);
	action->timeout  = 0;
	action->interval = 0;
	action->timer    = NULL;
	action->invoked  = FALSE;
	action->sent_update = FALSE;
	action->complete = FALSE;
	action->can_fail = FALSE;
	action->type     = action_type_rsc;
	action->xml      = action_copy;
	
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

	value = g_hash_table_lookup(action->params, "timeout");
	if(value != NULL) {
		action->timeout = crm_parse_int(value, NULL);
	}

	value = g_hash_table_lookup(action->params, "interval");
	if(value != NULL) {
		action->interval = crm_parse_int(value, NULL);
	}

	value = g_hash_table_lookup(action->params, "can_fail");
	if(value != NULL) {	
		cl_str_to_boolean(value, &(action->can_fail));
	}
	
	crm_debug_3("Action %d has timer set to %dms",
		  action->id, action->timeout);
	
	crm_malloc0(action->timer, sizeof(te_timer_t));
	action->timer->timeout   = 2 * action->timeout;
	action->timer->source_id = 0;
	action->timer->reason    = timeout_action;
	action->timer->action    = action;

	return action;
}

gboolean
extract_event(crm_data_t *msg)
{
	int shutdown = 0;
	const char *event_node = NULL;
	struct abort_blob_s 
	{
			const char *text;
			crm_data_t *update;
			te_reason_t reason;
	};

	struct abort_blob_s blob = { NULL, NULL, 0 };
	blob.reason = te_update;

/*
[cib fragment]
...
<status>
   <node_state id="node1" state=CRMD_STATE_ACTIVE exp_state="active">
     <lrm>
       <lrm_resources>
	 <rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/
	crm_debug_4("Extracting event from %s", crm_element_name(msg));
	xml_child_iter_filter(
		msg, node_state, XML_CIB_TAG_STATE,

		crm_data_t *attrs = NULL;
		crm_data_t *resources = NULL;

		const char *ccm_state  = crm_element_value(
			node_state, XML_CIB_ATTR_INCCM);
		const char *crmd_state  = crm_element_value(
			node_state, XML_CIB_ATTR_CRMDSTATE);

		/* Transient node attribute changes... */
		event_node = crm_element_value(node_state, XML_ATTR_ID);
		crm_debug("Processing state update from %s", event_node);
		crm_log_xml_debug_3(node_state,"Processing");

		if(blob.text == NULL) {
			blob.update = node_state;
		}
		
		attrs = find_xml_node(
			node_state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);

		if(attrs != NULL) {
			crm_info("Aborting on "XML_TAG_TRANSIENT_NODEATTRS" changes");
			if(blob.text == NULL) {
				blob.text = "Aborting on "XML_TAG_TRANSIENT_NODEATTRS" changes";
			}
		}
		
		resources = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		resources = find_xml_node(
			resources, XML_LRM_TAG_RESOURCES, FALSE);

		/* LRM resource update... */
		xml_child_iter(
			resources, rsc,  
			xml_child_iter(
				rsc, rsc_op,  
				
				crm_log_xml_debug_3(
					rsc_op, "Processing resource update");
				process_graph_event(rsc_op, event_node);
				);
			);

		/*
		 * node state update... possibly from a shutdown we requested
		 */
		if(safe_str_eq(ccm_state, XML_BOOLEAN_FALSE)
		   || safe_str_eq(crmd_state, CRMD_JOINSTATE_DOWN)) {
			action_t *shutdown = NULL;
			crm_debug_3("A shutdown we requested?");
			shutdown = match_down_event(0, event_node, NULL);
			
			if(shutdown != NULL) {
				process_trigger(shutdown->id);
				check_for_completion();

			} else {
				crm_info("Stonith/shutdown event not matched");
				if(blob.text == NULL) {
					blob.text="Stonith/shutdown event not matched";
				}
			}
		}

		shutdown = 0;
		ha_msg_value_int(node_state, XML_CIB_ATTR_SHUTDOWN, &shutdown);
		if(shutdown != 0) {
			crm_info("Aborting on "XML_CIB_ATTR_SHUTDOWN" attribute");
			if(blob.text == NULL) {
				blob.text = "Aborting on "XML_CIB_ATTR_SHUTDOWN" attribute";
			}
			
		}
		);

	if(blob.text != NULL) {
		send_complete(blob.text, blob.update, blob.reason, i_cancel);
	}
	
	return TRUE;
}

