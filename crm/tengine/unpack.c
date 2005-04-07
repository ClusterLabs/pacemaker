/* $Id: unpack.c,v 1.26 2005/04/07 14:00:05 andrew Exp $ */
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

cib_t *te_cib_conn = NULL;
action_t* unpack_action(crm_data_t *xml_action);
crm_data_t *create_shutdown_event(const char *node, int op_status);
void set_timer_value(te_timer_t *timer, const char *time, int time_default);
extern int transition_counter;

void
set_timer_value(te_timer_t *timer, const char *time, int time_default)
{
	if(timer == NULL) {
		return;
	}
	
	timer->timeout = time_default;
	int tmp_time = crm_get_msec(time);
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

	const char *time = crm_element_value(xml_graph, "transition_timeout");
	set_timer_value(transition_timer, time, default_transition_timeout);
	transition_timeout = transition_timer->timeout;
	
	time = crm_element_value(xml_graph, "transition_fuzz");
	set_timer_value(transition_fuzz_timer, time, transition_fuzz_timeout);

	transition_counter++;

	crm_info("Beginning transition %d - timeout set to %d",
		 transition_counter, transition_timer->timeout);

	xml_child_iter(
		xml_graph, synapse, "synapse",

		synapse_t *new_synapse = NULL;

		crm_devel("looking in synapse %s", crm_element_value(synapse, XML_ATTR_ID));
		
		crm_malloc(new_synapse, sizeof(synapse_t));
		new_synapse->id        = num_synapses++;
		new_synapse->complete  = FALSE;
		new_synapse->confirmed = FALSE;
		new_synapse->actions   = NULL;
		new_synapse->inputs    = NULL;
		
		graph = g_list_append(graph, new_synapse);

		crm_devel("look for actions in synapse %s", crm_element_value(synapse, XML_ATTR_ID));

		xml_child_iter(
			synapse, actions, "action_set",

			xml_child_iter(
				actions, action, NULL,
				
				action_t *new_action = unpack_action(action);
				num_actions++;
				
				if(new_action == NULL) {
					continue;
				}
				crm_devel("Adding action %d to synapse %d",
						 new_action->id, new_synapse->id);

				new_synapse->actions = g_list_append(
					new_synapse->actions,
					new_action);
				);
			
			);

		crm_devel("look for inputs in synapse %s", crm_element_value(synapse, XML_ATTR_ID));

		xml_child_iter(
			synapse, inputs, "inputs",

			xml_child_iter(
				inputs, trigger, NULL,

				xml_child_iter(
					trigger, input, NULL,

					action_t *new_input =
						unpack_action(input);

					if(new_input == NULL) {
						continue;
					}

					crm_devel("Adding input %d to synapse %d",
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
	const char *tmp        = crm_element_value(xml_action, XML_ATTR_ID);
	action_t   *action     = NULL;
	crm_data_t *action_copy = NULL;

	if(tmp == NULL) {
		crm_err("Actions must have an id!");
		crm_xml_devel(xml_action, "Action with missing id");
		return NULL;
	}
	
	action_copy = copy_xml_node_recursive(xml_action);
	crm_malloc(action, sizeof(action_t));
	if(action == NULL) {
		return NULL;
	}
	
	action->id       = atoi(tmp);
	action->timeout  = 0;
	action->timer    = NULL;
	action->invoked  = FALSE;
	action->complete = FALSE;
	action->can_fail = FALSE;
	action->type     = action_type_rsc;
	action->xml      = action_copy;
	
	if(safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_RSC_OP)) {
		action->type = action_type_rsc;

	} else if(safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_PSEUDO_EVENT)) {
		action->type = action_type_pseudo;

	} else if(safe_str_eq(crm_element_name(action_copy), XML_GRAPH_TAG_CRM_EVENT)) {
		action->type = action_type_crm;
	}

	action->timeout = crm_get_msec(
		crm_element_value(action_copy, XML_ATTR_TIMEOUT));

	crm_devel("Action %d has timer set to %dms",
		  action->id, action->timeout);
	
	crm_malloc(action->timer, sizeof(te_timer_t));
	action->timer->timeout   = action->timeout;
	action->timer->source_id = -1;
	action->timer->reason    = timeout_action;
	action->timer->action    = action;

	tmp = crm_element_value(action_copy, "can_fail");
	crm_str_to_boolean(tmp, &(action->can_fail));

	return action;
}

gboolean
extract_event(crm_data_t *msg)
{
	gboolean abort  = FALSE;
	const char *event_node = NULL;

/*
[cib fragment]
...
<status>
   <node_state id="node1" state=CRMD_STATE_ACTIVE exp_state="active">
     <lrm>
       <lrm_resources>
	 <rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/
	crm_trace("Extracting event from %s", crm_element_name(msg));
	xml_child_iter(
		msg, node_state, XML_CIB_TAG_STATE,

		crm_data_t *resources = NULL;

		const char *ccm_state  = crm_element_value(
			node_state, XML_CIB_ATTR_INCCM);
		const char *crmd_state = crm_element_value(
			node_state, XML_CIB_ATTR_CRMDSTATE);
		const char *join_state = crm_element_value(
			node_state, XML_CIB_ATTR_JOINSTATE);

		crm_xml_devel(node_state,"Processing");
		
		if(crm_element_value(node_state, XML_CIB_ATTR_SHUTDOWN) != NULL) {
			send_complete(
				"Aborting on "XML_CIB_ATTR_SHUTDOWN" attribute",
				node_state, te_update);
			break;
			
		} else if(crm_element_value(node_state, XML_CIB_ATTR_STONITH) != NULL) {
			/* node marked for STONITH
			 *   possibly by us when a shutdown timmed out
			 */
			int action_id = -1;
			crm_devel("Checking for STONITH");
			event_node = crm_element_value(node_state, XML_ATTR_UNAME);
			action_id = match_down_event(
				event_node, CRM_OP_SHUTDOWN, LRM_OP_DONE);
			
			if(action_id < 0) {
				send_complete(
					"Stonith/shutdown event not matched",
					node_state, te_update);
				break;
			} else {
				process_trigger(action_id);
				check_for_completion();
			}
			continue;
		}

		resources = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		resources = find_xml_node(
			resources, XML_LRM_TAG_RESOURCES, FALSE);

		if(crmd_state != NULL || ccm_state != NULL || join_state != NULL) {
			/* simple node state update...
			 *   possibly from a shutdown we requested
			 */
			crm_devel("Processing state update");
			if(crmd_state != NULL
			   && safe_str_neq(crmd_state, OFFLINESTATUS)) {
				/* the node is comming up,
				 *  only recompute after the join completes,
				 *  we dont need to check for this
				 */
				continue;
				
			} else if(join_state != NULL
				  && safe_str_neq(join_state, CRMD_JOINSTATE_DOWN)) {
				/* the node is comming up,
				 *  only recompute after the join completes,
				 *  we dont need to check for this
				 */
				continue;

			} else {
				/* this may be called more than once per shutdown
				 * ie. once per update of each field
				 */
				int action_id = -1;
				crm_devel("Checking if this was a known shutdown");
				event_node = crm_element_value(node_state, XML_ATTR_UNAME);
				action_id = match_down_event(
					event_node, NULL, LRM_OP_DONE);

				if(action_id < 0) {
					send_complete("Stonith/shutdown event not matched", node_state, te_update);
					break;
				} else {
					process_trigger(action_id);
					check_for_completion();
				}
			}
			
			if(ccm_state != NULL && crm_is_true(ccm_state)) {
				crm_devel("Ignore - new CCM node");
			}
		}
		if(resources != NULL) {
			/* LRM resource update...
			 */
			xml_child_iter(
				resources, child, NULL, 

				crm_xml_devel(child, "Processing LRM resource update");
				abort = !process_graph_event(child);
				if(abort) {
					break;
				}
				);
			
			if(abort) {
				break;
			}
		}
		);
	
	return !abort;
}

crm_data_t*
create_shutdown_event(const char *node, int op_status)
{
	crm_data_t *event = create_xml_node(NULL, XML_CIB_TAG_STATE);
	char *code = crm_itoa(op_status);

	set_xml_property_copy(event, XML_LRM_ATTR_TARGET, node);
/*	event_rsc    = set_xml_property_copy(event, XML_ATTR_ID); */
	set_xml_property_copy(event, XML_LRM_ATTR_RC, "0");
	set_xml_property_copy(
		event, XML_LRM_ATTR_LASTOP, XML_CIB_ATTR_SHUTDOWN);
	set_xml_property_copy(
		event, XML_LRM_ATTR_RSCSTATE, CRMD_RSCSTATE_GENERIC_OK);
	set_xml_property_copy(event, XML_LRM_ATTR_OPSTATUS, code);
	
	crm_free(code);
	return event;
}
