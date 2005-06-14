/* $Id: unpack.c,v 1.37 2005/06/14 11:38:26 davidlee Exp $ */
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

cib_t *te_cib_conn = NULL;
action_t* unpack_action(crm_data_t *xml_action);
crm_data_t *create_shutdown_event(const char *node, int op_status);
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
	transition_timeout = transition_timer->timeout;
	
	time = crm_element_value(xml_graph, "transition_fuzz");

	transition_counter = crm_atoi(t_id, "-1");

	crm_info("Beginning transition %d : timeout set to %dms",
		 transition_counter, transition_timer->timeout);

	xml_child_iter(
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

		xml_child_iter(
			synapse, actions, "action_set",

			xml_child_iter(
				actions, action, NULL,
				
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
	crm_data_t *nvpair_list = NULL;

	if(tmp == NULL) {
		crm_err("Actions must have an id!");
		crm_log_xml_debug_3(xml_action, "Action with missing id");
		return NULL;
	}
	
	action_copy = copy_xml(xml_action);
	crm_malloc0(action, sizeof(action_t));
	if(action == NULL) {
		return NULL;
	}
	
	action->id       = atoi(tmp);
	action->timeout  = 0;
	action->interval = 0;
	action->timer    = NULL;
	action->invoked  = FALSE;
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

	nvpair_list = find_xml_node(action_copy, XML_TAG_ATTRS, FALSE);
	if(nvpair_list == NULL) {
		crm_debug_2("No attributes in %s",
			    crm_element_name(action_copy));
	}
	
	xml_child_iter(
		nvpair_list, node_iter, XML_CIB_TAG_NVPAIR,
		
		const char *key   = crm_element_value(
			node_iter, XML_NVPAIR_ATTR_NAME);
		const char *value = crm_element_value(
			node_iter, XML_NVPAIR_ATTR_VALUE);

		if(safe_str_eq(key, "timeout")) {
			action->timeout = crm_get_msec(value);

		} else if(safe_str_eq(key, "interval")) {
			action->interval = crm_get_msec(value);
		}
		);

	crm_debug_3("Action %d has timer set to %dms",
		  action->id, action->timeout);
	
	crm_malloc0(action->timer, sizeof(te_timer_t));
	action->timer->timeout   = 2 * action->timeout;
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
	xml_child_iter(
		msg, node_state, XML_CIB_TAG_STATE,

		crm_data_t *resources = NULL;

		const char *ccm_state  = crm_element_value(
			node_state, XML_CIB_ATTR_INCCM);
		const char *crmd_state  = crm_element_value(
			node_state, XML_CIB_ATTR_CRMDSTATE);

		blob.update = node_state;
		
		event_node = crm_element_value(node_state, XML_ATTR_UNAME);

		crm_log_xml_debug_3(node_state,"Processing");

		if(crm_element_value(node_state, XML_CIB_ATTR_SHUTDOWN) != NULL) {
			blob.text = "Aborting on "XML_CIB_ATTR_SHUTDOWN" attribute";
			break;
			
/* is this still required??? */
		} else if(crm_element_value(node_state, CRM_OP_FENCE) != NULL) {
			/* node marked for STONITH
			 *   possibly by us when a shutdown timed out
			 */
			int action_id = -1;
			crm_debug_3("Checking for STONITH");
			event_node = crm_element_value(node_state, XML_ATTR_UNAME);
			action_id = match_down_event(
				event_node, CRM_OP_SHUTDOWN, LRM_OP_DONE);
			
			if(action_id < 0) {
				blob.text="Stonith/shutdown event not matched";
				break;

			} else {
				process_trigger(action_id);
				check_for_completion();
			}
/* END: is this still required??? */
		}

		resources = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		resources = find_xml_node(
			resources, XML_LRM_TAG_RESOURCES, FALSE);

		/*
		 * node state update... possibly from a shutdown we requested
		 */
		crm_debug_3("Processing state update");
		if(safe_str_eq(ccm_state, XML_BOOLEAN_FALSE)
		   || safe_str_eq(crmd_state, CRMD_JOINSTATE_DOWN)) {
			int action_id = -1;
			crm_debug_3("A shutdown we requested?");
			action_id = match_down_event(
				event_node, NULL, LRM_OP_DONE);
			
			if(action_id >= 0) {
				process_trigger(action_id);
				check_for_completion();
			} else {
				blob.text="Stonith/shutdown event not matched";
				break;
			}
		}
		if(resources != NULL) {
			/* LRM resource update...
			 */
			xml_child_iter(
				resources, child, NULL, 

				crm_log_xml_debug_3(
					child,"Processing LRM resource update");
				if(!process_graph_event(child, event_node)) {
					/* the transition has already been
					 * aborted and with better details
					 */
					return TRUE;
				}
				);
		}
		);

	if(blob.text != NULL) {
		send_complete(blob.text, blob.update, blob.reason, i_cancel);
	}
	
	return TRUE;
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
		event, XML_LRM_ATTR_RSCSTATE, CRMD_ACTION_GENERIC_OK);
	set_xml_property_copy(event, XML_LRM_ATTR_OPSTATUS, code);
	
	crm_free(code);
	return event;
}
