/* $Id: unpack.c,v 1.11 2004/12/05 16:32:03 andrew Exp $ */
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

gboolean process_te_message(xmlNodePtr msg, IPC_Channel *sender);
action_t* unpack_action(xmlNodePtr xml_action);
xmlNodePtr create_shutdown_event(const char *node, int op_status);
void set_timer_value(te_timer_t *timer, const char *time, int time_default);
extern int transition_counter;

void
set_timer_value(te_timer_t *timer, const char *time, int time_default)
{
	if(timer == NULL) {
		return;
	}
	
	timer->timeout = time_default;
	if(time != NULL) {
		int tmp_time = atoi(time);
		if(tmp_time > 0) {
			timer->timeout = tmp_time;
		}
	}
}


gboolean
unpack_graph(xmlNodePtr xml_graph)
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

	const char *time = xmlGetProp(xml_graph, "transition_timeout");
	set_timer_value(transition_timer, time, default_transition_timeout);
	transition_timeout = transition_timer->timeout;
	
	time = xmlGetProp(xml_graph, "transition_fuzz");
	set_timer_value(transition_fuzz_timer, time, transition_fuzz_timeout);

	transition_counter++;

	crm_info("Beginning transition %d - timeout set to %d",
		 transition_counter, transition_timer->timeout);

	xml_child_iter(
		xml_graph, synapse, "synapse",

		synapse_t *new_synapse = NULL;

		crm_debug("looking in synapse %s", xmlGetProp(synapse, "id"));
		
		crm_malloc(new_synapse, sizeof(synapse_t));
		new_synapse->id        = num_synapses++;
		new_synapse->complete  = FALSE;
		new_synapse->confirmed = FALSE;
		new_synapse->actions   = NULL;
		new_synapse->inputs    = NULL;
		
		graph = g_list_append(graph, new_synapse);

		crm_debug("look for actions in synapse %s", xmlGetProp(synapse, "id"));

		xml_child_iter(
			synapse, actions, "action_set",

			xml_child_iter(
				actions, action, NULL,
				
				action_t *new_action = unpack_action(action);
				num_actions++;
				
				if(new_action == NULL) {
					action = action->next;
					break;
				}
				crm_debug("Adding action %d to synapse %d",
						 new_action->id, new_synapse->id);

				new_synapse->actions = g_list_append(
					new_synapse->actions,
					new_action);
				);
			
			);

		crm_debug("look for inputs in synapse %s", xmlGetProp(synapse, "id"));

		xml_child_iter(
			synapse, inputs, "inputs",

			xml_child_iter(
				inputs, trigger, NULL,

				xml_child_iter(
					trigger, input, NULL,

					action_t *new_input =
						unpack_action(input);

					if(new_input == NULL) {
						input = input->next;
						break;
					}

					crm_debug("Adding input %d to synapse %d",
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
unpack_action(xmlNodePtr xml_action) 
{
	const char *tmp        = xmlGetProp(xml_action, "id");
	action_t   *action     = NULL;
	xmlNodePtr action_copy = NULL;

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
	
	if(safe_str_eq(action_copy->name, "rsc_op")) {
		action->type = action_type_rsc;

	} else if(safe_str_eq(action_copy->name, "pseudo_event")) {
		action->type = action_type_pseudo;

	} else if(safe_str_eq(action_copy->name, "crm_event")) {
		action->type = action_type_crm;
	}

	tmp = xmlGetProp(action_copy, "timeout");
	if(tmp != NULL) {
		action->timeout = atoi(tmp);
	}
	crm_debug("Action %d has timer set to %d",
		  action->id, action->timeout);
	
	crm_malloc(action->timer, sizeof(te_timer_t));
	action->timer->timeout   = action->timeout;
	action->timer->source_id = -1;
	action->timer->reason    = timeout_action;
	action->timer->action    = action;

	tmp = xmlGetProp(action_copy, "can_fail");
	if(safe_str_eq(tmp, "true")) {
		action->can_fail = TRUE;
	}

	return action;
}


gboolean
extract_event(xmlNodePtr msg)
{
	gboolean abort      = FALSE;
	xmlNodePtr iter     = NULL;
	xmlNodePtr cib      = NULL;
	const char *section = NULL;
	const char *event_node   = NULL;

/*
[cib fragment]
...
<status>
   <node_state id="node1" state=CRMD_STATE_ACTIVE exp_state="active">
     <lrm>
       <lrm_resources>
	 <rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/

	crm_trace("Extracting event");
	
	iter = find_xml_node(msg, XML_TAG_FRAGMENT);
	section = xmlGetProp(iter, XML_ATTR_SECTION);

	if(safe_str_eq(section, XML_CIB_TAG_CRMCONFIG)) {
		/* ignore - for the moment */
		crm_debug("Ignoring changes to the %s section",
			  XML_CIB_TAG_CRMCONFIG);
		return TRUE;
		
	} else if(safe_str_neq(section, XML_CIB_TAG_STATUS)) {
		/* these too are never expected	 */
		crm_debug("Ignoring changes outside the %s section",
			  XML_CIB_TAG_STATUS);
		return FALSE;
	}
	
	cib = find_xml_node(iter, XML_TAG_CIB);
	iter = get_object_root(XML_CIB_TAG_STATUS, cib);
	if(iter != NULL) {
		iter = iter->children;
	} else {
		crm_xml_warn(cib, XML_CIB_TAG_STATUS " section missing?");
	}
	
	
	while(abort == FALSE && iter != NULL) {
		xmlNodePtr node_state = iter;
		xmlNodePtr child = iter->children;
		xmlNodePtr shutdown = NULL;
		const char *state = xmlGetProp(
			node_state, XML_CIB_ATTR_CRMDSTATE);
		iter = iter->next;

		crm_xml_devel(node_state,"Processing");
		
		if(xmlGetProp(node_state, XML_CIB_ATTR_SHUTDOWN) != NULL) {
			crm_trace("Aborting on %s attribute",
				  XML_CIB_ATTR_SHUTDOWN);
			abort = TRUE;
			
		} else if(xmlGetProp(node_state, XML_CIB_ATTR_STONITH) != NULL) {
			/* node marked for STONITH
			 *   possibly by us when a shutdown timmed out
			 */
			crm_trace("Checking for STONITH");
			event_node = xmlGetProp(node_state, XML_ATTR_UNAME);

			shutdown = create_shutdown_event(
				event_node, LRM_OP_TIMEOUT);

			process_graph_event(shutdown);

			free_xml(shutdown);
			
		} else if(state != NULL && child == NULL) {
			/* simple node state update...
			 *   possibly from a shutdown we requested
			 */
			crm_trace("Processing simple state update");
			if(safe_str_neq(state, OFFLINESTATUS)) {
				/* always recompute */
				abort = TRUE;
				continue;
			}
			
			event_node = xmlGetProp(node_state, XML_ATTR_UNAME);
			shutdown = create_shutdown_event(
				event_node, LRM_OP_DONE);

			process_graph_event(shutdown);

			free_xml(shutdown);

		} else if(state == NULL && child != NULL) {
			/* LRM resource update...
			 */
			crm_trace("Processing LRM resource update");
			child = find_xml_node(node_state, XML_CIB_TAG_LRM);
			child = find_xml_node(child, XML_LRM_TAG_RESOURCES);

			if(child != NULL) {
				child = child->children;
			} else {
				abort = TRUE;
			}
			
			event_node = xmlGetProp(node_state, XML_ATTR_UNAME);
			while(abort == FALSE && child != NULL) {
				process_graph_event(child);
				child = child->next;
			}	
		} else if(state != NULL && child != NULL) {
			/* this is a complex event and could not be completely
			 * due to any request we made
			 */
			crm_trace("Aborting on complex update");
			abort = TRUE;
			
		} else {
			/* ignore */
			crm_err("Ignoring message");
		}
	}
	
	return !abort;
}

gboolean
process_te_message(xmlNodePtr msg, IPC_Channel *sender)
{
	xmlNodePtr graph = NULL;
	const char *sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);
	const char *ref    = xmlGetProp(msg, XML_ATTR_REFERENCE);
	const char *op     = get_xml_attr(
		msg, XML_TAG_OPTIONS, XML_ATTR_OP, FALSE);


	crm_debug("Recieved %s (%s) message", op, ref);

	if (MSG_LOG) {
		struct stat buf;
		char *xml;
		if(stat(DEVEL_DIR, &buf) != 0) {
			cl_perror("Stat of %s failed... exiting", DEVEL_DIR);
			exit(100);
		}

		if(msg_te_strm == NULL) {
			msg_te_strm = fopen(DEVEL_DIR"/te.log", "w");
		}
		xml = dump_xml_formatted(msg);
		fprintf(msg_te_strm, "[Input %s]\t%s\n",
			op, xml);
		fflush(msg_te_strm);
		crm_free(xml);
	}

	if(safe_str_eq(xmlGetProp(msg, XML_ATTR_MSGTYPE), XML_ATTR_RESPONSE)
	   && safe_str_neq(op, CRM_OP_EVENTCC)) {
#ifdef MSG_LOG
	fprintf(msg_te_strm, "[Result ]\tDiscarded\n");
	fflush(msg_te_strm);
#endif
		crm_info("Message was a response not a request.  Discarding");
		return TRUE;
	}

	crm_debug("Processing %s (%s) message", op, ref);
	
	if(op == NULL){
		/* error */
	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */

	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
		crm_verbose("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
	} else if(strcmp(op, CRM_OP_TRANSITION) == 0) {

		crm_trace("Initializing graph...");
		initialize_graph();

		graph = find_xml_node(msg, "transition_graph");
		crm_trace("Unpacking graph...");
		unpack_graph(graph);
		crm_trace("Initiating transition...");

		in_transition = TRUE;

		if(initiate_transition() == FALSE) {
			/* nothing to be done.. means we're done. */
			crm_info("No actions to be taken..."
			       " transition compelte.");
		}
		crm_trace("Processing complete...");
		
	} else if(strcmp(op, CRM_OP_TEABORT) == 0) {
		initialize_graph();

	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_err("Received quit message, terminating");
		exit(0);
		
	} else if(in_transition == FALSE) {
		crm_info("Received event_cc while not in a transition..."
			 "  Poking the Policy Engine");
		send_abort("Initiate a transition", NULL);
		
	} else if(strcmp(op, CRM_OP_EVENTCC) == 0) {
		const char *true_op = get_xml_attr (msg, XML_TAG_OPTIONS,
						    XML_ATTR_TRUEOP, TRUE);
		crm_trace("Processing %s...", CRM_OP_EVENTCC);
		if(true_op == NULL) {
			crm_err(
			       "Illegal update,"
			       " the original operation must be specified");
			send_abort("Illegal update", msg);
			
		} else if(strcmp(true_op, CRM_OP_CIB_CREATE) == 0
		   || strcmp(true_op, CRM_OP_CIB_DELETE) == 0
		   || strcmp(true_op, CRM_OP_CIB_REPLACE) == 0
		   || strcmp(true_op, CRM_OP_WELCOME) == 0
		   || strcmp(true_op, CRM_OP_SHUTDOWN_REQ) == 0
		   || strcmp(true_op, CRM_OP_CIB_ERASE) == 0) {

			/* these are always unexpected, trigger the PE */
			send_abort("Config update", msg);
			
		} else if(strcmp(true_op, CRM_OP_CIB_UPDATE) == 0) {
			/* this may not be un-expected */
/*			if( */
			extract_event(msg);
/*			== FALSE){
				send_abort(msg);
			} */
			
		} else {
			crm_err(
			       "Did not expect copy of action %s", op);
		}
		
	}

	crm_debug("finished processing message");
	print_state(FALSE);
	
	return TRUE;
}
		

xmlNodePtr
create_shutdown_event(const char *node, int op_status)
{
	xmlNodePtr event = create_xml_node(NULL, XML_CIB_TAG_STATE);
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
