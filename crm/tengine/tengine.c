/* $Id: tengine.c,v 1.36 2004/11/12 17:14:34 andrew Exp $ */
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

gboolean graph_complete = FALSE;
GListPtr graph = NULL;
IPC_Channel *crm_ch = NULL;
uint transition_timeout = 30*1000; /* 30 seconds */
uint transition_fuzz_timeout = 0;
uint default_transition_timeout = 30*1000; /* 30 seconds */
uint next_transition_timeout = 30*1000; /* 30 seconds */

void fire_synapse(synapse_t *synapse);
gboolean initiate_action(action_t *action);
gboolean confirm_synapse(synapse_t *synapse, int action_id);
void process_trigger(int action_id);
void check_synapse_triggers(synapse_t *synapse, int action_id);

gboolean in_transition = FALSE;
te_timer_t *transition_timer = NULL;
te_timer_t *transition_fuzz_timer = NULL;
int transition_counter = 0;

gboolean
initialize_graph(void)
{
	if(transition_timer == NULL) {
		crm_malloc(transition_timer, sizeof(te_timer_t));
	    
		transition_timer->timeout   = 10;
		transition_timer->source_id = -1;
		transition_timer->reason    = timeout_timeout;
		transition_timer->action    = NULL;
	} else {
		stop_te_timer(transition_timer);
	}
	
	if(transition_fuzz_timer == NULL) {
		crm_malloc(transition_fuzz_timer, sizeof(te_timer_t));
	
		transition_fuzz_timer->timeout   = 10;
		transition_fuzz_timer->source_id = -1;
		transition_fuzz_timer->reason    = timeout_fuzz;
		transition_fuzz_timer->action    = NULL;
	} else {
		stop_te_timer(transition_fuzz_timer);
	}
	
	while(g_list_length(graph) > 0) {
		synapse_t *synapse = g_list_nth_data(graph, 0);

		while(g_list_length(synapse->actions) > 0) {
			action_t *action = g_list_nth_data(synapse->actions,0);
			synapse->actions = g_list_remove(
				synapse->actions, action);

			if(action->timer->source_id > 0) {
				crm_debug("Removing timer for action: %d",
					  action->id);
				
				g_source_remove(action->timer->source_id);
			}

			free_xml(action->xml);
			crm_free(action->timer);
			crm_free(action);
		}

		while(g_list_length(synapse->inputs) > 0) {
			action_t *action = g_list_nth_data(synapse->inputs, 0);
			synapse->inputs =
				g_list_remove(synapse->inputs, action);

			free_xml(action->xml);
			crm_free(action);
			
		}
		graph = g_list_remove(graph, synapse);
		crm_free(synapse);
	}

	graph = NULL;
	return TRUE;
}

/*
 * returns the ID of the action if a match is found
 * returns -1 if a match was not found
 * returns -2 if a match was found but the action failed (and was
 *            not allowed to)
 */
int
match_graph_event(action_t *action, xmlNodePtr event)
{
	const char *allow_fail  = NULL;
	const char *this_action = NULL;
	const char *this_node   = NULL;
	const char *this_rsc    = NULL;

	const char *event_node;
	const char *event_rsc;
	const char *rsc_state;
	const char *event_action;
	const char *event_rc;
	const char *op_status;
	
	action_t *match = NULL;
	int op_status_i = -3;

	if(event == NULL) {
		crm_trace("Ignoring NULL event");
		return -1;
	}
	
	event_node   = xmlGetProp(event, XML_LRM_ATTR_TARGET);
	event_action = xmlGetProp(event, XML_LRM_ATTR_LASTOP);
	event_rsc    = xmlGetProp(event, XML_ATTR_ID);
	event_rc     = xmlGetProp(event, XML_LRM_ATTR_RC);
	rsc_state    = xmlGetProp(event, XML_LRM_ATTR_RSCSTATE);
	op_status    = xmlGetProp(event, XML_LRM_ATTR_OPSTATUS);
	
	if(op_status != NULL) {
		op_status_i = atoi(op_status);
	}
	
	this_action = xmlGetProp(action->xml, XML_LRM_ATTR_TASK);
	this_node   = xmlGetProp(action->xml, XML_LRM_ATTR_TARGET);
	this_rsc    = xmlGetProp(action->xml, XML_LRM_ATTR_RSCID);
	
	crm_devel("matching against: <%s task=%s node=%s rsc_id=%s/>",
		  action->xml->name, this_action, this_node, this_rsc);
	
	if(safe_str_neq(this_node, event_node)) {
		crm_devel("node mismatch: %s", event_node);

	} else if(safe_str_neq(this_action, event_action)) {	
		crm_devel("action mismatch: %s", event_action);
		
	} else if(safe_str_eq(action->xml->name, "rsc_op")) {
		crm_devel("rsc_op");
		if(safe_str_eq(this_rsc, event_rsc)) {
			match = action;
		} else {
			crm_devel("bad rsc (%s) != (%s)", this_rsc, event_rsc);
		}
		
	} else if(safe_str_eq(action->xml->name, "crm_event")) {
		crm_devel("crm_event");
		match = action;
		
	} else {
		crm_devel("no match");
	}
	
	if(match == NULL) {
		crm_debug("didnt match current action");
		return -1;
	}

	crm_debug("matched");

	/* stop this event's timer if it had one */
	stop_te_timer(match->timer);

	/* Process OP status */
	allow_fail = xmlGetProp(match->xml, "allow_fail");
	switch(op_status_i) {
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			if(safe_str_neq(allow_fail, XML_BOOLEAN_TRUE)) {
				crm_err("Action %s to %s on %s resulted in"
					" failure... aborting transition.",
					event_action, event_rsc, event_node);
				send_abort("Action failed", match->xml);
				return -2;
			}
			break;
		case LRM_OP_CANCELLED:
			/* do nothing?? */
			crm_warn("Dont know what to do for cancelled ops yet");
			break;
		default:
			crm_err("Unsupported action result: %d", op_status_i);
			send_abort("Unsupport action result", match->xml);
			return -2;
	}
	
	crm_devel("Action %d was successful, looking for next action",
		match->id);

	match->complete = TRUE;
	return match->id;
}

gboolean
process_graph_event(xmlNodePtr event)
{
	int action_id          = -1;
	int op_status_i        = 0;
	const char *op_status  = xmlGetProp(event, XML_LRM_ATTR_OPSTATUS);

	next_transition_timeout = transition_timeout;
	
	if(op_status != NULL) {
		op_status_i = atoi(op_status);
	}
	
	if(op_status_i == -1) {
		/* just information that the action was sent */
		crm_trace("Ignoring TE initiated updates");
		return TRUE;
	}

	slist_iter(
		synapse, synapse_t, graph, lpc,

		/* lookup event */
		slist_iter(
			action, action_t, synapse->actions, lpc2,

			action_id = match_graph_event(action, event);
			if(action_id != -1) {
				break;
			}
			);
		if(action_id != -1) {
			break;
		}
		);
	
	if(action_id > -1) {
		crm_xml_devel(event, "Event found");
		
	} else if(action_id == -2) {
		crm_xml_info(event, "Event found but failed");
		
	} else if(event != NULL) {
		/* unexpected event, trigger a pe-recompute */
		/* possibly do this only for certain types of actions */
		send_abort("Event not matched", event);
		return FALSE;
/*	} else { we dont care, a transition is starting */
	}


	process_trigger(action_id);
	
	if(graph_complete) {
		/* allow some slack until we are pretty sure nothing
		 * else is happening
		 */
		crm_info("Transition complete");
		print_state(TRUE);
		
		if(transition_fuzz_timer->timeout > 0) {
			crm_info("Allowing the system to stabilize for %d ms"
				 " before S_IDLE transition",
				 transition_fuzz_timer->timeout);

			start_te_timer(transition_fuzz_timer);
			
		} else {
			send_success("complete");
		}
		
	} else {
		/* restart the transition timer again */
		crm_info("Transition not yet complete");
		print_state(TRUE);
		transition_timer->timeout = next_transition_timeout;
		start_te_timer(transition_timer);
	}

	return TRUE;
}




gboolean
initiate_action(action_t *action) 
{
	gboolean ret = FALSE;

	xmlNodePtr options = NULL;
	xmlNodePtr data    = NULL;

	const char *on_node   = NULL;
	const char *id        = NULL;
	const char *runnable  = NULL;
	const char *optional  = NULL;
	const char *task      = NULL;
	const char *discard   = NULL;
	const char *timeout   = NULL;
	const char *destination = NULL;
	
#ifndef TESTING
	xmlNodePtr rsc_op  = NULL;
#endif

	discard  = xmlGetProp(action->xml, XML_LRM_ATTR_DISCARD);
	on_node  = xmlGetProp(action->xml, XML_LRM_ATTR_TARGET);
	id       = xmlGetProp(action->xml, XML_ATTR_ID);
	runnable = xmlGetProp(action->xml, XML_LRM_ATTR_RUNNABLE);
	optional = xmlGetProp(action->xml, XML_LRM_ATTR_OPTIONAL);
	task     = xmlGetProp(action->xml, XML_LRM_ATTR_TASK);
	timeout  = xmlGetProp(action->xml, "timeout");

	if(id == NULL || strlen(id) == 0
	   || task == NULL || strlen(task) == 0) {
		/* error */
		crm_err("Failed on corrupted command: %s (id=%s) %s",
			action->xml->name, crm_str(id), crm_str(task));

	} else if(action->type == action_type_pseudo){
		crm_info("Executing pseudo-event (%d): "
			 "%s on %s", action->id, task, on_node);
		
		action->complete = TRUE;
		process_trigger(action->id);
		ret = TRUE;
			
	} else if(on_node == NULL || strlen(on_node) == 0) {
		/* error */
		crm_err("Failed on corrupted command: %s (id=%s) %s on %s",
			action->xml->name, crm_str(id),
			crm_str(task), crm_str(on_node));
			
	} else if(action->type == action_type_crm){
		/*
		  <crm_msg op=XML_LRM_ATTR_TASK to=XML_RES_ATTR_TARGET>
		*/
		crm_info("Executing crm-event (%s): %s on %s",
			 id, task, on_node);
#ifndef TESTING
		data = NULL;
		action->complete = TRUE;
		destination = CRM_SYSTEM_CRMD;
		options = create_xml_node(NULL, XML_TAG_OPTIONS);
		set_xml_property_copy(options, XML_ATTR_OP, task);
#endif			
		ret = TRUE;
	} else if(action->type == action_type_rsc){
		crm_info("Executing rsc-op (%s): %s %s on %s",
			 id, task,
			 xmlGetProp(action->xml->children, XML_ATTR_ID),
			 on_node);

		/* let everyone know this was invoked */
		do_update_cib(action->xml, -1);

#ifndef TESTING
		/*
		  <msg_data>
		  <rsc_op id="operation number" on_node="" task="">
		  <resource>...</resource>
		*/
		data    = create_xml_node(NULL, "msg_data");
		rsc_op  = create_xml_node(data, "rsc_op");
		options = create_xml_node(NULL, XML_TAG_OPTIONS);

		set_xml_property_copy(options, XML_ATTR_OP, "rsc_op");
		
		set_xml_property_copy(rsc_op, XML_ATTR_ID, id);
		set_xml_property_copy(rsc_op, XML_LRM_ATTR_TASK, task);
		set_xml_property_copy(rsc_op, XML_LRM_ATTR_TARGET, on_node);
			
		add_node_copy(rsc_op, action->xml->children);

		destination = CRM_SYSTEM_LRMD;
		
			
#endif			
		ret = TRUE;
			
	} else {
		crm_err("Failed on unsupported command type: "
			"%s, %s (id=%s) on %s",
			action->xml->name, task, id, on_node);
	}

	if(ret && options != NULL) {
		char *counter = crm_itoa(transition_counter);
		set_xml_property_copy(
			options, "transition_id", crm_str(counter));
		crm_free(counter);

		crm_xml_debug(options, "Performing");
		if(data != NULL) {
			crm_xml_debug(data, "Performing");
		}
#ifdef MSG_LOG
		if(msg_te_strm != NULL) {
			char *message = dump_xml_formatted(data);
			char *ops = dump_xml_formatted(options);
			fprintf(msg_te_strm, "[Action]\t%s\n%s\n",
				crm_str(ops), crm_str(message));
			fflush(msg_te_strm);
			crm_free(message);
			crm_free(ops);
		}
#endif
		send_ipc_request(
			crm_ch, options, data, on_node,
			destination, CRM_SYSTEM_TENGINE, NULL, NULL);

		if(action->timeout > 0) {
			crm_debug("Setting timer for action %d",action->id);
			start_te_timer(action->timer);
		}

	}
	
	free_xml(options);
	free_xml(data);
	
	return ret;
}

gboolean
initiate_transition(void)
{
	crm_info("Initating transition");

	process_graph_event(NULL);

	return TRUE;
}

void
check_synapse_triggers(synapse_t *synapse, int action_id)
{
	synapse->triggers_complete = TRUE;
			
	if(synapse->confirmed) {
		crm_debug("Skipping confirmed synapse %d", synapse->id);
		return;
			
	} else if(synapse->complete == FALSE) {
		crm_debug("Checking pre-reqs for %d", synapse->id);
		/* lookup prereqs */
		slist_iter(
			prereq, action_t, synapse->inputs, lpc,
				
			crm_devel("Processing input %d", prereq->id);
				
			if(prereq->id == action_id) {
				crm_devel("Marking input %d complete",
					  action_id);
				prereq->complete = TRUE;
					
			} else if(prereq->complete == FALSE) {
				crm_devel("Inputs for synapse %d not satisfied",
					  synapse->id);
				synapse->triggers_complete = FALSE;
			}
				
			);
	}
}

void
fire_synapse(synapse_t *synapse) 
{
	if(synapse == NULL) {
		crm_err("Synapse was NULL!");
		return;
	}
	
	crm_debug("Checking if synapse %d needs to be fired", synapse->id);
	if(synapse->complete) {
		crm_debug("Skipping complete synapse %d", synapse->id);
		return;
		
	} else if(synapse->triggers_complete == FALSE) {
		crm_debug("Synapse %d not yet satisfied", synapse->id);
		return;
	}
	
	crm_devel("All inputs for synapse %d satisfied... invoking actions",
		  synapse->id);

	synapse->complete = TRUE;
	slist_iter(
		action, action_t, synapse->actions, lpc,

		/* allow some leway */
		int tmp_time = 2 * action->timeout;
		gboolean passed = FALSE;
		action->invoked = TRUE;

		/* Invoke the action and start the timer */
		passed = initiate_action(action);

		if(passed == FALSE) {
			crm_err("Failed initiating <%s id=%d> in synapse %d",
				action->xml->name, action->id, synapse->id);

			send_abort("Action init failed", action->xml);
			return;
		} 
		if(tmp_time > next_transition_timeout) {
			next_transition_timeout = tmp_time;
		}
			
		);
	
	crm_debug("Synapse %d complete", synapse->id);
}

gboolean
confirm_synapse(synapse_t *synapse, int action_id) 
{
	gboolean complete = TRUE;
	synapse->confirmed = TRUE;
	slist_iter(
		action, action_t, synapse->actions, lpc,
		
		if(action->type == action_type_rsc
		   && action->complete == FALSE) {
			complete = FALSE;
			synapse->confirmed = FALSE;
			crm_debug("Found an incomplete action"
				  " - transition not complete");
			break;
		}
		);
	return complete;
}

void
process_trigger(int action_id) 
{
	graph_complete = TRUE;
	
	crm_debug("Processing trigger from action %d", action_id);
	
	/* something happened, stop the timer and start it again at the end */
	stop_te_timer(transition_timer);
	
	slist_iter(
		synapse, synapse_t, graph, lpc,
		
		if(synapse->confirmed) {
			crm_debug("Skipping confirmed synapse %d", synapse->id);
			continue;
		}
		
		check_synapse_triggers(synapse, action_id);
		
		fire_synapse(synapse);

		if(graph == NULL) {
			crm_err("Trigger processing aborted after failed synapse");
			break;
		}
		
		crm_debug("Checking if %d is confirmed", synapse->id);
		if(synapse->complete == FALSE) {
			crm_debug("Found an incomplete synapse"
				  " - transition not complete");
			/* indicate that the transition is not yet complete */
			graph_complete = FALSE;
			
		} else if(synapse->confirmed == FALSE) {
			graph_complete = graph_complete
				&& confirm_synapse(synapse, action_id);
			
		}

		crm_debug("%d is %s", synapse->id,
			  synapse->confirmed?"confirmed":synapse->complete?"complete":"pending");
		
		);
}
	
