/* $Id: tengine.c,v 1.52 2005/03/15 09:28:04 zhenh Exp $ */
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
void check_synapse_triggers(synapse_t *synapse, int action_id);

gboolean in_transition = FALSE;
te_timer_t *transition_timer = NULL;
te_timer_t *transition_fuzz_timer = NULL;
int transition_counter = 1;

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
				crm_devel("Removing timer for action: %d",
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
match_graph_event(action_t *action, crm_data_t *event)
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
	
	event_node   = crm_element_value(event, XML_LRM_ATTR_TARGET);
	event_action = crm_element_value(event, XML_LRM_ATTR_LASTOP);
	event_rsc    = crm_element_value(event, XML_ATTR_ID);
	event_rc     = crm_element_value(event, XML_LRM_ATTR_RC);
	rsc_state    = crm_element_value(event, XML_LRM_ATTR_RSCSTATE);
	op_status    = crm_element_value(event, XML_LRM_ATTR_OPSTATUS);
	
	if(op_status != NULL) {
		op_status_i = atoi(op_status);
	}
	
	this_action = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	this_node   = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	this_rsc    = crm_element_value(action->xml, XML_LRM_ATTR_RSCID);
	
	crm_devel("matching against: <%s task=%s node=%s rsc_id=%s/>",
		  crm_element_name(action->xml), this_action, this_node, this_rsc);
	if(safe_str_neq(this_action, event_action)) {	
		crm_info("Action %d : Action mismatch %s", action->id, event_action);
		
	} else if(safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_CRM_EVENT)) {
		if(safe_str_eq(this_action, XML_CIB_ATTR_STONITH)) {
			
		} else if(safe_str_neq(this_node, event_node)) {
			crm_devel("node mismatch: %s", event_node);
		} else {
			crm_devel(XML_GRAPH_TAG_CRM_EVENT);
			match = action;
		}
		
		crm_devel(XML_GRAPH_TAG_CRM_EVENT);
		match = action;
		
	} else if(safe_str_neq(this_node, event_node)) {
		crm_info("Action %d : Node mismatch %s", action->id, event_node);

	} else if(safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_RSC_OP)) {
		crm_devel(XML_GRAPH_TAG_RSC_OP);
		if(safe_str_eq(this_rsc, event_rsc)) {
			match = action;
		} else {
			crm_info("Action %d : bad rsc (%s) != (%s)",
				 action->id, this_rsc, event_rsc);
		}
		
	} else {
		crm_devel("no match");
	}
	
	if(match == NULL) {
		crm_devel("didnt match current action");
		return -1;
	}

	crm_devel("matched");

	/* stop this event's timer if it had one */
	stop_te_timer(match->timer);

	/* Process OP status */
	allow_fail = crm_element_value(match->xml, "allow_fail");
	switch(op_status_i) {
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			if(FALSE == crm_is_true(allow_fail)) {
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

int
match_down_event(const char *target, const char *filter, int rc)
{
	const char *allow_fail  = NULL;
	const char *this_action = NULL;
	const char *this_node   = NULL;
	action_t *match = NULL;
	
	slist_iter(
		synapse, synapse_t, graph, lpc,

		/* lookup event */
		slist_iter(
			action, action_t, synapse->actions, lpc2,

			crm_data_t *action_args = NULL;
			if(action->type != action_type_crm) {
				continue;
			}
			
			this_action = crm_element_value(
				action->xml, XML_LRM_ATTR_TASK);

			if(filter != NULL && safe_str_neq(this_action, filter)) {
				continue;
			}
			
			if(safe_str_eq(this_action, XML_CIB_ATTR_STONITH)) {
				action_args = find_xml_node(
					action->xml, "args", TRUE);
				this_node = crm_element_value(
					action_args, XML_LRM_ATTR_TARGET);

			} else if(safe_str_eq(this_action, CRM_OP_SHUTDOWN)) {
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_TASK);
				this_node = crm_element_value(
					action->xml, XML_LRM_ATTR_TARGET);
			} else {
				crm_info("Action %d : Bad action %s",
					 action->id, this_action);
				continue;
			}
			
			if(safe_str_neq(this_node, target)) {
				crm_info("Action %d : Node mismatch: %s",
					 action->id, this_node);
				continue;
			}

			match = action;
			);
		if(match != NULL) {
			break;
		}
		);
	
	if(match == NULL) {
		crm_devel("didnt match current action");
		return -1;
	}

	crm_devel("matched");

	/* stop this event's timer if it had one */
	stop_te_timer(match->timer);

	/* Process OP status */
	switch(rc) {
		case STONITH_SUCCEEDED:
			break;
		case STONITH_CANNOT:
		case STONITH_TIMEOUT:
		case STONITH_GENERIC:
			allow_fail = crm_element_value(match->xml, "allow_fail");
			if(FALSE == crm_is_true(allow_fail)) {
				crm_err("Stonith of %s failed (%d)..."
					" aborting transition.", target, rc);
				send_abort("Action failed", match->xml);
				return -2;
			}
			break;
		default:
			crm_err("Unsupported action result: %d", rc);
			send_abort("Unsupport action result", match->xml);
			return -2;
	}
	
	crm_devel("Action %d was successful, looking for next action",
		match->id);

	match->complete = TRUE;
	return match->id;
}

gboolean
process_graph_event(crm_data_t *event)
{
	int action_id          = -1;
	int op_status_i        = 0;
	const char *op_status  = NULL;

	if(event != NULL) {
		op_status  = crm_element_value(event, XML_LRM_ATTR_OPSTATUS);
	}
	
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

	if(event == NULL) {
		crm_debug("a transition is starting");
		
	} else if(action_id > -1) {
		crm_xml_devel(event, "Event found");
		
	} else if(action_id == -2) {
		crm_xml_info(event, "Event found but failed");
		
	} else {
		/* unexpected event, trigger a pe-recompute */
		/* possibly do this only for certain types of actions */
		send_abort("Event not matched", event);
		return FALSE;
	}


	process_trigger(action_id);
	check_for_completion();

	return TRUE;
}

void
check_for_completion(void)
{
	if(graph_complete) {
		/* allow some slack until we are pretty sure nothing
		 * else is happening
		 */
		crm_info("Transition complete");
		
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
		crm_devel("Transition not yet complete");
		print_state(LOG_DEV);
		transition_timer->timeout = next_transition_timeout;
		start_te_timer(transition_timer);
	}
}

gboolean
initiate_action(action_t *action) 
{
	gboolean ret = FALSE;

	const char *on_node   = NULL;
	const char *id        = NULL;
	const char *task      = NULL;
	const char *timeout   = NULL;
	const char *destination = NULL;
	const char *msg_task    = XML_GRAPH_TAG_RSC_OP;
	crm_data_t *rsc_op  = NULL;

	on_node  = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	id       = crm_element_value(action->xml, XML_ATTR_ID);
	task     = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	timeout  = crm_element_value(action->xml, XML_ATTR_TIMEOUT);

	if(id == NULL || strlen(id) == 0
	   || task == NULL || strlen(task) == 0) {
		/* error */
#ifdef TESTING
		fprintf(stderr,"Failed on corrupted command: %s (id=%s) %s",
			crm_element_name(action->xml),
			crm_str(id), crm_str(task));
#endif			
		crm_err("Failed on corrupted command: %s (id=%s) %s",
			crm_element_name(action->xml),
			crm_str(id), crm_str(task));

	} else if(action->type == action_type_pseudo){
#ifdef TESTING
		fprintf(stderr,"Executing pseudo-event (%d): %s on %s",
			action->id, task, on_node);
#endif			
		crm_info("Executing pseudo-event (%d): "
			 "%s on %s", action->id, task, on_node);
		
		action->complete = TRUE;
		process_trigger(action->id);
		ret = TRUE;

	} else if(action->type == action_type_crm
		  && safe_str_eq(task, XML_CIB_ATTR_STONITH)){
		
/*         <args target="node1"/> */
		crm_data_t *action_args = find_xml_node(
			action->xml, "args", TRUE);
		const char *target = crm_element_value(action_args, XML_LRM_ATTR_TARGET);
		
#ifdef TESTING
		crm_info("Executing fencing operation (%s) on %s", id, target);
		fprintf(stderr, "Executing fencing operation (%s) on %s\n",
			id, target);
		ret = TRUE;
		action->complete = TRUE;
#else
		stonith_ops_t * st_op = NULL;
		const char *uuid = crm_element_value(action_args,XML_LRM_ATTR_TARGET_UUID);
		crm_malloc(st_op, sizeof(stonith_ops_t));
		st_op->optype = RESET;
		st_op->timeout = crm_atoi(timeout, "100"); /* ten seconds */
		st_op->node_name = crm_strdup(target);
 		CRM_DEV_ASSERT(uuid_parse(uuid, st_op->node_uuid) == 0);

		crm_info("Executing fencing operation (%s) on %s", id, target);

		if(stonithd_input_IPC_channel() == NULL) {
			crm_err("Cannot fence %s - stonith not available", target);
			
		} else if (ST_OK == stonithd_node_fence( st_op )) {
			ret = TRUE;
		}
#endif
		
	} else if(on_node == NULL || strlen(on_node) == 0) {
		/* error */
#ifdef TESTING
		fprintf(stderr,
			"Failed on corrupted command: %s (id=%s) %s on %s\n",
			crm_element_name(action->xml), crm_str(id),
			crm_str(task), crm_str(on_node));
#endif
		crm_err("Failed on corrupted command: %s (id=%s) %s on %s",
			crm_element_name(action->xml), crm_str(id),
			crm_str(task), crm_str(on_node));
			
	} else if(action->type == action_type_crm){
		/*
		  <crm_msg op=XML_LRM_ATTR_TASK to=XML_RES_ATTR_TARGET>
		*/
#ifdef TESTING
		fprintf(stderr, "Executing crm-event (%s): %s on %s\n",
			 id, task, on_node);
#endif
		crm_info("Executing crm-event (%s): %s on %s",
			 id, task, on_node);

		action->complete = TRUE;
		destination = CRM_SYSTEM_CRMD;
		msg_task = task;
		ret = TRUE;

	} else if(action->type == action_type_rsc){
		crm_data_t *rsc = find_xml_node(
			action->xml, XML_CIB_TAG_RESOURCE, TRUE);
#ifdef TESTING
		fprintf(stderr, "Executing rsc-op (%s): %s %s on %s\n",
			 id, task,
			 crm_element_value(rsc, XML_ATTR_ID),
			 on_node);
#endif
		crm_info("Executing rsc-op (%s): %s %s on %s",
			 id, task,
			 crm_element_value(rsc, XML_ATTR_ID),
			 on_node);

		/* let everyone know this was invoked */
		do_update_cib(action->xml, -1);

		/*
		  <msg_data>
		  <rsc_op id="operation number" on_node="" task="">
		  <resource>...</resource>
		*/
		rsc_op  = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);
		
		set_xml_property_copy(rsc_op, XML_ATTR_ID, id);
		set_xml_property_copy(rsc_op, XML_LRM_ATTR_TASK, task);
		set_xml_property_copy(rsc_op, XML_LRM_ATTR_TARGET, on_node);

		add_node_copy(rsc_op, rsc);
		destination = CRM_SYSTEM_LRMD;
		ret = TRUE;
			
	} else {
#ifdef TESTING
		fprintf(stderr, "Failed on unsupported command type: "
			"%s, %s (id=%s) on %s", crm_element_name(action->xml),
			task, id, on_node);
#endif
		crm_err("Failed on unsupported command type: "
			"%s, %s (id=%s) on %s",
			crm_element_name(action->xml), task, id, on_node);
	}

	if(ret) {
		HA_Message *cmd = NULL;
		char *counter = crm_itoa(transition_counter);

		if(rsc_op != NULL) {
			crm_xml_debug(rsc_op, "Performing");
		}
		cmd = create_request(msg_task, rsc_op, on_node, destination,
				     CRM_SYSTEM_TENGINE, NULL);

		ha_msg_add(cmd, "transition_id", crm_str(counter));
#ifndef TESTING
		send_ipc_message(crm_ch, cmd);
#else
		crm_log_message(LOG_DEBUG, cmd);
#endif
		crm_free(counter);

		if(action->timeout > 0) {
			crm_devel("Setting timer for action %d",action->id);
			start_te_timer(action->timer);
		}

	}
	free_xml(rsc_op);
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
		crm_devel("Skipping confirmed synapse %d", synapse->id);
		return;
			
	} else if(synapse->complete == FALSE) {
		crm_devel("Checking pre-reqs for %d", synapse->id);
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
	
	crm_devel("Checking if synapse %d needs to be fired", synapse->id);
	if(synapse->complete) {
		crm_devel("Skipping complete synapse %d", synapse->id);
		return;
		
	} else if(synapse->triggers_complete == FALSE) {
		crm_devel("Synapse %d not yet satisfied", synapse->id);
		return;
	}
	
	crm_devel("All inputs for synapse %d satisfied... invoking actions",
		  synapse->id);

	synapse->complete = TRUE;
	slist_iter(
		action, action_t, synapse->actions, lpc,

		/* allow some leway */
		unsigned tmp_time = 2 * action->timeout;
		gboolean passed = FALSE;
		action->invoked = TRUE;

		/* Invoke the action and start the timer */
		passed = initiate_action(action);

		if(passed == FALSE) {
			crm_err("Failed initiating <%s id=%d> in synapse %d",
				crm_element_name(action->xml), action->id, synapse->id);

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
			crm_devel("Found an incomplete action"
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
	
	crm_devel("Processing trigger from action %d", action_id);
	
	/* something happened, stop the timer and start it again at the end */
	stop_te_timer(transition_timer);
	
	slist_iter(
		synapse, synapse_t, graph, lpc,
		
		if(synapse->confirmed) {
			crm_devel("Skipping confirmed synapse %d", synapse->id);
			continue;
		}
		
		check_synapse_triggers(synapse, action_id);
		
		fire_synapse(synapse);

		if(graph == NULL) {
			crm_err("Trigger processing aborted after failed synapse");
			break;
		}
		
		crm_devel("Checking if %d is confirmed", synapse->id);
		if(synapse->complete == FALSE) {
			crm_devel("Found an incomplete synapse"
				  " - transition not complete");
			/* indicate that the transition is not yet complete */
			graph_complete = FALSE;
			
		} else if(synapse->confirmed == FALSE) {
			graph_complete = graph_complete
				&& confirm_synapse(synapse, action_id);
			
		}

		crm_devel("%d is %s", synapse->id,
			  synapse->confirmed?"confirmed":synapse->complete?"complete":"pending");
		
		);
}
	
