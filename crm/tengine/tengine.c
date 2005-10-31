/* $Id: tengine.c,v 1.105 2005/10/31 08:53:04 andrew Exp $ */
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

gboolean graph_complete = FALSE;
GListPtr graph = NULL;
IPC_Channel *crm_ch = NULL;
uint transition_idle_timeout = 30*1000; /* 30 seconds */

void fire_synapse(synapse_t *synapse);
gboolean initiate_action(action_t *action);
gboolean confirm_synapse(synapse_t *synapse, int action_id);
void check_synapse_triggers(synapse_t *synapse, int action_id);
void cib_action_updated(
	const HA_Message *msg, int call_id, int rc,
	crm_data_t *output, void *user_data);

te_timer_t *transition_timer = NULL;
te_timer_t *abort_timer = NULL;
int transition_counter = 1;
char *te_uuid = NULL;

const te_fsa_state_t te_state_matrix[i_invalid][s_invalid] = 
{
			/*  s_idle,          s_in_transition, s_abort_pending,   s_updates_pending */
/* Got an i_transition  */{ s_in_transition, s_abort_pending, s_abort_pending,   s_updates_pending },
/* Got an i_cancel      */{ s_idle,          s_abort_pending, s_abort_pending,   s_updates_pending },
/* Got an i_complete    */{ s_idle,          s_idle,          s_abort_pending,   s_updates_pending },
/* Got an i_cmd_complete*/{ s_idle,          s_in_transition, s_updates_pending, s_updates_pending },
/* Got an i_cib_complete*/{ s_idle,          s_in_transition, s_abort_pending,   s_idle },
/* Got an i_cib_confirm */{ s_idle,          s_in_transition, s_abort_pending,   s_updates_pending },
/* Got an i_cib_notify  */{ s_idle,          s_in_transition, s_abort_pending,   s_updates_pending }
};



te_fsa_state_t te_fsa_state = s_idle;


gboolean
initialize_graph(void)
{
	remove_cib_op_callback(-1, TRUE);

	if(transition_timer == NULL) {
		crm_malloc0(transition_timer, sizeof(te_timer_t));
	    
		transition_timer->timeout   = 10;
		transition_timer->source_id = -1;
		transition_timer->reason    = timeout_timeout;
		transition_timer->action    = NULL;
	} else {
		stop_te_timer(transition_timer);
	}

	if(abort_timer == NULL) {
		crm_malloc0(abort_timer, sizeof(te_timer_t));
	    
		abort_timer->timeout   = 10;
		abort_timer->source_id = -1;
		abort_timer->reason    = timeout_abort;
		abort_timer->action    = NULL;
	} else {
		stop_te_timer(abort_timer);
	}
	
	if(te_uuid == NULL) {
		cl_uuid_t new_uuid;
		crm_malloc0(te_uuid, sizeof(char)*38);
		cl_uuid_generate(&new_uuid);
		cl_uuid_unparse(&new_uuid, te_uuid);
		crm_info("Registering TE UUID: %s", te_uuid);
	}
	
	while(g_list_length(graph) > 0) {
		synapse_t *synapse = g_list_nth_data(graph, 0);

		while(g_list_length(synapse->actions) > 0) {
			action_t *action = g_list_nth_data(synapse->actions,0);
			synapse->actions = g_list_remove(
				synapse->actions, action);

			if(action->timer->source_id > 0) {
				crm_debug_3("Removing timer for action: %d",
					    action->id);
				
				Gmain_timeout_remove(action->timer->source_id);
			}
			g_hash_table_destroy(action->params);
			free_xml(action->xml);
			crm_free(action->timer);
			crm_free(action);
		}

		while(g_list_length(synapse->inputs) > 0) {
			action_t *action = g_list_nth_data(synapse->inputs, 0);
			synapse->inputs =
				g_list_remove(synapse->inputs, action);

			g_hash_table_destroy(action->params);
			free_xml(action->xml);
			crm_free(action->timer);
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
match_graph_event(action_t *action, crm_data_t *event, const char *event_node)
{
	const char *target_rc_s = NULL;
	const char *allow_fail  = NULL;
	const char *this_action = NULL;
	const char *this_node   = NULL;
	const char *this_uname  = NULL;
	const char *this_rsc    = NULL;
	const char *magic       = NULL;

	const char *this_event;
	char *update_te_uuid = NULL;
	const char *update_event;
	
	action_t *match = NULL;
	int op_status_i = -3;
	int op_rc_i = -3;
	int transition_i = -1;

	if(event == NULL) {
		crm_debug_4("Ignoring NULL event");
		return -1;
	}
	
	this_rsc = crm_element_value(action->xml, XML_LRM_ATTR_RSCID);
	
	if(this_rsc == NULL) {
		crm_debug_4("Skipping non-resource event");
		return -1;
	}

	crm_debug_3("Processing \"%s\" change", crm_element_name(event));
	update_event = crm_element_value(event, XML_ATTR_ID);
	magic        = crm_element_value(event, XML_ATTR_TRANSITION_MAGIC);

	if(magic == NULL) {
/* 		crm_debug("Skipping \"non-change\""); */
		crm_log_xml_debug(event, "Skipping \"non-change\"");
		return -3;
	}
	
	this_action = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	this_node   = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
	this_uname  = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

	this_event = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
	CRM_DEV_ASSERT(this_event != NULL);
	
	if(safe_str_neq(this_event, update_event)) {
		crm_debug_2("Action %d : Event mismatch %s vs. %s",
			    action->id, this_event, update_event);

	} else if(safe_str_neq(this_node, event_node)) {
		crm_debug_2("Action %d : Node mismatch %s (%s) vs. %s",
			    action->id, this_node, this_uname, event_node);
	} else {
		match = action;
	}
	
	if(match == NULL) {
		return -1;
	}
	
	crm_debug("Matched action (%d) %s", action->id, this_event);

	CRM_DEV_ASSERT(decode_transition_magic(
			       magic, &update_te_uuid,
			       &transition_i, &op_status_i, &op_rc_i));

	if(event == NULL) {
		crm_err("No event");

	} else if(transition_i == -1) {
		/* we never expect these - recompute */
		crm_err("Detected an action initiated outside of a transition");
		crm_log_message(LOG_ERR, event);
		return -5;
		
	} else if(safe_str_neq(update_te_uuid, te_uuid)) {
		crm_info("Detected an action from a different transitioner:"
			 " %s vs. %s", update_te_uuid, te_uuid);
		crm_log_message(LOG_INFO, event);
		return -6;
		
	} else if(transition_counter != transition_i) {
		crm_warn("Detected an action from a different transition:"
			 " %d vs. %d", transition_i, transition_counter);
		crm_log_message(LOG_INFO, event);
		return -3;
	}
	
	/* stop this event's timer if it had one */
	stop_te_timer(match->timer);
	match->complete = TRUE;

	target_rc_s = g_hash_table_lookup(match->params,XML_ATTR_TE_TARGET_RC);
	if(target_rc_s != NULL) {
		int target_rc = crm_parse_int(target_rc_s, NULL);
		if(target_rc == op_rc_i) {
			crm_info("Target rc: == %d", op_rc_i);
			if(op_status_i != LRM_OP_DONE) {
				crm_debug("Re-mapping op status to"
					  " LRM_OP_DONE for %s", update_event);
				op_status_i = LRM_OP_DONE;
			}
		} else {
			crm_info("Target rc: != %d", op_rc_i);
			if(op_status_i != LRM_OP_ERROR) {
				crm_info("Re-mapping op status to"
					 " LRM_OP_ERROR for %s", update_event);
				op_status_i = LRM_OP_ERROR;
			}
		}
	}
	
	/* Process OP status */
	allow_fail = g_hash_table_lookup(match->params, XML_ATTR_TE_ALLOWFAIL);
	switch(op_status_i) {
		case -3:
			crm_err("Action returned the same as last time..."
				" whatever that was!");
			crm_log_message(LOG_ERR, event);
			break;
		case LRM_OP_PENDING:
			crm_debug("Ignoring pending operation");
			return -4;
			break;
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			match->failed = TRUE;
			crm_warn("Action %s on %s failed: %s",
				 update_event, event_node,
				 op_status2text(op_status_i));
			if(FALSE == crm_is_true(allow_fail)) {
				send_complete("Action failed", event,
					      te_failed, i_cancel);
				return -2;
			}
			break;
		case LRM_OP_CANCELLED:
			/* do nothing?? */
			crm_err("Dont know what to do for cancelled ops yet");
			break;
		default:
			crm_err("Unsupported action result: %d", op_status_i);
			send_complete("Unsupport action result",
				      event, te_failed, i_cancel);
			return -2;
	}
	
	te_log_action(LOG_INFO, "Action %d confirmed", match->id);
	process_trigger(match->id);

	if(te_fsa_state != s_in_transition) {
		return -3;
	}
	return match->id;
}

action_t *
match_down_event(int id, const char *target, const char *filter)
{
	const char *this_action = NULL;
	const char *this_node   = NULL;
	action_t *match = NULL;

	slist_iter(
		synapse, synapse_t, graph, lpc,

		/* lookup event */
		slist_iter(
			action, action_t, synapse->actions, lpc2,

			if(id > 0 && action->id == id) {
				match = action;
				break;
			}
			
			this_action = crm_element_value(
				action->xml, XML_LRM_ATTR_TASK);

			if(action->type != action_type_crm) {
				continue;

			} else if(safe_str_eq(this_action, CRM_OP_LRM_REFRESH)){
				continue;
				
			} else if(filter != NULL
				  && safe_str_neq(this_action, filter)) {
				continue;
			}
			
			this_node = crm_element_value(
				action->xml, XML_LRM_ATTR_TARGET_UUID);

			if(this_node == NULL) {
				crm_log_xml_err(action->xml, "No node uuid");
			}
			
			if(safe_str_neq(this_node, target)) {
				crm_debug("Action %d : Node mismatch: %s",
					 action->id, this_node);
				continue;
			}

			match = action;
			break;
			);
		if(match != NULL) {
			/* stop this event's timer if it had one */
			break;
		}
		);
	
	if(match != NULL) {
		/* stop this event's timer if it had one */
		crm_debug("Match found for action %d: %s on %s", id,
			  crm_element_value(match->xml, XML_LRM_ATTR_TASK_KEY),
			  target);
		stop_te_timer(match->timer);
		match->complete = TRUE;

	} else if(id > 0) {
		crm_err("No match for action %d", id);
	} else {
		crm_warn("No match for shutdown action on %s", target);
	}
	return match;
}

static void
cib_fencing_updated(const HA_Message *msg, int call_id, int rc,
		    crm_data_t *output, void *user_data)
{
	if(rc < cib_ok) {
		crm_err("CIB update failed: %s", cib_error2string(rc));
		crm_log_xml_warn(msg, "[Failed Update]");
	}
	check_for_completion();
}

void
send_stonith_update(stonith_ops_t * op)
{
	enum cib_errors rc = cib_ok;
	const char *target = op->node_name;
	const char *uuid   = op->node_uuid;
	
	/* zero out the node-status & remove all LRM status info */
	crm_data_t *update = NULL;
	crm_data_t *node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	
	CRM_DEV_ASSERT(op->node_name != NULL);
	CRM_DEV_ASSERT(op->node_uuid != NULL);
	
	crm_xml_add(node_state, XML_ATTR_UUID,  uuid);
	crm_xml_add(node_state, XML_ATTR_UNAME, target);
	crm_xml_add(node_state, XML_CIB_ATTR_HASTATE,   DEADSTATUS);
	crm_xml_add(node_state, XML_CIB_ATTR_INCCM,     XML_BOOLEAN_NO);
	crm_xml_add(node_state, XML_CIB_ATTR_CRMDSTATE, OFFLINESTATUS);
	crm_xml_add(node_state, XML_CIB_ATTR_JOINSTATE, CRMD_JOINSTATE_DOWN);
	crm_xml_add(node_state, XML_CIB_ATTR_EXPSTATE,  CRMD_JOINSTATE_DOWN);
	crm_xml_add(node_state, XML_CIB_ATTR_REPLACE,   XML_CIB_TAG_LRM);
	create_xml_node(node_state, XML_CIB_TAG_LRM);
	
	update = create_cib_fragment(node_state, XML_CIB_TAG_STATUS);
	
	rc = te_cib_conn->cmds->update(
		te_cib_conn, XML_CIB_TAG_STATUS, update, NULL,
		cib_quorum_override);	
	
	if(rc < cib_ok) {
		const char *fail_text = "Couldnt update CIB after stonith";
		crm_err("CIB update failed: %s", cib_error2string(rc));
		send_complete(fail_text, update, te_failed, i_cancel);
		
	} else {
		/* delay processing the trigger until the update completes */
		add_cib_op_callback(rc, FALSE, NULL, cib_fencing_updated);
	}
	
	free_xml(node_state);
	free_xml(update);
	return;
}


gboolean
process_graph_event(crm_data_t *event, const char *event_node)
{
	int rc                = -1;
	int action_id         = -1;
	int op_status_i       = 0;
	const char *magic     = NULL;
	const char *rsc_id    = NULL;
	const char *op_status = NULL;

	if(event == NULL) {
		crm_debug("a transition is starting");

		process_trigger(action_id);
		check_for_completion();
		
		return TRUE;
	}
	rsc_id    = crm_element_value(event, XML_ATTR_ID);
	op_status = crm_element_value(event, XML_LRM_ATTR_OPSTATUS);
	magic     = crm_element_value(event, XML_ATTR_TRANSITION_MAGIC);

	if(op_status != NULL) {
		op_status_i = crm_parse_int(op_status, NULL);
		if(op_status_i == -1) {
			/* just information that the action was sent */
			crm_debug("Ignoring TE initiated updates");
			return TRUE;
		}
	}
	
	if(magic == NULL) {
		crm_log_xml_debug(event, "Skipping \"non-change\"");
		action_id = -3;
	} else {
		crm_debug("Processing CIB update: %s on %s: %s",
			  rsc_id, event_node, magic);
	}
	
	slist_iter(
		synapse, synapse_t, graph, lpc,

		/* lookup event */
		slist_iter(
			action, action_t, synapse->actions, lpc2,

			rc = match_graph_event(action, event, event_node);
			if(action_id >= 0 && rc >= 0) {
				crm_err("Additional match found: %d [%d]",
					rc, action_id);
			} else if(rc != -1) {
				action_id = rc;
			}
			);
		if(action_id != -1) {
			crm_debug("Terminating search: %d", action_id);
			break;
		}
		);

	if(action_id == -1) {
		/* didnt find a match...
		 * now try any dangling inputs
		 */
		slist_iter(
			synapse, synapse_t, graph, lpc,
			
			slist_iter(
				action, action_t, synapse->inputs, lpc2,
				
				rc = match_graph_event(action,event,event_node);
				if(action_id >=0 && rc >=0 && rc != action_id) {
					crm_err("Additional match found:"
						" %d [%d]", rc, action_id);
				} else if(rc != -1) {
					action_id = rc;
				}
				);
			if(action_id != -1) {
				break;
			}
			);
	}

	if(action_id > -1) {
		crm_log_xml_debug_3(event, "Event found");
		
	} else if(action_id == -2) {
		crm_log_xml_info(event, "Event failed");
		
#if 0
	} else if(action_id == -3) {
		crm_log_xml_info(event, "Old event found");
#endif
		
	} else if(action_id == -4) {
		crm_log_xml_debug(event, "Pending event found");
		
	} else {
		/* unexpected event, trigger a pe-recompute */
		/* possibly do this only for certain types of actions */
		crm_debug("Search terminated: %d", action_id);
		send_complete("Event not matched", event, te_update, i_cancel);
		return FALSE;
	}

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
		send_complete("complete", NULL, te_done, i_complete);
		
	} else {
		/* restart the transition timer again */
		crm_debug_3("Transition not yet complete");
		start_te_timer(transition_timer);
	}
}


gboolean
initiate_action(action_t *action) 
{
	gboolean ret = FALSE;
	gboolean send_command = FALSE;

	const char *on_node   = NULL;
	const char *id        = NULL;
	const char *task      = NULL;
	const char *timeout   = NULL;
	const char *msg_task    = XML_GRAPH_TAG_RSC_OP;

	on_node  = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	id       = crm_element_value(action->xml, XML_ATTR_ID);
	task     = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	timeout  = crm_element_value(action->xml, XML_ATTR_TIMEOUT);

	if(id == NULL || strlen(id) == 0
	   || task == NULL || strlen(task) == 0) {
		/* error */
		te_log_action(LOG_ERR, "Failed on corrupted command: %s (id=%s) %s",
			crm_element_name(action->xml),
			crm_str(id), crm_str(task));

	} else if(action->type == action_type_pseudo){
		te_log_action(LOG_INFO, "Executing pseudo-event (%d): "
			 "%s on %s", action->id, task, on_node);
		
		action->complete = TRUE;
		process_trigger(action->id);
		ret = TRUE;

	} else if(action->type == action_type_crm
		  && safe_str_eq(task, CRM_OP_FENCE)){

		char *key = NULL;
		const char *id = NULL;
		const char *uuid = NULL;
		const char *target = NULL;
		stonith_ops_t * st_op = NULL;

		id = ID(action->xml);
		target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
		uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

		CRM_DEV_ASSERT(id != NULL);
		CRM_DEV_ASSERT(uuid != NULL);
		CRM_DEV_ASSERT(target != NULL);

		te_log_action(LOG_INFO,"Executing fencing operation (%s) on %s",
			      id, target);
#ifdef TESTING
		ret = TRUE;
		action->complete = TRUE;
		process_trigger(action->id);
		return TRUE;
#endif
		crm_malloc0(st_op, sizeof(stonith_ops_t));
		st_op->optype = RESET;
		st_op->timeout = transition_idle_timeout / 2;
		st_op->node_name = crm_strdup(target);
		st_op->node_uuid = crm_strdup(uuid);
		st_op->private_data = crm_strdup(id);

		key = generate_transition_key(transition_counter, te_uuid);
		st_op->private_data = crm_concat(id, key, ';');
		crm_free(key);
		
		if(stonithd_input_IPC_channel() == NULL) {
			crm_err("Cannot fence %s - stonith not available",
				target);
			
		} else if (ST_OK == stonithd_node_fence( st_op )) {
			ret = TRUE;
		}
		
	} else if(on_node == NULL || strlen(on_node) == 0) {
		/* error */
		te_log_action(LOG_ERR,
			      "Failed on corrupted command: %s (id=%s) %s on %s",
			      crm_element_name(action->xml), crm_str(id),
			      crm_str(task), crm_str(on_node));
			
	} else if(action->type == action_type_crm){
		te_log_action(LOG_INFO, "Executing crm-event (%s): %s on %s",
			      id, task, on_node);

#ifdef TESTING
		action->complete = TRUE;
		process_trigger(action->id);
		return TRUE;
#endif
/* 		action->complete = TRUE; */
		msg_task = task;
		send_command = TRUE;

	} else if(action->type == action_type_rsc){
		/* never overwrite stop actions in the CIB with
		 *   anything other than completed results
		 *
		 * Writing pending stops makes it look like the
		 *   resource is running again
		 */
#ifdef TESTING
		action->invoked = FALSE;
		cib_action_update(action, LRM_OP_DONE);
		return TRUE;
#endif
		action->invoked = FALSE;
		if(safe_str_eq(task, CRMD_ACTION_START)
		   || safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
			cib_action_update(action, LRM_OP_PENDING);

		} else {
			cib_action_updated(NULL, 0, cib_ok, NULL, action);
		}
		ret = TRUE;

	} else {
		te_log_action(LOG_ERR,
			      "Failed on unsupported command type: "
			      "%s, %s (id=%s) on %s",
			      crm_element_name(action->xml), task, id, on_node);
	}

	if(send_command) {
		char *value = NULL;
		HA_Message *cmd = NULL;		
		char *counter = crm_itoa(transition_counter);

		cmd = create_request(msg_task, NULL, on_node, CRM_SYSTEM_CRMD,
				     CRM_SYSTEM_TENGINE, NULL);

		counter = generate_transition_key(transition_counter, te_uuid);
		crm_xml_add(cmd, XML_ATTR_TRANSITION_KEY, counter);
		ret = send_ipc_message(crm_ch, cmd);
		crm_free(counter);

		value = g_hash_table_lookup(action->params, XML_ATTR_TE_NOWAIT);
		if(ret == FALSE) {
			crm_err("Action %d failed: send", action->id);

		} else if(crm_is_true(value)) {
			crm_info("Skipping wait for %d", action->id);
			action->complete = TRUE;
			process_trigger(action->id);
			
		} else if(ret && action->timeout > 0) {
			crm_debug_3("Setting timer for action %d",action->id);
			action->timer->reason = timeout_action_warn;
			start_te_timer(action->timer);
		}
		
	}
	return ret;
}

gboolean
cib_action_update(action_t *action, int status)
{
	char *code = NULL;
	crm_data_t *fragment = NULL;
	crm_data_t *state    = NULL;
	crm_data_t *rsc      = NULL;
	crm_data_t *xml_op   = NULL;
	char *op_id = NULL;

	enum cib_errors rc = cib_ok;
	const char *task   = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	const char *rsc_id = crm_element_value(action->xml, XML_LRM_ATTR_RSCID);
	const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	const char *target_uuid =
		crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

	int call_options = cib_quorum_override;

	if(status == LRM_OP_TIMEOUT) {
		if(crm_element_value(action->xml, XML_LRM_ATTR_RSCID) != NULL) {
			crm_warn("%s: %s %s on %s timed out",
				 crm_element_name(action->xml), task, rsc_id, target);
		} else {
			crm_warn("%s: %s on %s timed out",
				 crm_element_name(action->xml), task, target);
		}
	}
	code = crm_itoa(status);
	
/*
  update the CIB

<node_state id="hadev">
      <lrm>
        <lrm_resources>
          <lrm_resource id="rsc2" last_op="start" op_code="0" target="hadev"/>
*/

	fragment = NULL;
	state    = create_xml_node(NULL, XML_CIB_TAG_STATE);

	crm_xml_add(state, XML_ATTR_UUID,  target_uuid);
	crm_xml_add(state, XML_ATTR_UNAME, target);
	
	rsc = create_xml_node(state, XML_CIB_TAG_LRM);
	rsc = create_xml_node(rsc,   XML_LRM_TAG_RESOURCES);
	rsc = create_xml_node(rsc,   XML_LRM_TAG_RESOURCE);

	xml_op = create_xml_node(rsc,XML_LRM_TAG_RSC_OP);
	
	crm_xml_add(rsc,    XML_ATTR_ID, rsc_id);
	crm_xml_add(xml_op, XML_ATTR_ID, task);
	
	op_id = generate_op_key(rsc_id, task, action->interval);
	crm_xml_add(xml_op, XML_ATTR_ID, op_id);
	crm_free(op_id);
	
	crm_xml_add(xml_op, XML_LRM_ATTR_TASK, task);
	crm_xml_add(rsc, XML_LRM_ATTR_RSCSTATE,
			      get_rsc_state(task, status));
	
	crm_xml_add(xml_op, XML_LRM_ATTR_OPSTATUS, code);
	crm_xml_add(xml_op, XML_LRM_ATTR_CALLID, "-1");
	crm_xml_add(xml_op, XML_LRM_ATTR_RC, code);
	crm_xml_add(xml_op, "origin", __FUNCTION__);

	crm_free(code);

	code = generate_transition_key(transition_counter, te_uuid);
	crm_xml_add(xml_op, XML_ATTR_TRANSITION_KEY, code);
	crm_free(code);

	code = generate_transition_magic(
		crm_element_value(xml_op, XML_ATTR_TRANSITION_KEY), status, status);
	crm_xml_add(xml_op,  XML_ATTR_TRANSITION_MAGIC, code);
	crm_free(code);
	
	set_node_tstamp(xml_op);

	fragment = create_cib_fragment(state, XML_CIB_TAG_STATUS);
	
	crm_debug_3("Updating CIB with \"%s\" (%s): %s %s on %s",
		  status<0?"new action":XML_ATTR_TIMEOUT,
		  crm_element_name(action->xml), crm_str(task), rsc_id, target);
	
#ifndef TESTING
	rc = te_cib_conn->cmds->update(
		te_cib_conn, XML_CIB_TAG_STATUS, fragment, NULL, call_options);

	crm_debug("Updating CIB with %s action %d: %s %s on %s (call_id=%d)",
		  op_status2text(status), action->id, task, rsc_id, target, rc);

	if(status == LRM_OP_PENDING) {
		crm_debug_2("Waiting for callback id: %d", rc);
		add_cib_op_callback(rc, FALSE, action, cib_action_updated);
	}
#else
	te_log_action(LOG_INFO, "Initiating action %d: %s %s on %s",
		      action->id, task, rsc_id, target);
	call_options = 0;
	{
		HA_Message *cmd = ha_msg_new(11);
		ha_msg_add(cmd, F_TYPE,		T_CRM);
		ha_msg_add(cmd, F_CRM_VERSION,	CRM_FEATURE_SET);
		ha_msg_add(cmd, F_CRM_MSG_TYPE, XML_ATTR_REQUEST);
		ha_msg_add(cmd, F_CRM_TASK,	CRM_OP_EVENTCC);
		ha_msg_add(cmd, F_CRM_SYS_TO,   CRM_SYSTEM_TENGINE);
		ha_msg_add(cmd, F_CRM_SYS_FROM, CRM_SYSTEM_TENGINE);
		ha_msg_addstruct(cmd, crm_element_name(state), state);
		send_ipc_message(crm_ch, cmd);
	}
#endif
	free_xml(fragment);
	free_xml(state);

	action->sent_update = TRUE;
	
	if(rc < cib_ok) {
		return FALSE;
	}

	return TRUE;
}


void
cib_action_updated(
	const HA_Message *msg, int call_id, int rc, crm_data_t *output, void *user_data)
{
	HA_Message *cmd = NULL;
	crm_data_t *rsc_op  = NULL;
	const char *task    = NULL;
	const char *rsc_id  = NULL;
	const char *on_node = NULL;
	const char *value = NULL;

	action_t *action = user_data;
	char *counter = crm_itoa(transition_counter);

	CRM_DEV_ASSERT(action != NULL);      if(crm_assert_failed) { return; }
	CRM_DEV_ASSERT(action->xml != NULL); if(crm_assert_failed) { return; }

	rsc_op  = action->xml;
	task    = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
	rsc_id  = crm_element_value(rsc_op, XML_LRM_ATTR_RSCID);
	on_node = crm_element_value(rsc_op, XML_LRM_ATTR_TARGET);
	counter = generate_transition_key(transition_counter, te_uuid);
	crm_xml_add(rsc_op, XML_ATTR_TRANSITION_KEY, counter);
	crm_free(counter);
	
	if(rc < cib_ok) {
		crm_err("Update for action %d: %s %s on %s FAILED",
			action->id, task, rsc_id, on_node);
		send_complete(cib_error2string(rc), output, te_failed, i_cancel);
		return;
	}

	if(te_fsa_state != s_in_transition) {
		int pending_updates = num_cib_op_callbacks();
		if(pending_updates == 0) {
			send_complete("CIB update queue empty", output,
				      te_done, i_cib_complete);
		} else {
			crm_debug("Still waiting on %d callbacks",
				pending_updates);
		}
		crm_debug("Not executing action: Not in a transition: %d",
			  te_fsa_state);
		return;
	}
	
	crm_info("Initiating action %d: %s %s on %s",
		 action->id, task, rsc_id, on_node);
	
	if(rsc_op != NULL) {
		crm_log_xml_debug_2(rsc_op, "Performing");
	}
	cmd = create_request(CRM_OP_INVOKE_LRM, rsc_op, on_node,
			     CRM_SYSTEM_LRMD, CRM_SYSTEM_TENGINE, NULL);
	

#ifndef TESTING
	send_ipc_message(crm_ch, cmd);
#else
	crm_log_message(LOG_INFO, cmd);
#endif
	
	action->invoked = TRUE;
	value = g_hash_table_lookup(action->params, XML_ATTR_TE_NOWAIT);
	if(crm_is_true(value)) {
		crm_info("Skipping wait for %d", action->id);
		action->complete = TRUE;
		process_trigger(action->id);

	} else if(action->timeout > 0) {
		crm_debug_3("Setting timer for action %d",action->id);
		action->timer->reason = timeout_action_warn;
		start_te_timer(action->timer);
	}
}

gboolean
initiate_transition(void)
{
	crm_info("Initating transition");

	process_graph_event(NULL, NULL);

	return TRUE;
}

void
check_synapse_triggers(synapse_t *synapse, int action_id)
{
	synapse->triggers_complete = TRUE;
			
	if(synapse->confirmed) {
		crm_debug_3("Skipping confirmed synapse %d", synapse->id);
		return;
			
	} else if(synapse->complete == FALSE) {
		crm_debug_3("Checking pre-reqs for %d", synapse->id);
		/* lookup prereqs */
		slist_iter(
			prereq, action_t, synapse->inputs, lpc,
				
			crm_debug_3("Processing input %d", prereq->id);
				
			if(prereq->id == action_id) {
				crm_debug_3("Marking input %d complete",
					  action_id);
				prereq->complete = TRUE;
					
			} else if(prereq->complete == FALSE) {
				crm_debug_3("Inputs for synapse %d not satisfied",
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
	
	crm_debug_3("Checking if synapse %d needs to be fired", synapse->id);
	if(synapse->complete) {
		crm_debug_3("Skipping complete synapse %d", synapse->id);
		return;
		
	} else if(synapse->triggers_complete == FALSE) {
		crm_debug_3("Synapse %d not yet satisfied", synapse->id);
		return;
	}
	
	crm_debug("All inputs for synapse %d satisfied... invoking actions",
		  synapse->id);

	synapse->complete = TRUE;
	slist_iter(
		action, action_t, synapse->actions, lpc,

		/* allow some leeway */
		int tmp_time = 2 * action->timeout;
		gboolean passed = FALSE;
		action->invoked = TRUE;

		/* Invoke the action and start the timer */
		passed = initiate_action(action);

		if(passed == FALSE) {
			crm_err("Failed initiating <%s id=%d> in synapse %d",
				crm_element_name(action->xml),
				action->id, synapse->id);

			send_complete("Action init failed", action->xml,
				      te_failed, i_cancel);
			return;
		} 
		if(tmp_time > transition_timer->timeout) {
			crm_debug("Action %d: Increasing IDLE timer to %d",
				  action->id, tmp_time);
			transition_timer->timeout = tmp_time;
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
		
		if(action->complete == FALSE) {
			complete = FALSE;
			synapse->confirmed = FALSE;
			crm_debug_3("Found an incomplete action"
				  " - transition not complete");
			break;
		}
		);

	if(complete) {
		crm_debug("Synapse %d complete (action=%d)",
			  synapse->id, action_id);
	}

	return complete;
}

void
process_trigger(int action_id) 
{
	if(te_fsa_state != s_in_transition) {
		int unconfirmed = unconfirmed_actions();
		crm_info("Trigger from action %d (%d more) discarded:"
			 " Not in transition", action_id, unconfirmed);
		if(unconfirmed == 0) {
			send_complete("Last pending action confirmed", NULL,
				      te_abort_confirmed, i_cmd_complete);
		}
		return;
	}
	
	graph_complete = TRUE;
	
	crm_debug_3("Processing trigger from action %d", action_id);

	/* something happened, stop the timer and start it again at the end */
	stop_te_timer(transition_timer);
	
	slist_iter(
		synapse, synapse_t, graph, lpc,
		
		if(synapse->confirmed) {
			crm_debug_3("Skipping confirmed synapse %d", synapse->id);
			continue;
		}
		
		check_synapse_triggers(synapse, action_id);
		
		fire_synapse(synapse);

		if(graph == NULL) {
			crm_err("Trigger processing aborted after failed synapse");
			break;
		}
		
		crm_debug_3("Checking if %d is confirmed", synapse->id);
		if(synapse->complete == FALSE) {
			crm_debug_3("Found an incomplete synapse"
				  " - transition not complete");
			/* indicate that the transition is not yet complete */
			graph_complete = FALSE;
			
		} else if(synapse->confirmed == FALSE) {
			gboolean confirmed = confirm_synapse(synapse,action_id);
			graph_complete = graph_complete && confirmed;
		}

		crm_debug_3("%d is %s", synapse->id,
			  synapse->confirmed?"confirmed":synapse->complete?"complete":"pending");
		
		);
}
	
