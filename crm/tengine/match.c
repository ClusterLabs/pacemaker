/* $Id: match.c,v 1.3 2006/01/11 13:06:11 andrew Exp $ */
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


/*
 * returns the ID of the action if a match is found
 * returns -1 if a match was not found
 * returns -2 if a match was found but the action failed (and was
 *            not allowed to)
 */
int
match_graph_event(action_t *action, crm_data_t *event, const char *event_node)
{
	int target_rc = 0;
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
		target_rc = crm_parse_int(target_rc_s, NULL);
		if(target_rc == op_rc_i) {
			crm_debug_2("Target rc: == %d", op_rc_i);
			if(op_status_i != LRM_OP_DONE) {
				crm_debug("Re-mapping op status to"
					  " LRM_OP_DONE for %s", update_event);
				op_status_i = LRM_OP_DONE;
			}
		} else {
			crm_debug_2("Target rc: != %d", op_rc_i);
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
			crm_warn("Action %s on %s failed (rc: %d vs. %d): %s",
				 update_event, event_node, target_rc, op_rc_i,
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
	
	te_log_action(LOG_INFO, "Action %s (%d) confirmed",
		      this_event, match->id);
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
		crm_debug_2("a transition is starting");

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
			crm_debug_2("Ignoring TE initiated updates");
			return TRUE;
		}
	}
	
	if(magic == NULL) {
		crm_log_xml_debug_2(event, "Skipping \"non-change\"");
		action_id = -3;
	} else {
		crm_debug_2("Processing CIB update: %s on %s: %s",
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
			crm_debug_2("Terminating search: %d", action_id);
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
		crm_log_xml_debug_2(event, "Event found");
		
	} else if(action_id == -2) {
		crm_log_xml_debug(event, "Event failed");
		
#if 0
	} else if(action_id == -3) {
		crm_log_xml_info(event, "Old event found");
#endif
		
	} else if(action_id == -4) {
		crm_log_xml_debug(event, "Pending event found");
		
	} else {
		/* unexpected event, trigger a pe-recompute */
		/* possibly do this only for certain types of actions */
		crm_debug_2("Search terminated: %d", action_id);
		send_complete("Event not matched", event, te_update, i_cancel);
		return FALSE;
	}

	check_for_completion();

	return TRUE;
}
	
