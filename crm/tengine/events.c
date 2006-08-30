/* $Id: events.c,v 1.23 2006/08/14 09:14:45 andrew Exp $ */
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

crm_data_t *need_abort(crm_data_t *update);
void process_graph_event(crm_data_t *event, const char *event_node);
int match_graph_event(
	crm_action_t *action, crm_data_t *event, const char *event_node);

crm_data_t *
need_abort(crm_data_t *update)
{
	crm_data_t *section_xml = NULL;
	const char *section = NULL;

	if(update == NULL) {
		return NULL;
	}
	
	section = XML_CIB_TAG_NODES;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, 
		       return section_xml;
		);

	section = XML_CIB_TAG_RESOURCES;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, 
		       return section_xml;
		);

	section = XML_CIB_TAG_CONSTRAINTS;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, 
		       return section_xml;
		);

	section = XML_CIB_TAG_CRMCONFIG;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, 
		       return section_xml;
		);
	return NULL;
}

static gboolean
fail_incompletable_actions(crm_graph_t *graph, const char *down_node) 
{
	const char *target = NULL;
	crm_data_t *last_action = NULL;

	slist_iter(
		synapse, synapse_t, graph->synapses, lpc,
		if (synapse->confirmed) {
			continue;
		}

		slist_iter(
			action, crm_action_t, synapse->actions, lpc,

			if(action->type == action_type_pseudo || action->confirmed) {
				continue;
			}
			
			target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
			if(safe_str_eq(target, down_node)) {
				action->failed = TRUE;
				last_action = action->xml;
				update_graph(graph, action);
				crm_notice("Action %d (%s) is scheduled for %s (offline)",
					   action->id, ID(action->xml), down_node);
			}
			
			);
		);

	if(last_action != NULL) {
		crm_warn("Node %s shutdown resulted in un-runnable actions", down_node);
		abort_transition(INFINITY, tg_restart, "Node failure", last_action);
		return TRUE;
	}
	
	return FALSE;
}

gboolean
extract_event(crm_data_t *msg)
{
	int shutdown = 0;
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
		crm_debug_2("Processing state update from %s", event_node);
		crm_log_xml_debug_3(node_state, "Processing");

		attrs = find_xml_node(
			node_state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);

		if(attrs != NULL) {
			crm_info("Aborting on "XML_TAG_TRANSIENT_NODEATTRS" changes for %s", event_node);
			abort_transition(INFINITY, tg_restart,
					 XML_TAG_TRANSIENT_NODEATTRS, attrs);
		}
		
		resources = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		resources = find_xml_node(
			resources, XML_LRM_TAG_RESOURCES, FALSE);

		/* LRM resource update... */
		xml_child_iter(
			resources, rsc,  
			xml_child_iter(
				rsc, rsc_op,  
				
				crm_log_xml_debug_3(rsc_op, "Processing resource update");
				process_graph_event(rsc_op, event_node);
				);
			);

		/*
		 * node state update... possibly from a shutdown we requested
		 */
		if(safe_str_eq(ccm_state, XML_BOOLEAN_FALSE)
		   || safe_str_eq(crmd_state, CRMD_JOINSTATE_DOWN)) {
			crm_action_t *shutdown = NULL;
			shutdown = match_down_event(0, event_node, NULL);
			
			if(shutdown != NULL) {
				update_graph(transition_graph, shutdown);
				trigger_graph();

			} else {
				crm_info("Stonith/shutdown of %s not matched", event_node);
				abort_transition(INFINITY, tg_restart, "Node failure", node_state);
			}			
			fail_incompletable_actions(transition_graph, event_node);
		}

		shutdown = 0;
		ha_msg_value_int(node_state, XML_CIB_ATTR_SHUTDOWN, &shutdown);
		if(shutdown != 0) {
			crm_info("Aborting on "XML_CIB_ATTR_SHUTDOWN" attribute for %s", event_node);
			abort_transition(INFINITY, tg_restart, "Shutdown request", node_state);
		}
		);

	return TRUE;
}

static void
update_failcount(crm_action_t *action, int rc) 
{
	crm_data_t *rsc = NULL;
	char *attr_name = NULL;
	
	const char *task     = NULL;
	const char *rsc_id   = NULL;
	const char *on_node  = NULL;
	const char *on_uuid  = NULL;
	const char *interval = NULL;

	if(rc == 99) {
		/* this is an internal code for "we're busy, try again" */
		return;
	}

	interval = g_hash_table_lookup(
		action->params, crm_meta_name("interval"));
	if(interval == NULL) {
		return;
	}

	CRM_CHECK(action->xml != NULL, return);

	rsc = find_xml_node(action->xml, XML_CIB_TAG_RESOURCE, TRUE);
	CRM_CHECK(rsc != NULL, return);
	rsc_id = ID(rsc);
	CRM_CHECK(rsc_id != NULL, return);
	
	task   = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	on_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	on_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

	CRM_CHECK(task != NULL, return);
	CRM_CHECK(on_uuid != NULL, return);
	CRM_CHECK(on_node != NULL, return);
	
	attr_name = crm_concat("fail-count", rsc_id, '-');
	crm_warn("Updating failcount for %s on %s after failed %s: rc=%d",
		 rsc_id, on_node, task, rc);
	
	update_attr(te_cib_conn, cib_none, XML_CIB_TAG_STATUS,
		    on_uuid, NULL,NULL, attr_name, XML_NVPAIR_ATTR_VALUE"++");
	
	crm_free(attr_name);	
}

/*
 * returns the ID of the action if a match is found
 * returns -1 if a match was not found
 * returns -2 if a match was found but the action failed (and was
 *            not allowed to)
 */
int
match_graph_event(
	crm_action_t *action, crm_data_t *event, const char *event_node)
{
	int log_level_fail = LOG_ERR;
	int target_rc = 0;
	const char *target_rc_s = NULL;
	const char *allow_fail  = NULL;
	const char *this_action = NULL;
	const char *this_node   = NULL;
	const char *this_uname  = NULL;
	const char *magic       = NULL;

	const char *this_event;
	char *update_te_uuid = NULL;
	const char *update_event;
	
	int op_status_i = -3;
	int op_rc_i = -3;
	int transition_i = -1;

	CRM_CHECK(event != NULL, return -1);
	
	crm_debug_3("Processing \"%s\" change", crm_element_name(event));
	update_event = crm_element_value(event, XML_ATTR_ID);
	magic        = crm_element_value(event, XML_ATTR_TRANSITION_MAGIC);

	CRM_CHECK(magic != NULL, return -2);
	
	this_action = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	this_uname  = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	this_event  = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
	this_node   = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

	CRM_CHECK(this_event != NULL, return -2);
	
	if(safe_str_neq(this_event, update_event)) {
		crm_debug_2("Action %d : Event mismatch %s vs. %s",
			    action->id, this_event, update_event);
		return -1;
		
	} else if(safe_str_neq(this_node, event_node)) {
		crm_debug_2("Action %d : Node mismatch %s (%s) vs. %s",
			    action->id, this_node, this_uname, event_node);
		return -1;

	}

	crm_debug_2("Matched action (%d) %s", action->id, this_event);

	CRM_CHECK(decode_transition_magic(
			       magic, &update_te_uuid,
			       &transition_i, &op_status_i, &op_rc_i), return -2);

	if(transition_i == -1) {
		/* we never expect these - recompute */
		crm_err("Detected action %s initiated outside of a transition",
			this_event);
		crm_log_message(LOG_ERR, event);
		crm_free(update_te_uuid);
		return -2;
		
	} else if(safe_str_neq(update_te_uuid, te_uuid)) {
		crm_info("Detected action %s from a different transitioner:"
			 " %s vs. %s", this_event, update_te_uuid, te_uuid);
		crm_log_message(LOG_INFO, event);
		crm_free(update_te_uuid);
		return -3;
		
	} else if(transition_graph->id != transition_i) {
		crm_warn("Detected an action %s from a different transition:"
			 " %d vs. %d", this_event, transition_i,
			 transition_graph->id);
		crm_log_message(LOG_INFO, event);
		crm_free(update_te_uuid);
		return -4;
	}

	crm_free(update_te_uuid);
	
	/* stop this event's timer if it had one */
	stop_te_timer(action->timer);
	action->confirmed = TRUE;

	target_rc_s = g_hash_table_lookup(
		action->params,crm_meta_name(XML_ATTR_TE_TARGET_RC));
	if(target_rc_s != NULL) {
		crm_debug_2("Target rc: %s vs. %d", target_rc_s, op_rc_i);
		target_rc = crm_parse_int(target_rc_s, NULL);
		if(target_rc == op_rc_i) {
			crm_debug_2("Target rc: == %d", op_rc_i);
			if(op_status_i != LRM_OP_DONE) {
				crm_debug_2("Re-mapping op status to"
					    " LRM_OP_DONE for %s",update_event);
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
	switch(op_status_i) {
		case -3:
			crm_err("Action returned the same as last time..."
				" whatever that was!");
			crm_log_message(LOG_ERR, event);
			break;
		case LRM_OP_PENDING:
			crm_debug("Ignoring pending operation");
			return -5;
			break;
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
			/* This is the code we use for direct nack's */
			if(op_rc_i == 99) {
				log_level_fail = LOG_WARNING;
			}
			/* fall through */
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			action->failed = TRUE;
			crm_log_maybe(log_level_fail,
				"Action %s on %s failed (target: %d vs. rc: %d): %s",
				update_event, this_uname, target_rc,
				op_rc_i, op_status2text(op_status_i));
			break;
		case LRM_OP_CANCELLED:
			/* do nothing?? */
			crm_err("Dont know what to do for cancelled ops yet");
			break;
		default:
			action->failed = TRUE;
			crm_err("Unsupported action result: %d", op_status_i);
	}

	update_graph(transition_graph, action);
	trigger_graph();
	
	if(action->failed) {
		allow_fail = g_hash_table_lookup(
			action->params, crm_meta_name(XML_ATTR_TE_ALLOWFAIL));
		if(crm_is_true(allow_fail)) {
			action->failed = FALSE;
		}
	}

	if(action->failed) {
		/* ignore probes */
		if(target_rc != EXECRA_NOT_RUNNING) {
			update_failcount(action, op_rc_i);
		}
		abort_transition(action->synapse->priority+1,
				 tg_restart, "Event failed", event);

	} else if(transition_graph->complete) {
		abort_transition(INFINITY, tg_restart,"No active graph", event);
	}

	te_log_action(LOG_INFO, "Action %s (%d) confirmed",
		      this_event, action->id);

	return action->id;
}

crm_action_t *
match_down_event(int id, const char *target, const char *filter)
{
	const char *this_action = NULL;
	const char *this_node   = NULL;
	crm_action_t *match = NULL;

	slist_iter(
		synapse, synapse_t, transition_graph->synapses, lpc,

		/* lookup event */
		slist_iter(
			action, crm_action_t, synapse->actions, lpc2,

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
		match->confirmed = TRUE;

	} else if(id > 0) {
		crm_err("No match for action %d", id);
	} else {
		crm_warn("No match for shutdown action on %s", target);
	}
	return match;
}


void
process_graph_event(crm_data_t *event, const char *event_node)
{
	int rc                = -1;
	const char *magic     = NULL;
	const char *rsc_id    = NULL;

	CRM_ASSERT(event != NULL);
	rsc_id    = crm_element_value(event, XML_ATTR_ID);
	magic     = crm_element_value(event, XML_ATTR_TRANSITION_MAGIC);

	if(magic == NULL) {
		crm_log_xml_debug_2(event, "Skipping \"non-change\"");
		return;
		
	} else {
		crm_debug_2("Processing CIB update: %s on %s: %s",
			  rsc_id, event_node, magic);
	}
	
	slist_iter(
		synapse, synapse_t, transition_graph->synapses, lpc,

		/* lookup event */
		slist_iter(
			action, crm_action_t, synapse->actions, lpc2,

			rc = match_graph_event(action, event, event_node);
			if(rc >= 0) {
				crm_log_xml_debug_2(event, "match:found");

			} else if(rc == -5) {
				crm_log_xml_debug_2(event, "match:pending");

			} else if(rc != -1) {
				crm_warn("Search for %s terminated: %d",
					 ID(event), rc);
				abort_transition(INFINITY, tg_restart,
						 "Unexpected event", event);
			}

			if(rc != -1) {
				return;
			}
			);
		);

	/* unexpected event, trigger a pe-recompute */
	/* possibly do this only for certain types of actions */
	crm_warn("Event not found.");
	crm_log_xml_info(event, "match:not-found");
	abort_transition(INFINITY, tg_restart, "Unexpected event", event);
	return;
}

