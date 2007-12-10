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

#include <crm_internal.h>

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
int match_graph_event(int action_id, crm_data_t *event, const char *event_node,
		      int op_status, int op_rc);

crm_data_t *
need_abort(crm_data_t *update)
{
	crm_data_t *section_xml = NULL;
	const char *section = NULL;

	if(update == NULL) {
		return NULL;
	}
	
        xml_prop_iter(update, name, value,
                      if(safe_str_eq(name, XML_ATTR_HAVE_QUORUM)) {
			      goto do_abort;
                      } else if(safe_str_eq(name, XML_ATTR_NUMPEERS)) {
			      goto do_abort;
                      } else if(safe_str_eq(name, XML_ATTR_GENERATION)) {
			      goto do_abort;
                      } else if(safe_str_eq(name, XML_ATTR_GENERATION_ADMIN)) {
			      goto do_abort;
		      }
		      continue;
	  do_abort:
		      crm_debug("Aborting on change to %s", name);
		      crm_log_xml_debug(update, "Abort: CIB Attrs");
		      return update;
                );

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
update_failcount(crm_data_t *event, const char *event_node, int rc) 
{
	int interval = 0;
	char *task = NULL;
	char *rsc_id = NULL;
	char *attr_name = NULL;
	const char *id  = ID(event);
	const char *on_uuid  = event_node;
	const char *value = XML_NVPAIR_ATTR_VALUE"++";

	if(rc == 99) {
		/* this is an internal code for "we're busy, try again" */
		return;
	}

	CRM_CHECK(on_uuid != NULL, return);

	CRM_CHECK(parse_op_key(id, &rsc_id, &task, &interval),
		  crm_err("Couldn't parse: %s", ID(event));
		  goto bail);
	CRM_CHECK(task != NULL, goto bail);
	CRM_CHECK(rsc_id != NULL, goto bail);

	if(safe_str_eq(task, CRMD_ACTION_START)
	   || safe_str_eq(task, CRMD_ACTION_STOP)) {
	    interval = 1;
	    value = "INFINITY";
	}
	
	if(interval > 0) {
		attr_name = crm_concat("fail-count", rsc_id, '-');
		crm_warn("Updating failcount for %s on %s after failed %s: rc=%d",
			 rsc_id, on_uuid, task, rc);
	
		update_attr(te_cib_conn, cib_none, XML_CIB_TAG_STATUS,
			    on_uuid, NULL,NULL, attr_name,
			    XML_NVPAIR_ATTR_VALUE"++", FALSE);
		crm_free(attr_name);
	}

  bail:
	crm_free(rsc_id);
	crm_free(task);
}

static int
status_from_rc(crm_action_t *action, int orig_status, int rc)
{
	int target_rc = 0;
	int status = orig_status;
	const char *target_rc_s = g_hash_table_lookup(
		action->params, crm_meta_name(XML_ATTR_TE_TARGET_RC));

	if(target_rc_s != NULL) {
		crm_debug_2("Target rc: %s vs. %d", target_rc_s, rc);
		target_rc = crm_parse_int(target_rc_s, NULL);
	}

	if(target_rc == rc) {
	    crm_debug_2("Target rc: == %d", rc);
	    if(status != LRM_OP_DONE) {
		crm_debug_2("Re-mapping op status to"
			    " LRM_OP_DONE for rc=%d", rc);
		status = LRM_OP_DONE;
	    }

	} else {
	    crm_debug_2("Target rc: != %d", rc);
	    if(status != LRM_OP_ERROR) {
		crm_info("Re-mapping op status to"
			 " LRM_OP_ERROR for rc=%d", rc);
		status = LRM_OP_ERROR;
	    }
	}
	
	/* 99 is the code we use for direct nack's */
	if(rc != 99 && status != LRM_OP_DONE) {
		const char *task, *uname;
		task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
		uname  = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
		crm_warn("Action %s on %s failed (target: %s vs. rc: %d): %s",
			 task, uname, crm_str(target_rc_s), rc, op_status2text(status));
	}

	return status;
}

/*
 * returns the ID of the action if a match is found
 * returns -1 if a match was not found
 * returns -2 if a match was found but the action failed (and was
 *            not allowed to)
 */
int
match_graph_event(int action_id, crm_data_t *event, const char *event_node,
		  int op_status, int op_rc)
{
	const char *target = NULL;
	const char *allow_fail = NULL;
	const char *this_event = ID(event);
	crm_action_t *action = NULL;

	action = get_action(action_id, FALSE);
	if(action == NULL) {
		return -1;
	}
	
	op_status = status_from_rc(action, op_status, op_rc);
	if(op_status != LRM_OP_DONE) {
		update_failcount(event, event_node, op_rc);
	}
	
	/* Process OP status */
	switch(op_status) {
		case LRM_OP_PENDING:
			crm_debug("Ignoring pending operation");
			return action->id;
			break;
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			action->failed = TRUE;
			break;
		case LRM_OP_CANCELLED:
			/* do nothing?? */
			crm_err("Dont know what to do for cancelled ops yet");
			break;
		default:
			action->failed = TRUE;
			crm_err("Unsupported action result: %d", op_status);
	}

	/* stop this event's timer if it had one */
	stop_te_timer(action->timer);
	action->confirmed = TRUE;
	
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
		abort_transition(action->synapse->priority+1,
				 tg_restart, "Event failed", event);
	}

	target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	te_log_action(LOG_INFO, "Action %s (%d) confirmed on %s (rc=%d)",
		      crm_str(this_event), action->id, crm_str(target),
		      op_status);

	return action->id;
}

crm_action_t *
get_action(int id, gboolean confirmed)
{
	slist_iter(
		synapse, synapse_t, transition_graph->synapses, lpc,

		slist_iter(
			action, crm_action_t, synapse->actions, lpc2,

			if(action->id == id) {
				if(confirmed) {
					stop_te_timer(action->timer);
					action->confirmed = TRUE;
				}
				return action;
			}
			)
		);
	return NULL;
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
	int rc = -1;
	int status = -1;

	int action = -1;
	int transition_num = -1;
	char *update_te_uuid = NULL;

	gboolean passed = FALSE;
	const char *id = NULL;
	const char *magic = NULL;
	
	CRM_ASSERT(event != NULL);

	id = ID(event);
	magic = crm_element_value(event, XML_ATTR_TRANSITION_MAGIC);

	if(magic == NULL) {
		/* non-change */
		return;
	}
	
	CRM_CHECK(decode_transition_magic(
			  magic, &update_te_uuid, &transition_num, &action,
			  &status, &rc),
		  crm_err("Invalid event %s detected", id);
		  abort_transition(INFINITY, tg_restart,"Bad event", event);
		);

	if(status == LRM_OP_PENDING) {
	    goto bail;
	}
	
	if(transition_num == -1) {
		crm_err("Action %s initiated outside of a transition", id);
		abort_transition(INFINITY, tg_restart,"Unexpected event",event);

	} else if(action < 0 || safe_str_neq(update_te_uuid, te_uuid)) {
		crm_info("Action %s initiated by a different transitioner", id);
		abort_transition(INFINITY, tg_restart,"Foreign event", event);
		
	} else if(transition_graph->id != transition_num) {
		crm_info("Detected action %s from a different transition:"
			" %d vs. %d", id, transition_num, transition_graph->id);
		abort_transition(INFINITY, tg_restart,"Old event", event);
		
	} else if(transition_graph->complete) {
		crm_info("Action %s arrived after a completed transition", id);
		abort_transition(INFINITY, tg_restart, "Inactive graph", event);

	} else if(match_graph_event(
			  action, event, event_node, status, rc) < 0) {
		crm_err("Unknown graph action %s", id);
		abort_transition(INFINITY, tg_restart, "Unknown event", event);

	} else {
		passed = TRUE;
		crm_debug_2("Processed update to %s: %s", id, magic);
	}

	if(passed == FALSE && rc > EXECRA_OK) {
		update_failcount(event, event_node, rc);
	}

  bail:
	crm_free(update_te_uuid);
	return;
}

