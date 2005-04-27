/* $Id: tengine.c,v 1.65 2005/04/27 09:48:54 andrew Exp $ */
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
void cib_action_updated(
	const HA_Message *msg, int call_id, int rc,
	crm_data_t *output, void *user_data);

gboolean in_transition = FALSE;
te_timer_t *transition_timer = NULL;
te_timer_t *transition_fuzz_timer = NULL;
int transition_counter = 1;

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
	
	if(transition_fuzz_timer == NULL) {
		crm_malloc0(transition_fuzz_timer, sizeof(te_timer_t));
	
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
match_graph_event(action_t *action, crm_data_t *event, const char *event_node)
{
	const char *allow_fail  = NULL;
	const char *this_action = NULL;
	const char *this_node   = NULL;
	const char *this_rsc    = NULL;

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
	
	crm_debug("matching against: <%s task=%s node=%s rsc_id=%s/>",
		  crm_element_name(action->xml), this_action, this_node, this_rsc);
	if(safe_str_neq(this_action, event_action)) {	
		crm_debug("Action %d : Action mismatch %s", action->id, event_action);
		
	} else if(safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_CRM_EVENT)) {
		if(safe_str_eq(this_action, XML_CIB_ATTR_STONITH)) {
			
		} else if(safe_str_neq(this_node, event_node)) {
			crm_debug("node mismatch: %s", event_node);
		} else {
			crm_devel(XML_GRAPH_TAG_CRM_EVENT);
			match = action;
		}
		
		crm_devel(XML_GRAPH_TAG_CRM_EVENT);
		match = action;
		
	} else if(safe_str_neq(this_node, event_node)) {
		crm_debug("Action %d : Node mismatch %s", action->id, event_node);

	} else if(safe_str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_RSC_OP)) {
		crm_devel(XML_GRAPH_TAG_RSC_OP);
		if(safe_str_eq(this_rsc, event_rsc)) {
			match = action;
		} else {
			crm_debug("Action %d : bad rsc (%s) != (%s)",
				 action->id, this_rsc, event_rsc);
		}
		
	} else {
		crm_debug("no match");
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
		case LRM_OP_PENDING:
			/* should never happen */
			CRM_DEV_ASSERT(op_status_i != LRM_OP_PENDING);
			break;
		case LRM_OP_DONE:
			break;
		case LRM_OP_ERROR:
		case LRM_OP_TIMEOUT:
		case LRM_OP_NOTSUPPORTED:
			crm_warn("Action %s for \"%s\" on %s failed: %s",
				event_action, event_rsc, event_node,
				op_status2text(op_status_i));
			if(FALSE == crm_is_true(allow_fail)) {
				send_complete(
					"Action failed", event, te_failed);
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
				      event, te_failed);
			return -2;
	}
	
	crm_debug("Action %d confirmed", match->id);
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
					action->xml, XML_TAG_ATTRS, TRUE);
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
				send_complete("Stonith failed",
					      match->xml, te_failed);
				return -2;
			}
			break;
		default:
			crm_err("Unsupported action result: %d", rc);
			send_complete("Unsupport Stonith result",
				      match->xml, te_failed);
			return -2;
	}
	
	crm_devel("Action %d was successful, looking for next action",
		match->id);

	match->complete = TRUE;
	return match->id;
}

gboolean
process_graph_event(crm_data_t *event, const char *event_node)
{
	int action_id          = -1;
	int op_status_i        = 0;
	const char *op_status  = NULL;
	const char *task  = NULL;

	if(event != NULL) {
		op_status  = crm_element_value(event, XML_LRM_ATTR_OPSTATUS);
		task  = crm_element_value(event, XML_LRM_ATTR_LASTOP);
	}

	next_transition_timeout = transition_timeout;
	
	if(op_status != NULL) {
		op_status_i = atoi(op_status);
	}
	
	if(op_status_i == -1) {
		/* just information that the action was sent */
		crm_debug("Ignoring TE initiated updates");
		return TRUE;
	}

	slist_iter(
		synapse, synapse_t, graph, lpc,

		/* lookup event */
		slist_iter(
			action, action_t, synapse->actions, lpc2,

			action_id = match_graph_event(action, event,event_node);
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
		send_complete("Event not matched", event, te_update);
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
			send_complete("complete", NULL, te_done);
		}
		
	} else {
		/* restart the transition timer again */
		crm_devel("Transition not yet complete");
		transition_timer->timeout = next_transition_timeout;
		start_te_timer(transition_timer);
	}
}

#ifdef TESTING
#   define te_log_action(log_level, fmt...) { \
		do_crm_log(log_level, __FILE__, __FUNCTION__, fmt);	\
		fprintf(stderr, fmt);				\
	}
#else
#   define te_log_action(log_level, fmt...) do_crm_log(log_level, __FILE__, __FUNCTION__, fmt)
#endif

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
		  && safe_str_eq(task, XML_CIB_ATTR_STONITH)){
		
		crm_data_t *action_args = find_xml_node(
			action->xml, XML_TAG_ATTRS, TRUE);
		const char *uuid = NULL;
		const char *target = NULL;
		const char *name = NULL;

		xml_child_iter(
			action_args, nvpair, XML_CIB_TAG_NVPAIR,

			name = crm_element_value(nvpair, XML_NVPAIR_ATTR_NAME);
			if(safe_str_eq(name, XML_LRM_ATTR_TARGET)) {
				target = crm_element_value(
					nvpair, XML_NVPAIR_ATTR_VALUE);
			} else if(safe_str_eq(name, XML_LRM_ATTR_TARGET_UUID)) {
				uuid = crm_element_value(
					nvpair, XML_NVPAIR_ATTR_VALUE);
			} 
			);
		CRM_DEV_ASSERT(target != NULL);
		CRM_DEV_ASSERT(uuid != NULL);

		te_log_action(LOG_INFO, "Executing fencing operation (%s) on %s", id, target);
#ifdef TESTING
		ret = TRUE;
		action->complete = TRUE;
#else
		stonith_ops_t * st_op = NULL;
		crm_malloc0(st_op, sizeof(stonith_ops_t));
		st_op->optype = RESET;
		st_op->timeout = crm_atoi(timeout, "100"); /* ten seconds */
		st_op->node_name = crm_strdup(target);
		st_op->node_uuid = crm_strdup(uuid);

		if(stonithd_input_IPC_channel() == NULL) {
			crm_err("Cannot fence %s - stonith not available",
				target);
			
		} else if (ST_OK == stonithd_node_fence( st_op )) {
			ret = TRUE;
		}
#endif
		
	} else if(on_node == NULL || strlen(on_node) == 0) {
		/* error */
		te_log_action(LOG_ERR,
			      "Failed on corrupted command: %s (id=%s) %s on %s\n",
			      crm_element_name(action->xml), crm_str(id),
			      crm_str(task), crm_str(on_node));
			
	} else if(action->type == action_type_crm){
		te_log_action(LOG_INFO, "Executing crm-event (%s): %s on %s",
			      id, task, on_node);

		action->complete = TRUE;
		msg_task = task;
		send_command = TRUE;

	} else if(action->type == action_type_rsc){
		cib_action_update(action, LRM_OP_PENDING);
		ret = TRUE;
			
	} else {
		te_log_action(LOG_ERR,
			      "Failed on unsupported command type: "
			      "%s, %s (id=%s) on %s",
			      crm_element_name(action->xml), task, id, on_node);
	}

	if(send_command) {
		HA_Message *cmd = NULL;
		char *counter = crm_itoa(transition_counter);

		cmd = create_request(msg_task, NULL, on_node, CRM_SYSTEM_CRMD,
				     CRM_SYSTEM_TENGINE, NULL);

		ha_msg_add(cmd, "transition_id", crm_str(counter));
#ifndef TESTING
		ret = send_ipc_message(crm_ch, cmd);
#else
		ret = TRUE;
		crm_log_message(LOG_INFO, cmd);
#endif
		crm_free(counter);

		if(ret && action->timeout > 0) {
			crm_devel("Setting timer for action %d",action->id);
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

	enum cib_errors rc = cib_ok;
	const char *task   = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	const char *rsc_id = crm_element_value(action->xml, XML_LRM_ATTR_RSCID);
	const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
	const char *target_uuid =
		crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

	int call_options = cib_inhibit_notify|cib_quorum_override;

	if(status == LRM_OP_TIMEOUT) {
		if(crm_element_value(action->xml, XML_LRM_ATTR_RSCID) != NULL) {
			crm_warn("%s: %s %s on %s timed out",
				 crm_element_name(action->xml), task, rsc_id, target);
		} else {
			crm_warn("%s: %s on %s timed out",
				 crm_element_name(action->xml), task, target);
		}
#ifdef TESTING
	/* turn the "pending" notification into a "op completed" notification
	 *  when testing... exercises more code this way.
	 */
	} else if(status == LRM_OP_PENDING) {
		status = LRM_OP_DONE;
#endif
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

	set_xml_property_copy(state, XML_ATTR_UUID,  target_uuid);
	set_xml_property_copy(state, XML_ATTR_UNAME, target);
	
	rsc = create_xml_node(state, XML_CIB_TAG_LRM);
	rsc = create_xml_node(rsc,   XML_LRM_TAG_RESOURCES);
	rsc = create_xml_node(rsc,   XML_LRM_TAG_RESOURCE);

	xml_op = create_xml_node(rsc,XML_LRM_TAG_RSC_OP);
	
	set_xml_property_copy(rsc,    XML_ATTR_ID, rsc_id);
	set_xml_property_copy(xml_op, XML_ATTR_ID, task);
	
	if(action->interval > 0) {
		char *op_id = generate_op_key(rsc_id, task, action->interval);
		set_xml_property_copy(xml_op, XML_ATTR_ID, op_id);
		crm_free(op_id);
	}
	
	set_xml_property_copy(xml_op, XML_LRM_ATTR_TASK, task);
	set_xml_property_copy(rsc, XML_LRM_ATTR_RSCSTATE,
			      get_rsc_state(task, status));
	
	set_xml_property_copy(rsc, XML_LRM_ATTR_OPSTATUS, code);
	set_xml_property_copy(rsc, XML_LRM_ATTR_RC, code);
	set_xml_property_copy(rsc, XML_LRM_ATTR_LASTOP, task);
	
	set_xml_property_copy(xml_op, XML_LRM_ATTR_OPSTATUS, code);
	set_xml_property_copy(xml_op, XML_LRM_ATTR_RC, code);
	set_xml_property_copy(xml_op, "origin", __FUNCTION__);
	
	set_node_tstamp(xml_op);
	
	crm_free(code);

	fragment = create_cib_fragment(state, NULL);
	
	crm_devel("Updating CIB with \"%s\" (%s): %s %s on %s",
		  status<0?"new action":XML_ATTR_TIMEOUT,
		  crm_element_name(action->xml), crm_str(task), rsc_id, target);
	
#ifndef TESTING
	rc = te_cib_conn->cmds->modify(
		te_cib_conn, XML_CIB_TAG_STATUS, fragment, NULL, call_options);

	crm_debug("Updating CIB with %s action %d: %s %s on %s (call_id=%d)",
		  op_status2text(status), action->id, task, rsc_id, target, rc);

	if(status == LRM_OP_PENDING) {
		crm_debug("Waiting for callback id: %d)", rc);
		add_cib_op_callback(rc, FALSE, action, cib_action_updated);
	}
#else
	fprintf(stderr, "Initiating action %d: %s %s on %s",
		action->id, task, rsc_id, target);
	call_options = 0;
	{
		HA_Message *cmd = ha_msg_new(11);
		ha_msg_add(cmd, F_TYPE,		T_CRM);
		ha_msg_add(cmd, F_CRM_VERSION,	CRM_VERSION);
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
	crm_data_t *rsc_op = NULL;
	const char *task    = NULL;
	const char *rsc_id  = NULL;
	const char *on_node = NULL;

	action_t *action = user_data;
	char *counter = crm_itoa(transition_counter);

	CRM_DEV_ASSERT(action != NULL);      if(crm_assert_failed) { return; }
	CRM_DEV_ASSERT(action->xml != NULL); if(crm_assert_failed) { return; }

	rsc_op  = action->xml;
	task    = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
	rsc_id  = crm_element_value(rsc_op, XML_LRM_ATTR_RSCID);
	on_node = crm_element_value(rsc_op, XML_LRM_ATTR_TARGET);

	if(rc < 0) {
		crm_err("Update for action %d: %s %s on %s FAILED",
			action->id, task, rsc_id, on_node);
		send_complete(cib_error2string(rc), output, te_failed);
		return;
	}
	
	crm_info("Initiating action %d: %s %s on %s",
		 action->id, task, rsc_id, on_node);
	
	if(rsc_op != NULL) {
		crm_xml_debug(rsc_op, "Performing");
	}
	cmd = create_request(
		task, rsc_op, on_node, CRM_SYSTEM_LRMD,CRM_SYSTEM_TENGINE,NULL);
	
	ha_msg_add(cmd, "transition_id", counter);
	crm_free(counter);

#ifndef TESTING
	send_ipc_message(crm_ch, cmd);
#else
	crm_log_message(LOG_INFO, cmd);
#endif
	
	if(action->timeout > 0) {
		crm_devel("Setting timer for action %d",action->id);
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
	
	crm_debug("All inputs for synapse %d satisfied... invoking actions",
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
				crm_element_name(action->xml),
				action->id, synapse->id);

			send_complete(
				"Action init failed", action->xml, te_failed);
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
		
		if(action->complete == FALSE) {
			complete = FALSE;
			synapse->confirmed = FALSE;
			crm_devel("Found an incomplete action"
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
			gboolean confirmed = confirm_synapse(synapse,action_id);
			graph_complete = graph_complete && confirmed;
		}

		crm_devel("%d is %s", synapse->id,
			  synapse->confirmed?"confirmed":synapse->complete?"complete":"pending");
		
		);
}
	
