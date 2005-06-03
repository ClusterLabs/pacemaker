/* $Id: utils.c,v 1.32 2005/06/03 14:05:41 andrew Exp $ */
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

extern cib_t *te_cib_conn;
extern int global_transition_timer;

void print_input(const char *prefix, action_t *input, gboolean to_file);
void print_action(const char *prefix, action_t *action, gboolean to_file);
gboolean timer_callback(gpointer data);

void
send_complete(const char *text, crm_data_t *msg,
	      te_reason_t reason, te_fsa_input_t input)
{	
	HA_Message *cmd = NULL;
	const char *op = CRM_OP_TEABORT;
	static te_reason_t last_reason = te_done;
	static crm_data_t *last_msg = NULL;
	static const char *last_text = NULL;

	te_fsa_state_t last_state = te_fsa_state;
	te_fsa_state = te_state_matrix[input][te_fsa_state];

	if(te_fsa_state == s_abort_pending && num_cib_op_callbacks() == 0) {
		te_fsa_state = te_state_matrix[i_cib_complete][te_fsa_state];
	}
	
	if(te_fsa_state != s_idle && input != i_cib_complete) {
		if(last_msg) {
			free_xml(last_msg);
		}
		last_msg = NULL;
		if(msg != NULL) {
			last_msg = copy_xml_node_recursive(msg);
		}
		last_text   = text;
		last_reason = reason;
		crm_info("CIB updates are pending.  Delay until they complete.");
		return;

	} else if(te_fsa_state != s_idle) {
		crm_err("Delaying \"%s\" notification until we are idle.",text);
		return;
		
	} else if(input == i_cib_complete) {
		msg    = last_msg;
		text   = last_text;
		reason = last_reason;
	}
	
	CRM_DEV_ASSERT(num_cib_op_callbacks() == 0);
	
	switch(reason) {
		case te_update:
			te_log_action(LOG_DEBUG,
				      "Transition status: %s by CIB update: %s",
				      last_state!=s_idle?"Aborted":"Triggered",
				      text);
			if(msg != NULL) {
				if(safe_str_eq(crm_element_name(msg),
					       XML_TAG_CIB)) {
					crm_data_t *status = get_object_root(XML_CIB_TAG_STATUS, msg);
					crm_data_t *generation = create_xml_node(NULL, XML_TAG_CIB);
					crm_debug("Cause:"
						 " full CIB replace/update");
					copy_in_properties(generation, msg);
					crm_log_xml_debug(generation, "[generation]");
					crm_log_xml_debug(status, "[in ]");
					free_xml(generation);
					
				} else {
					crm_log_xml_debug(msg, "Cause");
				}
			}
			print_state(LOG_DEBUG);
			break;
		case te_halt:
			te_log_action(LOG_INFO,"Transition status: Stopped%s%s",
				 text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			op = CRM_OP_TECOMPLETE;
			break;
		case te_abort_confirmed:
			te_log_action(LOG_INFO,
				      "Transition status: Confirmed Stopped%s%s",
				      text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			op = CRM_OP_TEABORTED;
			break;
		case te_abort:
			te_log_action(LOG_INFO,"Transition status: Stopped%s%s",
				      text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			break;
		case te_done:
			te_log_action(LOG_INFO,
				      "Transition status: Complete%s%s",
				      text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			op = CRM_OP_TECOMPLETE;
			break;
		case te_timeout:
			te_log_action(LOG_ERR,
				      "Transition status: Timed out after %dms",
				      transition_timer->timeout);
			print_state(LOG_WARNING);
			op = CRM_OP_TETIMEOUT;
			break;
		case te_failed:
			te_log_action(LOG_ERR, "Transition status: Aborted by failed action: %s", text);
			crm_log_xml_debug(msg, "Cause");
			print_state(LOG_WARNING);
			break;
	}
	
	initialize_graph();

	cmd = create_request(
		op, NULL, NULL, CRM_SYSTEM_DC, CRM_SYSTEM_TENGINE, NULL);

	if(text != NULL) {
		ha_msg_add(cmd, "message", text);
	}

	free_xml(last_msg);
	
#ifdef TESTING
	if(reason == te_done) {
		crm_log_message(LOG_INFO, cmd);
	} else {
		crm_log_message(LOG_ERR, cmd);
	}
	
	g_main_quit(mainloop);
	return;
#else
	send_ipc_message(crm_ch, cmd);
#endif	
#if 0
	if(is_ipc_empty(crm_ch)
	   && is_ipc_empty(te_cib_conn->cmds->channel(te_cib_conn)) ) {
		static gboolean mem_needs_init = TRUE;
		if(mem_needs_init) {
			crm_debug("Reached a stable point:"
				  " reseting memory usage stats to zero");
			crm_zero_mem_stats(NULL);
			mem_needs_init = FALSE;
			
		} else {
			crm_err("Reached a stable point:"
				  " checking memory usage");
			crm_mem_stats(NULL);
		}
	}
#endif	
}

void
print_state(int log_level)
{
	if(graph == NULL && log_level > LOG_DEBUG) {
		do_crm_log(LOG_DEBUG, __FILE__, __FUNCTION__, "###########");
		do_crm_log(LOG_DEBUG, __FILE__, __FUNCTION__,
			   "\tEmpty transition graph");
		do_crm_log(LOG_DEBUG, __FILE__, __FUNCTION__, "###########");
		return;
	}

	do_crm_log(log_level, __FILE__, __FUNCTION__, "###########");

	slist_iter(
		synapse, synapse_t, graph, lpc,

		do_crm_log(log_level, __FILE__, __FUNCTION__, "Synapse %d %s",
			   synapse->id,
			   synapse->confirmed?"was confirmed":synapse->complete?"was executed":"is pending");

		if(synapse->confirmed == FALSE) {
			slist_iter(
				action, action_t, synapse->actions, lpc2,
				print_action("\t", action, log_level);
				);
		}
		if(synapse->complete == FALSE) {
			slist_iter(
				input, action_t, synapse->inputs, lpc2,
				print_input("\t", input, log_level);
				);
		}
		
		);
	
	do_crm_log(log_level, __FILE__, __FUNCTION__, "###########");
}

void
print_input(const char *prefix, action_t *input, int log_level) 
{
	do_crm_log(log_level, __FILE__, __FUNCTION__, "%s[Input %d] %s (%s)",
		   prefix, input->id,
		   input->complete?"Satisfied":"Pending",
		   actiontype2text(input->type));

	if(input->complete == FALSE) {
		crm_log_xml((unsigned)log_level, "\t  Raw input", input->xml);
	}
}


void
print_action(const char *prefix, action_t *action, int log_level) 
{
	do_crm_log(log_level, __FILE__, __FUNCTION__, "%s[Action %d] %s (%s fail)",
		   prefix, action->id, action->complete?"Completed":
					action->invoked?"In-flight":"Pending",
		   action->can_fail?"can":"cannot");
		
	switch(action->type) {
		case action_type_pseudo:
			do_crm_log(log_level, __FILE__, __FUNCTION__,
				   "%s\tPseudo Op: %s", prefix,
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_TASK));
			break;
		case action_type_rsc:
			do_crm_log(log_level, __FILE__, __FUNCTION__,
				   "%s\tResource Op: %s/%s on %s", prefix,
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_RSCID),
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_TASK),
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_TARGET));
			break;
		case action_type_crm:	
			do_crm_log(log_level, __FILE__, __FUNCTION__,
				   "%s\tCRM Op: %s on %s", prefix,
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_TASK),
				   crm_element_value(
					   action->xml, XML_LRM_ATTR_TARGET));
			break;
	}

	if(action->timeout > 0 || action->timer->source_id > 0) {
		do_crm_log(log_level, __FILE__, __FUNCTION__,
			   "%s\ttimeout=%d, timer=%d", prefix,
			   action->timeout, action->timer->source_id);
	}
	
	if(action->complete == FALSE) {
		crm_log_xml(LOG_DEBUG_2, "\tRaw action", action->xml);
	}
}


gboolean
timer_callback(gpointer data)
{
	te_timer_t *timer = NULL;
	
	if(data == NULL) {
		crm_err("Timer popped with no data");
		return FALSE;
	}
	
	timer = (te_timer_t*)data;
	if(timer->source_id > 0) {
		g_source_remove(timer->source_id);
	}
	timer->source_id = -1;

	crm_err("Timer popped in state=%d", te_fsa_state);
	if(te_fsa_state != s_in_transition) {
		crm_debug("Ignoring timeout while not in transition");
		return TRUE;
		
	} else if(timer->reason == timeout_timeout) {
		
		/* global timeout - abort the transition */
		crm_warn("Transition timeout reached..."
			 " marking transition complete.");
		
		crm_warn("Some actions may not have been executed.");
			
		send_complete(XML_ATTR_TIMEOUT, NULL, te_timeout, i_cancel);
		
		return TRUE;
		
	} else if(timer->action == NULL) {
		crm_err("Action not present!");
		return FALSE;
		
	} else if(timer->reason == timeout_action_warn) {
		crm_warn("Action %d is taking more than 2x its timeout (%d)",
			timer->action->id, timer->action->timeout);
		crm_log_xml_debug(timer->action->xml, "Slow action");
		return TRUE;
		
	} else {
		/* fail the action
		 * - which may or may not abort the transition
		 */

		/* TODO: send a cancel notice to the LRM */
		/* TODO: use the ack from above to update the CIB */
		return cib_action_update(timer->action, LRM_OP_TIMEOUT);
	}
}

gboolean
start_te_timer(te_timer_t *timer)
{
	if(((int)timer->source_id) < 0 && timer->timeout > 0) {
		timer->source_id = Gmain_timeout_add(
			timer->timeout, timer_callback, (void*)timer);
		return TRUE;

	} else if(timer->timeout < 0) {
		crm_err("Tried to start timer with -ve period");
		
	} else {
		crm_debug_3("#!!#!!# Timer already running (%d)",
			  timer->source_id);
	}
	return FALSE;		
}


gboolean
stop_te_timer(te_timer_t *timer)
{
	if(timer == NULL) {
		return FALSE;
	}
	
	if(((int)timer->source_id) > 0) {
		g_source_remove(timer->source_id);
		timer->source_id = -2;

	} else {
		return FALSE;
	}

	return TRUE;
}

const char *
actiontype2text(action_type_e type)
{
	switch(type) {
		case action_type_pseudo:
			return "pseduo";
		case action_type_rsc:
			return "rsc";
		case action_type_crm:
			return "crm";
			
	}
	return "<unknown>";
}

const char *
get_rsc_state(const char *task, op_status_t status) 
{
	if(safe_str_eq(CRMD_ACTION_START, task)) {
		if(status == LRM_OP_PENDING) {
			return CRMD_ACTION_START_PENDING;
		} else if(status == LRM_OP_DONE) {
			return CRMD_ACTION_STARTED;
		} else {
			return CRMD_ACTION_START_FAIL;
		}
		
	} else if(safe_str_eq(CRMD_ACTION_STOP, task)) {
		if(status == LRM_OP_PENDING) {
			return CRMD_ACTION_STOP_PENDING;
		} else if(status == LRM_OP_DONE) {
			return CRMD_ACTION_STOPPED;
		} else {
			return CRMD_ACTION_STOP_FAIL;
		}
		
	} else {
		if(safe_str_eq(CRMD_ACTION_MON, task)) {
			if(status == LRM_OP_PENDING) {
				return CRMD_ACTION_MON_PENDING;
			} else if(status == LRM_OP_DONE) {
				return CRMD_ACTION_MON_OK;
			} else {
				return CRMD_ACTION_MON_FAIL;
			}
		} else {
			const char *rsc_state = NULL;
			if(status == LRM_OP_PENDING) {
				rsc_state = CRMD_ACTION_GENERIC_PENDING;
			} else if(status == LRM_OP_DONE) {
				rsc_state = CRMD_ACTION_GENERIC_OK;
			} else {
				rsc_state = CRMD_ACTION_GENERIC_FAIL;
			}
			crm_warn("Using status \"%s\" for op \"%s\"..."
				 " this is still in the experimental stage.",
				 rsc_state, task);
			return rsc_state;
		}
	}
}
