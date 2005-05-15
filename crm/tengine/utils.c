/* $Id: utils.c,v 1.28 2005/05/15 13:13:40 andrew Exp $ */
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
send_complete(const char *text, crm_data_t *msg, te_reason_t reason)
{	
	HA_Message *cmd = NULL;
	const char *op = CRM_OP_TEABORT;

	/* the transition is over... ignore all future callbacks
	 * resulting from our CIB updates (usually for pending operations)
	 */
	remove_cib_op_callback(-1, TRUE);
	
	if(reason == te_done && in_transition == FALSE) {
		crm_warn("Not in transition, not sending message");
		return;

	} else if(reason == te_timeout && in_transition == FALSE) {
		crm_err("Not in transition, not sending message");
		return;
	}

	switch(reason) {
		case te_update:
			crm_debug("Transition status: %s by CIB update: %s",
				  in_transition?"Aborted":"Triggered", text);
			if(msg != NULL) {
				if(safe_str_eq(crm_element_name(msg),
					       XML_TAG_CIB)) {
					crm_data_t *status = get_object_root(XML_CIB_TAG_STATUS, msg);
					crm_data_t *generation = create_xml_node(NULL, XML_TAG_CIB);
					crm_debug("Cause:"
						 " full CIB replace/update");
					copy_in_properties(generation, msg);
					crm_xml_debug(generation, "[generation]");
					crm_xml_debug(status, "[in ]");
					free_xml(generation);
					
				} else {
					crm_xml_debug(msg, "Cause");
				}
			}
			print_state(LOG_DEBUG);
			break;
		case te_halt:
			crm_info("Transition status: Stopped%s%s",
				 text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			op = CRM_OP_TECOMPLETE;
			break;
		case te_abort:
			crm_info("Transition status: Stopped%s%s",
				 text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			break;
		case te_done:
			crm_info("Transition status: Complete%s%s",
				 text?": ":"", text?text:"");
			print_state(LOG_DEBUG);
			op = CRM_OP_TECOMPLETE;
			break;
		case te_timeout:
			crm_err("Transition status: Timed out after %dms",
				transition_timer->timeout);
			print_state(LOG_WARNING);
			op = CRM_OP_TETIMEOUT;
			break;
		case te_failed:
			crm_err("Transition status: Aborted by failed action: %s",
				 text);
			crm_xml_debug(msg, "Cause");
			print_state(LOG_WARNING);
			break;
	}
	
	in_transition = FALSE;
	initialize_graph();

	cmd = create_request(
		op, NULL, NULL, CRM_SYSTEM_DC, CRM_SYSTEM_TENGINE, NULL);

	if(text != NULL) {
		ha_msg_add(cmd, "message", text);
	}
	
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
		crm_log_xml(LOG_VERBOSE, "\tRaw action", action->xml);
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
	
	if(timer->reason == timeout_fuzz) {
		crm_warn("Transition timeout reached..."
			 " marking transition complete.");
		send_complete("success", NULL, te_done);
		return TRUE;

	} else if(timer->reason == timeout_timeout) {
		
		/* global timeout - abort the transition */
		crm_warn("Transition timeout reached..."
			 " marking transition complete.");
		
		crm_warn("Some actions may not have been executed.");
			
		send_complete(XML_ATTR_TIMEOUT, NULL, te_timeout);
		
		return TRUE;
		
	} else if(timer->action == NULL) {
		crm_err("Action not present!");
		return FALSE;
		
	} else if(timer->reason == timeout_action_warn) {
		crm_warn("Action %d is taking more than 2x its timeout (%d)",
			timer->action->id, timer->action->timeout);
		crm_xml_debug(timer->action->xml, "Slow action");
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
		crm_devel("#!!#!!# Timer already running (%d)",
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
