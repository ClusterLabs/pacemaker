/* $Id: utils.c,v 1.7 2006/04/03 10:42:05 andrew Exp $ */
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

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/transition.h>
/* #include <sys/param.h> */
/* #include <clplumbing/cl_misc.h> */


extern crm_graph_functions_t *graph_fns;

static gboolean
pseudo_action_dummy(crm_graph_t *graph, crm_action_t *action) 
{
	crm_debug("Dummy event handler: action %d executed", action->id);
	action->confirmed = TRUE;
	update_graph(graph, action);
	return TRUE;
}

crm_graph_functions_t default_fns = {
	pseudo_action_dummy,
	pseudo_action_dummy,
	pseudo_action_dummy,
	pseudo_action_dummy
};

void
set_default_graph_functions(void) 
{
	crm_info("Setting default graph functions");
	graph_fns = &default_fns;
}

void
set_graph_functions(crm_graph_functions_t *fns) 
{
	crm_info("Setting custom graph functions");
	graph_fns = fns;

	CRM_ASSERT(graph_fns != NULL);
	CRM_ASSERT(graph_fns->rsc != NULL);
	CRM_ASSERT(graph_fns->crmd != NULL);
	CRM_ASSERT(graph_fns->pseudo != NULL);
	CRM_ASSERT(graph_fns->stonith != NULL);
}

const char *
transition_status(enum transition_status state) 
{
	switch(state) {
		case transition_active:
			return "active";
		case transition_pending:
			return "pending";
		case transition_complete:
			return "complete";
		case transition_stopped:
			return "stopped";
		case transition_terminated:
			return "terminated";
		case transition_action_failed:
			return "failed (action)";
		case transition_failed:
			return "failed";			
	}
	return "unknown";			
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

static void
print_input(const char *prefix, crm_action_t *input, int log_level) 
{
	const char *task_uuid = crm_element_value(
		input->xml, XML_LRM_ATTR_TASK_KEY);
	crm_log_maybe(log_level,
		      "%s[Input %d] %s (id: %s, type: %s, priority=%d)",
		      prefix, input->id,
		      input->confirmed?"Satisfied":"Pending",	
		      task_uuid,
		      actiontype2text(input->type), 
		      input->synapse->priority);

	if(input->confirmed == FALSE) {
		crm_log_xml(log_level+2, "\t\t\tRaw input: ", input->xml);
	}
}


void
print_graph_action(int log_level, const char *prefix, crm_action_t *action) 
{
	crm_log_maybe(log_level, "%s[Action %d] %s%s",
		      prefix, action->id,
		      action->confirmed?"Completed":
		        action->executed?"In-flight":
		        action->sent_update?"Update sent":"Pending",
		      action->can_fail?" (can fail)":"");
		
	switch(action->type) {
		case action_type_pseudo:
			crm_log_maybe(log_level, "%s\tPseudo Op: %s", prefix,
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_TASK_KEY));
			break;
		case action_type_rsc:
			crm_log_maybe(log_level, "%s\tResource Op: %s/%s on %s",
				      prefix,
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_RSCID),
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_TASK),
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_TARGET)
/* 				   crm_element_value( */
/* 					   action->xml, XML_LRM_ATTR_TARGET_UUID) */
				);
			break;
		case action_type_crm:	
			crm_log_maybe(log_level, "%s\tCRM Op: %s on %s (%s)",
				      prefix,
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_TASK),
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_TARGET),
				      crm_element_value(
					      action->xml, XML_LRM_ATTR_TARGET_UUID));
			break;
	}

	if(action->timeout > 0) {
		do_crm_log(log_level, __FILE__, __FUNCTION__,
			   "%s\ttimeout=%d, timer=%d", prefix,
			   action->timeout,
			   action->timer?action->timer->source_id:0);
	}
	
	if(action->confirmed == FALSE) {
		crm_log_xml(log_level+2, "\t\t\tRaw action: ", action->xml);
	}
}

void
print_graph(unsigned int log_level, crm_graph_t *graph)
{
	if(graph == NULL || graph->num_actions == 0) {
		if(log_level > LOG_DEBUG) {
			crm_debug("## Empty transition graph ##");
		}
		return;
	}

	slist_iter(
		synapse, synapse_t, graph->synapses, lpc,

		crm_log_maybe(log_level, "Synapse %d %s (priority: %d)",
			      synapse->id,
			      synapse->confirmed?"was confirmed":
			        synapse->executed?"was executed":
			      "is pending",
			      synapse->priority);
		
		if(synapse->confirmed == FALSE) {
			slist_iter(
				action, crm_action_t, synapse->actions, lpc2,
				print_graph_action(log_level, "\t", action);
				);
		}
		if(synapse->executed == FALSE) {
			slist_iter(
				input, crm_action_t, synapse->inputs, lpc2,
				print_input("\t", input, log_level);
				);
		}
		
		);
}

void
update_abort_priority(
	crm_graph_t *graph, int priority,
	enum transition_action action, const char *abort_reason)
{
	if(graph == NULL) {
		return;
	}
	
	if(graph->abort_priority < priority) {
		graph->abort_priority = priority;
		crm_info("Abort priority upgraded to %d", priority);
		if(graph->abort_reason != NULL) {
			crm_info("'%s'-class abort superceeded",
				 graph->abort_reason);
		}
		graph->abort_reason = abort_reason;
	}

	if(graph->completion_action < action) {
		crm_info("Abort action %d superceeded by %d",
			 graph->completion_action, action);
		graph->completion_action = action;
	}
}

