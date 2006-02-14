/* $Id: graph.c,v 1.1 2006/02/14 11:32:12 andrew Exp $ */
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


crm_graph_functions_t *graph_fns = NULL;


static gboolean
update_synapse_ready(synapse_t *synapse, int action_id) 
{
	gboolean updates = FALSE;
	CRM_DEV_ASSERT(synapse->executed == FALSE);
	CRM_DEV_ASSERT(synapse->confirmed == FALSE);

	synapse->ready = TRUE;
	slist_iter(
		prereq, crm_action_t, synapse->inputs, lpc,
		
		crm_debug_3("Processing input %d", prereq->id);
		
		if(prereq->id == action_id) {
			crm_debug_2("Marking input %d of synapse %d confirmed",
				    action_id, synapse->id);
			prereq->confirmed = TRUE;
			updates = TRUE;

		} else if(prereq->confirmed == FALSE) {
			synapse->ready = FALSE;
		}
		
		);

	if(updates) {
		crm_debug("Updated synapse %d", synapse->id);
	}
	return updates;
}
static gboolean
update_synapse_confirmed(synapse_t *synapse, int action_id) 
{
	gboolean updates = FALSE;
	CRM_DEV_ASSERT(synapse->executed);
	CRM_DEV_ASSERT(synapse->confirmed == FALSE);

	synapse->confirmed = TRUE;
	slist_iter(
		action, crm_action_t, synapse->actions, lpc,
		
		crm_debug_3("Processing action %d", action->id);
		
		if(action->id == action_id) {
			crm_debug_2("Marking action %d of synapse %d confirmed",
				    action_id, synapse->id);
			action->confirmed = TRUE;
			updates = TRUE;

		} else if(action->confirmed == FALSE) {
			synapse->confirmed = FALSE;
		}
		
		);

	if(updates) {
		crm_debug("Updated synapse %d", synapse->id);
	}
	return updates;
}

gboolean
update_graph(crm_graph_t *graph, int action_id) 
{
	gboolean rc = FALSE;
	gboolean updates = FALSE;
	slist_iter(
		synapse, synapse_t, graph->synapses, lpc,
		if (synapse->confirmed) {
			crm_debug_2("Synapse complete");
			
		} else if (synapse->executed) {
			crm_debug_2("Synapse executed");
			rc = update_synapse_confirmed(synapse, action_id);

		} else {
			rc = update_synapse_ready(synapse, action_id);
		}
		updates = updates || rc;
		);
	
	if(updates) {
		crm_debug("Updated graph with completed action %d", action_id);
	}
	return updates;
}


static gboolean
should_fire_synapse(synapse_t *synapse)
{
	CRM_DEV_ASSERT(synapse->executed == FALSE);
	CRM_DEV_ASSERT(synapse->confirmed == FALSE);
	
	crm_debug_3("Checking pre-reqs for %d", synapse->id);
	/* lookup prereqs */
	synapse->ready = TRUE;
	slist_iter(
		prereq, crm_action_t, synapse->inputs, lpc,
		
		crm_debug_3("Processing input %d", prereq->id);
		if(prereq->confirmed == FALSE) {
			crm_debug_3("Inputs for synapse %d not satisfied",
				    synapse->id);
			synapse->ready = FALSE;
			break;
		}
		);

	return synapse->ready;
}


static gboolean
initiate_action(crm_graph_t *graph, crm_action_t *action) 
{
	const char *id = NULL;
	int tmp_time = 2 * action->timeout;

	CRM_DEV_ASSERT(action->executed == FALSE);
	if(crm_assert_failed) {
		return FALSE;
	}

	id = ID(action->xml);
	CRM_DEV_ASSERT(id != NULL);
	if(crm_assert_failed) {
		return FALSE;
	}

	if(tmp_time > graph->transition_timeout) {
		crm_debug("Action %d: Increasing IDLE timer to %d",
			  action->id, tmp_time);
		graph->transition_timeout = tmp_time;
	}
	
	action->executed = TRUE;
	if(action->type == action_type_pseudo){
		te_log_action(LOG_INFO,
			      "Executing pseudo-event: %d", action->id);
		return graph_fns->pseudo(graph, action);

	} else if(action->type == action_type_rsc) {
		te_log_action(LOG_INFO, "Executing rsc-event: %d", action->id);
		return graph_fns->rsc(graph, action);

	} else if(action->type == action_type_crm) {
		const char *task = NULL;
		task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
		CRM_DEV_ASSERT(task != NULL);
		
		if(safe_str_eq(task, CRM_OP_FENCE)) {
			te_log_action(LOG_INFO, "Executing STONITH-event: %d",
				      action->id);
			return graph_fns->stonith(graph, action);
		}
		
		te_log_action(LOG_INFO, "Executing crm-event: %d", action->id);
		return graph_fns->crmd(graph, action);
	}
	
	te_log_action(LOG_ERR,
		      "Failed on unsupported command type: %s (id=%s)",
		      crm_element_name(action->xml), id);
	return FALSE;
}

static gboolean
fire_synapse(crm_graph_t *graph, synapse_t *synapse) 
{
	CRM_DEV_ASSERT(synapse != NULL);
	CRM_DEV_ASSERT(synapse->ready);
	CRM_DEV_ASSERT(synapse->confirmed == FALSE);
	
	crm_debug("Synapse %d fired", synapse->id);
	synapse->executed = TRUE;
	slist_iter(
		action, crm_action_t, synapse->actions, lpc,

		/* allow some leeway */
		gboolean passed = FALSE;

		/* Invoke the action and start the timer */
		passed = initiate_action(graph, action);
		CRM_DEV_ASSERT(passed == TRUE);
		if(passed == FALSE) {
			crm_err("Failed initiating <%s id=%d> in synapse %d",
				crm_element_name(action->xml),
				action->id, synapse->id);
			return FALSE;
		} 
		);
	
	return TRUE;
}

int
run_graph(crm_graph_t *graph) 
{	
	int num_fired = 0;
	int num_pending = 0;
	int num_skipped = 0;
	int num_complete = 0;
	int num_incomplete = 0;

	int stat_log_level = LOG_DEBUG;
	int pass_result = transition_active;

	crm_debug("Entering graph callback");
	if(graph_fns == NULL) {
		set_default_graph_functions();
	}
	if(graph == NULL) {
		return transition_complete;
	}
	
	slist_iter(
		synapse, synapse_t, graph->synapses, lpc,
		if (synapse->confirmed) {
			crm_debug_3("Synapse %d complete", synapse->id);
			num_complete++;
			
		} else if (synapse->executed) {
			crm_debug_3("Synapse %d executed", synapse->id);
			num_pending++;
			
		} else if(synapse->priority <= graph->abort_priority) {
			crm_debug("Skipping synapse %d: aborting", synapse->id);
			num_skipped++;
			
		} else {
			crm_debug_2("Synapse %d pending", synapse->id);
			if(should_fire_synapse(synapse)) {
				if(fire_synapse(graph, synapse) == FALSE) {
					return transition_failed;
				}
				num_fired++;

			} else {
				num_incomplete++;
			}
		}
		);

	if(num_pending == 0 && num_fired == 0) {
		stat_log_level = LOG_INFO;
		pass_result = transition_complete;
		if(num_incomplete != 0) {
			stat_log_level = LOG_ERR;
			pass_result = transition_terminated;

		} else if(num_skipped != 0) {
			stat_log_level = LOG_NOTICE;
		}
		crm_log_maybe(stat_log_level,
			      "Transition %d complete", graph->id);

	}
	crm_log_maybe(stat_log_level, "Complete: %d, Pending: %d,"
		      " Fired: %d, Skipped: %d, Incomplete: %d",
		      num_complete, num_pending, num_fired,
		      num_skipped, num_incomplete);
	
	return pass_result;
}
