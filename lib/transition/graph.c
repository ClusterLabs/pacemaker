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
	CRM_CHECK(synapse->executed == FALSE, return FALSE);
	CRM_CHECK(synapse->confirmed == FALSE, return FALSE);

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
		crm_debug_2("Updated synapse %d", synapse->id);
	}
	return updates;
}
static gboolean
update_synapse_confirmed(synapse_t *synapse, int action_id) 
{
	gboolean updates = FALSE;
	gboolean is_confirmed = TRUE;
	
	CRM_CHECK(synapse->executed, return FALSE);
	CRM_CHECK(synapse->confirmed == FALSE, return TRUE);

	is_confirmed = TRUE;
	slist_iter(
		action, crm_action_t, synapse->actions, lpc,
		
		crm_debug_3("Processing action %d", action->id);
		
		if(action->id == action_id) {
			crm_debug_2("Confirmed: Action %d of Synapse %d",
				 action_id, synapse->id);
			action->confirmed = TRUE;
			updates = TRUE;

		} else if(action->confirmed == FALSE) {
			is_confirmed = FALSE;
			crm_debug_3("Synapse %d still not confirmed after action %d",
				    synapse->id, action_id);
		}
		
		);

	if(is_confirmed && synapse->confirmed == FALSE) {
		crm_debug_2("Confirmed: Synapse %d", synapse->id);
		synapse->confirmed = TRUE;
		updates = TRUE;
	}
	
	if(updates) {
		crm_debug_3("Updated synapse %d", synapse->id);
	}
	return updates;
}

gboolean
update_graph(crm_graph_t *graph, crm_action_t *action) 
{
	gboolean rc = FALSE;
	gboolean updates = FALSE;
	slist_iter(
		synapse, synapse_t, graph->synapses, lpc,
		if (synapse->confirmed) {
			crm_debug_2("Synapse complete");
			
		} else if (synapse->executed) {
			crm_debug_2("Synapse executed");
			rc = update_synapse_confirmed(synapse, action->id);

		} else if(action->failed == FALSE || synapse->priority == INFINITY) {
			rc = update_synapse_ready(synapse, action->id);
		}
		updates = updates || rc;
		);
	
	if(updates) {
		crm_debug_2("Updated graph with completed action %d",
			    action->id);
	}
	return updates;
}


static gboolean
should_fire_synapse(synapse_t *synapse)
{
	CRM_CHECK(synapse->executed == FALSE, return FALSE);
	CRM_CHECK(synapse->confirmed == FALSE, return FALSE);
	
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

	CRM_CHECK(action->executed == FALSE, return FALSE);

	id = ID(action->xml);
	CRM_CHECK(id != NULL, return FALSE);

	if(tmp_time > graph->transition_timeout) {
		crm_debug("Action %d: Increasing IDLE timer to %d",
			  action->id, tmp_time);
		graph->transition_timeout = tmp_time;
	}
	
	action->executed = TRUE;
	if(action->type == action_type_pseudo){
		crm_debug_2("Executing pseudo-event: %d", action->id);
		return graph_fns->pseudo(graph, action);

	} else if(action->type == action_type_rsc) {
		crm_debug_2("Executing rsc-event: %d", action->id);
		return graph_fns->rsc(graph, action);

	} else if(action->type == action_type_crm) {
		const char *task = NULL;
		task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
		CRM_CHECK(task != NULL, return FALSE);
		
		if(safe_str_eq(task, CRM_OP_FENCE)) {
			crm_debug_2("Executing STONITH-event: %d",
				      action->id);
			return graph_fns->stonith(graph, action);
		}
		
		crm_debug_2("Executing crm-event: %d", action->id);
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
	CRM_CHECK(synapse != NULL, return FALSE);
	CRM_CHECK(synapse->ready, return FALSE);
	CRM_CHECK(synapse->confirmed == FALSE, return TRUE);
	
	crm_debug_2("Synapse %d fired", synapse->id);
	synapse->executed = TRUE;
	slist_iter(
		action, crm_action_t, synapse->actions, lpc,

		/* allow some leeway */
		gboolean passed = FALSE;

		/* Invoke the action and start the timer */
		passed = initiate_action(graph, action);
		if(passed == FALSE) {
			crm_err("Failed initiating <%s id=%d> in synapse %d",
				crm_element_name(action->xml),
				action->id, synapse->id);
			synapse->confirmed = TRUE;
			action->confirmed = TRUE;
			action->failed = TRUE;
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

	const char *status = "In-progress";
	
	if(graph_fns == NULL) {
		set_default_graph_functions();
	}
	if(graph == NULL) {
		return transition_complete;
	}

	crm_debug_2("Entering graph %d callback", graph->id);

	slist_iter(
		synapse, synapse_t, graph->synapses, lpc,
		if (synapse->confirmed) {
			crm_debug_3("Synapse %d complete", synapse->id);
			num_complete++;
			
		} else if (synapse->executed) {
			int pending_log = LOG_DEBUG_2;
			if(synapse->priority > graph->abort_priority) {
				pending_log = LOG_DEBUG_3;
			} 
			do_crm_log(pending_log,
				      "Synapse %d: confirmation pending",
				      synapse->id);

			/* Is this running approximation good enough for batch_limit? */
			num_pending++;
			
		} else if(synapse->priority < graph->abort_priority) {
			crm_debug_2("Skipping synapse %d: aborting",
				    synapse->id);
			num_skipped++;
			
		} else {
			if(should_fire_synapse(synapse)) {
				crm_debug_2("Synapse %d fired", synapse->id);
				num_fired++;
				CRM_CHECK(fire_synapse(graph, synapse),
					  stat_log_level = LOG_ERR;
					  graph->abort_priority = INFINITY;
					  num_incomplete++;
					  num_fired--);

				if (synapse->confirmed == FALSE) {
				    num_pending++;
				}
				
			} else {
				crm_debug_2("Synapse %d cannot fire",
					    synapse->id);
				num_incomplete++;
			}
		}
		
		if(graph->batch_limit > 0 && num_pending > graph->batch_limit) {
		    crm_debug("Throttling output: batch limit (%d) reached",
			      graph->batch_limit);
		    break;
		}
		);

	if(num_pending == 0 && num_fired == 0) {
		graph->complete = TRUE;
		stat_log_level = LOG_NOTICE;
		pass_result = transition_complete;
		status = "Complete";

		if(num_incomplete != 0 && graph->abort_priority <= 0) {
			stat_log_level = LOG_WARNING;
			pass_result = transition_terminated;
			status = "Terminated";

		} else if(num_skipped != 0) {
			status = "Stopped";
		}

	} else if(num_fired == 0) {
		pass_result = transition_pending;
	}
	
	
	do_crm_log(stat_log_level+1,
		   "====================================================");
	do_crm_log(stat_log_level,
		   "Transition %d (Complete=%d, Pending=%d,"
		   " Fired=%d, Skipped=%d, Incomplete=%d, Source=%s): %s",
		   graph->id, num_complete, num_pending, num_fired,
		   num_skipped, num_incomplete, graph->source, status);
	
	return pass_result;
}
