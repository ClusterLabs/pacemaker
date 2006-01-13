/* $Id: tengine.c,v 1.109 2006/01/13 10:31:14 andrew Exp $ */
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
	
	crm_debug_2("Synapse %d fired", synapse->id);
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
		crm_debug("Synapse %d complete", synapse->id);
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
	
