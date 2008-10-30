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
#include <crmd_fsa.h>
#include <crmd_messages.h>

GCHSource *stonith_src = NULL;
GTRIGSource *stonith_reconnect = NULL;

static void
tengine_stonith_connection_destroy(gpointer user_data)
{
    if(stonith_src == NULL) {
	crm_info("Fencing daemon disconnected");

    } else {
	crm_crit("Fencing daemon connection failed");	
	G_main_set_trigger(stonith_reconnect);
    }

    stonith_op_active = 0;
    if(transition_graph) {
	transition_graph->transition_timeout = active_timeout;
    
	crm_info("Restoring transition timeout: %d",
		 transition_graph->transition_timeout);
    }
    
    /* cbchan will be garbage at this point, arrange for it to be reset */
    set_stonithd_input_IPC_channel_NULL(); 
    stonith_src = NULL;
    return;
}

static gboolean
tengine_stonith_dispatch(IPC_Channel *sender, void *user_data)
{
    while(stonithd_op_result_ready()) {
	if (sender->ch_status != IPC_CONNECT) {
	    /* The message which was pending for us is that
	     * the IPC status is now IPC_DISCONNECT */
	    break;
	}
	
	if(ST_FAIL == stonithd_receive_ops_result(FALSE)) {
	    crm_err("stonithd_receive_ops_result() failed");
	}
    }
    
    if (sender->ch_status != IPC_CONNECT) {
	tengine_stonith_connection_destroy(NULL);
	return FALSE;
    }
    return TRUE;
}

gboolean
te_connect_stonith(gpointer user_data)
{
	int lpc = 0;
	int rc = ST_OK;
	IPC_Channel *fence_ch = NULL;
	if(stonith_src != NULL) {
	    crm_debug("Still connected");
	    return TRUE;
	}
	
	for(lpc = 0; lpc < 30; lpc++) {
	    crm_info("Attempting connection to fencing daemon...");
	    
	    sleep(1);
	    rc = stonithd_signon("tengine");
	    if(rc == ST_OK) {
		break;
	    }
	    
	    if(user_data != NULL) {
		crm_err("Sign-in failed: triggered a retry");
		G_main_set_trigger(stonith_reconnect);
		return TRUE;
	    }
	    
	    crm_err("Sign-in failed: pausing and trying again in 2s...");
	    sleep(1);
	}
	
	CRM_ASSERT(rc == ST_OK); /* If not, we failed 30 times... just get out */
	CRM_ASSERT(stonithd_set_stonith_ops_callback(
		       tengine_stonith_callback) == ST_OK);
	
	crm_debug_2("Grabbing IPC channel");
	fence_ch = stonithd_input_IPC_channel();
	CRM_ASSERT(fence_ch != NULL);
	
	crm_debug_2("Attaching to mainloop");
	stonith_src = G_main_add_IPC_Channel(
	    G_PRIORITY_LOW, fence_ch, FALSE, tengine_stonith_dispatch, NULL,
	    tengine_stonith_connection_destroy);
	
	CRM_ASSERT(stonith_src != NULL);
	crm_info("Connected");
	return TRUE;
}

gboolean
start_global_timer(crm_action_timer_t *timer, int timeout)
{
	CRM_ASSERT(timer != NULL);
	CRM_CHECK(timer->source_id == 0, return FALSE);

	if(stonith_op_active == 0) {
		crm_debug("Skipping transition timer while stonith op is active");

	} else if(timeout <= 0) {
		crm_err("Tried to start timer with period: %d", timeout);

	} else if(timer->source_id == 0) {
		crm_debug("Starting abort timer: %dms", timeout);
		timer->timeout = timeout;
		timer->source_id = Gmain_timeout_add(
			timeout, global_timer_callback, (void*)timer);
		CRM_ASSERT(timer->source_id != 0);
		return TRUE;

	} else {
		crm_err("Timer is already active with period: %d", timer->timeout);
	}
	
	return FALSE;		
}

gboolean
stop_te_timer(crm_action_timer_t *timer)
{
	const char *timer_desc = "action timer";
	
	if(timer == NULL) {
		return FALSE;
	}
	if(timer->reason == timeout_abort) {
		timer_desc = "global timer";
		crm_debug_2("Stopping %s", timer_desc);
	}
	
	if(timer->source_id != 0) {
		crm_debug_2("Stopping %s", timer_desc);
		Gmain_timeout_remove(timer->source_id);
		timer->source_id = 0;

	} else {
		crm_debug_2("%s was already stopped", timer_desc);
		return FALSE;
	}

	return TRUE;
}

gboolean
te_graph_trigger(gpointer user_data) 
{
    int timeout = 0;
    enum transition_status graph_rc = -1;

    crm_debug_2("Invoking graph %d in state %s",
	      transition_graph->id, fsa_state2string(fsa_state));

    switch(fsa_state) {
	case S_STARTING:
	case S_PENDING:
	case S_NOT_DC:
	case S_HALT:
	case S_ILLEGAL:
	case S_STOPPING:
	case S_TERMINATE:
	    return TRUE;
	    break;
	default:
	    break;
    }
    
    if(transition_graph->complete == FALSE) {
	graph_rc = run_graph(transition_graph);
	timeout = transition_graph->transition_timeout;
	print_graph(LOG_DEBUG_3, transition_graph);

	if(graph_rc == transition_active) {
		crm_debug_3("Transition not yet complete");
		stop_te_timer(transition_timer);
		start_global_timer(transition_timer, timeout);
		return TRUE;		

	} else if(graph_rc == transition_pending) {
		crm_debug_3("Transition not yet complete - no actions fired");
		return TRUE;		
	}
	
	if(graph_rc != transition_complete) {
		crm_err("Transition failed: %s", transition_status(graph_rc));
		print_graph(LOG_WARNING, transition_graph);
	}
    }
    
    crm_info("Transition %d is now complete", transition_graph->id);
    transition_graph->complete = TRUE;
    notify_crmd(transition_graph);
    
    return TRUE;	
}

void
trigger_graph_processing(const char *fn, int line) 
{
	G_main_set_trigger(transition_trigger);
	crm_debug_2("%s:%d - Triggered graph processing", fn, line);
}

void
abort_transition_graph(
	int abort_priority, enum transition_action abort_action,
	const char *abort_text, xmlNode *reason, const char *fn, int line) 
{
	int log_level = LOG_INFO;
	const char *magic = NULL;
	CRM_CHECK(transition_graph != NULL, return);
	
	if(reason) {
	    magic = crm_element_value(reason, XML_ATTR_TRANSITION_MAGIC);
	    do_crm_log(log_level,
		       "%s:%d - Triggered transition abort (complete=%d, tag=%s, id=%s, magic=%s) : %s",
		       fn, line, transition_graph->complete, TYPE(reason), ID(reason), magic?magic:"NA", abort_text);
	} else {
	    do_crm_log(log_level,
		       "%s:%d - Triggered transition abort (complete=%d) : %s",
		       fn, line, transition_graph->complete, abort_text);
	}
	
	switch(fsa_state) {
	    case S_STARTING:
	    case S_PENDING:
	    case S_NOT_DC:
	    case S_HALT:
	    case S_ILLEGAL:
	    case S_STOPPING:
	    case S_TERMINATE:
		do_crm_log(log_level,
			   "Abort suppressed: state=%s (complete=%d)",
			   fsa_state2string(fsa_state), transition_graph->complete);
		return;
	    default:
		break;
	}

	if(magic == NULL) {
	    crm_log_xml(log_level+1, "Cause", reason);
	}
	
	if(transition_graph->complete) {
	    register_fsa_input(C_FSA_INTERNAL, I_PE_CALC, NULL);
	    return;
	}

	update_abort_priority(
		transition_graph, abort_priority, abort_action, abort_text);	
	
	G_main_set_trigger(transition_trigger);
}

