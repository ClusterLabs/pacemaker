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
#include <crmd_fsa.h>
#include <crmd_messages.h>

GCHSource *stonith_src = NULL;
crm_trigger_t *stonith_reconnect = NULL;

static gboolean
fail_incompletable_stonith(crm_graph_t *graph) 
{
    const char *task = NULL;
    xmlNode *last_action = NULL;

    if(graph == NULL) {
	return FALSE;
    }
    
    slist_iter(
	synapse, synapse_t, graph->synapses, lpc,
	if (synapse->confirmed) {
	    continue;
	}

	slist_iter(
	    action, crm_action_t, synapse->actions, lpc,

	    if(action->type != action_type_crm || action->confirmed) {
		continue;
	    }

	    task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
	    if(task && safe_str_eq(task, CRM_OP_FENCE)) {
		action->failed = TRUE;
		last_action = action->xml;
		update_graph(graph, action);
		crm_notice("Failing action %d (%s): STONITHd terminated",
			   action->id, ID(action->xml));
	    }
	    );
	);

    if(last_action != NULL) {
	crm_warn("STONITHd failure resulted in un-runnable actions");
	abort_transition(INFINITY, tg_restart, "Stonith failure", last_action);
	return TRUE;
    }
	
    return FALSE;
}

static void
tengine_stonith_connection_destroy(stonith_t *st, const char *event, xmlNode *msg)
{
    if(is_set(fsa_input_register, R_ST_REQUIRED)) {
	crm_crit("Fencing daemon connection failed");	
	mainloop_set_trigger(stonith_reconnect);

    } else {
	crm_info("Fencing daemon disconnected");
    }

    /* cbchan will be garbage at this point, arrange for it to be reset */
    stonith_api->state = stonith_disconnected;

    if(AM_I_DC) {
	fail_incompletable_stonith(transition_graph);
	trigger_graph();
    }
}

/*
<notify t="st_notify" subt="st_fence" st_op="st_fence" st_rc="0" >
  <st_calldata >
    <st-reply st_origin="stonith_construct_reply" t="stonith-ng" st_rc="0" st_op="st_query" st_callid="0" st_clientid="09fcbd8b-156a-4727-ab37-4f8b2071847c" st_remote_op="1230801d-dba5-42ac-8e2c-bf444fb2a401" st_callopt="0" st_delegate="pcmk-4" >
      <st_calldata >
        <st-reply st_origin="stonith_construct_async_reply" t="stonith-ng" st_op="reboot" st_remote_op="1230801d-dba5-42ac-8e2c-bf444fb2a401" st_callid="0" st_callopt="0" st_rc="0" src="pcmk-4" seq="2" state="0" st_target="pcmk-1" />
*/

static void
tengine_stonith_notify(stonith_t *st, const char *event, xmlNode *msg)
{
    int rc = -99;
    const char *target = NULL;
    xmlNode *action = get_xpath_object("//@src", msg, LOG_ERR);

    if(action == NULL) {
	crm_log_xml(LOG_ERR, "Notify data not found", msg);
	return;
    }
    
    crm_element_value_int(action, F_STONITH_RC, &rc);
    target = crm_element_value(action, F_STONITH_TARGET);

    crm_info("%s was terminated (%s) by %s for %s: %d (reference: %s)",
	     target, 
	     crm_element_value(action, F_STONITH_OPERATION),
	     crm_element_value(action, F_STONITH_DELEGATE),
	     crm_element_value(action, "src"),
	     rc,
	     crm_element_value(action, F_STONITH_REMOTE));
    
    if(rc == stonith_ok && safe_str_eq(target, fsa_our_dc)) {
	const char *uuid = get_uuid(target);
	crm_notice("Target was our leader %s/%s", target, uuid);
	/* send_stonith_update(action, target, uuid); */
    }
}

gboolean
te_connect_stonith(gpointer user_data)
{
	int lpc = 0;
	int rc = stonith_ok;

	if(stonith_api == NULL) {
	    stonith_api = stonith_api_new();
	}

	if(stonith_api->state != stonith_disconnected) {
	    crm_debug_2("Still connected");
	    return TRUE;
	}
	
	for(lpc = 0; lpc < 30; lpc++) {
	    crm_info("Attempting connection to fencing daemon...");
	    
	    sleep(1);
	    rc = stonith_api->cmds->connect(stonith_api, crm_system_name, NULL, NULL);
	    
	    if(rc == stonith_ok) {
		break;
	    }
	    
	    if(user_data != NULL) {
		crm_err("Sign-in failed: triggered a retry");
		mainloop_set_trigger(stonith_reconnect);
		return TRUE;
	    } 

	    crm_err("Sign-in failed: pausing and trying again in 2s...");
	    sleep(1);
	}
	
	CRM_CHECK(rc == stonith_ok, return TRUE); /* If not, we failed 30 times... just get out */
	stonith_api->cmds->register_notification(
	    stonith_api, T_STONITH_NOTIFY_DISCONNECT, tengine_stonith_connection_destroy);

	stonith_api->cmds->register_notification(
	    stonith_api, STONITH_OP_FENCE, tengine_stonith_notify);

	crm_info("Connected");
	return TRUE;
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
		g_source_remove(timer->source_id);
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
    enum transition_status graph_rc = -1;
    if(transition_graph == NULL) {
	crm_debug("Nothing to do");
	return TRUE;
    }
    
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
	print_graph(LOG_DEBUG_3, transition_graph);

	if(graph_rc == transition_active) {
		crm_debug_3("Transition not yet complete");
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
	mainloop_set_trigger(transition_trigger);
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
	    int diff_add_updates     = 0;
	    int diff_add_epoch       = 0;
	    int diff_add_admin_epoch = 0;
	    
	    int diff_del_updates     = 0;
	    int diff_del_epoch       = 0;
	    int diff_del_admin_epoch = 0;
	    xmlNode *diff = get_xpath_object("//"F_CIB_UPDATE_RESULT"//diff", reason, LOG_DEBUG_2);
	    magic = crm_element_value(reason, XML_ATTR_TRANSITION_MAGIC);

	    if(diff) {
		cib_diff_version_details(
		    diff,
		    &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
		    &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);
		do_crm_log(log_level,
			   "%s:%d - Triggered transition abort (complete=%d, tag=%s, id=%s, magic=%s, cib=%d.%d.%d) : %s",
			   fn, line, transition_graph->complete, TYPE(reason), ID(reason), magic?magic:"NA",
			   diff_add_admin_epoch,diff_add_epoch,diff_add_updates, abort_text);
		
	    } else {
		do_crm_log(log_level,
			   "%s:%d - Triggered transition abort (complete=%d, tag=%s, id=%s, magic=%s) : %s",
			   fn, line, transition_graph->complete, TYPE(reason), ID(reason), magic?magic:"NA", abort_text);
	    }

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

	if(magic == NULL && reason != NULL) {
	    crm_log_xml(log_level+1, "Cause", reason);
	}
	
	/* Make sure any queued calculations are discarded ASAP */
	crm_free(fsa_pe_ref);
	fsa_pe_ref = NULL;
	
	if(transition_graph->complete) {
	    register_fsa_input(C_FSA_INTERNAL, I_PE_CALC, NULL);
	    return;
	}

	update_abort_priority(
		transition_graph, abort_priority, abort_action, abort_text);	
	
	mainloop_set_trigger(transition_trigger);
}

