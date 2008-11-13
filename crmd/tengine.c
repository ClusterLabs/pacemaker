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
#include <crmd_fsa.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <unistd.h>			/* for access */
#include <clplumbing/cl_signal.h>
#include <clplumbing/realtime.h>
#include <sys/types.h>	/* for calls to open */
#include <sys/stat.h>	/* for calls to open */
#include <fcntl.h>	/* for calls to open */
#include <pwd.h>	/* for getpwuid */
#include <grp.h>	/* for initgroups */

#include <sys/time.h>	/* for getrlimit */
#include <sys/resource.h>/* for getrlimit */

#include <errno.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>
#include <tengine.h>
#include <te_callbacks.h>


extern crm_graph_functions_t te_graph_fns;
struct crm_subsystem_s *te_subsystem  = NULL;


static void global_cib_callback(const xmlNode *msg, int callid ,int rc, xmlNode *output) 
{
}

static crm_graph_t *create_blank_graph(void) 
{
    crm_graph_t *a_graph = unpack_graph(NULL, NULL);
    a_graph->complete = TRUE;
    a_graph->abort_reason = "DC Takeover";
    a_graph->completion_action = tg_restart;
    return a_graph;    
}

/*	 A_TE_START, A_TE_STOP, A_TE_RESTART	*/
void
do_te_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
    int dummy;
    gboolean init_ok = TRUE;
	
    cl_uuid_t new_uuid;
    char uuid_str[UU_UNPARSE_SIZEOF];
	
    if(action & A_TE_STOP) {
	stop_te_timer(transition_timer);
	if(transition_graph) {
	    destroy_graph(transition_graph);
	    transition_graph = NULL;
	}

	if(fsa_cib_conn && cib_ok != fsa_cib_conn->cmds->del_notify_callback(
	       fsa_cib_conn, T_CIB_DIFF_NOTIFY, te_update_diff)) {
	    crm_err("Could not set CIB notification callback");
	    init_ok = FALSE;
	}

	clear_bit_inplace(fsa_input_register, te_subsystem->flag_connected);
	crm_info("Transitioner is now inactive");
	
	if(stonith_src) {
	    GCHSource *source = stonith_src;
	    crm_info("Disconnecting STONITH...");
	    stonith_src = NULL; /* so that we don't try to reconnect */
	    G_main_del_IPC_Channel(source);
	    stonithd_signoff();	    
	}
    }

    if((action & A_TE_START) == 0) {
	return;

    } else if(is_set(fsa_input_register, te_subsystem->flag_connected)) {
	crm_debug("The transitioner is already active");
	return;

    } else if((action & A_TE_START) && cur_state == S_STOPPING) {
	crm_info("Ignoring request to start %s while shutting down",
		 te_subsystem->name);
	return;
    }	

    cl_uuid_generate(&new_uuid);
    cl_uuid_unparse(&new_uuid, uuid_str);
    te_uuid = crm_strdup(uuid_str);
    crm_info("Registering TE UUID: %s", te_uuid);
	
    if(transition_trigger == NULL) {
	transition_trigger = G_main_add_TriggerHandler(
	    G_PRIORITY_LOW, te_graph_trigger, NULL, NULL);
    }

    if(stonith_reconnect == NULL) {
	stonith_reconnect = G_main_add_TriggerHandler(
	    G_PRIORITY_LOW, te_connect_stonith, &dummy, NULL);
    }
		    
    if(cib_ok != fsa_cib_conn->cmds->add_notify_callback(
	   fsa_cib_conn, T_CIB_DIFF_NOTIFY, te_update_diff)) {
	crm_err("Could not set CIB notification callback");
	init_ok = FALSE;
    }

    if(cib_EXISTS != fsa_cib_conn->cmds->add_notify_callback(
	   fsa_cib_conn, T_CIB_DIFF_NOTIFY, te_update_diff)) {
	crm_err("Set duplicate CIB notification callback");
    }

    if(cib_ok != fsa_cib_conn->cmds->set_op_callback(fsa_cib_conn, global_cib_callback)) {
	crm_err("Could not set CIB global callback");
	init_ok = FALSE;
    }
    
    if(init_ok) {
	G_main_set_trigger(stonith_reconnect);

	set_graph_functions(&te_graph_fns);

	if(transition_graph) {
	    destroy_graph(transition_graph);			    
	}
			
	/* create a blank one */
	transition_graph = create_blank_graph();
	crm_malloc0(transition_timer, sizeof(crm_action_timer_t));
	transition_timer->source_id = 0;
	transition_timer->reason    = timeout_abort;
	transition_timer->action    = NULL;

	crm_debug("Transitioner is now active");
	set_bit_inplace(fsa_input_register, te_subsystem->flag_connected);
    }
}

/*	 A_TE_INVOKE, A_TE_CANCEL	*/
void
do_te_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	if(AM_I_DC == FALSE) {
		crm_err("Not DC: No need to invoke the TE (anymore): %s",
			fsa_action2string(action));
		return;
		
	} else if(fsa_state != S_TRANSITION_ENGINE && (action & A_TE_INVOKE)) {
		crm_err("No need to invoke the TE (%s) in state %s",
			fsa_action2string(action),
			fsa_state2string(fsa_state));
		return;
	}

	if(action & A_TE_CANCEL) {
		crm_debug("Cancelling the active Transition");
		abort_transition(INFINITY, tg_restart, "Peer Cancelled", NULL);

	} else if(action & A_TE_HALT) {
		abort_transition(INFINITY, tg_stop, "Peer Halt", NULL);

	} else if(action & A_TE_INVOKE) {
		const char *value = NULL;
		xmlNode *graph_data = NULL;
		ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
		const char *ref = crm_element_value(input->msg, XML_ATTR_REFERENCE);
		const char *graph_file = crm_element_value(input->msg, F_CRM_TGRAPH);
		const char *graph_input = crm_element_value(input->msg, F_CRM_TGRAPH_INPUT);

		if(graph_file == NULL && input->xml == NULL) {			
		    crm_log_xml_err(input->msg, "Bad command");
		    register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		    return;
		}
		
		if(transition_graph->complete == FALSE) {
			crm_info("Another transition is already active");
			abort_transition(INFINITY, tg_restart, "Transition Active", NULL);
			return;
		}
		
		stop_te_timer(transition_timer);
		graph_data = input->xml;
		
		if(graph_data == NULL && graph_file != NULL) {
		    graph_data = filename2xml(graph_file);
		}

		CRM_CHECK(graph_data != NULL,
			  crm_err("Input raised by %s is invalid", msg_data->origin);
			  crm_log_xml_err(input->msg, "Bad command");
			  return);
		
		destroy_graph(transition_graph);
		transition_graph = unpack_graph(graph_data, graph_input);
		CRM_CHECK(transition_graph != NULL, transition_graph = create_blank_graph(); return);
		crm_info("Processing graph %d (ref=%s) derived from %s", transition_graph->id, ref, graph_input);
		if(transition_graph->transition_timeout > 0) {
		    start_global_timer(transition_timer, transition_graph->transition_timeout);
		}
		
		value = crm_element_value(graph_data, "failed-stop-offset");
		if(value) {
		    failed_stop_offset = crm_strdup(value);
		}
		
		value = crm_element_value(graph_data, "failed-start-offset");
		if(value) {
		    failed_start_offset = crm_strdup(value);
		}
		
		trigger_graph();
		print_graph(LOG_DEBUG_2, transition_graph);
		
		if(graph_data != input->xml) {
		    free_xml(graph_data);
		}	
	}
}

#if 0
gboolean shuttingdown;
gboolean tengine_shutdown(int nsig, gpointer unused)
{  
	shuttingdown = TRUE;
	abort_transition(INFINITY, tg_shutdown, "Shutdown", NULL);
	return TRUE;
}

gboolean te_stop(void)
{
    destroy_graph(transition_graph);
    crm_free(transition_timer);
    
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
	stonithd_signoff();
    }
#endif	
    crm_free(te_uuid);
}

#endif
