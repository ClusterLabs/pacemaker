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

#include <hb_config.h>

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


struct crm_subsystem_s *te_subsystem  = NULL;

/*	 A_TE_START, A_TE_STOP, A_TE_RESTART	*/
void
do_te_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	struct crm_subsystem_s *this_subsys = te_subsystem;
	
	long long stop_actions = A_TE_STOP;
	long long start_actions = A_TE_START;
	
/* 		if(action & stop_actions && cur_state != S_STOPPING */
/* 		   && is_set(fsa_input_register, R_TE_PEND)) { */
/* 			result = I_WAIT_FOR_EVENT; */
/* 			return result; */
/* 		} */
	
	if(action & stop_actions) {
		stop_subsystem(this_subsys, FALSE);
	}

	if(action & start_actions) {
		if(cur_state != S_STOPPING) {
			if(start_subsystem(this_subsys) == FALSE) {
				register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
			}
		} else {
			crm_info("Ignoring request to start %s while shutting down",
				 this_subsys->name);
		}
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
	HA_Message *cmd = NULL;
	
	
	if(AM_I_DC == FALSE) {
		crm_debug("Not DC: No need to invoke the TE (anymore): %s",
			  fsa_action2string(action));
		return;
		
	} else if(fsa_state != S_TRANSITION_ENGINE && (action & A_TE_INVOKE)) {
		crm_debug("No need to invoke the TE (%s) in state %s",
			  fsa_action2string(action),
			  fsa_state2string(fsa_state));
		return;

	} else if(!is_set(fsa_input_register, te_subsystem->flag_required)) {
		crm_err("Ignoring action %s in state: %s"
			" - We dont want the TE anymore",
			fsa_action2string(action), fsa_state2string(cur_state));
		return;
		
	} else if(is_set(fsa_input_register, R_TE_CONNECTED) == FALSE) {
		crm_info("Waiting for the TE to connect before action %s",
			fsa_action2string(action));
		
		if(action & A_TE_INVOKE) {
			register_fsa_input(
				msg_data->fsa_cause, msg_data->fsa_input,
				msg_data->data);
		}

		crmd_fsa_stall(NULL);
		return;
	}

	if(action & A_TE_INVOKE) {
		ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
		const char *graph_file = cl_get_string(input->msg, F_CRM_TGRAPH);
		const char *graph_input = cl_get_string(input->msg, F_CRM_TGRAPH_INPUT);

		if(graph_file != NULL || input->xml != NULL) {			
			crm_debug("Starting a transition");
			set_bit_inplace(fsa_input_register, R_IN_TRANSITION);
			
			cmd = create_request(
				CRM_OP_TRANSITION, input->xml, NULL,
				CRM_SYSTEM_TENGINE, CRM_SYSTEM_DC, NULL);

			ha_msg_add(cmd, F_CRM_TGRAPH_INPUT, graph_input);
			if(graph_file) {
				ha_msg_add(cmd, F_CRM_TGRAPH, graph_file);
			}
			
			send_request(cmd, NULL);

		} else {
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		}
	
	} else if(action & A_TE_CANCEL) {
		crm_debug("Cancelling the active Transition");
		cmd = create_request(
			CRM_OP_TEABORT, NULL, NULL,
			CRM_SYSTEM_TENGINE, CRM_SYSTEM_DC, NULL);
		
		send_request(cmd, NULL);

	} else if(action & A_TE_HALT) {
		cmd = create_request(
			CRM_OP_TE_HALT, NULL, NULL,
			CRM_SYSTEM_TENGINE, CRM_SYSTEM_DC, NULL);
		
		send_request(cmd, NULL);
	}
}



