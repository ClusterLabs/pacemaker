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

#include <crm/dmalloc_wrapper.h>

struct crm_subsystem_s *te_subsystem  = NULL;


/*	 A_TE_START, A_TE_STOP, A_TE_RESTART	*/
enum crmd_fsa_input
do_te_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	enum crmd_fsa_input result = I_NULL;
	struct crm_subsystem_s *this_subsys = te_subsystem;
	
	long long stop_actions = A_TE_STOP;
	long long start_actions = A_TE_START;
	
/* 		if(action & stop_actions && cur_state != S_STOPPING */
/* 		   && is_set(fsa_input_register, R_TE_PEND)) { */
/* 			result = I_WAIT_FOR_EVENT; */
/* 			return result; */
/* 		} */
	
	if(action & stop_actions) {
		if(stop_subsystem(this_subsys) == FALSE) {
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		}

		cleanup_subsystem(this_subsys);
	}

	if(action & start_actions) {
		if(cur_state != S_STOPPING) {
			if(start_subsystem(this_subsys) == FALSE) {
				register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
				cleanup_subsystem(this_subsys);
			}
		} else {
			crm_info("Ignoring request to start %s while shutting down",
				 this_subsys->name);
		}
	}

	return result;
}

/*	 A_TE_INVOKE, A_TE_CANCEL	*/
enum crmd_fsa_input
do_te_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	enum crmd_fsa_input ret = I_NULL;
	HA_Message *cmd = NULL;
	

	if(is_set(fsa_input_register, R_TE_CONNECTED) == FALSE){
		crm_info("Waiting for the TE to connect");
		crmd_fsa_stall();
		return I_NULL;		
	}

	if(action & A_TE_INVOKE) {
		ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
		if(input->xml != NULL) {
			cmd = create_request(
				CRM_OP_TRANSITION, input->xml, NULL,
				CRM_SYSTEM_TENGINE, CRM_SYSTEM_DC, NULL);
			
			send_request(cmd, NULL);

		} else {
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		}
	
	} else if(action & A_TE_CANCEL) {
		cmd = create_request(
			CRM_OP_TEABORT, NULL, NULL,
			CRM_SYSTEM_TENGINE, CRM_SYSTEM_DC, NULL);
		
		send_request(cmd, NULL);
	}

	return ret;
}



