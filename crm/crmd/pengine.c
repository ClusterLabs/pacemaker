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

#define CLIENT_EXIT_WAIT 30

struct crm_subsystem_s *pe_subsystem  = NULL;

/*	 A_PE_START, A_PE_STOP, A_TE_RESTART	*/
enum crmd_fsa_input
do_pe_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	enum crmd_fsa_input result = I_NULL;
	struct crm_subsystem_s *this_subsys = pe_subsystem;

	long long stop_actions = A_PE_STOP;
	long long start_actions = A_PE_START;
	
	if(action & stop_actions) {
		crm_info("Stopping %s", this_subsys->command);
		if(stop_subsystem(this_subsys) == FALSE) {
			result = I_FAIL;
			
		} else if(this_subsys->pid > 0) {
			int lpc = CLIENT_EXIT_WAIT;
			int pid_status = -1;
			while(lpc-- > 0
			      && this_subsys->pid > 0
			      && CL_PID_EXISTS(this_subsys->pid)) {

				sleep(1);

				if(waitpid(this_subsys->pid,
					   &pid_status, WNOHANG) > 0) {
					this_subsys->pid = -1;
					break;
				}
			}
			
			if(this_subsys->pid != -1) {
				crm_err("Proc %s is still active with pid=%d",
				       this_subsys->command, this_subsys->pid);
				result = I_FAIL;
			} 
		}

		cleanup_subsystem(this_subsys);
	}

	if(action & start_actions) {

		if(cur_state != S_STOPPING) {
			crm_info("Starting %s", this_subsys->command);
			if(start_subsystem(this_subsys) == FALSE) {
				result = I_FAIL;
				cleanup_subsystem(this_subsys);
			}
		} else {
			crm_info("Ignoring request to start %s while shutting down",
			       this_subsys->command);
		}
	}
	
	return result;
}

char *fsa_pe_ref = NULL;

/*	 A_PE_INVOKE	*/
enum crmd_fsa_input
do_pe_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	xmlNodePtr local_cib = NULL;

	if(is_set(fsa_input_register, R_PE_CONNECTED) == FALSE){
		
		crm_info("Waiting for the PE to connect");
		crmd_fsa_stall();
		return I_NULL;		
	}
	
	local_cib = get_cib_copy();

	crm_verbose("Invoking %s with %p", CRM_SYSTEM_PENGINE, local_cib);

	if(fsa_pe_ref) {
		crm_free(fsa_pe_ref);
		fsa_pe_ref = NULL;
	}

	send_request(NULL, local_cib, CRM_OP_PECALC,
		     NULL, CRM_SYSTEM_PENGINE, &fsa_pe_ref);

	return I_NULL;
}
