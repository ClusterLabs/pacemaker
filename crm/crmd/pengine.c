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
		if(stop_subsystem(this_subsys) == FALSE) {
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		}
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

char *fsa_pe_ref = NULL;

/*	 A_PE_INVOKE	*/
enum crmd_fsa_input
do_pe_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	crm_data_t *local_cib = NULL;
	HA_Message *cmd = NULL;

	if(is_set(fsa_input_register, R_PE_CONNECTED) == FALSE){
		
		crm_info("Waiting for the PE to connect");
		crmd_fsa_stall();
		return I_NULL;		
	}
	
	local_cib = get_cib_copy(fsa_cib_conn);

	crm_verbose("Invoking %s with %p", CRM_SYSTEM_PENGINE, local_cib);

	CRM_DEV_ASSERT(fsa_cib_conn->state != cib_disconnected);
	CRM_DEV_ASSERT(local_cib != NULL);
	if(crm_assert_failed) {
		/* wait for the congestion to ease? */
		crm_timer_start(wait_timer);
		crmd_fsa_stall();
		return I_NULL;		
	}
	CRM_DEV_ASSERT(crm_element_value(local_cib, XML_ATTR_DC_UUID) != NULL);
	
	if(fsa_pe_ref) {
		crm_free(fsa_pe_ref);
		fsa_pe_ref = NULL;
	}

	cmd = create_request(
		CRM_OP_PECALC, local_cib, NULL,
		CRM_SYSTEM_PENGINE, CRM_SYSTEM_DC, NULL);

	send_request(cmd, &fsa_pe_ref);
	free_xml(local_cib);
	
	return I_NULL;
}
