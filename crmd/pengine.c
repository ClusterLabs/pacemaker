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
#include <clplumbing/timers.h>
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
#include <crm/common/cluster.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/cib.h>
#include <crmd.h>


#define CLIENT_EXIT_WAIT 30

struct crm_subsystem_s *pe_subsystem  = NULL;
void do_pe_invoke_callback(xmlNode *msg, int call_id, int rc,
			   xmlNode *output, void *user_data);

/*	 A_PE_START, A_PE_STOP, A_TE_RESTART	*/
void
do_pe_control(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	struct crm_subsystem_s *this_subsys = pe_subsystem;

	long long stop_actions = A_PE_STOP;
	long long start_actions = A_PE_START;
	
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

int fsa_pe_query = 0;
char *fsa_pe_ref = NULL;

/*	 A_PE_INVOKE	*/
void
do_pe_invoke(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	if(is_set(fsa_input_register, R_PE_CONNECTED) == FALSE){
		crm_info("Waiting for the PE to connect");
		crmd_fsa_stall(NULL);
		return;		
	}

	if(is_set(fsa_input_register, R_HAVE_CIB) == FALSE) {
		crm_err("Attempted to invoke the PE without a consistent"
			" copy of the CIB!");

		/* start the join from scratch */
		register_fsa_input_before(C_FSA_INTERNAL, I_ELECTION, NULL);
		return;		
	}
	
	crm_debug("Requesting the current CIB: %s",fsa_state2string(fsa_state));
	fsa_pe_query = fsa_cib_conn->cmds->query(
		fsa_cib_conn, NULL, NULL, cib_scope_local);
	if(FALSE == add_cib_op_callback(
		   fsa_pe_query, TRUE, NULL, do_pe_invoke_callback)) {
		crm_err("Cant retrieve the CIB to invoke the %s subsystem with",
			pe_subsystem->name);
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}
}

void
do_pe_invoke_callback(xmlNode *msg, int call_id, int rc,
		      xmlNode *output, void *user_data)
{
	xmlNode *cmd = NULL;
	xmlNode *local_cib = NULL;
	
#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(output), XML_TAG_CIB)) {
		local_cib = output;
	} else {
		local_cib = find_xml_node(output, XML_TAG_CIB, TRUE);
	}
#else
	local_cib = output;
#endif
	if(call_id != fsa_pe_query) {
		crm_debug_2("Skipping superceeded CIB query: %d (current=%d)",
			    call_id, fsa_pe_query);
		return;
		
	} else if(AM_I_DC == FALSE
	   || is_set(fsa_input_register, R_PE_CONNECTED) == FALSE) {
		crm_debug("No need to invoke the PE anymore");
		return;

	} else if(need_transition(fsa_state) == FALSE) {
		crm_debug("Discarding PE request in state: %s",
			  fsa_state2string(fsa_state));
		return;

	} else if(last_peer_update != 0) {
	    crm_debug("Re-asking for the CIB: peer update %d still pending",
		      last_peer_update);
	    
	    mssleep(500);
	    register_fsa_action(A_PE_INVOKE);
	    return;

	} else if(fsa_state != S_POLICY_ENGINE) {
	    crm_err("Invoking PE in state: %s", fsa_state2string(fsa_state));
	}

	CRM_DEV_ASSERT(local_cib != NULL);
	CRM_DEV_ASSERT(crm_element_value(local_cib, XML_ATTR_DC_UUID) != NULL);

	crm_xml_add_int(local_cib, XML_ATTR_HAVE_QUORUM, fsa_has_quorum);
	crm_xml_add_int(local_cib, XML_ATTR_CCM_TRANSITION, crm_peer_seq);
	
	if(fsa_pe_ref) {
		crm_free(fsa_pe_ref);
		fsa_pe_ref = NULL;
	}

	cmd = create_request(CRM_OP_PECALC, local_cib, NULL,
			     CRM_SYSTEM_PENGINE, CRM_SYSTEM_DC, NULL);

	send_request(cmd, &fsa_pe_ref);
	crm_debug("Invoking the PE: ref=%s, seq=%llu, quorate=%d",
		  fsa_pe_ref, crm_peer_seq, fsa_has_quorum);
	free_xml(cmd);
}
