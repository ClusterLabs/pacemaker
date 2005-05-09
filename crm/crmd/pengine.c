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
void do_pe_invoke_callback(const HA_Message *msg, int call_id, int rc,
			   crm_data_t *output, void *user_data);

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
	int call_id = 0;

	/*
	 *	FIXME: The CIB might have a different version of membership than the CRM
	 *	We need to allow for that possibility.
	 *	We could set a flag saying we're waiting for the membership versions (and quorum!)
	 *	to synchronize before going on.  I don't know if anything bad happens
	 *	if the CIB is ahead of us.  But I know for sure that bad things
	 *	happen when the CIB is behind us (the CRM).
	 *
	 *	This probably has effects beyond that of running things without quorum
	 *	or failing to run things when we have quorum.
	 *
	 *	We might try and run things on nodes that aren't running, and we
	 *	might fail to schedule something on a node which is really available
	 *	for use.  I'm pretty sure I've seen the latter occur
	 *
	 *	A crude method would be to poll every 100ms and detect when the CRM
	 *	and CIB membership versions are the same.  I suspect if I knew
	 *	the code better, there probably is a callback which occurs when the
	 *	CIB is updated which we could use to trigger the delayed PE invocation.
	 *	There _might_ also need to be a mechanism for cancelling this delayed
	 *	pengine invocation - depending on what else happens after we
	 *	get this far (this doesn't seem that likely)
	 *	--AlanR.
	 *
	 */
	if(is_set(fsa_input_register, R_PE_CONNECTED) == FALSE){
		if(pe_subsystem->pid > 0) {
			int pid_status = -1;
			int rc = waitpid(
				pe_subsystem->pid, &pid_status, WNOHANG);

			if(rc > 0 && WIFEXITED(pid_status)) {
				clear_bit_inplace(fsa_input_register,
						  pe_subsystem->flag_connected);
	
				if(is_set(fsa_input_register,
					  pe_subsystem->flag_required)) {
					/* this wasnt supposed to happen */
					crm_err("%s[%d] terminated during start",
						pe_subsystem->name,
						pe_subsystem->pid);
					register_fsa_error(
						C_FSA_INTERNAL, I_ERROR, NULL);
				}
				pe_subsystem->pid = -1;
				return I_NULL;
			}
		} 
		
		crm_info("Waiting for the PE to connect");
		crmd_fsa_stall();
		return I_NULL;		
	}

	call_id = fsa_cib_conn->cmds->query(
		fsa_cib_conn, NULL, NULL, cib_scope_local);
	if(FALSE == add_cib_op_callback(
		   call_id, TRUE, NULL, do_pe_invoke_callback)) {
		crm_err("Cant retrieve the CIB to invoke the %s subsystem with",
			pe_subsystem->name);
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}
	
	return I_NULL;		
}

void
do_pe_invoke_callback(const HA_Message *msg, int call_id, int rc,
		      crm_data_t *output, void *user_data)
{
	HA_Message *cmd = NULL;
	int ccm_transition_id = -1;
	gboolean cib_has_quorum = FALSE;
	crm_data_t *local_cib = find_xml_node(output, XML_TAG_CIB, TRUE);

	if(AM_I_DC == FALSE
	   || is_set(fsa_input_register, R_PE_CONNECTED) == FALSE
	   || fsa_state != S_POLICY_ENGINE) {
		crm_debug("No need to invoke the PE anymore");
		return;
	}

	crm_verbose("Invoking %s with %p", CRM_SYSTEM_PENGINE, local_cib);

	CRM_DEV_ASSERT(local_cib != NULL);
	CRM_DEV_ASSERT(crm_element_value(local_cib, XML_ATTR_DC_UUID) != NULL);

	cib_has_quorum = crm_is_true(
		crm_element_value(local_cib, XML_ATTR_HAVE_QUORUM));

	ccm_transition_id = crm_atoi(
		crm_element_value(local_cib, XML_ATTR_CCM_TRANSITION), "-1");

	if(ccm_transition_id != fsa_membership_copy->id) {
		crm_err("Re-asking for the CIB until membership/quorum"
			" matches: CIB=%d, CRM=%d",
			ccm_transition_id, fsa_membership_copy->id);
		register_fsa_input_adv(C_FSA_INTERNAL, I_NULL, NULL, A_PE_INVOKE, TRUE, __FUNCTION__);
		return;
	}
	
	if(fsa_pe_ref) {
		crm_free(fsa_pe_ref);
		fsa_pe_ref = NULL;
	}

	cmd = create_request(
		CRM_OP_PECALC, local_cib, NULL,
		CRM_SYSTEM_PENGINE, CRM_SYSTEM_DC, NULL);

	send_request(cmd, &fsa_pe_ref);
}
