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


struct crm_subsystem_s *cib_subsystem = NULL;

int cib_retries = 0;


static void
revision_check_callback(xmlNode *msg, int call_id, int rc,
			xmlNode *output, void *user_data)
{
	int cmp = -1;
	const char *revision = NULL;
	xmlNode *generation = NULL;
#if CRM_DEPRECATED_SINCE_2_0_4
	if(safe_str_eq(crm_element_name(output), XML_TAG_CIB)) {
		generation = output;
	} else {
		generation = find_xml_node(output, XML_TAG_CIB, TRUE);
	}
#else
	generation = output;
	CRM_DEV_ASSERT(safe_str_eq(crm_element_name(generation), XML_TAG_CIB));
#endif
	
	if(rc != cib_ok) {
		fsa_data_t *msg_data = NULL;
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
		return;
	}
	
	crm_debug_3("Checking our feature revision is allowed: %s",
		    CIB_FEATURE_SET);

	revision = crm_element_value(generation, XML_ATTR_CIB_REVISION);
	cmp = compare_version(revision, CIB_FEATURE_SET);
	
	if(cmp > 0) {
		crm_err("This build (%s) does not support the current"
			" resource configuration", VERSION);
		crm_err("We can support up to CIB feature set %s (current=%s)",
			CIB_FEATURE_SET, revision);
		crm_err("Shutting down the CRM");
		/* go into a stall state */
		register_fsa_error_adv(
			C_FSA_INTERNAL, I_SHUTDOWN, NULL, NULL, __FUNCTION__);
		return;
	}

	revision = crm_element_value(generation, XML_ATTR_CRM_VERSION);
	cmp = compare_version(revision, CRM_FEATURE_SET);
	
	if(cmp > 0) {
		crm_err("This build (%s) does not support the current"
			" resource configuration", VERSION);
		crm_err("We can support up to CRM feature set %s (current=%s)",
			revision, CRM_FEATURE_SET);
		crm_err("Shutting down the CRM");
		/* go into a stall state */
		register_fsa_error_adv(
			C_FSA_INTERNAL, I_SHUTDOWN, NULL, NULL, __FUNCTION__);
		return;
	}
}

static void
do_cib_replaced(const char *event, xmlNode *msg)
{
	crm_debug("Updating the CIB after a replace");
 	populate_cib_nodes(FALSE);
	do_update_cib_nodes(AM_I_DC, __FUNCTION__);
	if(AM_I_DC) {
		/* start the join process again so we get everyone's LRM status */
		register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
	}
}

/*	 A_CIB_STOP, A_CIB_START, A_CIB_RESTART,	*/
void
do_cib_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	struct crm_subsystem_s *this_subsys = cib_subsystem;
	
	long long stop_actions = A_CIB_STOP;
	long long start_actions = A_CIB_START;

	if(action & stop_actions) {
		crm_info("Disconnecting CIB");
		clear_bit_inplace(fsa_input_register, R_CIB_CONNECTED);
		CRM_ASSERT(fsa_cib_conn != NULL);
		if(fsa_cib_conn->state != cib_disconnected) {
			fsa_cib_conn->cmds->set_slave(
				fsa_cib_conn, cib_scope_local);
			fsa_cib_conn->cmds->signoff(fsa_cib_conn);
		}
	}

	if(action & start_actions) {
		int rc = cib_ok;
		
		CRM_ASSERT(fsa_cib_conn != NULL);
		
		if(cur_state == S_STOPPING) {
			crm_err("Ignoring request to start %s after shutdown",
				this_subsys->name);
			return;
		}

		rc = fsa_cib_conn->cmds->signon(
			fsa_cib_conn, CRM_SYSTEM_CRMD, cib_command);

		if(rc != cib_ok) {
			/* a short wait that usually avoids stalling the FSA */
			sleep(1); 
			rc = fsa_cib_conn->cmds->signon(
				fsa_cib_conn, CRM_SYSTEM_CRMD, cib_command);
		}
		
		if(rc != cib_ok){
			crm_debug("Could not connect to the CIB service");

		} else if(cib_ok != fsa_cib_conn->cmds->set_connection_dnotify(
				  fsa_cib_conn, crmd_cib_connection_destroy)) {
			crm_err("Could not set dnotify callback");
			
		} else if(cib_ok != fsa_cib_conn->cmds->add_notify_callback(
				  fsa_cib_conn, T_CIB_REPLACE_NOTIFY,
				  do_cib_replaced)) {
			crm_err("Could not set CIB notification callback");
			
		} else {
			set_bit_inplace(
				fsa_input_register, R_CIB_CONNECTED);
		}
		
		if(is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {
			
			cib_retries++;
			crm_warn("Couldn't complete CIB registration %d"
				 " times... pause and retry",
				 cib_retries);
			
			if(cib_retries < 30) {
				crm_timer_start(wait_timer);
				crmd_fsa_stall(NULL);
				
			} else {
				crm_err("Could not complete CIB"
					" registration  %d times..."
					" hard error", cib_retries);
				register_fsa_error(
					C_FSA_INTERNAL, I_ERROR, NULL);
			}
		} else {
			int call_id = 0;
			
			crm_info("CIB connection established");
			
			call_id = fsa_cib_conn->cmds->query(
				fsa_cib_conn, NULL, NULL, cib_scope_local);
			
			add_cib_op_callback(call_id, FALSE, NULL,
					    revision_check_callback);
			cib_retries = 0;
		}
	}
}

/*	 A_CIB_INVOKE, A_CIB_BUMPGEN, A_UPDATE_NODESTATUS	*/
void
do_cib_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	xmlNode *answer = NULL;
	ha_msg_input_t *cib_msg = fsa_typed_data(fsa_dt_ha_msg);
	const char *sys_from = crm_element_value(cib_msg->msg, F_CRM_SYS_FROM);

	if(fsa_cib_conn->state == cib_disconnected) {
		if(cur_state != S_STOPPING) {
			crm_err("CIB is disconnected");
			crm_log_xml(LOG_WARNING, "CIB Input", cib_msg->msg);
			return;
		}
		crm_info("CIB is disconnected");
		crm_log_xml(LOG_DEBUG, "CIB Input", cib_msg->msg);
		return;
		
	}
	
	if(action & A_CIB_INVOKE) {
		if(safe_str_eq(sys_from, CRM_SYSTEM_CRMD)) {
			action = A_CIB_INVOKE_LOCAL;
		} else if(safe_str_eq(sys_from, CRM_SYSTEM_DC)) {
			action = A_CIB_INVOKE_LOCAL;
		}
	}
	

	if(action & A_CIB_INVOKE || action & A_CIB_INVOKE_LOCAL) {
		int call_options = 0;
		enum cib_errors rc  = cib_ok;
		xmlNode *cib_frag  = NULL;
		
		const char *section  = NULL;
		const char *op   = crm_element_value(cib_msg->msg, F_CRM_TASK);

		section  = crm_element_value(cib_msg->msg, F_CIB_SECTION);
		
		crm_element_value_int(cib_msg->msg, F_CIB_CALLOPTS, &call_options);

		crm_log_xml(LOG_MSG, "udpate", cib_msg->msg);
		if(op == NULL) {
			crm_err("Invalid CIB Message");
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
			return;
		}

		cib_frag = NULL;
		rc = fsa_cib_conn->cmds->variant_op(
			fsa_cib_conn, op, NULL, section,
			cib_msg->xml, &cib_frag, call_options);

		if(rc < cib_ok || (action & A_CIB_INVOKE)) {
			answer = create_reply(cib_msg->msg, cib_frag);
			crm_xml_add(answer,XML_ATTR_RESULT,cib_error2string(rc));
		}
		
		if(action & A_CIB_INVOKE) {
			if(relay_message(answer, TRUE) == FALSE) {
				crm_err("Confused what to do with cib result");
				crm_log_xml(LOG_ERR, "reply", answer);
				free_xml(answer);
				register_fsa_input(C_FSA_INTERNAL, I_ERROR, NULL);
				return;
			}

		} else if(rc < cib_ok) {
			ha_msg_input_t *input = NULL;
			crm_err("Internal CRM/CIB command from %s() failed: %s",
				msg_data->origin, cib_error2string(rc));
			crm_log_xml(LOG_WARNING, "CIB Input", cib_msg->msg);
			crm_log_xml(LOG_WARNING, "CIB Reply", answer);
			
			input = new_ha_msg_input(answer);
			register_fsa_input(C_FSA_INTERNAL, I_ERROR, input);
			free_xml(answer);
			delete_ha_msg_input(input);
		}

	} else {
		crm_err("Unexpected action %s in %s",
			fsa_action2string(action), __FUNCTION__);
	}
}

