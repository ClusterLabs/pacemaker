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

struct crm_subsystem_s *cib_subsystem = NULL;

int cib_retries = 0;


/*	 A_CIB_STOP, A_CIB_START, A_CIB_RESTART,	*/
enum crmd_fsa_input
do_cib_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	enum crmd_fsa_input result = I_NULL;
	struct crm_subsystem_s *this_subsys = cib_subsystem;
	
	long long stop_actions = A_CIB_STOP;
	long long start_actions = A_CIB_START;

	if(action & stop_actions) {
		if(fsa_cib_conn != NULL
		   && fsa_cib_conn->state != cib_disconnected) {
			fsa_cib_conn->cmds->signoff(fsa_cib_conn);
		}
	}

	if(action & start_actions) {
		if(cur_state != S_STOPPING) {
			if(fsa_cib_conn == NULL) {
				fsa_cib_conn = cib_new();
			}
			if(cib_ok != fsa_cib_conn->cmds->signon(
				   fsa_cib_conn, CRM_SYSTEM_CRMD, cib_command)){
				crm_debug("Could not connect to the CIB service");
#if 0
			} else if(cib_ok != fsa_cib_conn->cmds->set_op_callback(
					  fsa_cib_conn, crmd_cib_op_callback)) {
				crm_err("Could not set op callback");
#endif
			} else if(fsa_cib_conn->cmds->set_connection_dnotify(
					  fsa_cib_conn,
					  crmd_cib_connection_destroy)!=cib_ok){
				crm_err("Could not set dnotify callback");

			} else {
				set_bit_inplace(
					fsa_input_register, R_CIB_CONNECTED);
			}

			if(is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {

				cib_retries++;
				crm_warn("Could complete CIB registration %d"
					 " times... pause and retry",
					 cib_retries);

				if(cib_retries < 30) {
					crm_timer_start(wait_timer);
					crmd_fsa_stall();

				} else {
					crm_err("Could not complete CIB"
						" registration  %d times..."
						" hard error", cib_retries);
					register_fsa_error(
						C_FSA_INTERNAL, I_ERROR, NULL);
				}
			} else {
				cib_retries = 0;
			}
			
		} else {
			crm_info("Ignoring request to start %s after shutdown",
				 this_subsys->name);
		}
	}
	
	return result;
}

/*	 A_CIB_INVOKE, A_CIB_BUMPGEN, A_UPDATE_NODESTATUS	*/
enum crmd_fsa_input
do_cib_invoke(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	HA_Message *answer = NULL;
	enum crmd_fsa_input result = I_NULL;
	ha_msg_input_t *cib_msg = fsa_typed_data(fsa_dt_ha_msg);
	const char *sys_from = cl_get_string(cib_msg->msg, F_CRM_SYS_FROM);

	if(fsa_cib_conn->state == cib_disconnected) {
		if(cur_state != S_STOPPING) {
			crm_err("CIB is disconnected");
			crm_log_message_adv(LOG_WARNING, "CIB Input", cib_msg->msg);
			return I_NULL;
		}
		crm_info("CIB is disconnected");
		crm_log_message_adv(LOG_DEBUG, "CIB Input", cib_msg->msg);
		return I_NULL;
		
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
		crm_data_t *cib_frag  = NULL;
		
		const char *section  = NULL;
		const char *op   = cl_get_string(cib_msg->msg, F_CRM_TASK);

		section  = cl_get_string(cib_msg->msg, F_CIB_SECTION);
		
		ha_msg_value_int(cib_msg->msg, F_CIB_CALLOPTS, &call_options);

		crm_log_message(LOG_MSG, cib_msg->msg);
		crm_xml_devel(cib_msg->xml, "[CIB update]");
		if(op == NULL) {
			crm_err("Invalid CIB Message");
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
			return I_NULL;
		}

		cib_frag = NULL;
		rc = fsa_cib_conn->cmds->variant_op(
			fsa_cib_conn, op, NULL, section,
			cib_msg->xml, &cib_frag, call_options);

		if(rc < cib_ok || (action & A_CIB_INVOKE)) {
			answer = create_reply(cib_msg->msg, cib_frag);
			ha_msg_add(answer,XML_ATTR_RESULT,cib_error2string(rc));
		}
		
		if(action & A_CIB_INVOKE) {
			if(relay_message(answer, TRUE) == FALSE) {
				crm_err("Confused what to do with cib result");
				crm_log_message(LOG_ERR, answer);
				crm_msg_del(answer);
				result = I_ERROR;
			}

		} else if(rc < cib_ok) {
			ha_msg_input_t *input = NULL;
			crm_err("Internal CRM/CIB command from %s() failed: %s",
				msg_data->origin, cib_error2string(rc));
			crm_log_message_adv(LOG_WARNING, "CIB Input", cib_msg->msg);
			crm_log_message_adv(LOG_WARNING, "CIB Reply", answer);
			
			input = new_ha_msg_input(answer);
			register_fsa_input(C_FSA_INTERNAL, I_ERROR, input);
			crm_msg_del(answer);
			delete_ha_msg_input(input);
		}
		
		return result;

	} else {
		crm_err("Unexpected action %s in %s",
			fsa_action2string(action), __FUNCTION__);
	}
	
	return I_NULL;
}

/* frees fragment as part of delete_ha_msg_input() */
void
update_local_cib_adv(
	crm_data_t *msg_data, gboolean do_now, const char *raised_from)
{
	HA_Message *msg = NULL;
	ha_msg_input_t *fsa_input = NULL;
	int call_options = cib_quorum_override|cib_scope_local;

	CRM_DEV_ASSERT(msg_data != NULL);
	
	crm_malloc(fsa_input, sizeof(ha_msg_input_t));

	msg = create_request(CRM_OP_CIB_UPDATE, msg_data, NULL,
			     CRM_SYSTEM_CIB, CRM_SYSTEM_CRMD, NULL);

	ha_msg_add(msg, F_CIB_SECTION,
		   crm_element_value(msg_data, XML_ATTR_SECTION));
	ha_msg_add_int(msg, F_CIB_CALLOPTS, call_options);
	ha_msg_add(msg, "call_origin", raised_from);

	fsa_input->msg = msg;
	fsa_input->xml = msg_data;

	if(AM_I_DC && crm_assert_failed) {	
/* 		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL); */
	}
	
	if(do_now == FALSE) {
		crm_devel("Registering event with FSA");
		register_fsa_input_adv(C_FSA_INTERNAL, I_CIB_OP, fsa_input, 0,
				       FALSE, raised_from);
	} else {
		fsa_data_t *op_data = NULL;
		crm_devel("Invoking CIB handler directly");
		crm_malloc(op_data, sizeof(fsa_data_t));

		op_data->fsa_cause	= C_FSA_INTERNAL;
		op_data->fsa_input	= I_CIB_OP;
		op_data->origin		= raised_from;
		op_data->data		= fsa_input;
		op_data->data_type	= fsa_dt_ha_msg;

		do_cib_invoke(A_CIB_INVOKE_LOCAL, C_FSA_INTERNAL, fsa_state,
			      I_CIB_OP, op_data);

		crm_free(op_data);
		crm_devel("CIB handler completed");
	}
	
	crm_devel("deleting input");
#if 0
	delete_ha_msg_input(fsa_input);
#else
 	crm_msg_del(fsa_input->msg);
	crm_free(fsa_input);
	/* BUG: it should be possible to free this but for some reason I cant */
/*  	free_xml(fsa_input->xml); */
#endif
	crm_devel("deleted input");
}

