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
void crmd_update_confirm(const char *event, struct ha_msg *msg);

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
		if(fsa_cib_conn->state != cib_disconnected) {
			fsa_cib_conn->cmds->signoff(fsa_cib_conn);
		}
	}

	if(action & start_actions) {
		
		if(cur_state != S_STOPPING) {
			if(fsa_cib_conn->cmds->signon(
				   fsa_cib_conn, cib_command) != cib_ok) {
				result = I_FAIL;
				crm_err("Could not connect to the CIB service");
				
			} else if(fsa_cib_conn->cmds->add_notify_callback(
					  fsa_cib_conn, T_CIB_UPDATE_CONFIRM,
					  crmd_update_confirm) != cib_ok) {
				result = I_FAIL;
				crm_err("Could not set notify callback");
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
	xmlNodePtr cib_msg = NULL;
	xmlNodePtr answer = NULL;
	enum crmd_fsa_input result = I_NULL;
	
	if(msg_data->data != NULL) {
		cib_msg = (xmlNodePtr)msg_data->data;
	}
	
	
	if(action & A_CIB_INVOKE || action & A_CIB_INVOKE_LOCAL) {
		enum cib_errors rc  = cib_ok;
		xmlNodePtr cib_frag  = NULL;
		xmlNodePtr msg_copy = copy_xml_node_recursive(cib_msg);
		xmlNodePtr options  = find_xml_node(msg_copy, XML_TAG_OPTIONS);
		
		const char *sys_from = xmlGetProp(msg_copy, XML_ATTR_SYSFROM);
		const char *type     = xmlGetProp(options, XML_ATTR_MSGTYPE);
		const char *op       = xmlGetProp(options, XML_ATTR_OP);
		
		cib_t *cib = NULL;
		
		crm_xml_devel(msg_copy, "[CIB update]");
		if(cib_msg == NULL) {
			crm_err("No message for CIB command");
			return I_NULL; /* I_ERROR */
			
		} else if(op == NULL) {
			crm_xml_devel(msg_copy, "Invalid CIB Message");
			return I_NULL; /* I_ERROR */
			
		}
		
		crm_debug("is dc? %d, type=%s", AM_I_DC, type);
		rc = cib->cmds->variant_op(
			cib, op, NULL, NULL, NULL, &cib_frag,
			cib_scope_local|cib_sync_call);
		
		answer = create_reply(cib_msg, cib_frag);
		set_xml_attr(answer, XML_TAG_OPTIONS,
			     XML_ATTR_RESULT, cib_error2string(rc), TRUE);
		
		if(AM_I_DC == FALSE) {
			if(relay_message(answer, TRUE) == FALSE) {
				crm_err("Confused what to do with cib result");
				crm_xml_devel(answer, "Couldnt route: ");
				result = I_ERROR;
			}
		}
		
		/* the TENGINE will get CC'd by other means. */
		if(AM_I_DC
		   && sys_from != NULL
		   && safe_str_neq(sys_from, CRM_SYSTEM_CRMD)
		   && safe_str_neq(sys_from, CRM_SYSTEM_DC)
		   && relay_message(answer, TRUE) == FALSE) {
			crm_err("Confused what to do with cib result");
			crm_xml_devel(answer, "Couldnt route: ");
			result = I_ERROR;
		}
		
		return result;


	} else {
		crm_err("Unexpected action %s in %s",
			fsa_action2string(action), __FUNCTION__);
	}
	
	return I_NULL;
}

enum crmd_fsa_input
update_local_cib(xmlNodePtr msg_data, gboolean callbacks)
{
	enum crmd_fsa_input result = I_NULL;
	enum cib_errors rc = cib_ok;
	
	const char *section = xmlGetProp(msg_data, XML_ATTR_SECTION);
	int call_options = cib_scope_local|cib_sync_call;
	
	if(callbacks == FALSE) {
		call_options |= cib_inhibit_notify;
	}
	
	rc = fsa_cib_conn->cmds->modify(
		fsa_cib_conn, section, msg_data, NULL, call_options);
	
	if(rc != cib_ok) {
		crm_err("Resource state update failed: %s",
			cib_error2string(result));
		result = I_FAIL;
	}
	return result;
}

void
crmd_update_confirm(const char *event, struct ha_msg *msg)
{
	int rc = -1;
	const char *op = cl_get_string(msg, F_CIB_OPERATION);

	ha_msg_value_int(msg, F_CIB_RC, &rc);

	if(rc != cib_ok) {
		crm_trace("Ignoring failed CIB update");
		return;
	}
	
	if(safe_str_eq(op, CRM_OP_CIB_ERASE)) {
		/* regenerate everyone's state and our node entry */
		register_fsa_input(C_UNKNOWN, I_ELECTION_DC, NULL);
	}
}
