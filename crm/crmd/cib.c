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
		/* dont do anything, its embedded now */
	}

	if(action & start_actions) {

		if(cur_state != S_STOPPING) {
			if(startCib(CIB_FILENAME) == FALSE)
				result = I_FAIL;

		} else {
			crm_info("Ignoring request to start %s after shutdown",
				 this_subsys->command);
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
	xmlNodePtr new_options = NULL;
	const char *section = NULL;
	enum crmd_fsa_input result = I_NULL;

	if(msg_data->data != NULL) {
		cib_msg = (xmlNodePtr)msg_data->data;
	}
	
	
	if(action & A_CIB_INVOKE || action & A_CIB_INVOKE_LOCAL) {
/*		gboolean is_update   = FALSE; */
		xmlNodePtr msg_copy = copy_xml_node_recursive(cib_msg);
		xmlNodePtr options  = find_xml_node(msg_copy, XML_TAG_OPTIONS);

		const char *sys_from = xmlGetProp(msg_copy, XML_ATTR_SYSFROM);
		const char *host_from= xmlGetProp(msg_copy, XML_ATTR_HOSTFROM);
		const char *type     = xmlGetProp(options, XML_ATTR_MSGTYPE);
		const char *op       = xmlGetProp(options, XML_ATTR_OP);
		
		crm_xml_devel(msg_copy, "[CIB update]");
		if(cib_msg == NULL) {
			crm_err("No message for CIB command");
			return I_NULL; /* I_ERROR */

		} else if(op == NULL) {
			crm_xml_devel(msg_copy, "Invalid CIB Message");
			return I_NULL; /* I_ERROR */

		}
		if(AM_I_DC
		   && safe_str_eq(op, CRM_OP_RETRIVE_CIB)
		   && safe_str_eq(type, XML_ATTR_RESPONSE)) {
			/* we actually need to process this as a REPLACE,
			 * not pretty, but fake the op type...
			 */
			crm_debug("Mapping %s reply to a %s request",
				  CRM_OP_RETRIVE_CIB, CRM_OP_REPLACE);
			
			set_xml_property_copy(
				options, XML_ATTR_OP, CRM_OP_REPLACE);

			crm_xml_devel(msg_copy, "[CIB revised update]");
			
		} else if(safe_str_eq(op, CRM_OP_RETRIVE_CIB)) {
			crm_debug("is dc? %d, type=%s", AM_I_DC, type);
		}
		
		set_xml_property_copy(msg_copy, XML_ATTR_SYSTO, "cib");
		answer = process_cib_message(msg_copy, TRUE);

		if(action & A_CIB_INVOKE) {

			if(AM_I_DC == FALSE) {
				if(relay_message(answer, TRUE) == FALSE) {
					crm_err("Confused what to do with cib result");
					crm_xml_devel(answer, "Couldnt route: ");
					result = I_ERROR;
				}
				
			} else if(strcmp(op, CRM_OP_CREATE) == 0
			   || strcmp(op, CRM_OP_UPDATE) == 0
			   || strcmp(op, CRM_OP_DELETE) == 0
			   || strcmp(op, CRM_OP_REPLACE) == 0
			   || strcmp(op, CRM_OP_RETRIVE_CIB) == 0
			   || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
				register_fsa_input(
					C_IPC_MESSAGE, I_CIB_UPDATE, cib_msg);
				
			} else if(strcmp(op, CRM_OP_RETRIVE_CIB) == 0) {
				crm_info("Retrieved latest CIB from %s",
					host_from);
				set_bit_inplace(fsa_input_register,R_HAVE_CIB);

			} else if(strcmp(op, CRM_OP_ERASE) == 0) {
				/* regenerate everyone's state and our node entry */
				register_fsa_input(
					C_UNKNOWN, I_ELECTION_DC, NULL);
			}
			
			/* the TENGINE will get CC'd by other means. */
			if(AM_I_DC
			   && sys_from != NULL
			   && safe_str_neq(sys_from, CRM_SYSTEM_TENGINE) 
			   && safe_str_neq(sys_from, CRM_SYSTEM_CRMD)
			   && safe_str_neq(sys_from, CRM_SYSTEM_DC)
			   && relay_message(answer, TRUE) == FALSE) {
				crm_err("Confused what to do with cib result");
				crm_xml_devel(answer, "Couldnt route: ");
				result = I_ERROR;
				
			}
			
/* 		} else { */
/* 			put_message(answer); */
/* 			return I_REQUEST; */
			
		}
		
		return result;

	} else if(action & A_CIB_BUMPGEN) {
/*		xmlNodePtr options   = find_xml_node(cib_msg, XML_TAG_OPTIONS); */
/*		const char *op       = xmlGetProp(options, XML_ATTR_OP); */

		if(AM_I_DC == FALSE) {
			return I_NULL;
		}

 		/* check if the response was ok before next bit */

/*		if(safe_str_neq(op, CRM_OP_WELCOME)) { */
			/* set the section so that we dont always send the
			 * whole thing
			 */
		section = get_xml_attr(
			cib_msg, XML_TAG_OPTIONS,
			XML_ATTR_FILTER_TYPE, FALSE);
/*		} */
		
		if(section != NULL) {
			new_options = set_xml_attr(
				NULL, XML_TAG_OPTIONS, XML_ATTR_FILTER_TYPE,
				section, TRUE);
		}
		
		answer = process_cib_request(
			CRM_OP_BUMP, new_options, NULL);

		free_xml(new_options);

		if(answer == NULL) {
			crm_err("Result of BUMP in %s was NULL",
			       __FUNCTION__);
			return I_FAIL;
		}

		send_request(NULL, answer, CRM_OP_REPLACE,
			     NULL, CRM_SYSTEM_CRMD, NULL);
		
		free_xml(answer);

	} else {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
	
	
	return I_NULL;
}

enum crmd_fsa_input
invoke_local_cib(xmlNodePtr msg_options,
		 xmlNodePtr msg_data,
		 const char *operation)
{
	enum crmd_fsa_input result = I_NULL;
	xmlNodePtr request = NULL;
	fsa_data_t *fsa_data = NULL;

	msg_options = set_xml_attr(msg_options, XML_TAG_OPTIONS,
				   XML_ATTR_OP, operation, TRUE);

	request = create_request(msg_options,
				 msg_data,
				 NULL,
				 CRM_SYSTEM_CIB,
				 AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD,
				 NULL,
				 NULL);

	crm_malloc(fsa_data, sizeof(fsa_data_t));
	fsa_data->fsa_input = I_CIB_UPDATE;
	fsa_data->fsa_cause = C_IPC_MESSAGE;
	fsa_data->data = request;

	result = do_cib_invoke(
		A_CIB_INVOKE_LOCAL, C_FSA_INTERNAL, fsa_state,
		I_CIB_OP, fsa_data);

	crm_free(fsa_data);
	free_xml(request);

	return I_NULL;
}
