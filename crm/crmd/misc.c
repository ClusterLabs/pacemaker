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
#include <portability.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crm/common/xmlutils.h>

#include <heartbeat.h>

#include <crm/dmalloc_wrapper.h>

/*	A_LOG, A_WARN, A_ERROR	*/
enum crmd_fsa_input
do_log(long long action,
       enum crmd_fsa_cause cause,
       enum crmd_fsa_state cur_state,
       enum crmd_fsa_input current_input,
       void *data)
{
	int log_type = LOG_DEBUG;

	FNIN();

	if(action & A_LOG) log_type = LOG_INFO;
	if(action & A_WARN) log_type = LOG_WARNING;
	if(action & A_ERROR) log_type = LOG_ERR;
	
	cl_log(log_type,
	       "[[FSA]] Input (%s) was received while in state (%s)",
	       fsa_input2string(current_input),
	       fsa_state2string(cur_state));
	
	FNRET(I_NULL);
}

void
CrmdClientStatus(const char * node, const char * client,
		 const char * status, void * private)
{
	const char    *join = NULL;
	const char   *extra = NULL;
	xmlNodePtr   update = NULL;
	xmlNodePtr fragment = NULL;

	if(safe_str_eq(status, JOINSTATUS)){
		status = ONLINESTATUS;
		extra  = XML_CIB_ATTR_CLEAR_SHUTDOWN;

	} else if(safe_str_eq(status, LEAVESTATUS)){
		status = OFFLINESTATUS;
		join   = CRMD_JOINSTATE_DOWN;
		extra  = XML_CIB_ATTR_CLEAR_SHUTDOWN;
	}
	
	cl_log(LOG_NOTICE,
	       "Status update: Client %s/%s now has status [%s]\n",
	       node, client, status);

	if(AM_I_DC) {
		update = create_node_state(node, NULL, status, join);

		if(extra != NULL) {
			set_xml_property_copy(update, extra, XML_BOOLEAN_TRUE);
		}
		
		fragment = create_cib_fragment(update, NULL);
		store_request(NULL, fragment,
			      CRM_OP_UPDATE, CRM_SYSTEM_DCIB);
		
		free_xml(fragment);
		free_xml(update);

		s_crmd_fsa(C_CRMD_STATUS_CALLBACK, I_NULL, NULL);
		
	} else {
		cl_log(LOG_ERR, "Got client status callback in non-DC mode");
	}
}

