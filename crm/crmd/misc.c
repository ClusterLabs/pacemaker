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
#include <heartbeat.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd_fsa.h>
#include <crmd_messages.h>

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

	

	if(action & A_LOG) log_type = LOG_INFO;
	if(action & A_WARN) log_type = LOG_WARNING;
	if(action & A_ERROR) log_type = LOG_ERR;
	
	do_crm_log(log_type, __FUNCTION__, 
	       "[[FSA]] Input (%s) was received while in state (%s)",
	       fsa_input2string(current_input),
	       fsa_state2string(cur_state));
	
	return I_NULL;
}

