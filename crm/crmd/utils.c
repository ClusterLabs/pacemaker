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
#include <crmd_fsa.h>

#include <clplumbing/Gmain_timeout.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>


#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <crm/dmalloc_wrapper.h>


gboolean
timer_popped(gpointer data)
{
	fsa_timer_t *timer = (fsa_timer_t *)data;

	crm_info("#!!#!!# Timer %s just popped!",
	       fsa_input2string(timer->fsa_input));
	
	stopTimer(timer); // dont make it go off again

	s_crmd_fsa(C_TIMER_POPPED, timer->fsa_input, NULL);
	
	return TRUE;
}

gboolean
startTimer(fsa_timer_t *timer)
{
	if(((int)timer->source_id) < 0
		&& timer->period_ms > 0) {
		timer->source_id =
			Gmain_timeout_add(timer->period_ms,
					  timer->callback,
					  (void*)timer);
/*
		crm_verbose("#!!#!!# Started %s timer (%d)",
			   fsa_input2string(timer->fsa_input),
			   timer->source_id);
*/
	} else if(timer->period_ms < 0) {
		crm_err("Tried to start timer %s with -ve period",
			fsa_input2string(timer->fsa_input));
		
	} else {
		crm_info("#!!#!!# Timer %s already running (%d)",
		       fsa_input2string(timer->fsa_input),
		       timer->source_id);
		return FALSE;		
	}
	return TRUE;
}


gboolean
stopTimer(fsa_timer_t *timer)
{
	if(((int)timer->source_id) > 0) {
/*
		crm_verbose("#!!#!!# Stopping %s timer (%d)",
			   fsa_input2string(timer->fsa_input),
			   timer->source_id);
*/
		g_source_remove(timer->source_id);
		timer->source_id = -2;

	} else {
		crm_info("#!!#!!# Timer %s already stopped (%d)",
		       fsa_input2string(timer->fsa_input),
		       timer->source_id);
		return FALSE;
	}
	return TRUE;
}


long long
toggle_bit(long long action_list, long long action)
{
	crm_trace("Toggling bit %.16llx", action);
	action_list ^= action;
	crm_trace("Result %.16llx", action_list & action);
	return action_list;
}

long long
clear_bit(long long action_list, long long action)
{
	crm_trace("Clearing bit\t%.16llx", action);

	// ensure its set
	action_list |= action;

	// then toggle
	action_list = action_list ^ action;

	return action_list;
}

long long
set_bit(long long action_list, long long action)
{
	crm_trace("Adding bit\t%.16llx", action);
	action_list |= action;
	return action_list;
}

void
toggle_bit_inplace(long long *action_list, long long action)
{
	*action_list = toggle_bit(*action_list, action);
}

void
clear_bit_inplace(long long *action_list, long long action)
{
	*action_list = clear_bit(*action_list, action);
}

void
set_bit_inplace(long long *action_list, long long action)
{
	*action_list = set_bit(*action_list, action);
}



gboolean
is_set(long long action_list, long long action)
{
//	crm_verbose("Checking bit\t%.16llx", action);
	return ((action_list & action) == action);
}


xmlNodePtr
create_node_state(const char *node,
		  const char *ccm_state,
		  const char *crmd_state,
		  const char *join_state)
{
	xmlNodePtr node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	
	set_xml_property_copy(node_state, XML_ATTR_ID, node);
	if(ccm_state != NULL) {
		set_xml_property_copy(node_state, XML_CIB_ATTR_INCCM,     ccm_state);
	}

	if(crmd_state != NULL) {
		set_xml_property_copy(node_state, XML_CIB_ATTR_CRMDSTATE,     crmd_state);
	}

	if(join_state != NULL) {
		set_xml_property_copy(node_state, XML_CIB_ATTR_JOINSTATE,     join_state);
	}

	xml_message_debug(node_state, "created");

	return node_state;
}

const char *
fsa_input2string(enum crmd_fsa_input input)
{
	const char *inputAsText = NULL;
	
	switch(input){
		case I_NULL:
			inputAsText = "I_NULL";
			break;
		case I_CCM_EVENT:
			inputAsText = "I_CCM_EVENT";
			break;
		case I_CIB_OP:
			inputAsText = "I_CIB_OP";
			break;
		case I_CIB_UPDATE:
			inputAsText = "I_CIB_UPDATE";
			break;
		case I_DC_TIMEOUT:
			inputAsText = "I_DC_TIMEOUT";
			break;
		case I_ELECTION:
			inputAsText = "I_ELECTION";
			break;
		case I_PE_CALC:
			inputAsText = "I_PE_CALC";
			break;
		case I_RELEASE_DC:
			inputAsText = "I_RELEASE_DC";
			break;
		case I_ELECTION_DC:
			inputAsText = "I_ELECTION_DC";
			break;
		case I_ERROR:
			inputAsText = "I_ERROR";
			break;
		case I_FAIL:
			inputAsText = "I_FAIL";
			break;
		case I_INTEGRATION_TIMEOUT:
			inputAsText = "I_INTEGRATION_TIMEOUT";
			break;
		case I_NODE_JOIN:
			inputAsText = "I_NODE_JOIN";
			break;
		case I_NODE_LEFT:
			inputAsText = "I_NODE_LEFT";
			break;
		case I_NOT_DC:
			inputAsText = "I_NOT_DC";
			break;
		case I_RECOVERED:
			inputAsText = "I_RECOVERED";
			break;
		case I_RELEASE_FAIL:
			inputAsText = "I_RELEASE_FAIL";
			break;
		case I_RELEASE_SUCCESS:
			inputAsText = "I_RELEASE_SUCCESS";
			break;
		case I_RESTART:
			inputAsText = "I_RESTART";
			break;
		case I_REQUEST:
			inputAsText = "I_REQUEST";
			break;
		case I_ROUTER:
			inputAsText = "I_ROUTER";
			break;
		case I_SHUTDOWN:
			inputAsText = "I_SHUTDOWN";
			break;
		case I_STARTUP:
			inputAsText = "I_STARTUP";
			break;
		case I_SUCCESS:
			inputAsText = "I_SUCCESS";
			break;
		case I_TERMINATE:
			inputAsText = "I_TERMINATE";
			break;
		case I_WELCOME:
			inputAsText = "I_WELCOME";
			break;
		case I_WELCOME_ACK:
			inputAsText = "I_WELCOME_ACK";
			break;
		case I_DC_HEARTBEAT:
			inputAsText = "I_DC_HEARTBEAT";
			break;
		case I_WAIT_FOR_EVENT:
			inputAsText = "I_WAIT_FOR_EVENT";
			break;
		case I_LRM_EVENT:
			inputAsText = "I_LRM_EVENT";
			break;
		case I_ILLEGAL:
			inputAsText = "I_ILLEGAL";
			break;
	}

	if(inputAsText == NULL) {
		crm_err("Input %d is unknown", input);
		inputAsText = "<UNKNOWN_INPUT>";
	}
	
	return inputAsText;
}

const char *
fsa_state2string(enum crmd_fsa_state state)
{
	const char *stateAsText = NULL;
	
	switch(state){
		case S_IDLE:
			stateAsText = "S_IDLE";
			break;
		case S_ELECTION:
			stateAsText = "S_ELECTION";
			break;
		case S_INTEGRATION:
			stateAsText = "S_INTEGRATION";
			break;
		case S_NOT_DC:
			stateAsText = "S_NOT_DC";
			break;
		case S_POLICY_ENGINE:
			stateAsText = "S_POLICY_ENGINE";
			break;
		case S_RECOVERY:
			stateAsText = "S_RECOVERY";
			break;
		case S_RECOVERY_DC:
			stateAsText = "S_RECOVERY_DC";
			break;
		case S_RELEASE_DC:
			stateAsText = "S_RELEASE_DC";
			break;
		case S_PENDING:
			stateAsText = "S_PENDING";
			break;
		case S_STOPPING:
			stateAsText = "S_STOPPING";
			break;
		case S_TERMINATE:
			stateAsText = "S_TERMINATE";
			break;
		case S_TRANSITION_ENGINE:
			stateAsText = "S_TRANSITION_ENGINE";
			break;
		case S_ILLEGAL:
			stateAsText = "S_ILLEGAL";
			break;
	}

	if(stateAsText == NULL) {
		crm_err("State %d is unknown", state);
		stateAsText = "<UNKNOWN_STATE>";
	}
	
	return stateAsText;
}

const char *
fsa_cause2string(enum crmd_fsa_cause cause)
{
	const char *causeAsText = NULL;
	
	switch(cause){
		case C_UNKNOWN:
			causeAsText = "C_UNKNOWN";
			break;
		case C_STARTUP:
			causeAsText = "C_STARTUP";
			break;
		case C_IPC_MESSAGE:
			causeAsText = "C_IPC_MESSAGE";
			break;
		case C_HA_MESSAGE:
			causeAsText = "C_HA_MESSAGE";
			break;
		case C_CCM_CALLBACK:
			causeAsText = "C_CCM_CALLBACK";
			break;
		case C_TIMER_POPPED:
			causeAsText = "C_TIMER_POPPED";
			break;
		case C_SHUTDOWN:
			causeAsText = "C_SHUTDOWN";
			break;
		case C_HEARTBEAT_FAILED:
			causeAsText = "C_HEARTBEAT_FAILED";
			break;
		case C_SUBSYSTEM_CONNECT:
			causeAsText = "C_SUBSYSTEM_CONNECT";
			break;
		case C_LRM_OP_CALLBACK:
			causeAsText = "C_LRM_OP_CALLBACK";
			break;
		case C_LRM_MONITOR_CALLBACK:
			causeAsText = "C_LRM_MONITOR_CALLBACK";
			break;
		case C_CRMD_STATUS_CALLBACK:
			causeAsText = "C_CRMD_STATUS_CALLBACK";
			break;
		case C_ILLEGAL:
			causeAsText = "C_ILLEGAL";
			break;
	}

	if(causeAsText == NULL) {
		crm_err("Cause %d is unknown", cause);
		causeAsText = "<UNKNOWN_CAUSE>";
	}
	
	return causeAsText;
}

const char *
fsa_action2string(long long action)
{
	const char *actionAsText = NULL;
	
	switch(action){

		case A_NOTHING:
			actionAsText = "A_NOTHING";
			break;
		case O_SHUTDOWN:
			actionAsText = "O_SHUTDOWN";
			break;
		case O_RELEASE:
			actionAsText = "O_RELEASE";
			break;
		case A_STARTUP:
			actionAsText = "A_STARTUP";
			break;
		case A_STARTED:
			actionAsText = "A_STARTED";
			break;
		case A_HA_CONNECT:
			actionAsText = "A_HA_CONNECT";
			break;
		case A_HA_DISCONNECT:
			actionAsText = "A_HA_DISCONNECT";
			break;
		case A_LRM_CONNECT:
			actionAsText = "A_LRM_CONNECT";
			break;
		case A_LRM_DISCONNECT:
			actionAsText = "A_LRM_DISCONNECT";
			break;
		case O_DC_TIMER_RESTART:
			actionAsText = "O_DC_TIMER_RESTART";
			break;
		case A_DC_TIMER_STOP:
			actionAsText = "A_DC_TIMER_STOP";
			break;
		case A_DC_TIMER_START:
			actionAsText = "A_DC_TIMER_START";
			break;
		case A_ELECTION_COUNT:
			actionAsText = "A_ELECTION_COUNT";
			break;
		case A_ELECTION_TIMEOUT:
			actionAsText = "A_ELECTION_TIMEOUT";
			break;
		case A_ELECT_TIMER_START:
			actionAsText = "A_ELECT_TIMER_START";
			break;
		case A_ELECT_TIMER_STOP:
			actionAsText = "A_ELECT_TIMER_STOP";
			break;
		case A_ELECTION_VOTE:
			actionAsText = "A_ELECTION_VOTE";
			break;
		case A_ANNOUNCE:
			actionAsText = "A_ANNOUNCE";
			break;
		case A_JOIN_ACK:
			actionAsText = "A_JOIN_ACK";
			break;
		case A_JOIN_WELCOME:
			actionAsText = "A_JOIN_WELCOME";
			break;
		case A_JOIN_WELCOME_ALL:
			actionAsText = "A_JOIN_WELCOME_ALL";
			break;
		case A_JOIN_PROCESS_ACK:
			actionAsText = "A_JOIN_PROCESS_ACK";
			break;
		case A_MSG_PROCESS:
			actionAsText = "A_MSG_PROCESS";
			break;
		case A_MSG_ROUTE:
			actionAsText = "A_MSG_ROUTE";
			break;
		case A_MSG_STORE:
			actionAsText = "A_MSG_STORE";
			break;
		case A_RECOVER:
			actionAsText = "A_RECOVER";
			break;
		case A_DC_RELEASE:
			actionAsText = "A_DC_RELEASE";
			break;
		case A_DC_RELEASED:
			actionAsText = "A_DC_RELEASED";
			break;
		case A_DC_TAKEOVER:
			actionAsText = "A_DC_TAKEOVER";
			break;
		case A_SHUTDOWN:
			actionAsText = "A_SHUTDOWN";
			break;
		case A_SHUTDOWN_REQ:
			actionAsText = "A_SHUTDOWN_REQ";
			break;
		case A_STOP:
			actionAsText = "A_STOP  ";
			break;
		case A_EXIT_0:
			actionAsText = "A_EXIT_0";
			break;
		case A_EXIT_1:
			actionAsText = "A_EXIT_1";
			break;
		case A_CCM_CONNECT:
			actionAsText = "A_CCM_CONNECT";
			break;
		case A_CCM_DISCONNECT:
			actionAsText = "A_CCM_DISCONNECT";
			break;
		case A_CCM_EVENT:
			actionAsText = "A_CCM_EVENT";
			break;
		case A_CCM_UPDATE_CACHE:
			actionAsText = "A_CCM_UPDATE_CACHE";
			break;
		case A_CIB_BUMPGEN:
			actionAsText = "A_CIB_BUMPGEN";
			break;
		case A_CIB_INVOKE:
			actionAsText = "A_CIB_INVOKE";
			break;
		case O_CIB_RESTART:
			actionAsText = "O_CIB_RESTART";
			break;
		case A_CIB_START:
			actionAsText = "A_CIB_START";
			break;
		case A_CIB_STOP:
			actionAsText = "A_CIB_STOP";
			break;
		case A_TE_INVOKE:
			actionAsText = "A_TE_INVOKE";
			break;
		case O_TE_RESTART:
			actionAsText = "O_TE_RESTART";
			break;
		case A_TE_START:
			actionAsText = "A_TE_START";
			break;
		case A_TE_STOP:
			actionAsText = "A_TE_STOP";
			break;
		case A_TE_CANCEL:
			actionAsText = "A_TE_CANCEL";
			break;
		case A_TE_COPYTO:
			actionAsText = "A_TE_COPYTO";
			break;
		case A_PE_INVOKE:
			actionAsText = "A_PE_INVOKE";
			break;
		case O_PE_RESTART:
			actionAsText = "O_PE_RESTART";
			break;
		case A_PE_START:
			actionAsText = "A_PE_START";
			break;
		case A_PE_STOP:
			actionAsText = "A_PE_STOP";
			break;
		case A_NODE_BLOCK:
			actionAsText = "A_NODE_BLOCK";
			break;
		case A_UPDATE_NODESTATUS:
			actionAsText = "A_UPDATE_NODESTATUS";
			break;
		case A_LOG:
			actionAsText = "A_LOG   ";
			break;
		case A_ERROR:
			actionAsText = "A_ERROR ";
			break;
		case A_WARN:
			actionAsText = "A_WARN  ";
			break;
	}

	if(actionAsText == NULL) {
		crm_err("Action %.16llx is unknown", action);
		actionAsText = "<UNKNOWN_ACTION>";
	}
	
	return actionAsText;
}


void
cleanup_subsystem(struct crm_subsystem_s *the_subsystem)
{
	int pid_status = -1;
	the_subsystem->ipc = NULL;
	clear_bit_inplace(&fsa_input_register,
			  the_subsystem->flag);

	/* Forcing client to die */
	kill(the_subsystem->pid, -9);
	
	// cleanup the ps entry
	waitpid(the_subsystem->pid, &pid_status, WNOHANG);
	the_subsystem->pid = -1;
}

enum crmd_fsa_input
invoke_local_cib(xmlNodePtr msg_options,
		 xmlNodePtr msg_data,
		 const char *operation)
{
	enum crmd_fsa_input result = I_NULL;
	xmlNodePtr request = NULL;
	

	msg_options = set_xml_attr(msg_options, XML_TAG_OPTIONS,
				   XML_ATTR_OP, operation, TRUE);

	request = create_request(msg_options,
				 msg_data,
				 NULL,
				 CRM_SYSTEM_CIB,
				 AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD,
				 NULL,
				 NULL);

	result = do_cib_invoke(A_CIB_INVOKE_LOCAL,
			       C_UNKNOWN,
			       fsa_state,
			       I_CIB_OP,
			       request);

	free_xml(request);
	
	return result;
}
