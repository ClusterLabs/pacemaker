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
#include <crm/cib.h>
#include <crmd_fsa.h>

#include <clplumbing/Gmain_timeout.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <heartbeat.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crmd_messages.h>
#include <crmd_utils.h>

#include <crm/dmalloc_wrapper.h>

void copy_ccm_node(oc_node_t a_node, oc_node_t *a_node_copy);

/*	A_DC_TIMER_STOP, A_DC_TIMER_START,
 *	A_FINALIZE_TIMER_STOP, A_FINALIZE_TIMER_START
 *	A_INTEGRATE_TIMER_STOP, A_INTEGRATE_TIMER_START
 */
enum crmd_fsa_input
do_timer_control(long long action,
		   enum crmd_fsa_cause cause,
		   enum crmd_fsa_state cur_state,
		   enum crmd_fsa_input current_input,
		   fsa_data_t *msg_data)
{
	gboolean timer_op_ok = TRUE;
	

	if(action & A_DC_TIMER_STOP) {
		timer_op_ok = stopTimer(election_trigger);

	} else if(action & A_FINALIZE_TIMER_STOP) {
		timer_op_ok = stopTimer(finalization_timer);

	} else if(action & A_INTEGRATE_TIMER_STOP) {
		timer_op_ok = stopTimer(integration_timer);

/* 	} else if(action & A_ELECTION_TIMEOUT_STOP) { */
/* 		timer_op_ok = stopTimer(election_timeout); */
	}

	/* dont start a timer that wasnt already running */
	if(action & A_DC_TIMER_START && timer_op_ok) {
		startTimer(election_trigger);

	} else if(action & A_FINALIZE_TIMER_START) {
		startTimer(finalization_timer);

	} else if(action & A_INTEGRATE_TIMER_START) {
		startTimer(integration_timer);

/* 	} else if(action & A_ELECTION_TIMEOUT_START) { */
/* 		startTimer(election_timeout); */
	}
	
	return I_NULL;
}

gboolean
timer_popped(gpointer data)
{
	fsa_timer_t *timer = (fsa_timer_t *)data;

	crm_info("Timer %s just popped!",
		 fsa_input2string(timer->fsa_input));
	
	stopTimer(timer); /* make it _not_ go off again */

	if(timer->fsa_input != I_NULL) {
		register_fsa_input(C_TIMER_POPPED, timer->fsa_input, NULL);
	}
	s_crmd_fsa(C_TIMER_POPPED);
	
	return TRUE;
}

gboolean
startTimer(fsa_timer_t *timer)
{
	if((timer->source_id == (guint)-1 || timer->source_id == (guint)-2)
	   && timer->period_ms > 0) {
		timer->source_id =
			Gmain_timeout_add(timer->period_ms,
					  timer->callback,
					  (void*)timer);
		crm_debug("Started %s timer (%d)",
			  fsa_input2string(timer->fsa_input),
			  timer->source_id);

	} else if(timer->period_ms < 0) {
		crm_err("Tried to start timer %s with -ve period",
			fsa_input2string(timer->fsa_input));
		
	} else {
		crm_debug("Timer %s already running (%d)",
			  fsa_input2string(timer->fsa_input),
			  timer->source_id);
		return FALSE;		
	}
	return TRUE;
}


gboolean
stopTimer(fsa_timer_t *timer)
{
	if(timer->source_id != (guint)-1 && timer->source_id != (guint)-2) {
		crm_devel("Stopping %s timer (%d)",
			   fsa_input2string(timer->fsa_input),
			   timer->source_id);
		g_source_remove(timer->source_id);
		timer->source_id = -2;
		
	} else {
		timer->source_id = -2;
		crm_debug("Timer %s already stopped (%d)",
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

	/* ensure its set */
	action_list |= action;

	/* then toggle */
	action_list = action_list ^ action;

	return action_list;
}

long long
set_bit(long long action_list, long long action)
{
	crm_trace("Setting bit\t%.16llx", action);
	action_list |= action;
	return action_list;
}


gboolean
is_set(long long action_list, long long action)
{
/*	crm_verbose("Checking bit\t%.16llx", action); */
	return ((action_list & action) == action);
}

gboolean
is_set_any(long long action_list, long long action)
{
/*	crm_verbose("Checking bit\t%.16llx", action); */
	return ((action_list & action) != 0);
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
		case I_INTEGRATED:
			inputAsText = "I_INTEGRATED";
			break;
		case I_FINALIZED:
			inputAsText = "I_FINALIZED";
			break;
		case I_NODE_JOIN:
			inputAsText = "I_NODE_JOIN";
			break;
		case I_JOIN_OFFER:
			inputAsText = "I_JOIN_OFFER";
			break;
		case I_JOIN_REQUEST:
			inputAsText = "I_JOIN_REQUEST";
			break;
		case I_JOIN_RESULT:
			inputAsText = "I_JOIN_RESULT";
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
		case I_PE_SUCCESS:
			inputAsText = "I_PE_SUCCESS";
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
		case I_TE_SUCCESS:
			inputAsText = "I_TE_SUCCESS";
			break;
		case I_TERMINATE:
			inputAsText = "I_TERMINATE";
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
		case I_PENDING:
			inputAsText = "I_PENDING";
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
		case S_FINALIZE_JOIN:
			stateAsText = "S_FINALIZE_JOIN";
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
		case S_STARTING:
			stateAsText = "S_STARTING";
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
		case C_HA_DISCONNECT:
			causeAsText = "C_HA_DISCONNECT";
			break;
		case C_FSA_INTERNAL:
			causeAsText = "C_FSA_INTERNAL";
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
		case A_READCONFIG:
			actionAsText = "A_READCONFIG";
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
		case A_LRM_EVENT:
			actionAsText = "A_LRM_EVENT";
			break;
		case A_LRM_INVOKE:
			actionAsText = "A_LRM_INVOKE";
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
		case A_INTEGRATE_TIMER_START:
			actionAsText = "A_INTEGRATE_TIMER_START";
			break;
		case A_INTEGRATE_TIMER_STOP:
			actionAsText = "A_INTEGRATE_TIMER_STOP";
			break;
		case A_FINALIZE_TIMER_START:
			actionAsText = "A_FINALIZE_TIMER_START";
			break;
		case A_FINALIZE_TIMER_STOP:
			actionAsText = "A_FINALIZE_TIMER_STOP";
			break;
		case A_ELECTION_COUNT:
			actionAsText = "A_ELECTION_COUNT";
			break;
		case A_ELECTION_VOTE:
			actionAsText = "A_ELECTION_VOTE";
			break;
		case A_CL_JOIN_ANNOUNCE:
			actionAsText = "A_CL_JOIN_ANNOUNCE";
			break;
		case A_CL_JOIN_REQUEST:
			actionAsText = "A_CL_JOIN_REQUEST";
			break;
		case A_CL_JOIN_RESULT:
			actionAsText = "A_CL_JOIN_RESULT";
			break;
		case A_DC_JOIN_OFFER_ALL:
			actionAsText = "A_DC_JOIN_OFFER_ALL";
			break;
		case A_DC_JOIN_OFFER_ONE:
			actionAsText = "A_DC_JOIN_OFFER_ONE";
			break;
		case A_DC_JOIN_PROCESS_REQ:
			actionAsText = "A_DC_JOIN_PROCESS_REQ";
			break;
		case A_DC_JOIN_PROCESS_ACK:
			actionAsText = "A_DC_JOIN_PROCESS_ACK";
			break;
		case A_DC_JOIN_FINALIZE:
			actionAsText = "A_DC_JOIN_FINALIZE";
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
fsa_dump_actions(long long action, const char *text)
{
	if(is_set(action, A_READCONFIG)) {
		crm_debug("Action %.16llx (A_READCONFIG) %s", A_READCONFIG, text);
	}
	if(is_set(action, A_STARTUP)) {
		crm_debug("Action %.16llx (A_STARTUP) %s", A_STARTUP, text);
	}
	if(is_set(action, A_STARTED)) {
		crm_debug("Action %.16llx (A_STARTED) %s", A_STARTED, text);
	}
	if(is_set(action, A_HA_CONNECT)) {
		crm_debug("Action %.16llx (A_CONNECT) %s", A_HA_CONNECT, text);
	}
	if(is_set(action, A_HA_DISCONNECT)) {
		crm_debug("Action %.16llx (A_DISCONNECT) %s",
			  A_HA_DISCONNECT, text);
	}
	if(is_set(action, A_LRM_CONNECT)) {
		crm_debug("Action %.16llx (A_LRM_CONNECT) %s",
			  A_LRM_CONNECT, text);
	}
	if(is_set(action, A_LRM_EVENT)) {
		crm_debug("Action %.16llx (A_LRM_EVENT) %s",
			  A_LRM_EVENT, text);
	}
	if(is_set(action, A_LRM_INVOKE)) {
		crm_debug("Action %.16llx (A_LRM_INVOKE) %s",
			  A_LRM_INVOKE, text);
	}
	if(is_set(action, A_LRM_DISCONNECT)) {
		crm_debug("Action %.16llx (A_LRM_DISCONNECT) %s",
			  A_LRM_DISCONNECT, text);
	}
	if(is_set(action, A_DC_TIMER_STOP)) {
		crm_debug("Action %.16llx (A_DC_TIMER_STOP) %s",
			  A_DC_TIMER_STOP, text);
	}
	if(is_set(action, A_DC_TIMER_START)) {
		crm_debug("Action %.16llx (A_DC_TIMER_START) %s",
			  A_DC_TIMER_START, text);
	}
	if(is_set(action, A_INTEGRATE_TIMER_START)) {
		crm_debug("Action %.16llx (A_INTEGRATE_TIMER_START) %s",
			  A_INTEGRATE_TIMER_START, text);
	}
	if(is_set(action, A_INTEGRATE_TIMER_STOP)) {
		crm_debug("Action %.16llx (A_INTEGRATE_TIMER_STOP) %s",
			  A_INTEGRATE_TIMER_STOP, text);
	}
	if(is_set(action, A_FINALIZE_TIMER_START)) {
		crm_debug("Action %.16llx (A_FINALIZE_TIMER_START) %s",
			  A_FINALIZE_TIMER_START, text);
	}
	if(is_set(action, A_FINALIZE_TIMER_STOP)) {
		crm_debug("Action %.16llx (A_FINALIZE_TIMER_STOP) %s",
			  A_FINALIZE_TIMER_STOP, text);
	}
	if(is_set(action, A_ELECTION_COUNT)) {
		crm_debug("Action %.16llx (A_ELECTION_COUNT) %s",
			  A_ELECTION_COUNT, text);
	}
	if(is_set(action, A_ELECTION_VOTE)) {
		crm_debug("Action %.16llx (A_ELECTION_VOTE) %s",
			  A_ELECTION_VOTE, text);
	}
	if(is_set(action, A_CL_JOIN_ANNOUNCE)) {
		crm_debug("Action %.16llx (A_CL_JOIN_ANNOUNCE) %s",
			  A_CL_JOIN_ANNOUNCE, text);
	}
	if(is_set(action, A_CL_JOIN_REQUEST)) {
		crm_debug("Action %.16llx (A_CL_JOIN_REQUEST) %s",
			  A_CL_JOIN_REQUEST, text);
	}
	if(is_set(action, A_CL_JOIN_RESULT)) {
		crm_debug("Action %.16llx (A_CL_JOIN_RESULT) %s",
			  A_CL_JOIN_RESULT, text);
	}
	if(is_set(action, A_DC_JOIN_OFFER_ALL)) {
		crm_debug("Action %.16llx (A_DC_JOIN_OFFER_ALL) %s",
			  A_DC_JOIN_OFFER_ALL, text);
	}
	if(is_set(action, A_DC_JOIN_OFFER_ONE)) {
		crm_debug("Action %.16llx (A_DC_JOIN_OFFER_ONE) %s",
			  A_DC_JOIN_OFFER_ONE, text);
	}
	if(is_set(action, A_DC_JOIN_PROCESS_REQ)) {
		crm_debug("Action %.16llx (A_DC_JOIN_PROCESS_REQ) %s",
			  A_DC_JOIN_PROCESS_REQ, text);
	}
	if(is_set(action, A_DC_JOIN_PROCESS_ACK)) {
		crm_debug("Action %.16llx (A_DC_JOIN_PROCESS_ACK) %s",
			  A_DC_JOIN_PROCESS_ACK, text);
	}
	if(is_set(action, A_DC_JOIN_FINALIZE)) {
		crm_debug("Action %.16llx (A_DC_JOIN_FINALIZE) %s",
			  A_DC_JOIN_FINALIZE, text);
	}
	if(is_set(action, A_MSG_PROCESS)) {
		crm_debug("Action %.16llx (A_MSG_PROCESS) %s",
			  A_MSG_PROCESS, text);
	}
	if(is_set(action, A_MSG_ROUTE)) {
		crm_debug("Action %.16llx (A_MSG_ROUTE) %s",
			  A_MSG_ROUTE, text);
	}
	if(is_set(action, A_MSG_STORE)) { 
		crm_debug("Action %.16llx (A_MSG_STORE) %s",
			  A_MSG_STORE, text);
	}
	if(is_set(action, A_RECOVER)) {
		crm_debug("Action %.16llx (A_RECOVER) %s",
			  A_RECOVER, text);
	}
	if(is_set(action, A_DC_RELEASE)) {
		crm_debug("Action %.16llx (A_DC_RELEASE) %s",
			  A_DC_RELEASE, text);
	}
	if(is_set(action, A_DC_RELEASED)) {
		crm_debug("Action %.16llx (A_DC_RELEASED) %s",
			  A_DC_RELEASED, text);
	}
	if(is_set(action, A_DC_TAKEOVER)) {
		crm_debug("Action %.16llx (A_DC_TAKEOVER) %s",
			  A_DC_TAKEOVER, text);
	}
	if(is_set(action, A_SHUTDOWN)) {
		crm_debug("Action %.16llx (A_SHUTDOWN) %s", A_SHUTDOWN, text);
	}
	if(is_set(action, A_SHUTDOWN_REQ)) {
		crm_debug("Action %.16llx (A_SHUTDOWN_REQ) %s",
			  A_SHUTDOWN_REQ, text);
	}
	if(is_set(action, A_STOP)) {
		crm_debug("Action %.16llx (A_STOP  ) %s", A_STOP  , text);
	}
	if(is_set(action, A_EXIT_0)) {
		crm_debug("Action %.16llx (A_EXIT_0) %s", A_EXIT_0, text);
	}
	if(is_set(action, A_EXIT_1)) {
		crm_debug("Action %.16llx (A_EXIT_1) %s", A_EXIT_1, text);
	}
	if(is_set(action, A_CCM_CONNECT)) {
		crm_debug("Action %.16llx (A_CCM_CONNECT) %s",
			  A_CCM_CONNECT, text);
	}
	if(is_set(action, A_CCM_DISCONNECT)) {
		crm_debug("Action %.16llx (A_CCM_DISCONNECT) %s",
			  A_CCM_DISCONNECT, text);
	}
	if(is_set(action, A_CCM_EVENT)) {
		crm_debug("Action %.16llx (A_CCM_EVENT) %s",
			  A_CCM_EVENT, text);
	}
	if(is_set(action, A_CCM_UPDATE_CACHE)) {
		crm_debug("Action %.16llx (A_CCM_UPDATE_CACHE) %s",
			  A_CCM_UPDATE_CACHE, text);
	}
	if(is_set(action, A_CIB_BUMPGEN)) {
		crm_debug("Action %.16llx (A_CIB_BUMPGEN) %s",
			  A_CIB_BUMPGEN, text);
	}
	if(is_set(action, A_CIB_INVOKE)) {
		crm_debug("Action %.16llx (A_CIB_INVOKE) %s",
			  A_CIB_INVOKE, text);
	}
	if(is_set(action, A_CIB_START)) {
		crm_debug("Action %.16llx (A_CIB_START) %s",
			  A_CIB_START, text);
	}
	if(is_set(action, A_CIB_STOP)) {
		crm_debug("Action %.16llx (A_CIB_STOP) %s", A_CIB_STOP, text);
	}
	if(is_set(action, A_TE_INVOKE)) {
		crm_debug("Action %.16llx (A_TE_INVOKE) %s", A_TE_INVOKE, text);
	}
	if(is_set(action, A_TE_START)) {
		crm_debug("Action %.16llx (A_TE_START) %s",
			  A_TE_START, text);
	}
	if(is_set(action, A_TE_STOP)) {
		crm_debug("Action %.16llx (A_TE_STOP) %s", A_TE_STOP, text);
	}
	if(is_set(action, A_TE_CANCEL)) {
		crm_debug("Action %.16llx (A_TE_CANCEL) %s",
			  A_TE_CANCEL, text);
	}
	if(is_set(action, A_TE_COPYTO)) {
		crm_debug("Action %.16llx (A_TE_COPYTO) %s",
			  A_TE_COPYTO, text);
	}
	if(is_set(action, A_PE_INVOKE)) {
		crm_debug("Action %.16llx (A_PE_INVOKE) %s",
			  A_PE_INVOKE, text);
	}
	if(is_set(action, A_PE_START)) {
		crm_debug("Action %.16llx (A_PE_START) %s", A_PE_START, text);
	}
	if(is_set(action, A_PE_STOP)) {
		crm_debug("Action %.16llx (A_PE_STOP) %s", A_PE_STOP, text);
	}
	if(is_set(action, A_NODE_BLOCK)) {
		crm_debug("Action %.16llx (A_NODE_BLOCK) %s",
			  A_NODE_BLOCK, text);
	}
	if(is_set(action, A_UPDATE_NODESTATUS)) {
		crm_debug("Action %.16llx (A_UPDATE_NODESTATUS) %s",
			  A_UPDATE_NODESTATUS, text);
	}
	if(is_set(action, A_LOG)) {
		crm_debug("Action %.16llx (A_LOG   ) %s", A_LOG, text);
	}
	if(is_set(action, A_ERROR)) {
		crm_debug("Action %.16llx (A_ERROR ) %s", A_ERROR, text);
	}
	if(is_set(action, A_WARN)) {
		crm_debug("Action %.16llx (A_WARN  ) %s", A_WARN, text);
	}
}


void
create_node_entry(const char *uuid, const char *uname, const char *type)
{
	
	/* make sure a node entry exists for the new node
	 *
	 * this will add anyone except the first ever node in the cluster
	 *   since it will also be the DC which doesnt go through the
	 *   join process (with itself).  We can include a special case
	 *   later if desired.
	 */
	xmlNodePtr tmp2 = NULL;
	xmlNodePtr tmp1 = create_xml_node(NULL, XML_CIB_TAG_NODE);

	crm_debug("Creating node entry for %s", uname);
	set_uuid(tmp1, XML_ATTR_UUID, uname);
	
	set_xml_property_copy(tmp1, XML_ATTR_UNAME, uname);
	set_xml_property_copy(tmp1, XML_ATTR_TYPE, type);
	
	tmp2 = create_cib_fragment(tmp1, NULL);

	/* do not forward this to the TE */
	invoke_local_cib(NULL, tmp2, CRM_OP_UPDATE);
	
	free_xml(tmp2);
	free_xml(tmp1);
	
}

xmlNodePtr
create_node_state(const char *uuid,
		  const char *uname,
		  const char *ccm_state,
		  const char *crmd_state,
		  const char *join_state,
		  const char *exp_state)
{
	xmlNodePtr node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);

	crm_debug("Creating node state entry for %s", uname);
	set_uuid(node_state, XML_ATTR_UUID, uname);
	set_xml_property_copy(node_state, XML_ATTR_UNAME, uname);

	set_xml_property_copy(
		node_state, XML_CIB_ATTR_INCCM, ccm_state);

	set_xml_property_copy(
		node_state, XML_CIB_ATTR_CRMDSTATE, crmd_state);

	set_xml_property_copy(
		node_state, XML_CIB_ATTR_JOINSTATE, join_state);
	
	set_xml_property_copy(
		node_state, XML_CIB_ATTR_EXPSTATE, exp_state);

	crm_xml_devel(node_state, "created");

	return node_state;
}


void
set_uuid(xmlNodePtr node, const char *attr, const char *uname) 
{
	uuid_t uuid_raw;
	char *uuid_calc = NULL;
	
	crm_malloc(uuid_calc, sizeof(char)*50);

	if(uuid_calc != NULL) {
		if(fsa_cluster_conn->llc_ops->get_uuid_by_name(
			   fsa_cluster_conn, uname, uuid_raw) == HA_FAIL) {
			crm_err("Could not calculate UUID for %s", uname);
			crm_free(uuid_calc);
			uuid_calc = crm_strdup(uname);
			
		} else {
			uuid_unparse(uuid_raw, uuid_calc);
		}
		
		set_xml_property_copy(node, attr, uuid_calc);
	}
	
	crm_free(uuid_calc);
}/*memory leak*/ /* BEAM BUG - this is not a memory leak */



struct crmd_ccm_data_s *
copy_ccm_data(const struct crmd_ccm_data_s *ccm_input) 
{
	const oc_ev_membership_t *oc_in =
		(const oc_ev_membership_t *)ccm_input->oc;
	struct crmd_ccm_data_s *ccm_input_copy = NULL;

	crm_malloc(ccm_input_copy, sizeof(struct crmd_ccm_data_s));

	ccm_input_copy->oc = copy_ccm_oc_data(oc_in);
	ccm_input_copy->event = ccm_input->event;
	
	return ccm_input_copy;
}

oc_ev_membership_t *
copy_ccm_oc_data(const oc_ev_membership_t *oc_in) 
{
	int lpc = 0;
	int size = 0;
	int offset = 0;
	int num_nodes = 0;
	oc_ev_membership_t *oc_copy = NULL;

	if(oc_in->m_n_member > 0
	   && num_nodes < oc_in->m_n_member + oc_in->m_memb_idx) {
		num_nodes = oc_in->m_n_member + oc_in->m_memb_idx;
		crm_devel("Updated ccm nodes to %d - 1", num_nodes);
	}
	if(oc_in->m_n_in > 0
	   && num_nodes < oc_in->m_n_in + oc_in->m_in_idx) {
		num_nodes = oc_in->m_n_in + oc_in->m_in_idx;
		crm_devel("Updated ccm nodes to %d - 2", num_nodes);
	}
	if(oc_in->m_n_out > 0
	   && num_nodes < oc_in->m_n_out + oc_in->m_out_idx) {
		num_nodes = oc_in->m_n_out + oc_in->m_out_idx;
		crm_devel("Updated ccm nodes to %d - 3", num_nodes);
	}

	/* why 2*??
	 * ccm code does it like this so i guess its right...
	 */
	size = sizeof(oc_ev_membership_t)
		+ sizeof(int)
		+ 2*num_nodes*sizeof(oc_node_t);

	crm_devel("Copying %d ccm nodes", num_nodes);
	
	crm_malloc(oc_copy, size);

	oc_copy->m_instance = oc_in->m_instance;
	oc_copy->m_n_member = oc_in->m_n_member;
	oc_copy->m_memb_idx = oc_in->m_memb_idx;
	oc_copy->m_n_out    = oc_in->m_n_out;
	oc_copy->m_out_idx  = oc_in->m_out_idx;
	oc_copy->m_n_in     = oc_in->m_n_in;
	oc_copy->m_in_idx   = oc_in->m_in_idx;

	crm_debug("instance=%d, nodes=%d (idx=%d), new=%d (idx=%d), lost=%d (idx=%d)",
		  oc_in->m_instance,
		  oc_in->m_n_member,
		  oc_in->m_memb_idx,
		  oc_in->m_n_in,
		  oc_in->m_in_idx,
		  oc_in->m_n_out,
		  oc_in->m_out_idx);

	offset = oc_in->m_memb_idx;
	for(lpc = 0; lpc < oc_in->m_n_member; lpc++) {
		crm_devel("Copying ccm member node %d", lpc);
		oc_node_t a_node      = oc_in->m_array[lpc+offset];
		oc_node_t *a_node_copy = &(oc_copy->m_array[lpc+offset]);
		copy_ccm_node(a_node, a_node_copy);
		
	}

	offset = oc_in->m_in_idx;
	for(lpc = 0; lpc < oc_in->m_n_in; lpc++) {
		crm_devel("Copying ccm new node %d", lpc);
		oc_node_t a_node      = oc_in->m_array[lpc+offset];
		oc_node_t *a_node_copy = &(oc_copy->m_array[lpc+offset]);
		copy_ccm_node(a_node, a_node_copy);
		
	}

	offset = oc_in->m_out_idx;
	for(lpc = 0; lpc < oc_in->m_n_out; lpc++) {
		crm_devel("Copying ccm lost node %d", lpc);
		oc_node_t a_node      = oc_in->m_array[lpc+offset];
		oc_node_t *a_node_copy = &(oc_copy->m_array[lpc+offset]);
		copy_ccm_node(a_node, a_node_copy);
	}
	
	return oc_copy;
}


void
copy_ccm_node(oc_node_t a_node, oc_node_t *a_node_copy)
{
	crm_devel("Copying ccm node: id=%d, born=%d, uname=%s",
		  a_node.node_id, a_node.node_born_on,
		  a_node.node_uname);
	
	a_node_copy->node_id      = a_node.node_id;
	a_node_copy->node_born_on = a_node.node_born_on;	
	a_node_copy->node_uname   = NULL;
	
	if(a_node.node_uname != NULL) {
			a_node_copy->node_uname =
				crm_strdup(a_node.node_uname);
	} else {
		crm_err("Node Id %d had a NULL uname!",
			a_node.node_id);
	}
	
	crm_devel("Copied ccm node: id=%d, born=%d, uname=%s",
		  a_node_copy->node_id, a_node_copy->node_born_on,
		  a_node_copy->node_uname);
}


lrm_op_t *
copy_lrm_op(const lrm_op_t *op)
{
	lrm_op_t *op_copy = NULL;
	crm_malloc(op_copy, sizeof(lrm_op_t));

	op_copy->op_type = crm_strdup(op->op_type);
 	/* input fields */
/* 	GHashTable*		params; */
	op_copy->params    = NULL;
	op_copy->timeout   = op->timeout;
	op_copy->interval  = op->interval; 
	op_copy->target_rc = op->target_rc; 

	/* in the CRM, this is always a char* */
	op_copy->user_data = crm_strdup((char*)op->user_data); 

	/* output fields */
	op_copy->op_status = op->op_status; 
	op_copy->rc        = op->rc; 
	op_copy->call_id   = op->call_id; 
	op_copy->output    = NULL;
	if(op->output!= NULL) {
		op_copy->output    = crm_strdup(op->output);
	}
	op_copy->rsc_id    = crm_strdup(op->rsc_id);
	op_copy->app_name  = crm_strdup(op->app_name);

	/*please notice the client needs release the memory of rsc.*/
	op_copy->rsc = copy_lrm_rsc(op->rsc);

	return op_copy;
}


lrm_rsc_t *
copy_lrm_rsc(const lrm_rsc_t *rsc)
{
	lrm_rsc_t *rsc_copy = NULL;
	crm_malloc(rsc_copy, sizeof(lrm_rsc_t));

	rsc_copy->id       = crm_strdup(rsc->id);
	rsc_copy->type     = crm_strdup(rsc->type);
	rsc_copy->class    = NULL;
	rsc_copy->provider = NULL;

	if(rsc->class != NULL) {
		rsc_copy->class    = crm_strdup(rsc->class);
	}
	if(rsc->provider != NULL) {
		rsc_copy->provider = crm_strdup(rsc->provider);
	}
/* 	GHashTable* 	params; */
	rsc_copy->params = NULL;
	rsc_copy->ops    = NULL;

	return rsc_copy;
}


