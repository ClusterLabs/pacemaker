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
#include <fsa_matrix.h>
#include <fsa_proto.h>
#include <stdio.h>

#include <crm/common/xmlutils.h>
#include <crm/common/msgutils.h>
#include <crm/msg_xml.h>

#include <clplumbing/Gmain_timeout.h>

#include <crmd_messages.h>
#include <string.h>
#include <time.h>

#include <crm/dmalloc_wrapper.h>

long long
do_state_transition(long long actions,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_state next_state,
		    enum crmd_fsa_input current_input,
		    void *data);

#ifdef DOT_FSA_ACTIONS
# ifdef FSA_TRACE
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	CRM_DEBUG("Invoking action %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, data);		\
	if( (x & O_DC_TICKLE) == 0 && next_input != I_DC_HEARTBEAT )	\
		fprintf(dot_strm,					\
			"\t// %s:\t%s\t(data? %s)\t(result=%s)\n",	\
			fsa_input2string(cur_input),			\
			fsa_action2string(x),				\
			data==NULL?"no":"yes",				\
			fsa_input2string(next_input));			\
	fflush(dot_strm);						\
	CRM_DEBUG("Result of action %s was %s",				\
		fsa_action2string(x), fsa_input2string(next_input));	\
     }
# else
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, data);		\
	if( (x & O_DC_TICKLE) == 0 && next_input != I_DC_HEARTBEAT )	\
		fprintf(dot_strm,					\
			"\t// %s:\t%s\t(data? %s)\t(result=%s)\n",	\
			fsa_input2string(cur_input),			\
			fsa_action2string(x),				\
			data==NULL?"no":"yes",				\
			fsa_input2string(next_input));			\
	fflush(dot_strm);						\
     }
# endif
#else
# ifdef FSA_TRACE
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	CRM_DEBUG("Invoking action %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, data);		\
	CRM_DEBUG("Result of action %s was %s",				\
		fsa_action2string(x), fsa_input2string(next_input));	\
     }
# else
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, data);		\
     }
# endif
#endif

#define ELSEIF_FSA_ACTION(x,y) else IF_FSA_ACTION(x,y)

const char *dot_intro = "digraph \"g\" {\n"
"	size = \"30,30\"\n"
"	graph [\n"
"		fontsize = \"12\"\n"
"		fontname = \"Times-Roman\"\n"
"		fontcolor = \"black\"\n"
"		bb = \"0,0,398.922306,478.927856\"\n"
"		color = \"black\"\n"
"	]\n"
"	node [\n"
"		fontsize = \"12\"\n"
"		fontname = \"Times-Roman\"\n"
"		fontcolor = \"black\"\n"
"		shape = \"ellipse\"\n"
"		color = \"black\"\n"
"	]\n"
"	edge [\n"
"		fontsize = \"12\"\n"
"		fontname = \"Times-Roman\"\n"
"		fontcolor = \"black\"\n"
"		color = \"black\"\n"
"	]\n"
"// special nodes\n"
"	\"S_PENDING\" \n"
"	[\n"
"	 color = \"blue\"\n"
"	 fontcolor = \"blue\"\n"
"	 ]\n"
"	\"S_TERMINATE\" \n"
"	[\n"
"	 color = \"red\"\n"
"	 fontcolor = \"red\"\n"
"	 ]\n"
"\n"
"// DC only nodes\n"
"	\"S_RECOVERY_DC\" [ fontcolor = \"green\" ]\n"
"	\"S_INTEGRATION\" [ fontcolor = \"green\" ]\n"
"	\"S_POLICY_ENGINE\" [ fontcolor = \"green\" ]\n"
"	\"S_TRANSITION_ENGINE\" [ fontcolor = \"green\" ]\n"
"	\"S_RELEASE_DC\" [ fontcolor = \"green\" ]\n"
"	\"S_IDLE\" [ fontcolor = \"green\" ]\n";


static FILE *dot_strm = NULL;

enum crmd_fsa_state fsa_state;
oc_node_list_t *fsa_membership_copy;
ll_cluster_t   *fsa_cluster_conn;
ll_lrm_t       *fsa_lrm_conn;
long long       fsa_input_register;
long long       fsa_actions = A_NOTHING;
const char     *fsa_our_uname;

fsa_timer_t *election_trigger = NULL;		/*  */
fsa_timer_t *election_timeout = NULL;		/*  */
fsa_timer_t *shutdown_escalation_timmer = NULL;	/*  */
fsa_timer_t *integration_timer = NULL;
fsa_timer_t *dc_heartbeat = NULL;

long long
toggle_bit(long long action_list, long long action)
{
//	CRM_DEBUG("Toggling bit %.16llx", action);
	action_list ^= action;
//	CRM_DEBUG("Result %.16llx", action_list & action);
	return action_list;
}

long long
clear_bit(long long action_list, long long action)
{
//	CRM_DEBUG("Clearing bit\t%.16llx", action);

	// ensure its set
	action_list |= action;

	// then toggle
	action_list = action_list ^ action;

	return action_list;
}

long long
set_bit(long long action_list, long long action)
{
//	CRM_DEBUG("Adding bit\t%.16llx", action);
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
//	CRM_DEBUG("Checking bit\t%.16llx", action);
	return ((action_list & action) == action);
}

gboolean
startTimer(fsa_timer_t *timer)
{
	if(((int)timer->source_id) < 0) {
		timer->source_id =
			Gmain_timeout_add(timer->period_ms,
					  timer->callback,
					  (void*)timer);
/*
		CRM_DEBUG("#!!#!!# Started %s timer (%d)",
			   fsa_input2string(timer->fsa_input),
			   timer->source_id);
*/
	} else {
		cl_log(LOG_INFO, "#!!#!!# Timer %s already running (%d)",
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
		CRM_DEBUG("#!!#!!# Stopping %s timer (%d)",
			   fsa_input2string(timer->fsa_input),
			   timer->source_id);
*/
		g_source_remove(timer->source_id);
		timer->source_id = -2;

	} else {
		cl_log(LOG_INFO, "#!!#!!# Timer %s already stopped (%d)",
		       fsa_input2string(timer->fsa_input),
		       timer->source_id);
		return FALSE;
	}
	return TRUE;
}

enum crmd_fsa_state
s_crmd_fsa(enum crmd_fsa_cause cause,
	   enum crmd_fsa_input initial_input,
	   void *data)
{
	long long actions = fsa_actions;
	long long new_actions = A_NOTHING;
	long long last_action = A_NOTHING;
	enum crmd_fsa_input last_input = initial_input;
	enum crmd_fsa_input cur_input;
	enum crmd_fsa_input next_input;
	enum crmd_fsa_state last_state, cur_state, next_state, starting_state;
	
	FNIN();

	starting_state = fsa_state;
	cur_input  = initial_input;
	next_input = initial_input;
	
	last_state = starting_state;
	cur_state  = starting_state;
	next_state = starting_state;

#ifdef FSA_TRACE
	CRM_DEBUG("FSA invoked with Cause: %s\n\tState: %s, Input: %s",
		   fsa_cause2string(cause),
		   fsa_state2string(cur_state),
		   fsa_input2string(cur_input));
#endif

	if(dot_strm == NULL) {
		dot_strm = fopen("/tmp/live.dot", "w");
		fprintf(dot_strm, "%s", dot_intro);
	}
	
	/*
	 * Process actions in order of priority but do only one
	 * action at a time to avoid complicating the ordering.
	 *
	 * Actions may result in a new I_ event, these are added to
	 * (not replace) existing actions before the next iteration.
	 *
	 */
	while(next_input != I_NULL || actions != A_NOTHING) {

		if(next_input == I_WAIT_FOR_EVENT) {
			/* we may be waiting for an a-sync task to "happen"
			 * and until it does, we cant do anything else
			 *
			 * Re-add the last action
			 */

			actions |= last_action;
					
			cl_log(LOG_INFO, "Wait until something else happens");
			break;
		}

#ifdef FSA_TRACE
		CRM_DEBUG("FSA while loop:\tState: %s, Input: %s",
			   fsa_state2string(cur_state),
			   fsa_input2string(cur_input));
#endif
		
		/* update input variables */
		cur_input = next_input;
		if(cur_input != I_NULL) {
			last_input = cur_input;
		}

		/* get the next batch of actions */
		new_actions = crmd_fsa_actions[cur_input][cur_state];
		if(new_actions != A_NOTHING) {
#ifdef FSA_TRACE
			CRM_DEBUG("Adding actions %.16llx", new_actions);
#endif
			actions |= new_actions;
		}

		/* logging : *before* the state is changed */
		IF_FSA_ACTION(A_ERROR, do_log)
		ELSEIF_FSA_ACTION(A_WARN, do_log)
		ELSEIF_FSA_ACTION(A_LOG,  do_log)

		/* update state variables */
		next_state  = crmd_fsa_state[cur_input][cur_state];
		last_state  = cur_state;
		cur_state   = next_state;
		fsa_state   = next_state;

		/* start doing things... */


		/*
		 * Hook for change of state.
		 * Allows actions to be added or removed when entering a state
		 */
		if(last_state != cur_state){
			actions = do_state_transition(actions, cause,
						      last_state, cur_state,
						      last_input, data);
		}

		/* this is always run, some inputs/states may make various
		 * actions irrelevant/invalid
		 */
		actions = clear_flags(actions, cause, cur_state, cur_input);

		/* regular action processing in order of action priority
		 *
		 * Make sure all actions that connect to required systems
		 * are performed first
		 */
		if(actions == A_NOTHING) {

			cl_log(LOG_INFO, "Nothing to do");
			next_input = I_NULL;
		
/*			// check registers, see if anything is pending
			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				CRM_DEBUG("(Re-)invoking shutdown");
				next_input = I_SHUTDOWN;
			} else if(is_set(fsa_input_register, R_INVOKE_PE)) {
				CRM_DEBUG("Invoke the PE somehow");
			}
*/
		}
	
	
		/* get out of here NOW! before anything worse happens */
	ELSEIF_FSA_ACTION(A_EXIT_1,	do_exit)
		
		ELSEIF_FSA_ACTION(A_STARTUP,	do_startup)
		
		ELSEIF_FSA_ACTION(A_CIB_START,  do_cib_control)
		ELSEIF_FSA_ACTION(A_HA_CONNECT, do_ha_control)
		ELSEIF_FSA_ACTION(A_LRM_CONNECT,do_lrm_control)
		ELSEIF_FSA_ACTION(A_CCM_CONNECT,do_ccm_control)
		ELSEIF_FSA_ACTION(A_ANNOUNCE,	do_announce)
		
		/* sub-system start */
		ELSEIF_FSA_ACTION(A_PE_START,	do_pe_control)
		ELSEIF_FSA_ACTION(A_TE_START,	do_te_control)
		
		/* sub-system restart
		 */
		ELSEIF_FSA_ACTION(O_CIB_RESTART,do_cib_control)
		ELSEIF_FSA_ACTION(O_PE_RESTART, do_pe_control)
		ELSEIF_FSA_ACTION(O_TE_RESTART, do_te_control)
		
		ELSEIF_FSA_ACTION(A_STARTED,	do_started)
		
		/* DC Timer */
		ELSEIF_FSA_ACTION(O_DC_TIMER_RESTART,	do_dc_timer_control)
		ELSEIF_FSA_ACTION(A_DC_TIMER_STOP,	do_dc_timer_control)
		ELSEIF_FSA_ACTION(A_DC_TIMER_START,	do_dc_timer_control)
		
		/*
		 * Highest priority actions
		 */
		ELSEIF_FSA_ACTION(A_TE_COPYTO,		do_te_copyto)
		ELSEIF_FSA_ACTION(A_SHUTDOWN_REQ,	do_shutdown_req)
		ELSEIF_FSA_ACTION(A_MSG_ROUTE,		do_msg_route)
		ELSEIF_FSA_ACTION(A_RECOVER,		do_recover)
		ELSEIF_FSA_ACTION(A_ELECTION_VOTE,	do_election_vote)
		ELSEIF_FSA_ACTION(A_ELECT_TIMER_START,	do_election_timer_ctrl)
		ELSEIF_FSA_ACTION(A_ELECT_TIMER_STOP,	do_election_timer_ctrl)
		ELSEIF_FSA_ACTION(A_ELECTION_COUNT,	do_election_count_vote)
		ELSEIF_FSA_ACTION(A_ELECTION_TIMEOUT,	do_election_timer_ctrl)
		
		/*
		 * "Get this over with" actions
		 */
		ELSEIF_FSA_ACTION(A_MSG_STORE,		do_msg_store)
		ELSEIF_FSA_ACTION(A_NODE_BLOCK,		do_node_block)
		
		/*
		 * High priority actions
		 * Update the cache first
		 */
		ELSEIF_FSA_ACTION(A_CCM_UPDATE_CACHE,	do_ccm_update_cache)
		ELSEIF_FSA_ACTION(A_CCM_EVENT,		do_ccm_event)
		
		/*
		 * Medium priority actions
		 */
		ELSEIF_FSA_ACTION(A_DC_TAKEOVER,	do_dc_takeover)
		ELSEIF_FSA_ACTION(A_DC_RELEASE,		do_dc_release)
		ELSEIF_FSA_ACTION(A_JOIN_WELCOME_ALL,	do_send_welcome)
		ELSEIF_FSA_ACTION(A_JOIN_WELCOME,	do_send_welcome)
		ELSEIF_FSA_ACTION(A_JOIN_ACK,		do_ack_welcome)
		ELSEIF_FSA_ACTION(A_JOIN_PROCESS_ACK,	do_process_welcome_ack)
		
		/*
		 * Low(er) priority actions
		 * Make sure the CIB is always updated before invoking the
		 * PE, and the PE before the TE
		 */
		ELSEIF_FSA_ACTION(A_UPDATE_NODESTATUS,	do_lrm_invoke)
		ELSEIF_FSA_ACTION(A_CIB_INVOKE_LOCAL,	do_cib_invoke)
		ELSEIF_FSA_ACTION(A_CIB_INVOKE,		do_cib_invoke)
		ELSEIF_FSA_ACTION(A_CIB_BUMPGEN,	do_cib_invoke)
		ELSEIF_FSA_ACTION(A_LRM_INVOKE,		do_lrm_invoke)
		ELSEIF_FSA_ACTION(A_LRM_EVENT,		do_lrm_event)
		ELSEIF_FSA_ACTION(A_TE_CANCEL,		do_te_invoke)
		ELSEIF_FSA_ACTION(A_PE_INVOKE,		do_pe_invoke)
		ELSEIF_FSA_ACTION(A_TE_INVOKE,		do_te_invoke)
		
		/* sub-system stop */
		ELSEIF_FSA_ACTION(A_PE_STOP,		do_pe_control)
		ELSEIF_FSA_ACTION(A_TE_STOP,		do_te_control)
		ELSEIF_FSA_ACTION(A_DC_RELEASED,	do_dc_release)

		ELSEIF_FSA_ACTION(A_HA_DISCONNECT,	do_ha_control)
		ELSEIF_FSA_ACTION(A_CCM_DISCONNECT,	do_ccm_control)
		ELSEIF_FSA_ACTION(A_LRM_DISCONNECT,	do_lrm_control)
		ELSEIF_FSA_ACTION(A_CIB_STOP,		do_cib_control)		
		/* time to go now... */
		
		/* Some of these can probably be consolidated */
		ELSEIF_FSA_ACTION(A_SHUTDOWN,   do_shutdown)
		ELSEIF_FSA_ACTION(A_STOP,	do_stop)
		
		/* exit gracefully */
		ELSEIF_FSA_ACTION(A_EXIT_0,	do_exit)

//		ELSEIF_FSA_ACTION(A_, do_)
		
		else if(is_message()) {
			xmlNodePtr stored_msg = NULL;
			
			fsa_message_queue_t msg = get_message();

			if(is_message() == FALSE) {
				actions = clear_bit(actions, A_MSG_PROCESS);
			}
			
			if(msg == NULL || msg->message == NULL) {
				cl_log(LOG_ERR,
				       "Invalid stored message");
				continue;
			}
			
			data = msg->message;

#ifdef DOT_FSA_ACTIONS
			fprintf(dot_strm,
				"\t// %s:\t%s\t(data? %s)",	
				fsa_input2string(cur_input),
				fsa_action2string(A_MSG_PROCESS),
				stored_msg==NULL?"no":"yes");
			fflush(dot_strm);
#endif
#ifdef FSA_TRACE
			CRM_DEBUG("Invoking action %s (%.16llx)",
				   fsa_action2string(A_MSG_PROCESS),
				   A_MSG_PROCESS);
#endif

			stored_msg = (xmlNodePtr)data;

#ifdef FSA_TRACE
			xml_message_debug(stored_msg,"FSA processing message");
#endif

			next_input = handle_message(stored_msg);

#ifdef DOT_FSA_ACTIONS
			fprintf(dot_strm, "\t(result=%s)\n",
				fsa_input2string(next_input));
#endif
			CRM_DEBUG("Result of action %s was %s",
				   fsa_action2string(A_MSG_PROCESS),
				   fsa_input2string(next_input));
			
			/* Error checking and reporting */
		} else if(cur_input != I_NULL && is_set(actions, A_NOTHING)) {
			cl_log(LOG_WARNING,
			       "No action specified for input,state (%s,%s)",
			       fsa_input2string(cur_input),
			       fsa_state2string(cur_state));
			
			next_input = I_NULL;
			
		} else if(cur_input == I_NULL && is_set(actions, A_NOTHING)) {
#ifdef FSA_TRACE
			cl_log(LOG_INFO, "Nothing left to do");
#endif			
		} else {
			cl_log(LOG_ERR, "Action %s (0x%llx) not supported ",
			       fsa_action2string(actions), actions);
			next_input = I_ERROR;
		}
	}
	
#ifdef FSA_TRACE
	CRM_DEBUG("################# Exiting the FSA (%s) ##################",
		  fsa_state2string(fsa_state));
#endif

#ifdef DOT_FSA_ACTIONS
	fprintf(dot_strm,			
		"\t// ### Exiting the FSA (%s)\n",
		fsa_state2string(fsa_state));
	fflush(dot_strm);
#endif

	// cleanup inputs?
	fsa_actions = actions;
	
	FNRET(fsa_state);
}


/*	A_NODE_BLOCK	*/
enum crmd_fsa_input
do_node_block(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{

	xmlNodePtr xml_message = (xmlNodePtr)data;
	const char *host_from  = xmlGetProp(xml_message, XML_ATTR_HOSTFROM);

	FNIN();
	
	(void)host_from;
	
	
	FNRET(I_NULL);
}


const char *
fsa_input2string(int input)
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
		case I_NODE_LEAVING:
			inputAsText = "I_NODE_LEAVING";
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
/* 		case I_SHUTDOWN_REQ: */
/* 			inputAsText = "I_SHUTDOWN_REQ"; */
/* 			break; */
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
		case I_ILLEGAL:
			inputAsText = "I_ILLEGAL";
			break;
	}

	if(inputAsText == NULL) {
		cl_log(LOG_ERR, "Input %d is unknown", input);
		inputAsText = "<UNKNOWN_INPUT>";
	}
	
	return inputAsText;
}

const char *
fsa_state2string(int state)
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
		cl_log(LOG_ERR, "State %d is unknown", state);
		stateAsText = "<UNKNOWN_STATE>";
	}
	
	return stateAsText;
}

const char *
fsa_cause2string(int cause)
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
		case C_ILLEGAL:
			causeAsText = "C_ILLEGAL";
			break;
	}

	if(causeAsText == NULL) {
		cl_log(LOG_ERR, "Cause %d is unknown", cause);
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
		cl_log(LOG_ERR, "Action %.16llx is unknown", action);
		actionAsText = "<UNKNOWN_ACTION>";
	}
	
	return actionAsText;
}

long long 
do_state_transition(long long actions,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_state next_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	long long tmp = A_NOTHING;
	
	if(current_input != I_NULL
	   && (current_input != I_DC_HEARTBEAT || cur_state != S_NOT_DC)){
		const char *state_from = fsa_state2string(cur_state);
		const char *state_to   = fsa_state2string(next_state);
		const char *input      = fsa_input2string(current_input);
			
		time_t now = time(NULL);
		
		fprintf(dot_strm,
			"\t\"%s\" -> \"%s\" [ label =\"%s\" ] // %s",
			state_from, state_to, input,
			asctime(localtime(&now)));
		fflush(dot_strm);
	}

	switch(next_state) {
		case S_PENDING:
		case S_NOT_DC:
			if(is_set(fsa_input_register, R_SHUTDOWN)){
				tmp = set_bit(actions, A_SHUTDOWN_REQ);
			}
			tmp = clear_bit(actions, A_RECOVER);
			break;
		case S_RECOVERY_DC:
		case S_RECOVERY:
			tmp = set_bit(actions, A_RECOVER);
			break;
		default:
			tmp = clear_bit(actions, A_RECOVER);
			break;
	}

	if(tmp != actions) {
		cl_log(LOG_INFO, "Action b4    %.16llx ", actions);
		cl_log(LOG_INFO, "Action after %.16llx ", tmp);
		actions = tmp;
	}

	return actions;
}

long long
clear_flags(long long actions,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input cur_input)
{

	if(is_set(fsa_input_register, R_SHUTDOWN)){
		clear_bit_inplace(&actions, A_DC_TIMER_START);
	}
	

	switch(cur_state) {
		case S_IDLE:
			break;
		case S_ELECTION:
			break;
		case S_INTEGRATION:
			break;
		case S_NOT_DC:
			break;
		case S_POLICY_ENGINE:
			break;
		case S_RECOVERY:
			break;
		case S_RECOVERY_DC:
			break;
		case S_RELEASE_DC:
			break;
		case S_PENDING:
			break;
		case S_STOPPING:
			break;
		case S_TERMINATE:
			break;
		case S_TRANSITION_ENGINE:
			break;
		case S_ILLEGAL:
			break;
	}
	return actions;
}
