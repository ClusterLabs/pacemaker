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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <clplumbing/Gmain_timeout.h>

#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <fsa_matrix.h>

#include <crm/dmalloc_wrapper.h>

extern GHashTable *joined_nodes;

long long
do_state_transition(long long actions,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_state next_state,
		    enum crmd_fsa_input current_input,
		    void *data);

long long clear_flags(long long actions,
			     enum crmd_fsa_cause cause,
			     enum crmd_fsa_state cur_state,
			     enum crmd_fsa_input cur_input);

void dump_rsc_info(void);

#ifdef DOT_FSA_ACTIONS
# ifdef FSA_TRACE
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	crm_verbose("Invoking action %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, data);		\
	if( (x & O_DC_TICKLE) == 0 && next_input != I_DC_HEARTBEAT )	\
		fprintf(dot_strm,					\
			"\t// %s:\t%s\t(data? %p)\t(result=%s)\n",	\
			fsa_input2string(cur_input),			\
			fsa_action2string(x),				\
			data,						\
			fsa_input2string(next_input));			\
	fflush(dot_strm);						\
	crm_verbose("Result of action %s was %s",			\
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
			"\t// %s:\t%s\t(data? %p)\t(result=%s)\n",	\
			fsa_input2string(cur_input),			\
			fsa_action2string(x),				\
			data,						\
			fsa_input2string(next_input));			\
	fflush(dot_strm);						\
     }
# endif
#else
# ifdef FSA_TRACE
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	crm_verbose("Invoking action %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, data);		\
	crm_verbose("Result of action %s was %s",			\
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

/* #define ELSEIF_FSA_ACTION(x,y) else IF_FSA_ACTION(x,y) */

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
const char     *fsa_our_dc;

fsa_timer_t *election_trigger = NULL;		/*  */
fsa_timer_t *election_timeout = NULL;		/*  */
fsa_timer_t *shutdown_escalation_timmer = NULL; /*  */
fsa_timer_t *integration_timer = NULL;
fsa_timer_t *dc_heartbeat = NULL;

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
	
	

	starting_state = fsa_state;
	cur_input  = initial_input;
	next_input = initial_input;
	
	last_state = starting_state;
	cur_state  = starting_state;
	next_state = starting_state;

#ifdef FSA_TRACE
	crm_verbose("FSA invoked with Cause: %s\tState: %s, Input: %s",
		   fsa_cause2string(cause),
		   fsa_state2string(cur_state),
		   fsa_input2string(cur_input));
#endif

#ifdef DOT_FSA_ACTIONS
	if(dot_strm == NULL) {
		dot_strm = fopen(DEVEL_DIR"/live.dot", "w");
		fprintf(dot_strm, "%s", dot_intro);
	}
	fprintf(dot_strm,
		"\t// FSA invoked: Cause=%s\tState=%s\tInput=%s\n",
		   fsa_cause2string(cause),
		   fsa_state2string(cur_state),
		   fsa_input2string(cur_input));

	fflush(dot_strm);
#endif
	/*
	 * Process actions in order of priority but do only one
	 * action at a time to avoid complicating the ordering.
	 *
	 * Actions may result in a new I_ event, these are added to
	 * (not replace) existing actions before the next iteration.
	 *
	 */
	while(next_input != I_NULL || actions != A_NOTHING || is_message()) {

		if(next_input == I_WAIT_FOR_EVENT) {
			/* we may be waiting for an a-sync task to "happen"
			 * and until it does, we cant do anything else
			 *
			 * Re-add the last action
			 */

			actions |= last_action;
					
			crm_info("Wait until something else happens");
			break;
		}

#ifdef FSA_TRACE
		crm_verbose("FSA while loop:\tState: %s, Input: %s",
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
			crm_verbose("Adding actions %.16llx", new_actions);
#endif
			actions |= new_actions;
		}

		/* logging : *before* the state is changed */
		IF_FSA_ACTION(A_ERROR, do_log)
		else IF_FSA_ACTION(A_WARN, do_log)
		else IF_FSA_ACTION(A_LOG,  do_log)

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

			crm_info("Nothing to do");
			next_input = I_NULL;
		
/*			// check registers, see if anything is pending
			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				crm_verbose("(Re-)invoking shutdown");
				next_input = I_SHUTDOWN;
			} else if(is_set(fsa_input_register, R_INVOKE_PE)) {
				crm_verbose("Invoke the PE somehow");
			}
*/
		}
	
	
		/* get out of here NOW! before anything worse happens */
	else IF_FSA_ACTION(A_EXIT_1,	do_exit)
		
		else IF_FSA_ACTION(A_STARTUP,	do_startup)
		
		else IF_FSA_ACTION(A_CIB_START,  do_cib_control)
		else IF_FSA_ACTION(A_READCONFIG,	do_read_config)
		else IF_FSA_ACTION(A_HA_CONNECT, do_ha_control)
		else IF_FSA_ACTION(A_LRM_CONNECT,do_lrm_control)
		else IF_FSA_ACTION(A_CCM_CONNECT,do_ccm_control)
		
		/* sub-system start */
		else IF_FSA_ACTION(A_TE_START,	do_te_control)
		else IF_FSA_ACTION(A_PE_START,	do_pe_control)
		
		/* sub-system restart
		 */
		else IF_FSA_ACTION(O_CIB_RESTART,do_cib_control)
		else IF_FSA_ACTION(O_PE_RESTART, do_pe_control)
		else IF_FSA_ACTION(O_TE_RESTART, do_te_control)
		
		else IF_FSA_ACTION(A_STARTED,	do_started)
		
		/* DC Timer */
		else IF_FSA_ACTION(O_DC_TIMER_RESTART,	do_dc_timer_control)
		else IF_FSA_ACTION(A_DC_TIMER_STOP,	do_dc_timer_control)
		else IF_FSA_ACTION(A_DC_TIMER_START,	do_dc_timer_control)
		
		/*
		 * Highest priority actions
		 */

		/* the order of these is finiky...
		 * the status section seems to dissappear after the BUMPGEN!!!
		 * Yet BUMPGEN is non-destructive
		 */
		else IF_FSA_ACTION(A_TE_COPYTO,		do_te_copyto)
		else IF_FSA_ACTION(A_CIB_BUMPGEN,	do_cib_invoke)

		else IF_FSA_ACTION(A_MSG_ROUTE,		do_msg_route)
		else IF_FSA_ACTION(A_RECOVER,		do_recover)
		else IF_FSA_ACTION(A_UPDATE_NODESTATUS,	do_update_node_status)
		else IF_FSA_ACTION(A_JOIN_ACK,		do_ack_welcome)
		else IF_FSA_ACTION(A_SHUTDOWN_REQ,	do_shutdown_req)
		else IF_FSA_ACTION(A_ELECTION_VOTE,	do_election_vote)
		else IF_FSA_ACTION(A_ELECT_TIMER_STOP,	do_election_timer_ctrl)
		else IF_FSA_ACTION(A_ELECT_TIMER_START,	do_election_timer_ctrl)
		else IF_FSA_ACTION(A_ELECTION_COUNT,	do_election_count_vote)
		else IF_FSA_ACTION(A_ELECTION_TIMEOUT,	do_election_timer_ctrl)
		
		/*
		 * "Get this over with" actions
		 */
		else IF_FSA_ACTION(A_MSG_STORE,		do_msg_store)
		
		/*
		 * High priority actions
		 * Update the cache first
		 */
		else IF_FSA_ACTION(A_CCM_UPDATE_CACHE,	do_ccm_update_cache)
		else IF_FSA_ACTION(A_CCM_EVENT,		do_ccm_event)
		
		/*
		 * Medium priority actions
		 */
		else IF_FSA_ACTION(A_DC_TAKEOVER,	do_dc_takeover)
		else IF_FSA_ACTION(A_DC_RELEASE,		do_dc_release)
		else IF_FSA_ACTION(A_JOIN_WELCOME_ALL,	do_send_welcome_all)
		else IF_FSA_ACTION(A_JOIN_WELCOME,	do_send_welcome)
		else IF_FSA_ACTION(A_JOIN_PROCESS_ACK,	do_process_welcome_ack)
		
		/*
		 * Low(er) priority actions
		 * Make sure the CIB is always updated before invoking the
		 * PE, and the PE before the TE
		 */
		else IF_FSA_ACTION(A_CIB_INVOKE_LOCAL,	do_cib_invoke)
		else IF_FSA_ACTION(A_CIB_INVOKE,		do_cib_invoke)
		else IF_FSA_ACTION(A_LRM_INVOKE,		do_lrm_invoke)
		else IF_FSA_ACTION(A_LRM_EVENT,		do_lrm_event)
		else IF_FSA_ACTION(A_TE_CANCEL,		do_te_invoke)
		else IF_FSA_ACTION(A_PE_INVOKE,		do_pe_invoke)
		else IF_FSA_ACTION(A_TE_INVOKE,		do_te_invoke)
		else IF_FSA_ACTION(A_ANNOUNCE,		do_announce)
		
		/* sub-system stop */
		else IF_FSA_ACTION(A_PE_STOP,		do_pe_control)
		else IF_FSA_ACTION(A_TE_STOP,		do_te_control)
		else IF_FSA_ACTION(A_DC_RELEASED,	do_dc_release)

		else IF_FSA_ACTION(A_HA_DISCONNECT,	do_ha_control)
		else IF_FSA_ACTION(A_CCM_DISCONNECT,	do_ccm_control)
		else IF_FSA_ACTION(A_LRM_DISCONNECT,	do_lrm_control)
		else IF_FSA_ACTION(A_CIB_STOP,		do_cib_control)		
		/* time to go now... */
		
		/* Some of these can probably be consolidated */
		else IF_FSA_ACTION(A_SHUTDOWN,   do_shutdown)
		else IF_FSA_ACTION(A_STOP,	do_stop)
		
		/* exit gracefully */
		else IF_FSA_ACTION(A_EXIT_0,	do_exit)

/*		else IF_FSA_ACTION(A_, do_) */
		
		else if((actions & A_MSG_PROCESS) != 0
			|| is_message()) {
			xmlNodePtr stored_msg = NULL;
			crm_verbose("Checking messages... %d",
				  g_list_length(fsa_message_queue));
			
			stored_msg = get_message();
			
			if(is_message() == FALSE) {
				actions = clear_bit(actions, A_MSG_PROCESS);
			}
			
			if(stored_msg == NULL) {
				crm_err("Invalid stored message");
				continue;
			}

			/*
			 * This is where we should clean up old messages
			 * The problem is that we dont always know the
			 * type of the data (and therefore the correct way
			 * to free it).  A wrapper is probably required.
			 */
			data = stored_msg;

#ifdef DOT_FSA_ACTIONS
			fprintf(dot_strm,
				"\t// %s:\t%s\t(data? %s)",	
				fsa_input2string(cur_input),
				fsa_action2string(A_MSG_PROCESS),
				stored_msg==NULL?XML_BOOLEAN_NO:XML_BOOLEAN_YES);
			fflush(dot_strm);
#endif
#ifdef FSA_TRACE
			crm_verbose("Invoking action %s (%.16llx)",
				   fsa_action2string(A_MSG_PROCESS),
				   A_MSG_PROCESS);
#endif

/*#ifdef FSA_TRACE*/
			crm_xml_devel(stored_msg,"FSA processing message");
/*#endif*/

			next_input = handle_message(stored_msg);

#ifdef DOT_FSA_ACTIONS
			fprintf(dot_strm, "\t(result=%s)\n",
				fsa_input2string(next_input));
#endif
#ifdef FSA_TRACE
			crm_verbose("Result of action %s was %s",
				   fsa_action2string(A_MSG_PROCESS),
				   fsa_input2string(next_input));
#endif
			
			/* Error checking and reporting */
		} else if(cur_input != I_NULL && is_set(actions, A_NOTHING)) {
			crm_warn(
			       "No action specified for input,state (%s,%s)",
			       fsa_input2string(cur_input),
			       fsa_state2string(cur_state));
			
			next_input = I_NULL;
			
		} else if(cur_input == I_NULL && is_set(actions, A_NOTHING)) {
#ifdef FSA_TRACE
			crm_info("Nothing left to do");
#endif			
		} else {
			crm_err("Action %s (0x%llx) not supported ",
			       fsa_action2string(actions), actions);
			next_input = I_ERROR;
		}

		if(is_message()) {
			actions |= A_MSG_PROCESS;
		}
	}
	
#ifdef FSA_TRACE
	crm_verbose("################# Exiting the FSA (%s) ##################",
		  fsa_state2string(fsa_state));
#endif

#ifdef DOT_FSA_ACTIONS
	fprintf(dot_strm,			
		"\t// ### Exiting the FSA (%s)\n",
		fsa_state2string(fsa_state));
	fflush(dot_strm);
#endif

	/* cleanup inputs? */
	fsa_actions = actions;
	
	return fsa_state;
}




long long 
do_state_transition(long long actions,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_state next_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	gboolean clear_recovery_bit = TRUE;
	long long tmp = actions;
	const char *state_from = fsa_state2string(cur_state);
	const char *state_to   = fsa_state2string(next_state);
	const char *input      = fsa_input2string(current_input);
	
	time_t now = time(NULL);

	if(cur_state == next_state) {
		crm_err("%s called in state %s with no transtion",
		       __FUNCTION__, state_from);
		return A_NOTHING;
	}
	
	
/*	if(current_input != I_NULL */
/*	   && (current_input != I_DC_HEARTBEAT || cur_state != S_NOT_DC)){ */
		
	fprintf(dot_strm,
		"\t\"%s\" -> \"%s\" [ label =\"%s\" ] // %s",
		state_from, state_to, input,
		asctime(localtime(&now)));
	fflush(dot_strm);
	/*}*/

	crm_info("State transition \"%s\" -> \"%s\" [ cause =\"%s\" %s ]",
		 state_from, state_to, input, asctime(localtime(&now)));

	switch(next_state) {
		case S_PENDING:
			break;
		case S_NOT_DC:
			if(is_set(fsa_input_register, R_SHUTDOWN)){
				crm_info("(Re)Issuing shutdown request now"
					 " that we have a new DC");
				tmp = set_bit(tmp, A_SHUTDOWN_REQ);
			}
			break;
		case S_RECOVERY_DC:
		case S_RECOVERY:
			clear_recovery_bit = FALSE;
			break;
		case S_POLICY_ENGINE:
			if(g_hash_table_size(joined_nodes)
			   != fsa_membership_copy->members_size) {
				crm_warn("Only %d (of %d) cluster nodes are"
					 " eligable to run resources.",
					 1+g_hash_table_size(joined_nodes),
					 fsa_membership_copy->members_size);
			} else {
				crm_info("All %d clusters nodes are"
					 " eligable to run resources.",
					 fsa_membership_copy->members_size);
			}
			break;
			
		case S_IDLE:
			dump_rsc_info();
			/* keep going */
		default:
			break;
	}

	if(clear_recovery_bit && next_state != S_PENDING) {
		tmp = clear_bit(tmp, A_RECOVER);
	} else if(clear_recovery_bit == FALSE) {
		tmp = set_bit(tmp, A_RECOVER);
	}
	
	if(tmp != actions) {
		crm_info("Action b4    %.16llx ", actions);
		crm_info("Action after %.16llx ", tmp);
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

void
dump_rsc_info(void)
{
	xmlNodePtr local_cib = get_cib_copy();
	xmlNodePtr root      = get_object_root(XML_CIB_TAG_STATUS, local_cib);
	xmlNodePtr resources = NULL;
	const char *rsc_id    = NULL;
	const char *node_id   = NULL;
	const char *rsc_state = NULL;
	const char *op_status = NULL;
	const char *last_rc   = NULL;
	const char *last_op   = NULL;

	
	const char *path[] = {
		XML_CIB_TAG_LRM,
		XML_LRM_TAG_RESOURCES
	};

	xml_child_iter(
		root, node, XML_CIB_TAG_STATE,
		
		resources = find_xml_node_nested(node, path, DIMOF(path));

		xml_child_iter(
			resources, rsc, XML_LRM_TAG_RESOURCE,

			rsc_id    = xmlGetProp(rsc, XML_ATTR_ID);
			node_id   = xmlGetProp(rsc, XML_LRM_ATTR_TARGET);
			rsc_state = xmlGetProp(rsc, XML_LRM_ATTR_RSCSTATE);
			op_status = xmlGetProp(rsc, XML_LRM_ATTR_OPSTATUS);
			last_rc   = xmlGetProp(rsc, XML_LRM_ATTR_RC);
			last_op   = xmlGetProp(rsc, XML_LRM_ATTR_LASTOP);
			
/* 			if(safe_str_eq(rsc_state, "stopped")) { */
/* 				continue; */
/* 			} */
			
			crm_info("Resource state: %s %s "
				 "[%s (rc=%s) after %s] on %s",
				 rsc_id, rsc_state,
				 op_status, last_rc, last_op, node_id);
			);
		);
}
