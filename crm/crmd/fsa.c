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

extern int num_join_invites;
extern GHashTable *join_requests;
extern GHashTable *confirmed_nodes;

long long
do_state_transition(long long actions,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_state next_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data);

long long clear_flags(long long actions,
			     enum crmd_fsa_cause cause,
			     enum crmd_fsa_state cur_state,
			     enum crmd_fsa_input cur_input);

void dump_rsc_info(void);

#ifdef DOT_FSA_ACTIONS
# ifdef FSA_TRACE
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	crm_verbose("Invoking action %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	next_input = y(x, cause, cur_state, last_input, fsa_data);	\
	crm_verbose("Action complete: %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	if( (x & O_DC_TICKLE) == 0 && next_input != I_DC_HEARTBEAT )	\
		fprintf(dot_strm, "\t// %s\n", fsa_action2string(x));	\
	fflush(dot_strm);						\
     }
# else
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, fsa_data);	\
	if( (x & O_DC_TICKLE) == 0 && next_input != I_DC_HEARTBEAT )	\
		fprintf(dot_strm, "\t// %s\n", fsa_action2string(x));	\
	fflush(dot_strm);						\
     }
# endif
#else
# ifdef FSA_TRACE
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	crm_verbose("Invoking action %s (%.16llx)",			\
		fsa_action2string(x), x);				\
	next_input = y(x, cause, cur_state, last_input, fsa_data);	\
	crm_verbose("Action complete: %s (%.16llx)",			\
		fsa_action2string(x), x);				\
     }
# else
#  define IF_FSA_ACTION(x,y)						\
     if(is_set(actions,x)) {						\
	last_action = x;						\
	actions = clear_bit(actions, x);				\
	next_input = y(x, cause, cur_state, last_input, fsa_data);	\
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
"	\"S_INTEGRATION\" [ fontcolor = \"green\" ]\n"
"	\"S_POLICY_ENGINE\" [ fontcolor = \"green\" ]\n"
"	\"S_TRANSITION_ENGINE\" [ fontcolor = \"green\" ]\n"
"	\"S_RELEASE_DC\" [ fontcolor = \"green\" ]\n"
"	\"S_IDLE\" [ fontcolor = \"green\" ]\n";


static FILE *dot_strm = NULL;

volatile enum crmd_fsa_state fsa_state;
oc_node_list_t *fsa_membership_copy;
ll_cluster_t   *fsa_cluster_conn;
ll_lrm_t       *fsa_lrm_conn;
volatile long long       fsa_input_register;
volatile long long       fsa_actions = A_NOTHING;
const char     *fsa_our_uname;
char	       *fsa_our_dc;

fsa_timer_t *election_trigger = NULL;		/*  */
fsa_timer_t *election_timeout = NULL;		/*  */
fsa_timer_t *shutdown_escalation_timer = NULL; /*  */
fsa_timer_t *integration_timer = NULL;
fsa_timer_t *finalization_timer = NULL;
fsa_timer_t *dc_heartbeat = NULL;
fsa_timer_t *wait_timer = NULL;

int fsa_join_reannouce = 0;
volatile gboolean do_fsa_stall = FALSE;


enum crmd_fsa_state
s_crmd_fsa(enum crmd_fsa_cause cause)
{
	fsa_data_t *fsa_data = NULL;
	long long actions = fsa_actions;
	long long new_actions = A_NOTHING;
	long long last_action = A_NOTHING;
	enum crmd_fsa_input last_input = I_NULL;
	enum crmd_fsa_input cur_input  = I_NULL;
	enum crmd_fsa_input next_input = I_NULL;
	enum crmd_fsa_state starting_state = fsa_state;
	enum crmd_fsa_state last_state = starting_state;
	enum crmd_fsa_state cur_state  = starting_state;
	enum crmd_fsa_state next_state = starting_state;
	
#ifdef FSA_TRACE
	crm_verbose("FSA invoked with Cause: %s\tState: %s",
		   fsa_cause2string(cause),
		   fsa_state2string(cur_state));
#endif

#ifdef DOT_FSA_ACTIONS
	if(dot_strm == NULL) {
		dot_strm = fopen(DEVEL_DIR"/live.dot", "w");
		fprintf(dot_strm, "%s", dot_intro);
		fflush(dot_strm);
	}
#endif
	
	/*
	 * Process actions in order of priority but do only one
	 * action at a time to avoid complicating the ordering.
	 *
	 * Actions may result in a new I_ event, these are added to
	 * (not replace) existing actions before the next iteration.
	 *
	 */
	do_fsa_stall = FALSE;
	while(next_input != I_NULL || actions != A_NOTHING || is_message()) {

		if(do_fsa_stall) {
			/* we may be waiting for an a-sync task to "happen"
			 * and until it does, we cant do anything else
			 */
			crm_info("Wait until something else happens");
			break;

		} else if((is_message() && fsa_data == NULL)
			  || (is_message() && actions == A_NOTHING && next_input == I_NULL)) {
			fsa_data_t *stored_msg = NULL;
			crm_debug("Finished with current input..."
				  " Checking messages (%d remaining)",
				  g_list_length(fsa_message_queue));

			next_input = I_NULL;
			stored_msg = get_message();
			
			if(stored_msg == NULL) {
				crm_crit("Invalid stored message");
				exit(1);
			}
			
			delete_fsa_input(fsa_data);
			
			if(stored_msg->fsa_cause == C_CCM_CALLBACK) {
				crm_devel("FSA processing CCM callback from %s",
					  stored_msg->where);

			} else if(stored_msg->fsa_cause == C_LRM_OP_CALLBACK) {
				crm_devel("FSA processing LRM callback from %s",
					  stored_msg->where);

			} else if(stored_msg->data == NULL) {
				crm_devel("FSA processing input from %s",
					  stored_msg->where);
				
			} else {
				crm_devel("FSA processing XML message from %s",
					  stored_msg->where);
				
				crm_xml_devel(stored_msg->data,
					      "FSA processing message");
			}

			fsa_data = stored_msg;

			/* set up the input */
			next_input = fsa_data->fsa_input;
			/* add any actions back to the queue */
			actions |= fsa_data->actions;
			/* update the cause */
			cause = fsa_data->fsa_cause;

			fsa_dump_actions(fsa_data->actions, "\tadded back");

			crm_debug("FSA input: State=%s\tCause=%s"
				  "\tInput=%s\tOrigin=%s()",
				  fsa_state2string(cur_state),
				  fsa_cause2string(fsa_data->fsa_cause),
				  fsa_input2string(fsa_data->fsa_input),
				  fsa_data->where);
#ifdef DOT_FSA_ACTIONS
			fprintf(dot_strm,
				"\t// FSA input: State=%s\tCause=%s"
				"\tInput=%s\tOrigin=%s()\n",
				fsa_state2string(cur_state),
				fsa_cause2string(fsa_data->fsa_cause),
				fsa_input2string(fsa_data->fsa_input),
				fsa_data->where);
			
			fflush(dot_strm);
#endif
			
		} else if(fsa_data == NULL) {
			crm_malloc(fsa_data, sizeof(fsa_data_t));
			fsa_data->fsa_input = I_NULL;
			fsa_data->fsa_cause = cause;
			fsa_data->actions   = A_NOTHING;
			fsa_data->where     = crm_strdup("s_crmd_fsa (enter)");
			fsa_data->data      = NULL;
		}
		

		/* update input variables */
		cur_input = next_input;
		if(cur_input != I_NULL) {
			/* record the most recent non I_NULL input */
			crm_devel("Updating last_input to %s",
				  fsa_input2string(cur_input));
			last_input = cur_input;
		}
		
		/* get the next batch of actions */
		new_actions = crmd_fsa_actions[cur_input][cur_state];
		if(new_actions != A_NOTHING) {
#ifdef FSA_TRACE
			crm_verbose("Adding actions %.16llx", new_actions);
			fsa_dump_actions(new_actions, "\tscheduled");
#endif
			actions |= new_actions;
		}

		if(fsa_data == NULL) {
			crm_err("No input for FSA.... terminating");
			exit(1);
		}

#ifdef FSA_TRACE
		crm_verbose("FSA while loop:\tState: %s, Cause: %s, Input: %s",
			   fsa_state2string(cur_state),
			   fsa_cause2string(fsa_data->fsa_cause),
			   fsa_input2string(fsa_data->fsa_input));
#endif
		

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
			actions = do_state_transition(
				actions, cause, last_state, cur_state,
				cur_input, fsa_data);
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

		/* get out of here NOW! before anything worse happens */
		IF_FSA_ACTION(A_EXIT_1,		do_exit)

		/* essential start tasks */
		else IF_FSA_ACTION(A_HA_CONNECT,	do_ha_control)
		else IF_FSA_ACTION(A_STARTUP,		do_startup)
		else IF_FSA_ACTION(A_CIB_START,		do_cib_control)
		else IF_FSA_ACTION(A_READCONFIG,	do_read_config)

		/* sub-system start/connect */
		else IF_FSA_ACTION(A_LRM_CONNECT,	do_lrm_control)
		else IF_FSA_ACTION(A_CCM_CONNECT,	do_ccm_control)
		else IF_FSA_ACTION(A_TE_START,		do_te_control)
		else IF_FSA_ACTION(A_PE_START,		do_pe_control)
		
		/* sub-system restart
		 */
		else IF_FSA_ACTION(O_CIB_RESTART,	do_cib_control)
		else IF_FSA_ACTION(O_PE_RESTART,	do_pe_control)
		else IF_FSA_ACTION(O_TE_RESTART,	do_te_control)
		
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
		else IF_FSA_ACTION(A_CL_JOIN_REQUEST,	do_cl_join_request)
		else IF_FSA_ACTION(A_CL_JOIN_RESULT,	do_cl_join_result)
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
		else IF_FSA_ACTION(A_STARTED,		do_started)
		
		/*
		 * Medium priority actions
		 */
		else IF_FSA_ACTION(A_DC_TAKEOVER,	 do_dc_takeover)
		else IF_FSA_ACTION(A_DC_RELEASE,	 do_dc_release)
		else IF_FSA_ACTION(A_DC_JOIN_OFFER_ALL,	 do_dc_join_offer_all)
		else IF_FSA_ACTION(A_DC_JOIN_OFFER_ONE,	 do_dc_join_offer_one)
		else IF_FSA_ACTION(A_DC_JOIN_PROCESS_REQ,do_dc_join_req)
		else IF_FSA_ACTION(A_DC_JOIN_PROCESS_ACK,do_dc_join_ack)
		
		/*
		 * Low(er) priority actions
		 * Make sure the CIB is always updated before invoking the
		 * PE, and the PE before the TE
		 */
		else IF_FSA_ACTION(A_CIB_INVOKE_LOCAL,	do_cib_invoke)
		else IF_FSA_ACTION(A_CIB_INVOKE,	do_cib_invoke)
		else IF_FSA_ACTION(A_DC_JOIN_FINALIZE,	do_dc_join_finalize)
		else IF_FSA_ACTION(A_LRM_INVOKE,	do_lrm_invoke)
		else IF_FSA_ACTION(A_LRM_EVENT,		do_lrm_event)
		else IF_FSA_ACTION(A_TE_CANCEL,		do_te_invoke)
		else IF_FSA_ACTION(A_PE_INVOKE,		do_pe_invoke)
		else IF_FSA_ACTION(A_TE_INVOKE,		do_te_invoke)
		else IF_FSA_ACTION(A_CL_JOIN_ANNOUNCE,	do_cl_join_announce)
		
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
		else IF_FSA_ACTION(A_SHUTDOWN,  do_shutdown)
		else IF_FSA_ACTION(A_STOP,	do_stop)
		
		/* exit gracefully */
		else IF_FSA_ACTION(A_EXIT_0,	do_exit)

/*		else IF_FSA_ACTION(A_, do_) */
		
			/* Error checking and reporting */
		else if(cur_input != I_NULL && actions == A_NOTHING) {
			crm_warn(
			       "No action specified for input,state (%s,%s)",
			       fsa_input2string(cur_input),
			       fsa_state2string(cur_state));
			
			next_input = I_NULL;
			
		} else if(cur_input == I_NULL && actions == A_NOTHING) {
#ifdef FSA_TRACE
			crm_info("Nothing left to do...");
			fsa_dump_actions(actions, "still here");
#endif
			break;
			
		} else {
			crm_err("Action %s (0x%llx) not supported ",
			       fsa_action2string(actions), actions);
			next_input = I_ERROR;
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
	delete_fsa_input(fsa_data);
	
	return fsa_state;
}




long long 
do_state_transition(long long actions,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_state next_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
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
	
	if(current_input != I_DC_HEARTBEAT && cur_state != S_NOT_DC){
		fprintf(dot_strm,
			"\t\"%s\" -> \"%s\" [ label=\"%s\" cause=%s origin=%s ] // %s",
			state_from, state_to, input, fsa_cause2string(cause), msg_data->where,
			asctime(localtime(&now)));
		fflush(dot_strm);
	}

	crm_info("State transition \"%s\" -> \"%s\" [ input=%s cause=%s origin=%s %s ]",
		 state_from, state_to, input, fsa_cause2string(cause), msg_data->where,
		 asctime(localtime(&now)));

	switch(next_state) {
		case S_ELECTION:
			crm_info("Resetting our DC to NULL on election");
			crm_free(fsa_our_dc);
			fsa_our_dc = NULL;
			break;
		case S_NOT_DC:
			if(is_set(fsa_input_register, R_SHUTDOWN)){
				crm_info("(Re)Issuing shutdown request now"
					 " that we have a new DC");
				tmp = set_bit(tmp, A_SHUTDOWN_REQ);
			}
			if(fsa_our_dc == NULL) {
				crm_err("Reached S_NOT_DC without a DC"
					" being recorded");
			}
			break;
		case S_RECOVERY:
			clear_recovery_bit = FALSE;
			break;
			
		case S_FINALIZE_JOIN:
			if(cause != C_FSA_INTERNAL) {
				crm_warn("Progressed to state %s after %s",
					 fsa_state2string(cur_state),
					 fsa_cause2string(cause));
			}
			if(g_hash_table_size(join_requests)
			   != fsa_membership_copy->members_size) {
				crm_warn("Only %d (of %d) cluster nodes "
					 "responded to the join offer.",
					 g_hash_table_size(join_requests),
					 fsa_membership_copy->members_size);
			} else {
				crm_info("All %d clusters nodes "
					 "responded to the join offer.",
					 fsa_membership_copy->members_size);
			}
			break;
			
		case S_POLICY_ENGINE:
			if(cause != C_FSA_INTERNAL) {
				crm_warn("Progressed to state %s after %s",
					 fsa_state2string(cur_state),
					 fsa_cause2string(cause));
			}
			
			if(g_hash_table_size(confirmed_nodes)
			   == fsa_membership_copy->members_size) {
				crm_info("All %d clusters nodes are"
					 " eligable to run resources.",
					 fsa_membership_copy->members_size);

			} else if(g_hash_table_size(confirmed_nodes)
				  == num_join_invites) {
				crm_warn("All %d (%d total) cluster "
					 "nodes are eligable to run resources",
					 g_hash_table_size(confirmed_nodes),
					 fsa_membership_copy->members_size);

			} else {
				crm_warn("Only %d of %d (%d total) cluster "
					 "nodes are eligable to run resources",
					 num_join_invites,
					 g_hash_table_size(confirmed_nodes),
					 fsa_membership_copy->members_size);
			}
			break;
			
		case S_IDLE:
			dump_rsc_info();
			break;
			
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
		clear_bit_inplace(actions, A_DC_TIMER_START);
	}

	if(cur_state == S_STOPPING) {
		clear_bit_inplace(
			actions,
			A_CCM_CONNECT|A_STARTED|A_LRM_CONNECT|
			A_HA_CONNECT|A_CIB_START);
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
