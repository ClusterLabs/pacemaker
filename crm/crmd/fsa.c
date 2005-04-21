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

extern uint highest_born_on;
extern int num_join_invites;
extern GHashTable *welcomed_nodes;
extern GHashTable *integrated_nodes;
extern GHashTable *finalized_nodes;
extern GHashTable *confirmed_nodes;
extern void initialize_join(gboolean before);

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
void dump_rsc_info_callback(const HA_Message *msg, int call_id, int rc,
			    crm_data_t *output, void *user_data);

void ghash_print_node(gpointer key, gpointer value, gpointer user_data);

#define DOT_PREFIX "live.dot: "
#define DOT_LOG    LOG_DEBUG
#define do_dot_log(fmt...)     do_crm_log(DOT_LOG, NULL, NULL, fmt)
#define do_dot_action(fmt...)  do_crm_log(DOT_LOG+1, NULL, NULL, fmt)

longclock_t action_start = 0;
longclock_t action_stop = 0;
longclock_t action_diff = 0;
int action_diff_ms = 0;

#define IF_FSA_ACTION(x,y)						\
   if(is_set(fsa_actions,x)) {						\
	   last_action = x;						\
	   fsa_actions = clear_bit(fsa_actions, x);			\
	   crm_verbose("Invoking action %s (%.16llx)",			\
		       fsa_action2string(x), x);			\
	   if(action_diff_max_ms > 0) {					\
		   action_start = time_longclock();			\
	   }								\
	   next_input = y(x, cause, fsa_state, last_input, fsa_data);	\
	   if(action_diff_max_ms > 0) {					\
		   action_stop = time_longclock();			\
		   action_diff = sub_longclock(action_start, action_stop); \
		   action_diff_ms = longclockto_ms(action_diff);	\
		   if(action_diff_ms > action_diff_max_ms) {		\
			   crm_err("Action %s took %dms to complete",	\
				   fsa_action2string(x),		\
				   action_diff_ms);			\
		   }							\
	   }								\
	   crm_verbose("Action complete: %s (%.16llx)",			\
		       fsa_action2string(x), x);			\
	   CRM_DEV_ASSERT(next_input == I_NULL); 			\
	   do_dot_action(DOT_PREFIX"\t// %s", fsa_action2string(x));	\
   }

/* #define ELSEIF_FSA_ACTION(x,y) else IF_FSA_ACTION(x,y) */
void init_dotfile(void);

void
init_dotfile(void)
{
	do_dot_log(DOT_PREFIX"digraph \"g\" {");
	do_dot_log(DOT_PREFIX"	size = \"30,30\"");
	do_dot_log(DOT_PREFIX"	graph [");
	do_dot_log(DOT_PREFIX"		fontsize = \"12\"");
	do_dot_log(DOT_PREFIX"		fontname = \"Times-Roman\"");
	do_dot_log(DOT_PREFIX"		fontcolor = \"black\"");
	do_dot_log(DOT_PREFIX"		bb = \"0,0,398.922306,478.927856\"");
	do_dot_log(DOT_PREFIX"		color = \"black\"");
	do_dot_log(DOT_PREFIX"	]");
	do_dot_log(DOT_PREFIX"	node [");
	do_dot_log(DOT_PREFIX"		fontsize = \"12\"");
	do_dot_log(DOT_PREFIX"		fontname = \"Times-Roman\"");
	do_dot_log(DOT_PREFIX"		fontcolor = \"black\"");
	do_dot_log(DOT_PREFIX"		shape = \"ellipse\"");
	do_dot_log(DOT_PREFIX"		color = \"black\"");
	do_dot_log(DOT_PREFIX"	]");
	do_dot_log(DOT_PREFIX"	edge [");
	do_dot_log(DOT_PREFIX"		fontsize = \"12\"");
	do_dot_log(DOT_PREFIX"		fontname = \"Times-Roman\"");
	do_dot_log(DOT_PREFIX"		fontcolor = \"black\"");
	do_dot_log(DOT_PREFIX"		color = \"black\"");
	do_dot_log(DOT_PREFIX"	]");
	do_dot_log(DOT_PREFIX"// special nodes");
	do_dot_log(DOT_PREFIX"	\"S_PENDING\" ");
	do_dot_log(DOT_PREFIX"	[");
	do_dot_log(DOT_PREFIX"	 color = \"blue\"");
	do_dot_log(DOT_PREFIX"	 fontcolor = \"blue\"");
	do_dot_log(DOT_PREFIX"	 ]");
	do_dot_log(DOT_PREFIX"	\"S_TERMINATE\" ");
	do_dot_log(DOT_PREFIX"	[");
	do_dot_log(DOT_PREFIX"	 color = \"red\"");
	do_dot_log(DOT_PREFIX"	 fontcolor = \"red\"");
	do_dot_log(DOT_PREFIX"	 ]");
	do_dot_log(DOT_PREFIX"// DC only nodes");
	do_dot_log(DOT_PREFIX"	\"S_INTEGRATION\" [ fontcolor = \"green\" ]");
	do_dot_log(DOT_PREFIX"	\"S_POLICY_ENGINE\" [ fontcolor = \"green\" ]");
	do_dot_log(DOT_PREFIX"	\"S_TRANSITION_ENGINE\" [ fontcolor = \"green\" ]");
	do_dot_log(DOT_PREFIX"	\"S_RELEASE_DC\" [ fontcolor = \"green\" ]");
	do_dot_log(DOT_PREFIX"	\"S_IDLE\" [ fontcolor = \"green\" ]");
}



volatile enum crmd_fsa_state fsa_state = S_STARTING;
oc_node_list_t *fsa_membership_copy;
ll_cluster_t   *fsa_cluster_conn;
ll_lrm_t       *fsa_lrm_conn;
volatile long long       fsa_input_register;
volatile long long       fsa_actions = A_NOTHING;
const char     *fsa_our_uname;
char	       *fsa_our_dc;
cib_t	*fsa_cib_conn = NULL;

fsa_timer_t *election_trigger = NULL;		/*  */
fsa_timer_t *election_timeout = NULL;		/*  */
fsa_timer_t *shutdown_escalation_timer = NULL; /*  */
fsa_timer_t *shutdown_timer = NULL;		/*  */
fsa_timer_t *integration_timer = NULL;
fsa_timer_t *finalization_timer = NULL;
fsa_timer_t *dc_heartbeat = NULL;
fsa_timer_t *wait_timer = NULL;

int fsa_join_reannouce = 0;
volatile gboolean do_fsa_stall = FALSE;

enum crmd_fsa_state
s_crmd_fsa(enum crmd_fsa_cause cause)
{
	time_t now;
	fsa_data_t *fsa_data = NULL;
	long long register_copy = fsa_input_register;
	long long new_actions = A_NOTHING;
	long long last_action = A_NOTHING;
	enum crmd_fsa_input last_input = I_NULL;
	enum crmd_fsa_input cur_input  = I_NULL;
	enum crmd_fsa_input next_input = I_NULL;
	enum crmd_fsa_state starting_state = fsa_state;
	enum crmd_fsa_state last_state = starting_state;
	enum crmd_fsa_state next_state = starting_state;
	
	crm_verbose("FSA invoked with Cause: %s\tState: %s",
		    fsa_cause2string(cause),
		    fsa_state2string(fsa_state));

	/*
	 * Process actions in order of priority but do only one
	 * action at a time to avoid complicating the ordering.
	 *
	 * Actions may result in a new I_ event, these are added to
	 * (not replace) existing actions before the next iteration.
	 *
	 */
	do_fsa_stall = FALSE;
	while(next_input != I_NULL || fsa_actions != A_NOTHING || is_message()) {

 		msg_queue_helper();

		if(do_fsa_stall) {
			/* we may be waiting for an a-sync task to "happen"
			 * and until it does, we cant do anything else
			 */
			crm_info("Wait until something else happens");
			break;

		} else if((is_message() && fsa_data == NULL)
			  || (is_message() && fsa_actions == A_NOTHING && next_input == I_NULL)) {
			fsa_data_t *stored_msg = NULL;
			crm_devel("Finished with current input..."
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
					  stored_msg->origin);

			} else if(stored_msg->fsa_cause == C_LRM_OP_CALLBACK) {
				crm_devel("FSA processing LRM callback from %s",
					  stored_msg->origin);

			} else if(stored_msg->data == NULL) {
				crm_devel("FSA processing input from %s",
					  stored_msg->origin);
				
			} else {
				ha_msg_input_t *ha_input = fsa_typed_data_adv(
					stored_msg, fsa_dt_ha_msg, __FUNCTION__);
				
				crm_devel("FSA processing XML message from %s",
					  stored_msg->origin);
				crm_log_message(LOG_MSG, ha_input->msg);
				crm_xml_devel(ha_input->xml,
					      "FSA message data");
			}

			fsa_data = stored_msg;

			/* set up the input */
			next_input = fsa_data->fsa_input;
			/* add any actions back to the queue */
			fsa_actions |= fsa_data->actions;
			/* update the cause */
			cause = fsa_data->fsa_cause;

			fsa_dump_actions(fsa_data->actions, "\tadded back");

			do_dot_log(DOT_PREFIX"\t// FSA input: State=%s \tCause=%s"
				" \tInput=%s \tOrigin=%s()",
				fsa_state2string(fsa_state),
				fsa_cause2string(fsa_data->fsa_cause),
				fsa_input2string(fsa_data->fsa_input),
				fsa_data->origin);
			
		} else if(fsa_data == NULL) {
			crm_malloc(fsa_data, sizeof(fsa_data_t));
			fsa_data->fsa_input = I_NULL;
			fsa_data->fsa_cause = cause;
			fsa_data->actions   = A_NOTHING;
			fsa_data->origin     = "s_crmd_fsa (enter)";
			fsa_data->data      = NULL;
			fsa_data->data_type = fsa_dt_none;
			if(fsa_data->origin == NULL) {
				crm_crit("Out of memory");
				exit(1);
			}
			
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
		new_actions = crmd_fsa_actions[cur_input][fsa_state];
		if(new_actions != A_NOTHING) {
#ifdef FSA_TRACE
			crm_verbose("Adding actions %.16llx for %s/%s",
				    new_actions, fsa_input2string(cur_input),
				    fsa_state2string(fsa_state));
			fsa_dump_actions(new_actions, "\tscheduled");
#endif
			fsa_actions |= new_actions;
		}

		if(fsa_data == NULL) {
			crm_err("No input for FSA.... terminating");
			exit(1);
		}

#ifdef FSA_TRACE
		crm_verbose("FSA while loop:\tState: %s, Cause: %s,"
			    " Input: %s, Origin=%s",
			    fsa_state2string(crmd_fsa_state[cur_input][fsa_state]),
			    fsa_cause2string(fsa_data->fsa_cause),
			    fsa_input2string(cur_input),
			    fsa_data->origin);
#endif

		/* logging : *before* the state is changed */
		IF_FSA_ACTION(A_ERROR, do_log)
		else IF_FSA_ACTION(A_WARN, do_log)
		else IF_FSA_ACTION(A_LOG,  do_log)

		/* this is always run, some inputs/states may make various
		 * actions irrelevant/invalid
		 */
		fsa_actions = clear_flags(fsa_actions, cause, fsa_state, cur_input);

		/* update state variables */
		next_state  = crmd_fsa_state[cur_input][fsa_state];
		last_state  = fsa_state;
		fsa_state   = next_state;

		/* start doing things... */

		/*
		 * Hook for change of state.
		 * Allows actions to be added or removed when entering a state
		 */
		if(last_state != fsa_state){
			fsa_actions = do_state_transition(
				fsa_actions, cause, last_state, fsa_state,
				cur_input, fsa_data);
		}
	
		/* regular action processing in order of action priority
		 *
		 * Make sure all actions that connect to required systems
		 * are performed first
		 */

		/* get out of here NOW! before anything worse happens */
		IF_FSA_ACTION(A_EXIT_1,		do_exit)

		else IF_FSA_ACTION(A_ERROR, do_log)
		else IF_FSA_ACTION(A_WARN, do_log)
		else IF_FSA_ACTION(A_LOG,  do_log)

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
		
		/* Timers */
/* 		else IF_FSA_ACTION(O_DC_TIMER_RESTART,      do_timer_control) */
		else IF_FSA_ACTION(A_DC_TIMER_STOP,         do_timer_control)
		else IF_FSA_ACTION(A_INTEGRATE_TIMER_STOP,  do_timer_control)
		else IF_FSA_ACTION(A_INTEGRATE_TIMER_START, do_timer_control)
		else IF_FSA_ACTION(A_FINALIZE_TIMER_STOP,   do_timer_control)
		else IF_FSA_ACTION(A_FINALIZE_TIMER_START,  do_timer_control)
		
		/*
		 * Highest priority actions
		 */
		else IF_FSA_ACTION(A_CIB_BUMPGEN,	do_cib_invoke)

		else IF_FSA_ACTION(A_MSG_ROUTE,		do_msg_route)
		else IF_FSA_ACTION(A_RECOVER,		do_recover)
		else IF_FSA_ACTION(A_CL_JOIN_REQUEST,	do_cl_join_request)
		else IF_FSA_ACTION(A_CL_JOIN_RESULT,	do_cl_join_result)
		else IF_FSA_ACTION(A_SHUTDOWN_REQ,	do_shutdown_req)

		else IF_FSA_ACTION(A_ELECTION_VOTE,	do_election_vote)
		else IF_FSA_ACTION(A_ELECTION_COUNT,	do_election_count_vote)
		
		/*
		 * High priority actions
		 * Update the cache first
		 */
		else IF_FSA_ACTION(A_CCM_UPDATE_CACHE,	do_ccm_update_cache)
		else IF_FSA_ACTION(A_CCM_EVENT,		do_ccm_event)
		else IF_FSA_ACTION(A_STARTED,		do_started)
		else IF_FSA_ACTION(A_CL_JOIN_QUERY,     do_cl_join_query)
		else IF_FSA_ACTION(A_DC_TIMER_START,    do_timer_control)
		
		/*
		 * Medium priority actions
		 */
		else IF_FSA_ACTION(A_DC_TAKEOVER,	 do_dc_takeover)
		else IF_FSA_ACTION(A_DC_RELEASE,	 do_dc_release)
		else IF_FSA_ACTION(A_ELECTION_START,	 do_election_vote)
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
		else IF_FSA_ACTION(A_DC_RELEASED,	do_dc_release)
		else IF_FSA_ACTION(A_PE_STOP,		do_pe_control)
		else IF_FSA_ACTION(A_TE_STOP,		do_te_control)
		else IF_FSA_ACTION(A_CCM_DISCONNECT,	do_ccm_control)

		else IF_FSA_ACTION(A_SHUTDOWN,		do_shutdown)
		else IF_FSA_ACTION(A_LRM_DISCONNECT,	do_lrm_control)
		else IF_FSA_ACTION(A_HA_DISCONNECT,	do_ha_control)
		else IF_FSA_ACTION(A_CIB_STOP,		do_cib_control)
		else IF_FSA_ACTION(A_STOP,		do_stop)
		
		/* exit gracefully */
		else IF_FSA_ACTION(A_EXIT_0,	do_exit)

/*		else IF_FSA_ACTION(A_, do_) */
		
			/* Error checking and reporting */
		else if(cur_input != I_NULL && fsa_actions == A_NOTHING) {
			crm_debug(
			       "No action specified for input,state (%s,%s)",
			       fsa_input2string(cur_input),
			       fsa_state2string(fsa_state));
			
			next_input = I_NULL;
			
		} else if(cur_input == I_NULL && fsa_actions == A_NOTHING) {
#ifdef FSA_TRACE
			crm_info("Nothing left to do...");
			fsa_dump_actions(fsa_actions, "still here");
#endif
			break;
			
		} else {
			crm_err("Action %s (0x%llx) not supported ",
			       fsa_action2string(fsa_actions), fsa_actions);
			next_input = I_ERROR;
		}
	}
	
	now = time(NULL);
	do_dot_log(DOT_PREFIX"\t// ### Exiting the FSA (%s%s): %s",
		  fsa_state2string(fsa_state), do_fsa_stall?": paused":"",
		  asctime(localtime(&now)));

	/* cleanup inputs? */
	delete_fsa_input(fsa_data);
	if(register_copy != fsa_input_register) {
		fsa_dump_inputs(LOG_DEBUG, fsa_input_register);
	}
	
	fsa_dump_queue(LOG_VERBOSE);
	
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
	
	do_dot_log(DOT_PREFIX"\t%s -> %s [ label=%s cause=%s origin=%s ] // %s",
		  state_from, state_to, input, fsa_cause2string(cause),
		  msg_data->origin, asctime(localtime(&now)));
	
	crm_info("State transition %s -> %s [ input=%s cause=%s origin=%s ]",
		 state_from, state_to, input, fsa_cause2string(cause),
		 msg_data->origin);

	/* the last two clauses might cause trouble later */
	if(election_timeout != NULL
	   && next_state != S_ELECTION
	   && next_state != S_RELEASE_DC
	   && next_state != S_PENDING) {
		crm_timer_stop(election_timeout);
/* 	} else { */
/* 		crm_timer_start(election_timeout); */
	}
#if 0
	if(is_set(fsa_input_register, R_SHUTDOWN)){
		set_bit_inplace(tmp, A_DC_TIMER_STOP);
	}
#endif
	if(next_state == S_INTEGRATION) {
		set_bit_inplace(tmp, A_INTEGRATE_TIMER_START);
	} else {
		set_bit_inplace(tmp, A_INTEGRATE_TIMER_STOP);
	}
	
	if(next_state == S_FINALIZE_JOIN) {
		set_bit_inplace(tmp, A_FINALIZE_TIMER_START);
	} else {
		set_bit_inplace(tmp, A_FINALIZE_TIMER_STOP);
	}
	
	if(next_state == S_PENDING) {
		set_bit_inplace(tmp, A_DC_TIMER_START);
	} else {
		set_bit_inplace(tmp, A_DC_TIMER_STOP);
	}
	if(next_state != S_ELECTION) {
		highest_born_on = 0;
	}
	
	switch(next_state) {
		case S_PENDING:			
		case S_ELECTION:
			crm_info("Resetting our DC to NULL on election");
			crm_free(fsa_our_dc);
			fsa_our_dc = NULL;
			break;
		case S_NOT_DC:
			if(is_set(fsa_input_register, R_SHUTDOWN)){
				crm_info("(Re)Issuing shutdown request now"
					 " that we have a new DC");
				set_bit_inplace(tmp, A_SHUTDOWN_REQ);
			}
			CRM_DEV_ASSERT(fsa_our_dc != NULL);
			if(fsa_our_dc == NULL) {
				crm_err("Reached S_NOT_DC without a DC"
					" being recorded");
			}
			break;
		case S_RECOVERY:
			clear_recovery_bit = FALSE;
			break;

		case S_FINALIZE_JOIN:
			if(cause == C_TIMER_POPPED) {
				crm_warn("Progressed to state %s after %s",
					 fsa_state2string(next_state),
					 fsa_cause2string(cause));
			}
			if(g_hash_table_size(welcomed_nodes) > 0) {
				char *msg = crm_strdup(
					"  Welcome reply not received from");
				
				crm_warn("%u cluster nodes failed to respond"
					 "to the join offer.",
					 g_hash_table_size(welcomed_nodes));
				g_hash_table_foreach(
					welcomed_nodes, ghash_print_node, msg);

			} else {
				crm_info("All %d cluster nodes "
					 "responded to the join offer.",
					 fsa_membership_copy->members_size);
			}
			break;
			
		case S_POLICY_ENGINE:
			if(cause == C_TIMER_POPPED) {
				crm_warn("Progressed to state %s after %s",
					 fsa_state2string(next_state),
					 fsa_cause2string(cause));
			}
			
			if(g_hash_table_size(finalized_nodes) > 0) {
				char *msg = crm_strdup(
					"  Confirm not received from");
				
				crm_err("%u cluster nodes failed to confirm"
					 " their join.",
					 g_hash_table_size(finalized_nodes));
				g_hash_table_foreach(
					finalized_nodes, ghash_print_node, msg);
				
			} else if(g_hash_table_size(confirmed_nodes)
				  == fsa_membership_copy->members_size) {
				crm_info("All %u cluster nodes are"
					 " eligable to run resources.",
					 fsa_membership_copy->members_size);
				
			} else {
				crm_warn("Only %u of %u cluster "
					 "nodes are eligable to run resources",
					 g_hash_table_size(confirmed_nodes),
					 fsa_membership_copy->members_size);
			}
/* 			initialize_join(FALSE); */
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
		fsa_dump_actions(actions ^ tmp, "New actions");
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
	long long saved_actions = actions;
	long long startup_actions = A_STARTUP|A_CIB_START|A_LRM_CONNECT|A_CCM_CONNECT|A_HA_CONNECT|A_READCONFIG|A_STARTED|A_CL_JOIN_QUERY;
	
	if(cur_state == S_STOPPING || is_set(fsa_input_register, R_SHUTDOWN)) {
		clear_bit_inplace(actions, startup_actions);
	}

	fsa_dump_actions(actions ^ saved_actions, "Cleared Actions");
	return actions;
}

void
dump_rsc_info(void)
{
}


void
ghash_print_node(gpointer key, gpointer value, gpointer user_data) 
{
	const char *text = user_data;
	const char *uname = key;
	crm_info("%s: %s", text, uname);
}
