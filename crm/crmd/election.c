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

#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/crm.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/dmalloc_wrapper.h>

void ghash_count_vote(gpointer key, gpointer value, gpointer user_data);

/*	A_ELECTION_VOTE	*/
enum crmd_fsa_input
do_election_vote(long long action,
		 enum crmd_fsa_cause cause,
		 enum crmd_fsa_state cur_state,
		 enum crmd_fsa_input current_input,
		 void *data)
{
	enum crmd_fsa_input election_result = I_NULL;
	

	/* dont vote if we're in one of these states or wanting to shut down */
	switch(cur_state) {
		case S_RECOVERY:
		case S_RECOVERY_DC:
		case S_STOPPING:
		case S_RELEASE_DC:
		case S_TERMINATE:
			return I_NULL;
			// log warning
			break;
		default:
			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				return I_NULL;
				// log warning
			}
			break;
	}
	
	send_request(NULL, NULL, CRM_OP_VOTE,
		     NULL, CRM_SYSTEM_CRMD, NULL);
	
	return election_result;
}

gboolean
do_dc_heartbeat(gpointer data)
{
	fsa_timer_t *timer = (fsa_timer_t *)data;
//	crm_debug("#!!#!!# Heartbeat timer just popped!");
	
	gboolean was_sent = send_request(NULL, NULL, CRM_OP_HBEAT, 
					 NULL, CRM_SYSTEM_CRMD, NULL);

	if(was_sent == FALSE) {
		// this is bad
		stopTimer(timer); // dont make it go off again
		s_crmd_fsa(C_HEARTBEAT_FAILED, I_SHUTDOWN, NULL);
	}
	
	return TRUE;
}

struct election_data_s 
{
		const char *winning_uname;
		unsigned int winning_bornon;
};

/*	A_ELECTION_COUNT	*/
enum crmd_fsa_input
do_election_count_vote(long long action,
		       enum crmd_fsa_cause cause,
		       enum crmd_fsa_state cur_state,
		       enum crmd_fsa_input current_input,
		       void *data)
{
	gboolean we_loose = FALSE;
	xmlNodePtr vote = (xmlNodePtr)data;
	enum crmd_fsa_input election_result = I_NULL;
	const char *vote_from = xmlGetProp(vote, XML_ATTR_HOSTFROM);
	
	

	if(vote_from == NULL || strcmp(vote_from, fsa_our_uname) == 0) {
		// dont count our own vote
		return election_result;
	}

	if(fsa_membership_copy->members_size < 1) {
		// if even we are not in the cluster then we should not vote
		return I_FAIL;
		
	}

	oc_node_t *our_node = (oc_node_t*)
		g_hash_table_lookup(fsa_membership_copy->members, fsa_our_uname);

	oc_node_t *your_node = (oc_node_t*)
		g_hash_table_lookup(fsa_membership_copy->members, vote_from);

#if 0
	crm_debug("%s (bornon=%d), our bornon (%d)",
		   vote_from, our_node->born, my_born);

	crm_debug("%s %s %s",
	       fsa_our_uname,
	       strcmp(fsa_our_uname, vote_from) < 0?"<":">=",
	       vote_from);
#endif
	
	if(is_set(fsa_input_register, R_SHUTDOWN)) {
		crm_debug("Election fail: we are shutting down");
		we_loose = TRUE;

	} else if(our_node == NULL) {
		crm_debug("Election fail: we dont exist in the CCM list");
		we_loose = TRUE;
		
	} else if(your_node == NULL) {
		crm_err("The other side doesnt exist in the CCM list");
		
	} else if(your_node->node_born_on < our_node->node_born_on) {
		crm_debug("Election fail: born_on");
		we_loose = TRUE;

	} else if(your_node->node_born_on == our_node->node_born_on
		  && strcmp(fsa_our_uname, vote_from) > 0) {
		crm_debug("Election fail: uname");
		we_loose = TRUE;

	} else {
		struct election_data_s election_data;
		election_data.winning_uname = NULL;
		election_data.winning_bornon = -1; // maximum integer
		
		crm_trace("We might win... we should vote (possibly again)");
		election_result = I_DC_TIMEOUT; // new "default"

		g_hash_table_foreach(fsa_membership_copy->members,
				     ghash_count_vote, &election_data);
		
		crm_debug("Election winner should be %s (born_on=%d)",
		       election_data.winning_uname, election_data.winning_bornon);
		
	
		if(safe_str_eq(election_data.winning_uname, fsa_our_uname)){
			crm_debug("Election win: lowest born_on and uname");
			election_result = I_ELECTION_DC;
		}
	}
	
	if(we_loose) {
		if(fsa_input_register & R_THE_DC) {
			crm_debug("Give up the DC");
			election_result = I_RELEASE_DC;
			
		} else {
			crm_debug("We werent the DC anyway");
			election_result = I_NOT_DC;
			
		}
	}

	if(we_loose || election_result == I_ELECTION_DC) {
		// cancel timer, its been decided
		stopTimer(election_timeout);
	}
	
	return election_result;
}

/*	A_ELECT_TIMER_START, A_ELECTION_TIMEOUT 	*/
// we won
enum crmd_fsa_input
do_election_timer_ctrl(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	

	if(action & A_ELECT_TIMER_START) {
		startTimer(election_timeout);
		
	} else if(action & A_ELECT_TIMER_STOP || action & A_ELECTION_TIMEOUT) {
		stopTimer(election_timeout);
		
	} else {
		crm_err("unexpected action %s",
		       fsa_action2string(action));
	}

	if(action & A_ELECTION_TIMEOUT) {
		crm_trace("The election timer went off, we win!");
	
		return I_ELECTION_DC;
		
	}

	
	return I_NULL;
}

/*	A_DC_TIMER_STOP, A_DC_TIMER_START	*/
enum crmd_fsa_input
do_dc_timer_control(long long action,
		   enum crmd_fsa_cause cause,
		   enum crmd_fsa_state cur_state,
		   enum crmd_fsa_input current_input,
		   void *data)
{
	gboolean timer_op_ok = TRUE;
	

	if(action & A_DC_TIMER_STOP) {
		timer_op_ok = stopTimer(election_trigger);
	}

	/* dont start a timer that wasnt already running */
	if(action & A_DC_TIMER_START && timer_op_ok) {
		startTimer(election_trigger);
	}
	
	return I_NULL;
}


/*	 A_DC_TAKEOVER	*/
enum crmd_fsa_input
do_dc_takeover(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
{
	xmlNodePtr update = NULL, fragment = NULL;
	

	crm_trace("################## Taking over the DC ##################");
	set_bit_inplace(&fsa_input_register, R_THE_DC);

	crm_verbose("Am I the DC? %s", AM_I_DC?XML_BOOLEAN_YES:XML_BOOLEAN_NO);
	
	fsa_our_dc = NULL;
	set_bit_inplace(&fsa_input_register, R_JOIN_OK);
	set_bit_inplace(&fsa_input_register, R_INVOKE_PE);
	
	clear_bit_inplace(&fsa_input_register, R_CIB_DONE);
	clear_bit_inplace(&fsa_input_register, R_HAVE_CIB);

	startTimer(dc_heartbeat);

	if (fsa_cluster_conn->llc_ops->set_cstatus_callback(
		    fsa_cluster_conn, crmd_client_status_callback, NULL)!=HA_OK){
		crm_err("Cannot set client status callback\n");
		crm_err("REASON: %s\n",
		       fsa_cluster_conn->llc_ops->errmsg(fsa_cluster_conn));
	}

	/* store our state in the CIB (since some fields will not be
	 *  filled in because the DC doesnt go through the join process
	 *  with itself
	 *
	 * bypass the TE for now, it will be informed in good time
	 */
	update = create_node_state(
		fsa_our_uname, NULL, ONLINESTATUS, CRMD_JOINSTATE_MEMBER);
	set_xml_property_copy(
		update,XML_CIB_ATTR_EXPSTATE, CRMD_STATE_ACTIVE);
	
	fragment = create_cib_fragment(update, NULL);
	store_request(NULL, fragment, CRM_OP_UPDATE, CRM_SYSTEM_DCIB);

	free_xml(update);
	free_xml(fragment);

	/* Async get client status information in the cluster */
	fsa_cluster_conn->llc_ops->client_status(
		fsa_cluster_conn, NULL, CRM_SYSTEM_CRMD, -1);
	
	return I_NULL;
}

/*	 A_DC_RELEASE	*/
enum crmd_fsa_input
do_dc_release(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      void *data)
{
	enum crmd_fsa_input result = I_NULL;
	

	crm_trace("################## Releasing the DC ##################");

	stopTimer(dc_heartbeat);
	if (fsa_cluster_conn->llc_ops->set_cstatus_callback(
		    fsa_cluster_conn, NULL, NULL)!=HA_OK){
		crm_err("Cannot unset client status callback\n");
		crm_err("REASON: %s\n",
		       fsa_cluster_conn->llc_ops->errmsg(fsa_cluster_conn));
		result = I_ERROR;
	}

	if(action & A_DC_RELEASE) {
		clear_bit_inplace(&fsa_input_register, R_THE_DC);
		
		/* get a new CIB from the new DC */
		clear_bit_inplace(&fsa_input_register, R_HAVE_CIB);
	} else if (action & A_DC_RELEASED) {

		if(cur_state == S_STOPPING) {
			result = I_SHUTDOWN; // necessary?
			result = I_RELEASE_SUCCESS;
		}
#if 0
		else if( are there errors ) {
			// we cant stay up if not healthy
			// or perhaps I_ERROR and go to S_RECOVER?
			result = I_SHUTDOWN;
		}
#endif
		else
			result = I_RELEASE_SUCCESS;

	} else {
		crm_err("Warning, do_dc_release invoked for action %s",
		       fsa_action2string(action));
	}

	crm_verbose("Am I still the DC? %s", AM_I_DC?XML_BOOLEAN_YES:XML_BOOLEAN_NO);

	return result;
}

void
ghash_count_vote(gpointer key, gpointer value, gpointer user_data)
{
	
	struct election_data_s *election_data =
		(struct election_data_s *)user_data;

	oc_node_t *cur_node = (oc_node_t*)value;
	const char *node_uname = (const char*)key;
	
	if(election_data->winning_bornon > cur_node->node_born_on) {
		election_data->winning_uname = node_uname;
		election_data->winning_bornon = cur_node->node_born_on;
		
	} else if(election_data->winning_bornon == cur_node->node_born_on
		  && (election_data->winning_uname == NULL
		      || strcmp(election_data->winning_uname, node_uname) > 0)) {
		election_data->winning_uname = node_uname;
		election_data->winning_bornon = cur_node->node_born_on;

	}
}

