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
		 fsa_data_t *msg_data)
{
	gboolean not_voting = FALSE;
	HA_Message *vote = NULL;
	
	/* dont vote if we're in one of these states or wanting to shut down */
	switch(cur_state) {
		case S_RECOVERY:
		case S_STOPPING:
		case S_RELEASE_DC:
		case S_TERMINATE:
			crm_warn("Not voting in election, we're in state %s",
				 fsa_state2string(cur_state));
			not_voting = TRUE;
			break;
		default:
 			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				crm_warn("Not voting in election,"
					 " we're shutting down");
				not_voting = TRUE;
			}
			break;
	}

	if(not_voting == FALSE) {
		if(is_set(fsa_input_register, R_STARTING)) {
			not_voting = TRUE;
		}
	}	

	vote = create_request(
		CRM_OP_VOTE, NULL, NULL,
		CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);
	
	if(action & A_ELECTION_START) {
		/* leaving out our version number, no other node out there
		 * will think we should win the election...
		 * which is what we want if we are the DC and want to shutdown 
		 */
		ha_msg_mod(vote, XML_ATTR_VERSION, "0");
		
	} else if(not_voting) {
		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);
		if(AM_I_DC) {
			return I_RELEASE_DC;
		} else {
			return I_NOT_DC;
		}
	}

	send_request(vote, NULL);
	startTimer(election_timeout);		

	return I_NULL;
}

char *dc_hb_msg = NULL;

gboolean
do_dc_heartbeat(gpointer data)
{
	fsa_timer_t *timer = (fsa_timer_t *)data;

/*	crm_debug("#!!#!!# Heartbeat timer just popped!"); */
	HA_Message *msg = ha_msg_new(5); 
	ha_msg_add(msg, F_TYPE,		T_CRM);
	ha_msg_add(msg, F_SUBTYPE,	XML_ATTR_REQUEST);
	ha_msg_add(msg, F_CRM_SYS_TO,   CRM_SYSTEM_CRMD);
	ha_msg_add(msg, F_CRM_SYS_FROM, CRM_SYSTEM_DC);
	ha_msg_add(msg, F_CRM_TASK,	CRM_OP_HBEAT);

	if(send_msg_via_ha(fsa_cluster_conn, msg) == FALSE) {
		/* this is bad */
		stopTimer(timer); /* dont make it go off again */

		register_fsa_input(C_HEARTBEAT_FAILED, I_SHUTDOWN, NULL);
		s_crmd_fsa(C_HEARTBEAT_FAILED);

		return FALSE;
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
		       fsa_data_t *msg_data)
{
	gboolean we_loose = FALSE;
	ha_msg_input_t *vote = fsa_typed_data(fsa_dt_ha_msg);
	enum crmd_fsa_input election_result = I_NULL;
	const char *vote_from    = cl_get_string(vote->msg, F_CRM_HOST_FROM);
	const char *your_version = cl_get_string(vote->msg, F_CRM_VERSION);
	oc_node_t *our_node = NULL, * your_node = NULL;
	struct election_data_s election_data;

	if(vote_from == NULL || strcmp(vote_from, fsa_our_uname) == 0) {
		/* dont count our own vote */
		return election_result;
	}

	if(fsa_membership_copy == NULL) {
		/* if the membership copy is NULL we REALLY shouldnt be voting
		 * the question is how we managed to get here.
		 */
		crm_err("Membership copy was NULL");
		return I_NULL;
		
	} else if(fsa_membership_copy->members_size < 1) {
		
		/* if even we are not in the cluster then we should not vote */
		return I_NULL;
	}

	our_node = (oc_node_t*)
		g_hash_table_lookup(fsa_membership_copy->members, fsa_our_uname);

	your_node = (oc_node_t*)
		g_hash_table_lookup(fsa_membership_copy->members, vote_from);

	if(is_set(fsa_input_register, R_SHUTDOWN)) {
		crm_debug("Election fail: we are shutting down");
		we_loose = TRUE;

	} else if(our_node == NULL) {
		crm_debug("Election fail: we dont exist in the CCM list");
		we_loose = TRUE;
		
	} else if(your_node == NULL) {
		crm_err("The other side doesnt exist in the CCM list");
		
	} else if(compare_version(your_version, CRM_VERSION) > 0) {
		crm_debug("Election fail: version");
		we_loose = TRUE;
		
	} else if(your_node->node_born_on < our_node->node_born_on) {
		crm_debug("Election fail: born_on");
		we_loose = TRUE;

	} else if(your_node->node_born_on == our_node->node_born_on
		  && strcmp(fsa_our_uname, vote_from) > 0) {
		crm_debug("Election fail: uname");
		we_loose = TRUE;

	} else {
		election_data.winning_uname = NULL;
		election_data.winning_bornon = -1; /* maximum integer */
		
		crm_trace("We might win... we should vote (possibly again)");
		election_result = I_ELECTION; /* new "default" */
	}
	
	if(we_loose) {
		stopTimer(election_timeout);
		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);
		if(fsa_input_register & R_THE_DC) {
			crm_debug("Give up the DC");
			election_result = I_RELEASE_DC;
			
		} else {
			crm_debug("We werent the DC anyway");
			election_result = I_PENDING;
			
		}
	}

	return election_result;
}

/*	A_ELECT_TIMER_START, A_ELECTION_TIMEOUT 	*/
/* we won */
enum crmd_fsa_input
do_election_timer_ctrl(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	return I_NULL;
}



/*	 A_DC_TAKEOVER	*/
enum crmd_fsa_input
do_dc_takeover(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	enum crmd_fsa_input result = I_NULL;
	crm_data_t *cib = createEmptyCib();
	crm_data_t *update = NULL;
	crm_data_t *output = NULL;
	int rc = cib_ok;
	
	crm_trace("################## Taking over the DC ##################");
	set_bit_inplace(fsa_input_register, R_THE_DC);

	crm_verbose("Am I the DC? %s", AM_I_DC?XML_BOOLEAN_YES:XML_BOOLEAN_NO);

	crm_free(fsa_our_dc);
	fsa_our_dc = crm_strdup(fsa_our_uname);

	set_bit_inplace(fsa_input_register, R_JOIN_OK);
	set_bit_inplace(fsa_input_register, R_INVOKE_PE);
	
	clear_bit_inplace(fsa_input_register, R_CIB_DONE);
	clear_bit_inplace(fsa_input_register, R_HAVE_CIB);

	startTimer(dc_heartbeat);

	fsa_cib_conn->cmds->set_slave_all(fsa_cib_conn, cib_none);
	fsa_cib_conn->cmds->set_master(fsa_cib_conn, cib_none);

	crm_debug("Update %s in the CIB to our uuid: %s",
		  XML_ATTR_DC_UUID, crm_element_value(cib, XML_ATTR_DC_UUID));
	
	set_uuid(cib, XML_ATTR_DC_UUID, fsa_our_uname);
	update = create_cib_fragment(cib, NULL);
	free_xml(cib);

	rc = fsa_cib_conn->cmds->modify(
		fsa_cib_conn, NULL, update, &output,
		cib_sync_call|cib_verbose);
	
	if(rc == cib_ok) {
		int revision_i = -1;
		const char *revision = NULL;

		crm_debug("Checking our feature revision is allowed: %d",
			  cib_feature_revision);

		cib = find_xml_node(output, XML_TAG_CIB, TRUE);
		
		revision = crm_element_value(cib, XML_ATTR_CIB_REVISION);
		revision_i = atoi(revision?revision:"0");

		if(revision_i > cib_feature_revision) {
			crm_err("Feature revision not permitted");
			/* go into a stall state */
			result = I_HALT;
		}

	} else if(rc == cib_revision_unsupported) {
		crm_err("Feature revision not permitted");
		/* go into a stall state */
		result = I_HALT;
		
	} else 	if(rc != cib_ok) {
		crm_err("DC UUID update failed: %s", cib_error2string(rc));
		result = I_FAIL;

	}
	
	free_xml(update);
	
	crm_debug("Requesting an initial dump of CRMD client_status");
	fsa_cluster_conn->llc_ops->client_status(
		fsa_cluster_conn, NULL, CRM_SYSTEM_CRMD, -1);
	
	return result;
}

/*	 A_DC_RELEASE	*/
enum crmd_fsa_input
do_dc_release(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	enum crmd_fsa_input result = I_NULL;
	

	crm_trace("################## Releasing the DC ##################");

	stopTimer(dc_heartbeat);
	if(action & A_DC_RELEASE) {
		clear_bit_inplace(fsa_input_register, R_THE_DC);
		
		/* get a new CIB from the new DC */
		clear_bit_inplace(fsa_input_register, R_HAVE_CIB);

	} else if (action & A_DC_RELEASED) {
		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);

		if(cur_state == S_STOPPING) {
			result = I_SHUTDOWN; /* necessary? */
			result = I_RELEASE_SUCCESS;
		}
#if 0
		else if( are there errors ) {
			/* we cant stay up if not healthy */
			/* or perhaps I_ERROR and go to S_RECOVER? */
			result = I_SHUTDOWN;
		}
#endif
		else {
			result = I_RELEASE_SUCCESS;
		}
		
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

