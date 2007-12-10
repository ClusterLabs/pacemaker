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
#include <crm_internal.h>

#include <heartbeat.h>

#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/crm.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_uuid.h>
#include <ha_version.h>

GHashTable *voted = NULL;
uint highest_born_on = -1;
static int current_election_id = 1;

/*	A_ELECTION_VOTE	*/
void
do_election_vote(long long action,
		 enum crmd_fsa_cause cause,
		 enum crmd_fsa_state cur_state,
		 enum crmd_fsa_input current_input,
		 fsa_data_t *msg_data)
{
	gboolean not_voting = FALSE;
	HA_Message *vote = NULL;
	
	/* don't vote if we're in one of these states or wanting to shut down */
	switch(cur_state) {
		case S_RECOVERY:
		case S_STOPPING:
		case S_TERMINATE:
			crm_warn("Not voting in election, we're in state %s",
				 fsa_state2string(cur_state));
			not_voting = TRUE;
			break;
		default:
			break;
	}

	if(not_voting == FALSE) {
		if(is_set(fsa_input_register, R_STARTING)) {
			not_voting = TRUE;
		}
	}	

	if(not_voting) {
		if(AM_I_DC) {
			register_fsa_input(C_FSA_INTERNAL, I_RELEASE_DC, NULL);

		} else {
			register_fsa_input(C_FSA_INTERNAL, I_PENDING, NULL);
		}
		return;
	}
	
	vote = create_request(
		CRM_OP_VOTE, NULL, NULL,
		CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

	current_election_id++;
	ha_msg_add(vote, F_CRM_ELECTION_OWNER, fsa_our_uuid);
	ha_msg_add_int(vote, F_CRM_ELECTION_ID, current_election_id);

	send_request(vote, NULL);
	crm_debug("Destroying voted hash");
	g_hash_table_destroy(voted);
	voted = NULL;
	
	if(cur_state == S_ELECTION || cur_state == S_RELEASE_DC) {
		crm_timer_start(election_timeout);		

	} else if(cur_state != S_INTEGRATION) {
		crm_err("Broken? Voting in state %s",
			fsa_state2string(cur_state));
	}
	
	return;
}

char *dc_hb_msg = NULL;
int beat_num = 0;

gboolean
do_dc_heartbeat(gpointer data)
{
#if 0
	fsa_timer_t *timer = (fsa_timer_t *)data;

	crm_debug_3("Sending DC Heartbeat %d", beat_num);
	HA_Message *msg = ha_msg_new(5); 
	ha_msg_add(msg, F_TYPE,		T_CRM);
	ha_msg_add(msg, F_SUBTYPE,	XML_ATTR_REQUEST);
	ha_msg_add(msg, F_CRM_SYS_TO,   CRM_SYSTEM_CRMD);
	ha_msg_add(msg, F_CRM_SYS_FROM, CRM_SYSTEM_DC);
	ha_msg_add(msg, F_CRM_TASK,	CRM_OP_HBEAT);
	ha_msg_add_int(msg, "dc_beat_seq", beat_num);
	beat_num++;

	if(send_msg_via_ha(fsa_cluster_conn, msg) == FALSE) {
		/* this is bad */
		crm_timer_stop(timer); /* make it not go off again */

		register_fsa_input(C_HEARTBEAT_FAILED, I_SHUTDOWN, NULL);
		return FALSE;
	}
#endif
	return TRUE;
}

struct election_data_s 
{
		const char *winning_uname;
		unsigned int winning_bornon;
};

static void
log_node(gpointer key, gpointer value, gpointer user_data)
{
	crm_err("%s: %s", (char*)user_data, (char*)key);
}

void
do_election_check(long long action,
		       enum crmd_fsa_cause cause,
		       enum crmd_fsa_state cur_state,
		       enum crmd_fsa_input current_input,
		  fsa_data_t *msg_data)
{
	int voted_size = g_hash_table_size(voted);
	int num_members = g_hash_table_size(fsa_membership_copy->members);
	
	/* in the case of #voted > #members, it is better to
	 *   wait for the timeout and give the cluster time to
	 *   stabilize
	 */
	if(fsa_state != S_ELECTION) {
		crm_debug("Ignore election check: we not in an election");

	} else if(voted_size >= num_members) {
		/* we won and everyone has voted */
		crm_timer_stop(election_timeout);
		register_fsa_input(C_FSA_INTERNAL, I_ELECTION_DC, NULL);
		if(voted_size > num_members) {
			char *data = NULL;
			
			data = crm_strdup("member");
			g_hash_table_foreach(
				fsa_membership_copy->members, log_node, data);
			crm_free(data);
			
			data = crm_strdup("voted");
			g_hash_table_foreach(voted, log_node, data);
			crm_free(data);
			
		}
		crm_debug("Destroying voted hash");
		g_hash_table_destroy(voted);
		voted = NULL;
		
	} else {
		crm_info("Still waiting on %d non-votes (%d total)",
			 num_members - voted_size, num_members);
	}

	return;
}


/*	A_ELECTION_COUNT	*/
void
do_election_count_vote(long long action,
		       enum crmd_fsa_cause cause,
		       enum crmd_fsa_state cur_state,
		       enum crmd_fsa_input current_input,
		       fsa_data_t *msg_data)
{
	int election_id = -1;
	gboolean we_loose = FALSE;
	enum crmd_fsa_input election_result = I_NULL;
	oc_node_t *our_node = NULL, *your_node = NULL;
	ha_msg_input_t *vote = fsa_typed_data(fsa_dt_ha_msg);
	const char *op            = cl_get_string(vote->msg, F_CRM_TASK);
	const char *vote_from     = cl_get_string(vote->msg, F_CRM_HOST_FROM);
	const char *your_version  = cl_get_string(vote->msg, F_CRM_VERSION);
	const char *election_owner= cl_get_string(vote->msg, F_CRM_ELECTION_OWNER);
	
	/* if the membership copy is NULL we REALLY shouldnt be voting
	 * the question is how we managed to get here.
	 */
	CRM_CHECK(fsa_membership_copy != NULL, return);
	CRM_CHECK(fsa_membership_copy->members != NULL, return);

	CRM_CHECK(vote_from != NULL, vote_from = fsa_our_uname);
	
	our_node = (oc_node_t*)g_hash_table_lookup(
		fsa_membership_copy->members, fsa_our_uname);

	your_node = (oc_node_t*)g_hash_table_lookup(
		fsa_membership_copy->members, vote_from);
	
	if(your_node == NULL) {
		crm_debug("Election ignore: The other side doesn't exist in CCM.");
		return;
	}	
	
 	if(voted == NULL) {
		crm_debug("Created voted hash");
 		voted = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
 	}

	ha_msg_value_int(vote->msg, F_CRM_ELECTION_ID, &election_id);
	crm_debug("Election %d, owner: %s", election_id, election_owner);
	
	/* update the list of nodes that have voted */
	if(crm_str_eq(fsa_our_uuid, election_owner, TRUE)) {
		if(election_id == current_election_id) {
			char *uname_copy = NULL;
			char *op_copy = crm_strdup(op);
			uname_copy = crm_strdup(your_node->node_uname);
			g_hash_table_replace(voted, uname_copy, op_copy);
			crm_info("Updated voted hash for %s to %s",
				 your_node->node_uname, op);
		} else {
			crm_debug("Ignore old '%s' from %s: %d vs. %d",
				  op, your_node->node_uname,
				  election_id, current_election_id);
			return;
		}
			
	} else {
		CRM_CHECK(safe_str_neq(op, CRM_OP_NOVOTE), return);
	}
	
	if(vote_from == NULL || crm_str_eq(vote_from, fsa_our_uname, TRUE)) {
		/* don't count our own vote */
		crm_info("Election ignore: our %s (%s)", op,crm_str(vote_from));
		return;

	} else if(crm_str_eq(op, CRM_OP_NOVOTE, TRUE)) {
		crm_info("Election ignore: no-vote from %s", vote_from);
		return;
	}

	crm_info("Election check: %s from %s", op, vote_from);
	if(our_node == NULL
		|| fsa_membership_copy->last_event == OC_EV_MS_EVICTED) {
		crm_info("Election fail: we don't exist in CCM");
		we_loose = TRUE;

	} else if(compare_version(your_version, CRM_FEATURE_SET) < 0) {
		crm_info("Election fail: version");
		we_loose = TRUE;
		
	} else if(compare_version(your_version, CRM_FEATURE_SET) > 0) {
		crm_info("Election pass: version");
		
	} else if(your_node->node_born_on < our_node->node_born_on) {
		crm_debug("Election fail: born_on");
		we_loose = TRUE;

	} else if(your_node->node_born_on > our_node->node_born_on) {
		crm_debug("Election pass: born_on");
		
	} else if(strcasecmp(fsa_our_uname, vote_from) > 0) {
		crm_debug("Election fail: uname");
		we_loose = TRUE;

	} else {
		CRM_CHECK(strcasecmp(fsa_our_uname, vote_from) != 0, ;);
		crm_debug("Them: %s (born=%d)  Us: %s (born=%d)",
			  vote_from, your_node->node_born_on,
			  fsa_our_uname, our_node->node_born_on);
/* cant happen...
 *	} else if(strcasecmp(fsa_our_uname, vote_from) == 0) {
 *
 * default...
 *	} else { // strcasecmp(fsa_our_uname, vote_from) < 0
 *		we win
 */
	}

	if(we_loose) {
		cl_uuid_t vote_uuid_s;
		gboolean vote_sent = FALSE;
		char vote_uuid[UU_UNPARSE_SIZEOF];
		HA_Message *novote = create_request(
			CRM_OP_NOVOTE, NULL, vote_from,
			CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

		update_dc(NULL, FALSE);
		
		if(cl_get_uuid(vote->msg, F_ORIGUUID, &vote_uuid_s) == HA_OK) {
			cl_uuid_unparse(&vote_uuid_s, vote_uuid);

		} else {
			cl_log_message(LOG_ERR, vote->msg);
		}
		
		crm_timer_stop(election_timeout);
		crm_debug("Election lost to %s (%s/%d)",
			  vote_from, vote_uuid, election_id);
		if(fsa_input_register & R_THE_DC) {
			crm_debug_3("Give up the DC to %s", vote_from);
			election_result = I_RELEASE_DC;
			
		} else {
			crm_debug_3("We werent the DC anyway");
			election_result = I_PENDING;
			
		}

		ha_msg_add(novote, F_CRM_ELECTION_OWNER, vote_uuid);
		ha_msg_add_int(novote, F_CRM_ELECTION_ID, election_id);
		
		vote_sent = send_request(novote, NULL);
		CRM_DEV_ASSERT(vote_sent);

		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);
		
	} else {
		if(cur_state == S_PENDING) {
			crm_debug("Election ignore: We already lost the election");
			return;
			
		} else {
			crm_info("Election won over %s", vote_from);
			election_result = I_ELECTION;
		}
		crm_debug("Destroying voted hash");
 		g_hash_table_destroy(voted);
		voted = NULL;
	}
	
	register_fsa_input(C_FSA_INTERNAL, election_result, NULL);
}

/*	A_ELECT_TIMER_START, A_ELECTION_TIMEOUT 	*/
/* we won */
void
do_election_timer_ctrl(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
}


static void
feature_update_callback(const HA_Message *msg, int call_id, int rc,
			crm_data_t *output, void *user_data)
{
	if(rc != cib_ok) {
		fsa_data_t *msg_data = NULL;
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}
}

/*	 A_DC_TAKEOVER	*/
void
do_dc_takeover(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	int rc = cib_ok;
	crm_data_t *cib = NULL;
	
	crm_info("Taking over DC status for this partition");
	set_bit_inplace(fsa_input_register, R_THE_DC);

	if(voted != NULL) {
		crm_debug_2("Destroying voted hash");
		g_hash_table_destroy(voted);
		voted = NULL;
	}
	
	set_bit_inplace(fsa_input_register, R_JOIN_OK);
	set_bit_inplace(fsa_input_register, R_INVOKE_PE);
	
 	fsa_cib_conn->cmds->set_slave_all(fsa_cib_conn, cib_none);
	fsa_cib_conn->cmds->set_master(fsa_cib_conn, cib_none);
	
	cib = createEmptyCib();
	crm_xml_add(cib, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
	crm_xml_add(cib, XML_ATTR_CIB_REVISION, CIB_FEATURE_SET);
	fsa_cib_update(XML_TAG_CIB, cib, cib_quorum_override, rc);
	add_cib_op_callback(rc, FALSE, NULL, feature_update_callback);

	update_attr(fsa_cib_conn, cib_none, XML_CIB_TAG_CRMCONFIG,
		    NULL, NULL, NULL, "dc-version", VERSION"-"HA_HG_VERSION, FALSE);

	free_xml(cib);
}


/*	 A_DC_RELEASE	*/
void
do_dc_release(long long action,
	      enum crmd_fsa_cause cause,
	      enum crmd_fsa_state cur_state,
	      enum crmd_fsa_input current_input,
	      fsa_data_t *msg_data)
{
	if(action & A_DC_RELEASE) {
		crm_debug("Releasing the role of DC");
		clear_bit_inplace(fsa_input_register, R_THE_DC);
		
	} else if (action & A_DC_RELEASED) {
		crm_info("DC role released");
#if 0
		if( are there errors ) {
			/* we cant stay up if not healthy */
			/* or perhaps I_ERROR and go to S_RECOVER? */
			result = I_SHUTDOWN;
		}
#endif
		register_fsa_input(C_FSA_INTERNAL, I_RELEASE_SUCCESS, NULL);
		
	} else {
		crm_err("Unknown action %s", fsa_action2string(action));
	}

	crm_debug_2("Am I still the DC? %s", AM_I_DC?XML_BOOLEAN_YES:XML_BOOLEAN_NO);

}

