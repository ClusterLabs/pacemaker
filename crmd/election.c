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
#include <crm/common/cluster.h>
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
const char *get_hg_version(void);
const char *get_hg_version(void) 
{
    /* limit this #define's use to a single file to avoid rebuilding more than necessary */
    return HA_HG_VERSION;
}

/*	A_ELECTION_VOTE	*/
void
do_election_vote(long long action,
		 enum crmd_fsa_cause cause,
		 enum crmd_fsa_state cur_state,
		 enum crmd_fsa_input current_input,
		 fsa_data_t *msg_data)
{
	gboolean not_voting = FALSE;
	xmlNode *vote = NULL;
	
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
	crm_xml_add(vote, F_CRM_ELECTION_OWNER, fsa_our_uuid);
	crm_xml_add_int(vote, F_CRM_ELECTION_ID, current_election_id);

	send_request(vote, NULL);
	crm_debug("Destroying voted hash");
	g_hash_table_destroy(voted);
	free_xml(vote);
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
	return TRUE;
}

struct election_data_s 
{
		const char *winning_uname;
		unsigned int winning_bornon;
};

static void
log_member_uname(gpointer key, gpointer value, gpointer user_data)
{
    if(crm_is_member_active(value)) {
	crm_err("%s: %s", (char*)user_data, (char*)key);
    }
}

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
	int num_members = crm_active_members();
	
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
			g_hash_table_foreach(crm_peer_cache, log_member_uname, data);
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
	static time_t last_election_loss = 0;
	enum crmd_fsa_input election_result = I_NULL;
	crm_node_t *our_node = NULL, *your_node = NULL;
	ha_msg_input_t *vote = fsa_typed_data(fsa_dt_ha_msg);
	const char *op            = crm_element_value(vote->msg, F_CRM_TASK);
	const char *vote_from     = crm_element_value(vote->msg, F_CRM_HOST_FROM);
	const char *your_version  = crm_element_value(vote->msg, F_CRM_VERSION);
	const char *election_owner= crm_element_value(vote->msg, F_CRM_ELECTION_OWNER);
	
	/* if the membership copy is NULL we REALLY shouldnt be voting
	 * the question is how we managed to get here.
	 */

	CRM_CHECK(vote->msg != NULL, crm_err("Bogus data from %s", msg_data->origin); return);
	CRM_CHECK(crm_peer_cache != NULL, return);
	CRM_CHECK(vote_from != NULL, vote_from = fsa_our_uname);
	
	our_node = g_hash_table_lookup(crm_peer_cache, fsa_our_uname);
	your_node = g_hash_table_lookup(crm_peer_cache, vote_from);
	
	if(your_node == NULL) {
	    crm_debug("Election ignore: The other side doesn't exist in CCM: %s", vote_from);
	    return;
	}	
	
 	if(voted == NULL) {
		crm_debug("Created voted hash");
 		voted = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
 	}

	crm_element_value_int(vote->msg, F_CRM_ELECTION_ID, &election_id);
	crm_debug("Election %d, owner: %s", election_id, election_owner);

	/* update the list of nodes that have voted */
	if(crm_str_eq(fsa_our_uuid, election_owner, TRUE)
	   || crm_str_eq(fsa_our_uname, election_owner, TRUE)) {
		if(election_id == current_election_id) {
			char *uname_copy = NULL;
			char *op_copy = crm_strdup(op);
			uname_copy = crm_strdup(your_node->uname);
			g_hash_table_replace(voted, uname_copy, op_copy);
			crm_info("Updated voted hash for %s to %s",
				 your_node->uname, op);
		} else {
			crm_debug("Ignore old '%s' from %s: %d vs. %d",
				  op, your_node->uname,
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
	if(our_node == NULL || safe_str_neq(our_node->state, CRM_NODE_MEMBER)) {
		crm_info("Election fail: we don't exist in CCM");
		we_loose = TRUE;

	} else if(compare_version(your_version, CRM_FEATURE_SET) < 0) {
		crm_info("Election fail: version");
		we_loose = TRUE;
		
	} else if(compare_version(your_version, CRM_FEATURE_SET) > 0) {
		crm_info("Election pass: version");
		
	} else if(is_heartbeat_cluster() && your_node->born < our_node->born) {
		crm_debug("Election fail: born_on");
		we_loose = TRUE;
		
	} else if(is_heartbeat_cluster() && your_node->born > our_node->born) {
		crm_debug("Election pass: born_on");

	} else if(fsa_our_uname == NULL
		  || strcasecmp(fsa_our_uname, vote_from) > 0) {
		crm_debug("Election fail: uname");
		we_loose = TRUE;

	} else {
		CRM_CHECK(strcasecmp(fsa_our_uname, vote_from) != 0, ;);
		crm_debug("Them: %s (born=%llu)  Us: %s (born=%llu)",
			  vote_from, (unsigned long long)your_node->born,
			  fsa_our_uname, (unsigned long long)our_node->born);
/* cant happen...
 *	} else if(strcasecmp(fsa_our_uname, vote_from) == 0) {
 *
 * default...
 *	} else { // strcasecmp(fsa_our_uname, vote_from) < 0
 *		we win
 */
	}

	if(we_loose) {
		gboolean vote_sent = FALSE;
		xmlNode *novote = create_request(
			CRM_OP_NOVOTE, NULL, vote_from,
			CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

		update_dc(NULL, FALSE);
		
		crm_timer_stop(election_timeout);
		crm_debug("Election lost to %s (%d)", vote_from, election_id);
		if(fsa_input_register & R_THE_DC) {
			crm_debug_3("Give up the DC to %s", vote_from);
			election_result = I_RELEASE_DC;
			
		} else {
			crm_debug_3("We werent the DC anyway");
			election_result = I_PENDING;
			
		}

		crm_xml_add(novote, F_CRM_ELECTION_OWNER, election_owner);
		crm_xml_add_int(novote, F_CRM_ELECTION_ID, election_id);
		
		vote_sent = send_request(novote, NULL);
		CRM_DEV_ASSERT(vote_sent);
		free_xml(novote);

		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);

		last_election_loss = time(NULL);

	} else {
		int dampen = 2;
		time_t tm_now = time(NULL);
		if(tm_now - last_election_loss < (time_t)dampen) {
			crm_debug("Election ignore: We already lost an election less than %ds ago", dampen);
			return;
		}
		last_election_loss = 0;
		election_result = I_ELECTION;
		crm_info("Election won over %s", vote_from);
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
feature_update_callback(xmlNode *msg, int call_id, int rc,
			xmlNode *output, void *user_data)
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
	xmlNode *cib = NULL;
	
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

