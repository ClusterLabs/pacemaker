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
#include <clplumbing/Gmain_timeout.h>

#include <crm/dmalloc_wrapper.h>

uint highest_born_on = -1;

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
		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);
		if(AM_I_DC) {
			register_fsa_input(C_FSA_INTERNAL, I_RELEASE_DC, NULL);

		} else {
			register_fsa_input(C_FSA_INTERNAL, I_PENDING, NULL);
		}
		return I_NULL;
	}
	
	vote = create_request(
		CRM_OP_VOTE, NULL, NULL,
		CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

	if(is_set(fsa_input_register, R_SHUTDOWN)) {
		crm_warn("Not voting in election, we're shutting down");
		cl_msg_remove(vote, F_CRM_VERSION);
	}

	send_request(vote, NULL);
	crm_timer_start(election_timeout);		

	return I_NULL;
}

char *dc_hb_msg = NULL;
int beat_num = 0;

gboolean
do_dc_heartbeat(gpointer data)
{
#if 0
	fsa_timer_t *timer = (fsa_timer_t *)data;

	crm_devel("Sending DC Heartbeat %d", beat_num);
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
		s_crmd_fsa(C_HEARTBEAT_FAILED);

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
		
	} else if(fsa_membership_copy->members != NULL) {
		our_node = (oc_node_t*)
			g_hash_table_lookup(fsa_membership_copy->members,fsa_our_uname);

		your_node = (oc_node_t*)
			g_hash_table_lookup(fsa_membership_copy->members,vote_from);
	}
	
	if(your_node == NULL) {
		crm_debug("Election ignore: The other side doesnt exist in CCM.");
		return I_NULL;
		
		/* if your_version == 0, then they're shutting down too */
	} else if(is_set(fsa_input_register, R_SHUTDOWN)) {
		if(your_version != NULL) {
			crm_info("Election fail: we are shutting down");
			we_loose = TRUE;
			
		} else {
			/* pretend nothing happened, they want to shutdown too*/
			crm_info("Election ignore: they are shutting down too");
			return I_NULL;
		}
		
	} else if(our_node == NULL
		|| fsa_membership_copy->last_event == OC_EV_MS_EVICTED) {
		crm_info("Election fail: we dont exist in CCM");
		we_loose = TRUE;
		
	} else if(your_version == NULL) {
		crm_info("Election pass: they are shutting down");

	} else if(compare_version(your_version, CRM_VERSION) > 0) {
		crm_debug("Election fail: version");
		we_loose = TRUE;
		
	} else if(compare_version(your_version, CRM_VERSION) < 0) {
		crm_debug("Election pass: version");
		
	} else if(your_node->node_born_on < our_node->node_born_on) {
		crm_debug("Election fail: born_on");
		we_loose = TRUE;

	} else if(your_node->node_born_on > our_node->node_born_on) {
		crm_debug("Election pass: born_on");
		
	} else if(strcmp(fsa_our_uname, vote_from) > 0) {
		crm_debug("Election fail: uname");
		we_loose = TRUE;
/* cant happen...
 *	} else if(strcmp(fsa_our_uname, vote_from) == 0) {
 *
 * default...
 *	} else { // strcmp(fsa_our_uname, vote_from) < 0
 *		we win
 */
	}

	if(we_loose) {
		crm_timer_stop(election_timeout);
		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);
		crm_info("Election lost to %s", vote_from);
		if(fsa_input_register & R_THE_DC) {
			crm_devel("Give up the DC to %s", vote_from);
			election_result = I_RELEASE_DC;
			
		} else {
			crm_devel("We werent the DC anyway");
			election_result = I_PENDING;
			
		}

	} else {
		crm_info("Election won over %s", vote_from);
#if 0
		if(cur_state == S_PENDING) {
			crm_info("We already lost the election");
			
		} else if(highest_born_on == 0
		   || your_node->node_born_on < highest_born_on) {
			election_result = I_ELECTION;
			highest_born_on = your_node->node_born_on;

		} else {
			crm_info("We've already voted down nodes born on %d and"
				 " later.  %s born on %d", highest_born_on,
				 vote_from, your_node->node_born_on);
		}
#else
		if(cur_state == S_PENDING) {
			crm_info("Election ignore: We already lost the election");
			return I_NULL;
			
		} else {
			election_result = I_ELECTION;
		}
#endif
	}
	

	register_fsa_input(C_FSA_INTERNAL, election_result, NULL);
	return I_NULL;
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

	if(dc_heartbeat->source_id == (guint)-1
	   || dc_heartbeat->source_id == (guint)-2) {
		crm_devel("Starting DC Heartbeat timer");
		dc_heartbeat->source_id = Gmain_timeout_add_full(
			G_PRIORITY_HIGH, dc_heartbeat->period_ms,
			dc_heartbeat->callback, dc_heartbeat, NULL);
	} else {
		crm_devel("DC Heartbeat timer already active");
	}
	
/* 	fsa_cib_conn->cmds->set_slave_all(fsa_cib_conn, cib_none); */
	fsa_cib_conn->cmds->set_master(fsa_cib_conn, cib_none);
	CRM_DEV_ASSERT(cib_not_master != fsa_cib_conn->cmds->is_master(fsa_cib_conn));

	set_uuid(fsa_cluster_conn, cib, XML_ATTR_DC_UUID, fsa_our_uname);
	crm_devel("Update %s in the CIB to our uuid: %s",
		  XML_ATTR_DC_UUID, crm_element_value(cib, XML_ATTR_DC_UUID));
	
	update = create_cib_fragment(cib, NULL);
	free_xml(cib);

	rc = fsa_cib_conn->cmds->modify(
		fsa_cib_conn, NULL, update, &output, cib_sync_call);
	
	if(rc == cib_ok) {
		int revision_i = -1;
		const char *revision = NULL;

		crm_data_t *generation = cib_get_generation(fsa_cib_conn);
		
		crm_devel("Checking our feature revision is allowed: %d",
			  cib_feature_revision);

		revision = crm_element_value(generation, XML_ATTR_CIB_REVISION);
		revision_i = atoi(revision?revision:"0");

		if(revision_i > cib_feature_revision) {
			crm_err("Feature revision not permitted");
			/* go into a stall state */
			result = I_HALT;
		}

		free_xml(generation);

	} else if(rc == cib_revision_unsupported) {
		crm_err("Feature revision not permitted");
		/* go into a stall state */
		result = I_HALT;
		
	} else 	if(rc != cib_ok) {
		crm_err("DC UUID update failed: %s", cib_error2string(rc));
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}
	
	free_xml(update);
	
	crm_devel("Requesting an initial dump of CRMD client_status");
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

	crm_timer_stop(dc_heartbeat);
	if(action & A_DC_RELEASE) {
		clear_bit_inplace(fsa_input_register, R_THE_DC);
		
		/* get a new CIB from the new DC */
		clear_bit_inplace(fsa_input_register, R_HAVE_CIB);

	} else if (action & A_DC_RELEASED) {
		fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);

		if(cur_state == S_STOPPING) {
			register_fsa_input(C_FSA_INTERNAL, I_RELEASE_SUCCESS, NULL);
		}
#if 0
		else if( are there errors ) {
			/* we cant stay up if not healthy */
			/* or perhaps I_ERROR and go to S_RECOVER? */
			result = I_SHUTDOWN;
		}
#endif
		else {
			register_fsa_input(C_FSA_INTERNAL, I_RELEASE_SUCCESS, NULL);
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

