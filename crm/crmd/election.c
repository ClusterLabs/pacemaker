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
#include <libxml/tree.h>
#include <crm/msg_xml.h>

#include <crm/common/xmlutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>
#include <crm/cib.h>
#include <string.h>
#include <crmd_messages.h>

#include <crm/dmalloc_wrapper.h>

GHashTable *joined_nodes = NULL;
void ghash_count_vote(gpointer key, gpointer value, gpointer user_data);
void ghash_send_welcome(gpointer key, gpointer value, gpointer user_data);

/*	A_ELECTION_VOTE	*/
enum crmd_fsa_input
do_election_vote(long long action,
		 enum crmd_fsa_cause cause,
		 enum crmd_fsa_state cur_state,
		 enum crmd_fsa_input current_input,
		 void *data)
{
	enum crmd_fsa_input election_result = I_NULL;
	FNIN();

	/* dont vote if we're in one of these states or wanting to shut down */
	switch(cur_state) {
		case S_RECOVERY:
		case S_RECOVERY_DC:
		case S_STOPPING:
		case S_RELEASE_DC:
		case S_TERMINATE:
			FNRET(I_NULL);
			// log warning
			break;
		default:
			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				FNRET(I_NULL);
				// log warning
			}
			break;
	}
	
	send_request(NULL, NULL, CRM_OPERATION_VOTE, NULL, CRM_SYSTEM_CRMD, NULL);
	
	FNRET(election_result);
}

gboolean
timer_popped(gpointer data)
{
	fsa_timer_t *timer = (fsa_timer_t *)data;

	cl_log(LOG_INFO, "#!!#!!# Timer %s just popped!",
	       fsa_input2string(timer->fsa_input));
	
	stopTimer(timer); // dont make it go off again

	s_crmd_fsa(C_TIMER_POPPED, timer->fsa_input, NULL);
	
	return TRUE;
}

gboolean
do_dc_heartbeat(gpointer data)
{
	fsa_timer_t *timer = (fsa_timer_t *)data;
//	cl_log(LOG_DEBUG, "#!!#!!# Heartbeat timer just popped!");
	
	gboolean was_sent = send_request(NULL, NULL, CRM_OPERATION_HBEAT, 
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
	
	FNIN();

	if(vote_from == NULL || strcmp(vote_from, fsa_our_uname) == 0) {
		// dont count our own vote
		FNRET(election_result);
	}

	if(fsa_membership_copy->members_size < 1) {
		// if even we are not in the cluster then we should not vote
		FNRET(I_FAIL);
		
	}

	oc_node_t *our_node = (oc_node_t*)
		g_hash_table_lookup(fsa_membership_copy->members, fsa_our_uname);

	oc_node_t *your_node = (oc_node_t*)
		g_hash_table_lookup(fsa_membership_copy->members, vote_from);

#if 0
	cl_log(LOG_DEBUG, "%s (bornon=%d), our bornon (%d)",
		   vote_from, our_node->born, my_born);

	cl_log(LOG_DEBUG, "%s %s %s",
	       fsa_our_uname,
	       strcmp(fsa_our_uname, vote_from) < 0?"<":">=",
	       vote_from);
#endif
	
	if(is_set(fsa_input_register, R_SHUTDOWN)) {
		cl_log(LOG_DEBUG,
		       "Election fail: we are shutting down");
		we_loose = TRUE;

	} else if(our_node == NULL) {
		cl_log(LOG_DEBUG,
		       "Election fail: we dont exist in the CCM list");
		we_loose = TRUE;
		
	} else if(your_node == NULL) {
		cl_log(LOG_ERR, "The other side doesnt exist in the CCM list");
		
	} else if(your_node->node_born_on < our_node->node_born_on) {
		cl_log(LOG_DEBUG, "Election fail: born_on");
		we_loose = TRUE;

	} else if(your_node->node_born_on == our_node->node_born_on
		  && strcmp(fsa_our_uname, vote_from) > 0) {
		cl_log(LOG_DEBUG, "Election fail: uname");
		we_loose = TRUE;

	} else {
		struct election_data_s election_data;
		election_data.winning_uname = NULL;
		election_data.winning_bornon = -1; // maximum integer
		
		CRM_DEBUG("We might win... we should vote (possibly again)");
		election_result = I_DC_TIMEOUT; // new "default"

		g_hash_table_foreach(fsa_membership_copy->members,
				     ghash_count_vote, &election_data);
		
		cl_log(LOG_DEBUG, "Election winner should be %s (born_on=%d)",
		       election_data.winning_uname, election_data.winning_bornon);
		
	
		if(safe_str_eq(election_data.winning_uname, fsa_our_uname)){
			cl_log(LOG_DEBUG, "Election win: lowest born_on and uname");
			election_result = I_ELECTION_DC;
		}
	}
	
	if(we_loose) {
		if(fsa_input_register & R_THE_DC) {
			cl_log(LOG_DEBUG, "Give up the DC");
			election_result = I_RELEASE_DC;
			
		} else {
			cl_log(LOG_DEBUG, "We werent the DC anyway");
			election_result = I_NOT_DC;
			
		}
	}

	if(we_loose || election_result == I_ELECTION_DC) {
		// cancel timer, its been decided
		stopTimer(election_timeout);
	}
	
	FNRET(election_result);
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
	FNIN();

	if(action & A_ELECT_TIMER_START) {
		CRM_DEBUG("Starting the election timer...");
		startTimer(election_timeout);
		
	} else if(action & A_ELECT_TIMER_STOP || action & A_ELECTION_TIMEOUT) {
		CRM_DEBUG("Stopping the election timer...");
		stopTimer(election_timeout);
		
	} else {
		cl_log(LOG_ERR, "unexpected action %s",
		       fsa_action2string(action));
	}

	if(action & A_ELECTION_TIMEOUT) {
		CRM_DEBUG("The election timer went off, we win!");
	
		FNRET(I_ELECTION_DC);
		
	}

	
	FNRET(I_NULL);
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
	FNIN();

	if(action & A_DC_TIMER_STOP) {
		timer_op_ok = stopTimer(election_trigger);
	}

	/* dont start a timer that wasnt already running */
	if(action & A_DC_TIMER_START && timer_op_ok) {
		startTimer(election_trigger);
	}
	
	FNRET(I_NULL);
}


/*	 A_DC_TAKEOVER	*/
enum crmd_fsa_input
do_dc_takeover(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
{
	FNIN();

	CRM_DEBUG("################## Taking over the DC ##################");
	set_bit_inplace(&fsa_input_register, R_THE_DC);

	CRM_DEBUG("Am I the DC? %s", AM_I_DC?"yes":"no");
	
	fsa_our_dc = NULL;
	set_bit_inplace(&fsa_input_register, R_JOIN_OK);
	set_bit_inplace(&fsa_input_register, R_INVOKE_PE);
	
	clear_bit_inplace(&fsa_input_register, R_CIB_DONE);
	clear_bit_inplace(&fsa_input_register, R_HAVE_CIB);

	startTimer(dc_heartbeat);

	FNRET(I_NULL);
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
	FNIN();

	CRM_DEBUG("################## Releasing the DC ##################");

	stopTimer(dc_heartbeat);

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
		cl_log(LOG_ERR, "Warning, do_dc_release invoked for action %s",
		       fsa_action2string(action));
	}

	CRM_DEBUG("Am I still the DC? %s", AM_I_DC?"yes":"no");

	FNRET(result);
}

/*	 A_JOIN_WELCOME, A_JOIN_WELCOME_ALL	*/
enum crmd_fsa_input
do_send_welcome(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	int num_sent = 0;
	FNIN();

	if(action & A_JOIN_WELCOME && data == NULL) {
		cl_log(LOG_ERR,
		       "Attempt to send welcome message "
		       "without a message to reply to!");
		FNRET(I_NULL);
		
	} else if(action & A_JOIN_WELCOME) {
		xmlNodePtr welcome = (xmlNodePtr)data;

		const char *join_to = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
		if(join_to != NULL) {
/*
			xmlNodePtr update =
				create_node_state(new_node, "active", "active", NULL);
			xmlNodePtr tmp1 = create_cib_fragment(update, NULL);
			send_request(NULL, tmp1, "update", NULL, CRM_SYSTEM_DCIB);
*/			
			send_request(NULL, NULL, CRM_OPERATION_WELCOME,
				     join_to, CRM_SYSTEM_CRMD, NULL);
			
		} else {
			cl_log(LOG_ERR, "No recipient for welcome message");
		}
		
		
		FNRET(I_NULL);
	}

// welcome everyone...

	/* Give everyone a chance to join before invoking the PolicyEngine */
	stopTimer(integration_timer);
	startTimer(integration_timer);
	
	if(joined_nodes != NULL) {
		g_hash_table_destroy(joined_nodes);
		joined_nodes = g_hash_table_new(&g_str_hash, &g_str_equal);
		
	}

	// reset everyones status back to down or in_ccm in the CIB
	xmlNodePtr update     = NULL;
	xmlNodePtr cib_copy   = get_cib_copy();
	xmlNodePtr tmp1       = get_object_root(XML_CIB_TAG_STATUS, cib_copy);
	xmlNodePtr node_entry = tmp1->children;

	// catch any nodes that are active in the CIB but not in the CCM list 
	while(node_entry != NULL){
		const char *state   = "down";
		const char *node_id = xmlGetProp(node_entry, "id");

		gpointer a_node =
			g_hash_table_lookup(fsa_membership_copy->members,
					    node_id);

		node_entry = node_entry->next;

		if(safe_str_eq(fsa_our_uname, node_id)) {
			continue;

		} else if(a_node != NULL) {
			// handled by do_update_cib_nodes()
			continue;
		}

		tmp1 = create_node_state(node_id, state, NULL, NULL);
		
		if(update == NULL) {
			update = tmp1;
		} else {
			update = xmlAddSibling(update, tmp1);
		}
	}

	// now process the CCM data
	free_xml(do_update_cib_nodes(update));
	free_xml(cib_copy);

	/* Avoid ordered message delays caused when the CRMd proc
	 * isnt running yet (ie. send as a broadcast msg which are never
	 * sent ordered.
	 */
	send_request(NULL, NULL, CRM_OPERATION_WELCOME,
		     NULL, CRM_SYSTEM_CRMD, NULL);

	g_hash_table_foreach(fsa_membership_copy->members,
				     ghash_send_welcome, &num_sent);

/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if(num_sent == 0) {
		// that was the last outstanding join ack)
		cl_log(LOG_INFO,"That was the last outstanding join ack");
		FNRET(I_SUCCESS);
		
	} else {
		cl_log(LOG_DEBUG,
		       "Still waiting on %d outstanding join acks",
		       num_sent);
		//dont waste time by invoking the pe yet;
	}
	
	FNRET(I_NULL);
}

xmlNodePtr
create_node_state(const char *node, const char *state,
		  const char *exp_state, xmlNodePtr lrm_data)
{
	xmlNodePtr node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	
	set_xml_property_copy(node_state, XML_ATTR_ID, node);
	set_xml_property_copy(node_state, "state",     state);
	if(exp_state != NULL) {
		set_xml_property_copy(node_state, "exp_state", exp_state);
	}
	
	if(lrm_data != NULL) {
//		set_xml_property_copy(data, "replace_lrm", "true");
		add_node_copy(node_state, lrm_data);
	}

	xml_message_debug(node_state, "created");

	return node_state;
}


/*	 A_JOIN_ACK	*/
enum crmd_fsa_input
do_ack_welcome(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	xmlNodePtr welcome = (xmlNodePtr)data;
	xmlNodePtr cib_copy;
	xmlNodePtr tmp1;
	xmlNodePtr tmp2;

	FNIN();
	
#if 0
	if(we are sick) {
		log error ;
		FNRET(I_NULL);
	} 
#endif
	fsa_our_dc = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
	
	if(fsa_our_dc == NULL) {
		cl_log(LOG_ERR, "Failed to determin our DC");
		FNRET(I_FAIL);
	}
	
	/* send our status section to the DC */
	cib_copy = get_cib_copy();
	tmp1 = get_object_root(XML_CIB_TAG_STATUS, cib_copy);
	tmp2 = create_cib_fragment(tmp1, NULL);
	
	send_ha_reply(fsa_cluster_conn, welcome, tmp2);

	free_xml(tmp2);
	free_xml(cib_copy);
	
	FNRET(I_NULL);
}

/*	 A_ANNOUNCE	*/
enum crmd_fsa_input
do_announce(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	xmlNodePtr msg = (xmlNodePtr)data;
	FNIN();
	
	/* Once we hear from the DC, we can stop the timer
	 *
	 * This timer was started either on startup or when a node
	 * left the CCM list
	 */

	/* dont announce if we're in one of these states */
	switch(cur_state) {
		case S_RECOVERY:
		case S_RECOVERY_DC:
		case S_RELEASE_DC:
		case S_TERMINATE:
			cl_log(LOG_WARNING,
			       "Do not announce ourselves in state %s",
			       fsa_state2string(cur_state));
			FNRET(I_NULL);
			break;
		default:
			break;
	}

	if(AM_I_OPERATIONAL) {
		const char *from = xmlGetProp(msg, XML_ATTR_HOSTFROM);

		if(from == NULL) {
			cl_log(LOG_ERR, "Failed to origin of ping message");
			FNRET(I_FAIL);
		}
		
		send_request(NULL, NULL, CRM_OPERATION_ANNOUNCE,
			     from, CRM_SYSTEM_DC, NULL);
	} else {
		/* Delay announce until we have finished local startup */
		cl_log(LOG_WARNING,
		       "Delaying announce until local startup is complete");
		FNRET(I_NULL);
	}
	
	FNRET(I_NULL);
}


/*	 A_JOIN_PROCESS_ACK	*/
enum crmd_fsa_input
do_process_welcome_ack(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	xmlNodePtr tmp1;
	xmlNodePtr tmp2;
	xmlNodePtr cib_fragment;
	xmlNodePtr msg_cib;
	xmlNodePtr join_ack = (xmlNodePtr)data;

	int size = 0;
	gboolean is_a_member  = FALSE;
	const char *join_from = xmlGetProp(join_ack, XML_ATTR_HOSTFROM);
	const char *ref       = xmlGetProp(join_ack, XML_ATTR_REFERENCE);

	FNIN();

	gpointer join_node =
		g_hash_table_lookup(fsa_membership_copy->members, join_from);

	if(join_node != NULL) {
		is_a_member = TRUE;
	}
	
	cib_fragment = find_xml_node(join_ack, XML_TAG_FRAGMENT);

	if(is_a_member == FALSE) {
		cl_log(LOG_ERR, "Node %s is not known to us (ref %s)",
		       join_from, ref);

		/* make sure any information from this node is discarded,
		 * it is invalid
		 */
		free_xml(cib_fragment);
		FNRET(I_FAIL);
	}

	cl_log(LOG_DEBUG, "Welcoming node %s after ACK (ref %s)",
	       join_from, ref);
	
	/* add them to our list of "active" nodes
	   TODO: still used?
	*/
	g_hash_table_insert(joined_nodes, strdup(join_from),strdup(join_from));

	if(cib_fragment == NULL) {
		cl_log(LOG_ERR,
		       "No status information was part of the"
		       " Welcome ACK from %s",
		       join_from);
		FNRET(I_NULL);
	}

	/* allow both node and status changes to be made */
	msg_cib = find_xml_node(cib_fragment, XML_TAG_CIB);
	set_xml_property_copy(msg_cib, XML_ATTR_FILTER_TYPE, "all");	

	tmp1 = get_object_root(XML_CIB_TAG_STATUS, msg_cib);
	tmp2 = get_object_root(XML_CIB_TAG_NODES, msg_cib);
	
	/* Make changes so that state=active for this node when the update
	 *  is processed by A_CIB_INVOKE
	 */
	tmp1 = find_entity(tmp1, XML_CIB_TAG_STATE, join_from, FALSE);
	set_xml_property_copy(tmp1, "state", "active");

	/* make sure a node entry exists for the new node
	 *
	 * this will add anyone except the first ever node in the cluster
	 *   since it will also be the DC which doesnt go through the
	 *   join process (with itself).  We can include a special case
	 *   later if desired.
	 */
	if(tmp2 == NULL) {
		cl_log(LOG_ERR, "Couldnt find NODES sections in fragment");
	} else {
		tmp2 = create_xml_node(tmp2, XML_CIB_TAG_NODE);
		set_xml_property_copy(tmp2, XML_ATTR_ID, join_from);
		set_xml_property_copy(tmp2, "uname", join_from);
		set_xml_property_copy(tmp2, XML_CIB_ATTR_NODETYPE, "node");
	}
	
	if(g_hash_table_size(joined_nodes)
	   == fsa_membership_copy->members_size) {
		cl_log(LOG_INFO,"That was the last outstanding join ack");
		FNRET(I_SUCCESS);
		/* The update isnt lost, the A_CIB_OP action is part of the
		 *   matrix for S_INTEGRATION + I_SUCCESS.
		 */

	} else {
		cl_log(LOG_DEBUG,
		       "Still waiting on %d outstanding join acks",
		       size);
		/* dont waste time by invoking the pe yet */
	}
	FNRET(I_CIB_OP);
}


void
ghash_send_welcome(gpointer key, gpointer value, gpointer user_data)
{
	int *num_sent = (int*)user_data;
	const char *node_uname = (const char*)key;

	if(strcmp(fsa_our_uname, node_uname) == 0) {
		// dont send one to ourselves
		return;
	}

#if 0
	if(send_request(NULL, NULL, CRM_OPERATION_WELCOME,
			node_uname, CRM_SYSTEM_CRMD, NULL)) {
		*num_sent++;
		CRM_DEBUG("Sent welcome message to %s", node_uname);
		
	} else {
		cl_log(LOG_ERR, "Couldnt send welcome message to %s", node_uname);
	}
#else 
	/* Avoid ordered message delays caused when the CRMd proc
	 * isnt running yet, for now we just want the counter... 
	 */
	*num_sent++;
#endif
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
