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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd_fsa.h>
#include <crmd_messages.h>

#include <crm/dmalloc_wrapper.h>

int num_join_invites = 0;
GHashTable *join_requests = NULL;
GHashTable *confirmed_nodes = NULL;
void finalize_join_for(gpointer key, gpointer value, gpointer user_data);


/*	 A_DC_JOIN_OFFER_ALL	*/
enum crmd_fsa_input
do_dc_join_offer_all(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	/* reset everyones status back to down or in_ccm in the CIB */
	xmlNodePtr update     = NULL;
	xmlNodePtr cib_copy   = get_cib_copy();
	xmlNodePtr tmp1       = get_object_root(XML_CIB_TAG_STATUS, cib_copy);
	xmlNodePtr tmp2       = NULL;

	/* Give everyone a chance to join before invoking the PolicyEngine */
	stopTimer(integration_timer);
	
	if(join_requests != NULL) {
		g_hash_table_destroy(join_requests);
	}
	join_requests = g_hash_table_new(&g_str_hash, &g_str_equal);

	/* mark ourselves joined */
	g_hash_table_insert(join_requests, crm_strdup(fsa_our_uname),
			    crm_strdup(CRMD_JOINSTATE_MEMBER));


	/* catch any nodes that are active in the CIB but not in the CCM list*/
	xml_child_iter(
		tmp1, node_entry, XML_CIB_TAG_STATE,

		const char *node_id = xmlGetProp(node_entry, XML_ATTR_UNAME);
		gpointer a_node = g_hash_table_lookup(
				fsa_membership_copy->members, node_id);

		if(a_node != NULL || (safe_str_eq(fsa_our_uname, node_id))) {
			/* handled by do_update_cib_node() */
			continue;
		}

		tmp2 = create_node_state(
			node_id, node_id,
			XML_BOOLEAN_NO, NULL, CRMD_JOINSTATE_DOWN);

		if(update == NULL) {
			update = tmp2;
		} else {
			update = xmlAddSibling(update, tmp2);
		}
		);

	/* now process the CCM data */
	free_xml(do_update_cib_nodes(update, TRUE));
	free_xml(cib_copy);

	/* Avoid ordered message delays caused when the CRMd proc
	 * isnt running yet (ie. send as a broadcast msg which are never
	 * sent ordered.
	 */
	send_request(NULL, NULL, CRM_OP_WELCOME,
		     NULL, CRM_SYSTEM_CRMD, NULL);	

/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if(join_requests == NULL) {
		if(fsa_membership_copy->members_size == 1) {
			/* we're the only ones in here */
			crm_info("Not expecting any join acks");
			return I_SUCCESS;
		}
		
	} else if(g_hash_table_size(join_requests)
		  >= (fsa_membership_copy->members_size -1)) {
		crm_info("That was the last outstanding join ack");
		return I_SUCCESS;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join acks",
		  fsa_membership_copy->members_size
		  - g_hash_table_size(join_requests) - 1);

	/* we shouldnt wait forever */
	crm_debug("Starting the integration timer");
	startTimer(integration_timer);
	
	return I_NULL;
}

/*	 A_DC_JOIN_OFFER_ONE	*/
enum crmd_fsa_input
do_dc_join_offer_one(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	xmlNodePtr update = NULL;
	xmlNodePtr welcome = NULL;
	const char *join_to = NULL;

	if(data == NULL) {
		crm_err("Attempt to send welcome message "
			 "without a message to reply to!");
		return I_NULL;
/*		return do_send_welcome_all( */
/*			A_JOIN_WELCOME_ALL,cause,cur_state,current_input,data); */
		
	}

	welcome = (xmlNodePtr)data;
	
	join_to = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
	if(join_to != NULL) {
		stopTimer(integration_timer);
		
		/* send the welcome */
		crm_debug("Sending %s to %s", CRM_OP_WELCOME, join_to);
			
		send_request(NULL, NULL, CRM_OP_WELCOME,
			     join_to, CRM_SYSTEM_CRMD, NULL);

		free_xml(update);
			
		/* if this client is sick, we shouldnt wait forever */
		crm_debug("Restarting the integration timer");
		startTimer(integration_timer);

	} else {
		crm_err("No recipient for welcome message");
	}
		
	return I_NULL;
}

/*	 A_DC_JOIN_PROCESS_REQ	*/
enum crmd_fsa_input
do_dc_join_req(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	xmlNodePtr generation;
	xmlNodePtr join_ack = (xmlNodePtr)data;
	const char *ack_nack = "memeber";

	gboolean is_a_member  = FALSE;
	const char *join_from = xmlGetProp(join_ack, XML_ATTR_HOSTFROM);
	const char *ref       = xmlGetProp(join_ack, XML_ATTR_REFERENCE);

	gpointer join_node =
		g_hash_table_lookup(fsa_membership_copy->members, join_from);

	if(join_node != NULL) {
		is_a_member = TRUE;
	}
	
	generation = find_xml_node(join_ack, "generation_tuple");

	crm_debug("Welcoming node %s after ACK (ref %s)",
	       join_from, ref);
	
	if(is_a_member == FALSE) {
		crm_err("Node %s is not known to us (ref %s)",
		       join_from, ref);
		/* NACK them */
		return I_FAIL;

	} else if(/* some reason */ 0) {
		/* NACK this client */
		ack_nack = "down";
	}
	
	
	/* add them to our list of CRMD_STATE_ACTIVE nodes
	   TODO: check its not already there
	*/
	g_hash_table_insert(join_requests,
			    crm_strdup(join_from), crm_strdup(ack_nack));

/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if(g_hash_table_size(join_requests)
		  >= fsa_membership_copy->members_size) {
		crm_info("That was the last outstanding join ack");
		return I_SUCCESS;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join acks",
		  fsa_membership_copy->members_size
		  - g_hash_table_size(join_requests));
	
	return I_NULL;
}


/*	A_DC_JOIN_FINALIZE	*/
enum crmd_fsa_input
do_dc_join_finalize(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	num_join_invites = 0;
	g_hash_table_foreach(join_requests, finalize_join_for, NULL);

	if(confirmed_nodes != NULL) {
		g_hash_table_destroy(confirmed_nodes);
	}
	confirmed_nodes = g_hash_table_new(&g_str_hash, &g_str_equal);

	/* mark ourselves confirmed */
	g_hash_table_insert(confirmed_nodes, crm_strdup(fsa_our_uname),
			    crm_strdup(CRMD_JOINSTATE_MEMBER));


	return I_NULL;
}

/*	A_DC_JOIN_PROCESS_ACK	*/
enum crmd_fsa_input
do_dc_join_ack(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	/* now update them to "member" */
	xmlNodePtr tmp1 = NULL, update = NULL;
	xmlNodePtr join_ack = (xmlNodePtr)data;
	const char *join_from = xmlGetProp(join_ack, XML_ATTR_HOSTFROM);

	const char *join_state = (const char *)
		g_hash_table_lookup(join_requests, join_from);
	
	if(join_state == NULL
	   || safe_str_neq(join_state, CRMD_JOINSTATE_MEMBER)) {
		crm_err("Node %s wasnt invited to join the cluster", join_from);
		return I_NULL;
	}
	
	g_hash_table_insert(confirmed_nodes, crm_strdup(join_from),
			    crm_strdup(CRMD_JOINSTATE_MEMBER));

	/* update node entry in the status section  */
	crm_debug("Updating node state to %s for %s", join_state, join_from);
	update = create_node_state(
		join_from, join_from, NULL, ONLINESTATUS, join_state);

	set_xml_property_copy(update,XML_CIB_ATTR_EXPSTATE, CRMD_STATE_ACTIVE);

	tmp1 = create_cib_fragment(update, NULL);
	invoke_local_cib(NULL, tmp1, CRM_OP_UPDATE);

	free_xml(tmp1);

	if(num_join_invites <= g_hash_table_size(confirmed_nodes)) {
		crm_info("That was the last outstanding join confirmation");
		return I_SUCCESS;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join confirmations",
		  num_join_invites - g_hash_table_size(confirmed_nodes));
	
	return I_CIB_OP;
}

void
finalize_join_for(gpointer key, gpointer value, gpointer user_data)
{
	if(key == NULL || value == NULL) {
		return;
	}
	xmlNodePtr tmp1 = NULL;
	const char *join_to = (const char *)key;
	const char *join_state = (const char *)value;

	/* make sure the node exists in the config section */
	create_node_entry(join_to, join_to, CRMD_JOINSTATE_MEMBER);

	if(safe_str_eq(join_state, CRMD_JOINSTATE_MEMBER)) {
		num_join_invites++;
	}

	/* TODO: create a ack or nack in tmp1 */
	
	/* send the ack/nack to the node */
	send_request(NULL, tmp1, CRM_OP_JOINACK,
		     join_to, CRM_SYSTEM_CRMD, NULL);	

	free_xml(tmp1);	
}
