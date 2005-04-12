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
GHashTable *join_offers         = NULL;
GHashTable *join_requests       = NULL;
GHashTable *confirmed_nodes     = NULL;
char *max_epoche = NULL;
char *max_generation_from = NULL;
crm_data_t *max_generation_xml = NULL;

void initialize_join(gboolean before);
void finalize_join_for(gpointer key, gpointer value, gpointer user_data);
void join_send_offer(gpointer key, gpointer value, gpointer user_data);
void finalize_sync_callback(const HA_Message *msg, int call_id, int rc,
			    crm_data_t *output, void *user_data);
void finialize_query_callback(const HA_Message *msg, int call_id, int rc,
			      crm_data_t *output, void *user_data);

/*	 A_DC_JOIN_OFFER_ALL	*/
enum crmd_fsa_input
do_dc_join_offer_all(long long action,
		     enum crmd_fsa_cause cause,
		     enum crmd_fsa_state cur_state,
		     enum crmd_fsa_input current_input,
		     fsa_data_t *msg_data)
{
	/* reset everyones status back to down or in_ccm in the CIB */
#if 0
	crm_data_t *cib_copy   = get_cib_copy(fsa_cib_conn);
	crm_data_t *tmp1       = get_object_root(XML_CIB_TAG_STATUS, cib_copy);
	crm_data_t *tmp2       = NULL;
#endif
	crm_data_t *fragment   = create_cib_fragment(NULL, NULL);
	crm_data_t *update     = find_xml_node(fragment, XML_TAG_CIB, TRUE);

	initialize_join(TRUE);
	
	/* catch any nodes that are active in the CIB but not in the CCM list*/
	update = get_object_root(XML_CIB_TAG_STATUS, update);
	CRM_DEV_ASSERT(update != NULL);

#if 0
	/* dont do this for now... involves too much blocking and I cant
	 * think of a sensible way to do it asyncronously
	 */
	xml_child_iter(
		tmp1, node_entry, XML_CIB_TAG_STATE,

		const char *node_id = crm_element_value(node_entry, XML_ATTR_UNAME);
		gpointer a_node = g_hash_table_lookup(
			fsa_membership_copy->members, node_id);

		if(a_node != NULL || (safe_str_eq(fsa_our_uname, node_id))) {
			/* handled by do_update_cib_node() */
			continue;
		}

		tmp2 = create_node_state(
			node_id, node_id, NULL,
			XML_BOOLEAN_NO, NULL, CRMD_JOINSTATE_PENDING, NULL);

		add_node_copy(update, tmp2);
		free_xml(tmp2);
		);
	free_xml(cib_copy);
#endif
	
	/* now process the CCM data */
	do_update_cib_nodes(fragment, TRUE);

/*  	free_xml(fragment);  */
/* BUG!  This should be able to be freed.
 * I cant find any reason why it shouldnt be able to be,
 * but libxml still corrupts memory
 */
	
#if 0
	/* Avoid ordered message delays caused when the CRMd proc
	 * isnt running yet (ie. send as a broadcast msg which are never
	 * sent ordered.
	 */
	send_request(NULL, NULL, CRM_OP_WELCOME,
		     NULL, CRM_SYSTEM_CRMD, NULL);	
#else

	crm_debug("Offering membership to %d clients",
		  fsa_membership_copy->members_size);
	
	g_hash_table_foreach(fsa_membership_copy->members,
			     join_send_offer, NULL);
	
#endif
/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if((ssize_t)g_hash_table_size(join_requests)
	   >= fsa_membership_copy->members_size) {
		crm_info("Not expecting any join acks");
		register_fsa_input(C_FSA_INTERNAL, I_INTEGRATED, NULL);
		return I_NULL;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join acks",
		  fsa_membership_copy->members_size
		  - g_hash_table_size(join_requests));

	return I_NULL;
}

/*	 A_DC_JOIN_OFFER_ONE	*/
enum crmd_fsa_input
do_dc_join_offer_one(long long action,
		     enum crmd_fsa_cause cause,
		     enum crmd_fsa_state cur_state,
		     enum crmd_fsa_input current_input,
		     fsa_data_t *msg_data)
{
	oc_node_t member;
	gpointer a_node = NULL;
	ha_msg_input_t *welcome = fsa_typed_data(fsa_dt_ha_msg);
	const char *join_to = NULL;

	if(welcome == NULL) {
		crm_err("Attempt to send welcome message "
			"without a message to reply to!");
		return I_NULL;
	}
	
	join_to = cl_get_string(welcome->msg, F_CRM_HOST_FROM);

	a_node = g_hash_table_lookup(join_requests, join_to);
	if(a_node != NULL
	   && (cur_state == S_INTEGRATION || cur_state == S_FINALIZE_JOIN)) {
		/* note: it _is_ possible that a node will have been
		 *  sick or starting up when the original offer was made.
		 *  however, it will either re-announce itself in due course
		 *  _or_ we can re-store the original offer on the client.
		 */
		crm_info("Re-offering membership to %s...", join_to);
	}

	crm_debug("Processing annouce request from %s in state %s",
		  join_to, fsa_state2string(cur_state));
	
	member.node_uname = crm_strdup(join_to);
	join_send_offer(NULL, &member, NULL);
	crm_free(member.node_uname);
	
	/* this was a genuine join request, cancel any existing
	 * transition and invoke the PE
	 */
	register_fsa_input_w_actions(
		msg_data->fsa_cause, I_NULL, NULL, A_TE_CANCEL);
	
	return I_NULL;
}

/*	 A_DC_JOIN_PROCESS_REQ	*/
enum crmd_fsa_input
do_dc_join_req(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	crm_data_t *generation = NULL;

	gboolean is_a_member = FALSE;
	const char *ack_nack = CRMD_JOINSTATE_MEMBER;
	ha_msg_input_t *join_ack = fsa_typed_data(fsa_dt_ha_msg);

	const char *join_from = cl_get_string(join_ack->msg,F_CRM_HOST_FROM);
	const char *ref       = cl_get_string(join_ack->msg,XML_ATTR_REFERENCE);
	const char *op	   = cl_get_string(join_ack->msg, F_CRM_TASK);

	gpointer join_node =
		g_hash_table_lookup(fsa_membership_copy->members, join_from);

	if(safe_str_neq(op, CRM_OP_WELCOME)) {
		crm_warn("Ignoring op=%s message", op);
		return I_NULL;
	}

	crm_devel("Processing req from %s", join_from);
	
	if(join_node != NULL) {
		is_a_member = TRUE;
	}
	
	generation = join_ack->xml;

	if(max_generation_xml == NULL) {
		max_generation_xml = copy_xml_node_recursive(generation);
		max_generation_from = crm_strdup(join_from);

	} else if(cib_compare_generation(max_generation_xml, generation) < 0) {
		clear_bit_inplace(fsa_input_register, R_HAVE_CIB);
		crm_devel("%s has a better generation number than the current max",
			  join_from);
		crm_xml_devel(max_generation_xml, "Max generation");
		crm_xml_devel(generation, "Their generation");
		crm_free(max_generation_from);
		free_xml(max_generation_xml);
		
		max_generation_from = crm_strdup(join_from);
		max_generation_xml = copy_xml_node_recursive(join_ack->xml);
	}
	
	crm_devel("Welcoming node %s after ACK (ref %s)", join_from, ref);
	
	if(is_a_member == FALSE) {
		/* nack them now so they are not counted towards the
		 * expected responses
		 */
		char *local_from = crm_strdup(join_from);
		char *local_down = crm_strdup(CRMD_JOINSTATE_DOWN);

		crm_err("Node %s is not known to us (ref %s)", join_from, ref);
		finalize_join_for(local_from, local_down, NULL);
		crm_free(local_from);
		crm_free(local_down);
		
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;

	} else if(/* some reason */ 0) {
		/* NACK this client */
		ack_nack = CRMD_JOINSTATE_DOWN;
	}
	
	/* add them to our list of CRMD_STATE_ACTIVE nodes
	   TODO: check its not already there
	*/
	g_hash_table_insert(
		join_requests, crm_strdup(join_from), crm_strdup(ack_nack));

	if((ssize_t)g_hash_table_size(join_requests)
	   >= fsa_membership_copy->members_size) {
		crm_info("That was the last outstanding join ack");
		register_fsa_input(C_FSA_INTERNAL, I_INTEGRATED, NULL);
		return I_NULL;
	}

	/* dont waste time by invoking the PE yet; */
	crm_debug("Still waiting on %d (of %d) outstanding join acks",
		  fsa_membership_copy->members_size
		  - g_hash_table_size(join_requests),
		  fsa_membership_copy->members_size);
	
	return I_NULL;
}



/*	A_DC_JOIN_FINALIZE	*/
enum crmd_fsa_input
do_dc_join_finalize(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	enum cib_errors rc = cib_ok;

	if(max_generation_from == NULL
	   || safe_str_eq(max_generation_from, fsa_our_uname)){
		set_bit_inplace(fsa_input_register, R_HAVE_CIB);
	}
	
	if(is_set(fsa_input_register, R_HAVE_CIB) == FALSE) {
		/* ask for the agreed best CIB */
		crm_info("Asking %s for its copy of the CIB",
			 crm_str(max_generation_from));

		fsa_cib_conn->call_timeout = 10;
		rc = fsa_cib_conn->cmds->query_from(
			fsa_cib_conn, max_generation_from, NULL, NULL, 0);
		fsa_cib_conn->call_timeout = 0; /* back to the default */
		add_cib_op_callback(rc, FALSE, crm_strdup(max_generation_from),
				    finalize_sync_callback);
		return I_NULL;
	}

	crm_devel("Bumping the epoche and syncing to %d clients",
		  g_hash_table_size(join_requests));
	fsa_cib_conn->cmds->bump_epoch(
		fsa_cib_conn, cib_scope_local|cib_quorum_override);
	rc = fsa_cib_conn->cmds->sync(fsa_cib_conn, NULL, cib_quorum_override);
	add_cib_op_callback(rc, FALSE, NULL, finalize_sync_callback);

	return I_NULL;
}

void
finialize_query_callback(const HA_Message *msg, int call_id, int rc,
			 crm_data_t *output, void *user_data)
{
/* 	static int lpc = 0; */
	crm_data_t *foreign_cib = NULL;
	char *remote_host = user_data;

	if(AM_I_DC == FALSE) {
		crm_debug("this call is no longer relevant");
		crm_free(remote_host);
		return;
	}
	
	if(rc == cib_ok) {
		crm_data_t *update = NULL;
		crm_data_t *cib = createEmptyCib();
		
		set_uuid(fsa_cluster_conn, cib,
			 XML_ATTR_DC_UUID, fsa_our_uname);
		crm_devel("Update %s in the CIB to our uuid: %s",
			  XML_ATTR_DC_UUID,
			  crm_element_value(cib, XML_ATTR_DC_UUID));
		update = create_cib_fragment(cib, NULL);
		free_xml(cib);
		
		update_local_cib(update);
	}
		
	if(rc == cib_remote_timeout) {
		crm_err("Sync from %s resulted in an error: %s."
			"  Use what we have...",
			remote_host, cib_error2string(rc));
#if 0
		/* restart the whole join process */
		register_fsa_error_adv(C_FSA_INTERNAL, I_ELECTION_DC,
				       NULL, NULL, __FUNCTION__);
#else
		rc = cib_ok;
#endif
	} else if(rc < cib_ok) {
		crm_err("Sync from %s resulted in an error: %s",
			remote_host, cib_error2string(rc));
		
		register_fsa_error_adv(
			C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);

	} else {
		foreign_cib = find_xml_node(output, XML_TAG_CIB, TRUE);
		CRM_DEV_ASSERT(foreign_cib != NULL);
		if(!crm_assert_failed) {
			rc = fsa_cib_conn->cmds->replace(
				fsa_cib_conn, NULL, foreign_cib, NULL,
				cib_quorum_override);
		}
	}

	if(rc >= 0) {
		crm_devel("Bumping the epoche and syncing to %d clients",
			  g_hash_table_size(join_requests));
		fsa_cib_conn->cmds->bump_epoch(
			fsa_cib_conn, cib_scope_local|cib_quorum_override);
		rc = fsa_cib_conn->cmds->sync(
			fsa_cib_conn, NULL, cib_quorum_override);
		add_cib_op_callback(rc, FALSE, NULL, finalize_sync_callback);
	}
	
	crm_free(remote_host);
	return;
}


void
finalize_sync_callback(const HA_Message *msg, int call_id, int rc,
		       crm_data_t *output, void *user_data) 
{
	CRM_DEV_ASSERT(cib_not_master != rc);
	if(rc != cib_ok) {
		register_fsa_error_adv(C_FSA_INTERNAL, I_FAIL,
				       NULL, NULL, __FUNCTION__);
		return;
	}
	
	num_join_invites = 0;
	crm_debug("Notifying %d clients of join results",
		  g_hash_table_size(join_requests));
	g_hash_table_foreach(join_requests, finalize_join_for, NULL);
}

/*	A_DC_JOIN_PROCESS_ACK	*/
enum crmd_fsa_input
do_dc_join_ack(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	/* now update them to "member" */
	crm_data_t *update = NULL;
	ha_msg_input_t *join_ack = fsa_typed_data(fsa_dt_ha_msg);
	const char *join_from = cl_get_string(join_ack->msg, F_CRM_HOST_FROM);
	const char *op = cl_get_string(join_ack->msg, F_CRM_TASK);
	const char *type = cl_get_string(join_ack->msg, F_SUBTYPE);
	const char *join_state = NULL;


	if(safe_str_neq(op, CRM_OP_JOINACK)) {
		crm_warn("Ignoring op=%s message", op);
		return I_NULL;

	} else if(safe_str_eq(type, XML_ATTR_REQUEST)) {
		crm_verbose("Ignoring request");
		crm_log_message(LOG_VERBOSE, join_ack->msg);
		return I_NULL;
	}
	
	crm_debug("Processing ack from %s", join_from);

	join_state = (const char *)
		g_hash_table_lookup(join_requests, join_from);
	
	if(join_state == NULL) {
		crm_err("Join not in progress: ignoring join from %s",
			join_from);
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
		
	} else if(safe_str_neq(join_state, CRMD_JOINSTATE_MEMBER)) {
		crm_err("Node %s wasnt invited to join the cluster",join_from);
		return I_NULL;
	}
	
	g_hash_table_insert(confirmed_nodes, crm_strdup(join_from),
			    crm_strdup(CRMD_JOINSTATE_MEMBER));

	/* the updates will actually occur in reverse order because of
	 * the LIFO nature of the fsa input queue
	 */
	
	/* update CIB with the current LRM status from the node */
	update_local_cib(copy_xml_node_recursive(join_ack->xml));

	/* update node entry in the status section  */
	crm_info("Updating node state to %s for %s", join_state, join_from);
	update = create_node_state(
		join_from, join_from,
		ACTIVESTATUS, NULL, ONLINESTATUS, join_state, join_state);

	set_xml_property_copy(update,XML_CIB_ATTR_EXPSTATE, CRMD_STATE_ACTIVE);

	update_local_cib(create_cib_fragment(update, NULL));

	if(num_join_invites <= (ssize_t)g_hash_table_size(confirmed_nodes)) {
		crm_info("That was the last outstanding join confirmation");
		register_fsa_input_later(C_FSA_INTERNAL, I_FINALIZED, NULL);
		
		return I_NULL;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join confirmations",
		  num_join_invites - g_hash_table_size(confirmed_nodes));
	
	return I_NULL;
}

void
finalize_join_for(gpointer key, gpointer value, gpointer user_data)
{
	const char *join_to = NULL;
	const char *join_state = NULL;
	HA_Message *acknak = NULL;
	
	if(key == NULL || value == NULL) {
		return;
	}

	join_to    = (const char *)key;
	join_state = (const char *)value;

	/* make sure the node exists in the config section */
	create_node_entry(join_to, join_to, CRMD_JOINSTATE_MEMBER);

	/* send the ack/nack to the node */
	acknak = create_request(
		CRM_OP_JOINACK, NULL, join_to,
		CRM_SYSTEM_CRMD, CRM_SYSTEM_DC, NULL);

	/* set the ack/nack */
	if(safe_str_eq(join_state, CRMD_JOINSTATE_MEMBER)) {
		crm_info("ACK'ing join request from %s, state %s",
			 join_to, join_state);
		num_join_invites++;
		ha_msg_add(acknak, CRM_OP_JOINACK, XML_BOOLEAN_TRUE);

	} else {
		crm_warn("NACK'ing join request from %s, state %s",
			 join_to, join_state);
		
		ha_msg_add(acknak, CRM_OP_JOINACK, XML_BOOLEAN_FALSE);
	}
	
	send_msg_via_ha(fsa_cluster_conn, acknak);
}

void
initialize_join(gboolean before)
{
	/* clear out/reset a bunch of stuff */
	if(join_offers != NULL) {
		g_hash_table_destroy(join_offers);
	}
	if(join_requests != NULL) {
		g_hash_table_destroy(join_requests);
	}
	if(confirmed_nodes != NULL) {
		g_hash_table_destroy(confirmed_nodes);
	}

	if(before) {
		if(max_generation_from != NULL) {
			crm_free(max_generation_from);
			max_generation_from = NULL;
		}
		if(max_generation_xml != NULL) {
			free_xml(max_generation_xml);
			max_generation_xml = NULL;
		}
		set_bit_inplace(fsa_input_register, R_HAVE_CIB);
		clear_bit_inplace(fsa_input_register, R_CIB_ASKED);
	}
	
	join_offers     = g_hash_table_new(g_str_hash, g_str_equal);
	join_requests   = g_hash_table_new(g_str_hash, g_str_equal);
	confirmed_nodes = g_hash_table_new(g_str_hash, g_str_equal);
}


void
join_send_offer(gpointer key, gpointer value, gpointer user_data)
{
	const char *join_to = NULL;
	void *a_node = NULL;
	const oc_node_t *member = (const oc_node_t*)value;

	if(member != NULL) {
		join_to = member->node_uname;
	}

	if(join_to == NULL) {
		crm_err("No recipient for welcome message");

	} else {
		HA_Message *offer = create_request(
			CRM_OP_WELCOME, NULL, join_to,
			CRM_SYSTEM_CRMD, CRM_SYSTEM_DC, NULL);

		/* send the welcome */
		crm_info("Sending %s to %s", CRM_OP_WELCOME, join_to);

		send_msg_via_ha(fsa_cluster_conn, offer);

		a_node = g_hash_table_lookup(join_requests, join_to);
		if(a_node == NULL) {
			g_hash_table_insert(join_offers, crm_strdup(join_to),
					    crm_strdup(CRMD_JOINSTATE_PENDING));
		}
	}
}

