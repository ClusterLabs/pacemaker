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

GHashTable *joined_nodes = NULL;

/*	 A_JOIN_WELCOME	*/
enum crmd_fsa_input
do_send_welcome(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	xmlNodePtr update = NULL;
	xmlNodePtr welcome = NULL;
	xmlNodePtr tmp1 = NULL;
	xmlNodePtr tmp2 = NULL;
	const char *join_to = NULL;

	if(action & A_JOIN_WELCOME && data == NULL) {
		crm_err("Attempt to send welcome message "
			 "without a message to reply to!");
		return I_NULL;
/*		return do_send_welcome_all( */
/*			A_JOIN_WELCOME_ALL,cause,cur_state,current_input,data); */
		
	} else if(action & A_JOIN_WELCOME) {
		welcome = (xmlNodePtr)data;

		join_to = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
		if(join_to != NULL) {
			stopTimer(integration_timer);

			/* update node status */
			crm_debug("Updating node state to %s for %s",
				  CRMD_JOINSTATE_PENDING, join_to);
			
			update = create_node_state(
				join_to, join_to,
				NULL, NULL, CRMD_JOINSTATE_PENDING);

			tmp1 = create_cib_fragment(update, NULL);
			invoke_local_cib(NULL, tmp1, CRM_OP_UPDATE);
			free_xml(tmp1);	
			
			/* Make sure they have the *whole* CIB */
			crm_debug("Sending complete CIB to %s", join_to);
			
			tmp1 = get_cib_copy();
			tmp2 = create_cib_fragment(tmp1, NULL);
			
			send_request(NULL, tmp2, CRM_OP_REPLACE,
				     join_to, CRM_SYSTEM_CRMD, NULL);
			
			free_xml(tmp1);	
			free_xml(tmp2);

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
	return I_ERROR;
}

/*	 A_JOIN_WELCOME_ALL	*/

enum crmd_fsa_input
do_send_welcome_all(long long action,
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
	startTimer(integration_timer);
	
	if(joined_nodes != NULL) {
		g_hash_table_destroy(joined_nodes);
		joined_nodes = g_hash_table_new(&g_str_hash, &g_str_equal);
	}

	/* catch any nodes that are active in the CIB but not in the CCM list*/
	xml_child_iter(
		tmp1, node_entry, XML_CIB_TAG_STATE,

		const char *node_id = xmlGetProp(node_entry, XML_ATTR_UNAME);
		gpointer a_node = g_hash_table_lookup(
				fsa_membership_copy->members, node_id);

		if(a_node != NULL || (safe_str_eq(fsa_our_uname, node_id))) {
			/* handled by do_update_cib_node() */
			xml_iter_continue(node_entry);
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

	/* Make sure everyone has the *whole* CIB */
	tmp1 = get_cib_copy();
	tmp2 = create_cib_fragment(tmp1, NULL);
	
	send_request(NULL, tmp2, CRM_OP_REPLACE,
		     NULL, CRM_SYSTEM_CRMD, NULL);
	
	free_xml(tmp1);	
	free_xml(tmp2);
	
	/* Avoid ordered message delays caused when the CRMd proc
	 * isnt running yet (ie. send as a broadcast msg which are never
	 * sent ordered.
	 */
	send_request(NULL, NULL, CRM_OP_WELCOME,
		     NULL, CRM_SYSTEM_CRMD, NULL);	

/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if(joined_nodes == NULL) {
		if(fsa_membership_copy->members_size == 1) {
			/* we're the only ones in here */
			crm_info("Not expecting any join acks");
			return I_SUCCESS;
		}
		
	} else if(g_hash_table_size(joined_nodes)
		  >= (fsa_membership_copy->members_size -1)) {
		crm_info("That was the last outstanding join ack");
		return I_SUCCESS;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join acks",
		  fsa_membership_copy->members_size
		  - g_hash_table_size(joined_nodes) - 1);
	
	return I_NULL;
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

	
	
#if 0
	if(we are sick) {
		log error ;
		return I_NULL;
	} 
#endif
	fsa_our_dc = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
	
	if(fsa_our_dc == NULL) {
		crm_err("Failed to determin our DC");
		return I_FAIL;
	}
	
	/* send our status section to the DC */
	cib_copy = get_cib_copy();
	tmp1 = get_object_root(XML_CIB_TAG_STATUS, cib_copy);
	if(tmp1 != NULL) {
		tmp2 = create_cib_fragment(tmp1->children, NULL);
		
		send_ha_reply(fsa_cluster_conn, welcome, tmp2);

		free_xml(tmp2);
	}
	
	free_xml(cib_copy);
	
	return I_NULL;
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
			crm_warn("Do not announce ourselves in state %s",
				 fsa_state2string(cur_state));
			return I_NULL;
			break;
		default:
			break;
	}

	if(AM_I_OPERATIONAL) {
		const char *from = xmlGetProp(msg, XML_ATTR_HOSTFROM);

		if(from == NULL) {
			crm_err("Failed to origin of ping message");
			return I_FAIL;
		}
		
		send_request(NULL, NULL, CRM_OP_ANNOUNCE,
			     from, CRM_SYSTEM_DC, NULL);
	} else {
		/* Delay announce until we have finished local startup */
		crm_warn("Delaying announce until local startup is complete");
		return I_NULL;
	}
	
	return I_NULL;
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

	gboolean is_a_member  = FALSE;
	const char *join_from = xmlGetProp(join_ack, XML_ATTR_HOSTFROM);
	const char *ref       = xmlGetProp(join_ack, XML_ATTR_REFERENCE);

	uuid_t uuid_raw;
	char *uuid_calc = NULL;

	gpointer join_node =
		g_hash_table_lookup(fsa_membership_copy->members, join_from);

	if(join_node != NULL) {
		is_a_member = TRUE;
	}
	
	cib_fragment = find_xml_node(join_ack, XML_TAG_FRAGMENT);

	crm_debug("Welcoming node %s after ACK (ref %s)",
	       join_from, ref);
	
	if(is_a_member == FALSE) {
		crm_err("Node %s is not known to us (ref %s)",
		       join_from, ref);

		/* make sure any information from this node is discarded,
		 * it is invalid
		 */
		free_xml(cib_fragment);
		return I_FAIL;
	}
	
	/* add them to our list of CRMD_STATE_ACTIVE nodes
	   TODO: still used?
	   TODO: check its not already there
	*/
	g_hash_table_insert(joined_nodes, strdup(join_from),strdup(join_from));

	if(cib_fragment == NULL) {
		crm_err("No status information was part of the"
			" Welcome ACK from %s",
			join_from);
		return I_NULL;
	}

	create_node_entry(join_from, join_from, "member");

	crm_malloc(uuid_calc, sizeof(char)*50);
	if(uuid_calc != NULL) {
		if(fsa_cluster_conn->llc_ops->get_uuid_by_name(
			   fsa_cluster_conn, join_from, uuid_raw) == HA_FAIL) {
			crm_err("Could not calculate UUID for %s", join_from);
			crm_free(uuid_calc);
			uuid_calc = crm_strdup(join_from);
			
		} else {
			uuid_unparse(uuid_raw, uuid_calc);
		}
	}
	
	/* Make changes so that exp_state=active for this node when the update
	 *  is processed by A_CIB_INVOKE
	 */
	msg_cib = find_xml_node(cib_fragment, XML_TAG_CIB);
	tmp1 = get_object_root(XML_CIB_TAG_STATUS, msg_cib);
	tmp2 = find_entity(tmp1, XML_CIB_TAG_STATE, uuid_calc, FALSE);

	if(tmp2 == NULL) {
		crm_err("Status entry for %s not found in update, adding",
			join_from);
		
		tmp2 = create_xml_node(tmp1, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp2, XML_ATTR_UUID,  uuid_calc);
		set_xml_property_copy(tmp2, XML_ATTR_UNAME, join_from);
	}

	crm_free(uuid_calc);	

	/* make sure these values are correct in the CIB */
	set_xml_property_copy(
		tmp2, XML_CIB_ATTR_EXPSTATE, CRMD_STATE_ACTIVE);
	set_xml_property_copy(
		tmp2, XML_CIB_ATTR_JOINSTATE,CRMD_JOINSTATE_MEMBER);

/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if(g_hash_table_size(joined_nodes)
		  >= (fsa_membership_copy->members_size -1)) {
		crm_info("That was the last outstanding join ack");
		return I_SUCCESS;
	}

	/* dont waste time by invoking the pe yet; */
	crm_debug("Still waiting on %d outstanding join acks",
		  fsa_membership_copy->members_size
		  - g_hash_table_size(joined_nodes) - 1);
	
	return I_CIB_OP;
}
