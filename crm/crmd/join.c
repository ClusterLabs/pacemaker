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

#include <heartbeat.h>

#include <crm/dmalloc_wrapper.h>

GHashTable *joined_nodes = NULL;

/*	 A_JOIN_WELCOME, A_JOIN_WELCOME_ALL	*/
enum crmd_fsa_input
do_send_welcome(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
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

			xmlNodePtr update = create_node_state(
				join_to, NULL, NULL, CRMD_JOINSTATE_PENDING);

			xmlNodePtr tmp1 = create_cib_fragment(update, NULL);
			store_request(NULL, tmp1, CRM_OP_UPDATE, CRM_SYSTEM_DCIB);

			send_request(NULL, NULL, CRM_OP_WELCOME,
				     join_to, CRM_SYSTEM_CRMD, NULL);

			free_xml(update);
			free_xml(tmp1);
			
		} else {
			cl_log(LOG_ERR, "No recipient for welcome message");
		}
		
		FNRET(I_NULL);

	}
	FNRET(I_ERROR);
}

// welcome everyone...

enum crmd_fsa_input
do_send_welcome_all(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	FNIN();

	// reset everyones status back to down or in_ccm in the CIB
	xmlNodePtr update     = NULL;
	xmlNodePtr cib_copy   = get_cib_copy();
	xmlNodePtr tmp1       = get_object_root(XML_CIB_TAG_STATUS, cib_copy);
	xmlNodePtr node_entry = tmp1->children;

	/* Give everyone a chance to join before invoking the PolicyEngine */
	stopTimer(integration_timer);
	startTimer(integration_timer);
	
	if(joined_nodes != NULL) {
		g_hash_table_destroy(joined_nodes);
		joined_nodes = g_hash_table_new(&g_str_hash, &g_str_equal);
		
	}

	// catch any nodes that are active in the CIB but not in the CCM list 
	while(node_entry != NULL){
		const char *node_id = xmlGetProp(node_entry, XML_ATTR_ID);

		gpointer a_node =
			g_hash_table_lookup(fsa_membership_copy->members,
					    node_id);

		node_entry = node_entry->next;

		if(a_node != NULL || (safe_str_eq(fsa_our_uname, node_id))) {
			/* handled by do_update_cib_node() */
			continue;
		}

		tmp1 = create_node_state(node_id, XML_BOOLEAN_NO, NULL, CRMD_JOINSTATE_DOWN);

		if(update == NULL) {
			update = tmp1;
		} else {
			update = xmlAddSibling(update, tmp1);
		}
	}

	// now process the CCM data
	free_xml(do_update_cib_nodes(update, TRUE));
	free_xml(cib_copy);

	/* Avoid ordered message delays caused when the CRMd proc
	 * isnt running yet (ie. send as a broadcast msg which are never
	 * sent ordered.
	 */
	send_request(NULL, NULL, CRM_OP_WELCOME,
		     NULL, CRM_SYSTEM_CRMD, NULL);

/* No point hanging around in S_INTEGRATION if we're the only ones here! */
	if(g_hash_table_size(joined_nodes)
	   == fsa_membership_copy->members_size) {
		// that was the last outstanding join ack)
		cl_log(LOG_INFO,"That was the last outstanding join ack");
		FNRET(I_SUCCESS);
		
	} else {
		cl_log(LOG_DEBUG,
		       "Still waiting on %d outstanding join acks",
		       fsa_membership_copy->members_size - g_hash_table_size(joined_nodes));
		// dont waste time by invoking the pe yet;
	}
	
	FNRET(I_NULL);
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
		
		send_request(NULL, NULL, CRM_OP_ANNOUNCE,
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
	
	/* add them to our list of CRMD_STATE_ACTIVE nodes
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

	/* make sure a node entry exists for the new node
	 *
	 * this will add anyone except the first ever node in the cluster
	 *   since it will also be the DC which doesnt go through the
	 *   join process (with itself).  We can include a special case
	 *   later if desired.
	 */
	tmp1 = create_xml_node(NULL, XML_CIB_TAG_NODE);
	set_xml_property_copy(tmp1, XML_ATTR_ID, join_from);
	set_xml_property_copy(tmp1, "uname", join_from);
	set_xml_property_copy(tmp1, XML_ATTR_TYPE, "node");
	
	tmp2 = create_cib_fragment(tmp1, NULL);

	/* do not forward this to the TE */
	invoke_local_cib(NULL, tmp2, CRM_OP_UPDATE);
	
	free_xml(tmp2);
	free_xml(tmp1);
	

	/* Make changes so that exp_state=active for this node when the update
	 *  is processed by A_CIB_INVOKE
	 */
	msg_cib = find_xml_node(cib_fragment, XML_TAG_CIB);
	tmp1 = get_object_root(XML_CIB_TAG_STATUS, msg_cib);
	tmp2 = find_entity(tmp1, XML_CIB_TAG_STATE, join_from, FALSE);

	if(tmp2 == NULL) {
		cl_log(LOG_ERR,
		       "Status entry for %s not found in update, adding",
		       join_from);
		
		tmp2 = create_xml_node(tmp1, XML_CIB_TAG_STATE);
		set_xml_property_copy(tmp2, XML_ATTR_ID, join_from);
	}
	
	set_xml_property_copy(tmp2, XML_CIB_ATTR_EXPSTATE, CRMD_STATE_ACTIVE);
	set_xml_property_copy(tmp2, XML_CIB_ATTR_JOINSTATE,      CRMD_JOINSTATE_MEMBER);

	
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
