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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crmd_fsa.h>
#include <crmd_messages.h>


int reannounce_count = 0;
void join_query_callback(xmlNode *msg, int call_id, int rc,
			 xmlNode *output, void *user_data);

extern ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t *orig);

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
void
do_cl_join_query(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	xmlNode *req = create_request(CRM_OP_JOIN_ANNOUNCE, NULL, NULL,
					 CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

	sleep(1);  /* give the CCM time to propogate to the DC */
	crm_debug("Querying for a DC");
	send_msg_via_ha(req);
	free_xml(req);
}


/*	 A_CL_JOIN_ANNOUNCE	*/

/* this is kind of a workaround for the fact that we may not be around
 * or are otherwise unable to reply when the DC sends out A_WELCOME_ALL
 */
void
do_cl_join_announce(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	/* Once we hear from the DC, we can stop the timer
	 *
	 * This timer was started either on startup or when a node
	 * left the CCM list
	 */

	/* dont announce if we're in one of these states */
	if(cur_state != S_PENDING) {
		crm_warn("Do not announce ourselves in state %s",
			 fsa_state2string(cur_state));
		return;
	}

	if(AM_I_OPERATIONAL) {
		/* send as a broadcast */
		xmlNode *req = create_request(
			CRM_OP_JOIN_ANNOUNCE, NULL, NULL,
			CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

		crm_debug("Announcing availability");
		update_dc(NULL, FALSE);
		send_msg_via_ha(req);
		free_xml(req);
	
	} else {
		/* Delay announce until we have finished local startup */
		crm_warn("Delaying announce until local startup is complete");
		return;
	}
}


static int query_call_id = 0;

/*	 A_CL_JOIN_REQUEST	*/
/* aka. accept the welcome offer */
void
do_cl_join_offer_respond(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
	const char *welcome_from = crm_element_value(input->msg, F_CRM_HOST_FROM);
	const char *join_id = crm_element_value(input->msg, F_CRM_JOIN_ID);
	
#if 0
	if(we are sick) {
		log error ;

		/* save the request for later? */
		return;
	} 
#endif

	crm_debug_2("Accepting join offer: join-%s",
		    crm_element_value(input->msg, F_CRM_JOIN_ID));
	
	/* we only ever want the last one */
	if(query_call_id > 0) {
		crm_debug_3("Cancelling previous join query: %d", query_call_id);
		remove_cib_op_callback(query_call_id, FALSE);
		query_call_id = 0;
	}

	update_dc(input->msg, FALSE);
	if(safe_str_neq(welcome_from, fsa_our_dc)) {
		/* dont do anything until DC's sort themselves out */
		crm_err("Expected a welcome from %s, but %s replied",
			fsa_our_dc, welcome_from);

		return;
	}

	CRM_DEV_ASSERT(input != NULL);
	query_call_id = fsa_cib_conn->cmds->query(
		fsa_cib_conn, NULL, NULL, cib_scope_local);
	add_cib_op_callback(
	    fsa_cib_conn, query_call_id, FALSE, crm_strdup(join_id), join_query_callback);
	crm_debug_2("Registered join query callback: %d", query_call_id);

	register_fsa_action(A_DC_TIMER_STOP);
}

void
join_query_callback(xmlNode *msg, int call_id, int rc,
		    xmlNode *output, void *user_data)
{
	xmlNode *local_cib = NULL;
	char *join_id = user_data;
	xmlNode *generation = create_xml_node(
		NULL, XML_CIB_TAG_GENERATION_TUPPLE);

	CRM_DEV_ASSERT(join_id != NULL);

	query_call_id = 0;
	
	if(rc == cib_ok) {
#if CRM_DEPRECATED_SINCE_2_0_4
		if(safe_str_eq(crm_element_name(output), XML_TAG_CIB)) {
			local_cib = output;
		} else {
			local_cib = find_xml_node(output, XML_TAG_CIB, TRUE);
		}
#else
		local_cib = output;
		CRM_DEV_ASSERT(safe_str_eq(crm_element_name(local_cib), XML_TAG_CIB));
#endif
	}
	
	if(local_cib != NULL) {
		xmlNode *reply = NULL;
		crm_debug("Respond to join offer join-%s", join_id);
		crm_debug("Acknowledging %s as our DC", fsa_our_dc);
		copy_in_properties(generation, local_cib);

		reply = create_request(
			CRM_OP_JOIN_REQUEST, generation, fsa_our_dc,
			CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

		crm_xml_add(reply, F_CRM_JOIN_ID, join_id);
		send_msg_via_ha(reply);
		free_xml(reply);

	} else {
		crm_err("Could not retrieve Generation to attach to our"
			" join acknowledgement: %s", cib_error2string(rc));
		register_fsa_error_adv(
			C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
	}
	
	crm_free(join_id);
	free_xml(generation);
}

/*	A_CL_JOIN_RESULT	*/
/* aka. this is notification that we have (or have not) been accepted */
void
do_cl_join_finalize_respond(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	xmlNode *tmp1      = NULL;
	gboolean   was_nack   = TRUE;
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);

	int join_id = -1;
	const char *op           = crm_element_value(input->msg,F_CRM_TASK);
	const char *ack_nack     = crm_element_value(input->msg,CRM_OP_JOIN_ACKNAK);
	const char *welcome_from = crm_element_value(input->msg,F_CRM_HOST_FROM);
	
	if(safe_str_neq(op, CRM_OP_JOIN_ACKNAK)) {
		crm_debug_2("Ignoring op=%s message", op);
		return;
	}

	/* calculate if it was an ack or a nack */
	if(crm_is_true(ack_nack)) {
		was_nack = FALSE;
	}

	crm_element_value_int(input->msg, F_CRM_JOIN_ID, &join_id);
	
	if(was_nack) {
		crm_err("Join join-%d with %s failed.  NACK'd",
			join_id, welcome_from);
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
		return;
	}

	if(AM_I_DC == FALSE && safe_str_eq(welcome_from, fsa_our_uname)) {
		crm_warn("Discarding our own welcome - we're no longer the DC");
		return;
	} 	

	update_dc(input->msg, TRUE);

	/* send our status section to the DC */
	crm_debug("Confirming join join-%d: %s",
		  join_id, crm_element_value(input->msg, F_CRM_TASK));
	tmp1 = do_lrm_query(TRUE);
	if(tmp1 != NULL) {
		xmlNode *reply = create_request(
			CRM_OP_JOIN_CONFIRM, tmp1, fsa_our_dc,
			CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);
		crm_xml_add_int(reply, F_CRM_JOIN_ID, join_id);
		
		crm_debug("join-%d: Join complete."
			  "  Sending local LRM status to %s",
			  join_id, fsa_our_dc);
		send_msg_via_ha(reply);
		free_xml(reply);
		if(AM_I_DC == FALSE) {
 			register_fsa_input_adv(
			    cause, I_NOT_DC, NULL, A_NOTHING, TRUE, __FUNCTION__);
		}
		free_xml(tmp1);
		
	} else {
		crm_err("Could not send our LRM state to the DC");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
	}
}
