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

int reannounce_count = 0;
void join_query_callback(const HA_Message *msg, int call_id, int rc,
			 crm_data_t *output, void *user_data);

extern ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t *orig);

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
enum crmd_fsa_input
do_cl_join_query(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	HA_Message *req = create_request(CRM_OP_JOIN_ANNOUNCE, NULL, NULL,
					 CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

	crm_debug("Querying for a DC");
	send_msg_via_ha(fsa_cluster_conn, req);
	
	return I_NULL;
}


/*	 A_CL_JOIN_ANNOUNCE	*/

/* this is kind of a workaround for the fact that we may not be around
 * or are otherwise unable to reply when the DC sends out A_WELCOME_ALL
 */
enum crmd_fsa_input
do_cl_join_announce(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
	
	/* Once we hear from the DC, we can stop the timer
	 *
	 * This timer was started either on startup or when a node
	 * left the CCM list
	 */

	/* dont announce if we're in one of these states */
	if(cur_state != S_PENDING) {
		crm_warn("Do not announce ourselves in state %s",
			 fsa_state2string(cur_state));
		return I_NULL;
	}

	if(AM_I_OPERATIONAL) {
		const char *hb_from = cl_get_string(
			input->msg, F_CRM_HOST_FROM);

		crm_debug("Announcing availability");
		if(hb_from == NULL) {
			crm_err("Failed to determin origin of hb message");
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
			return I_NULL;
		}

		if(fsa_our_dc == NULL) {
			update_dc(input->msg);

		} else if(safe_str_neq(fsa_our_dc, hb_from)) {
			/* reset the fsa_our_dc to NULL */
			crm_warn("Resetting our DC to NULL after DC_HB"
				 " from unrecognised node.");
			update_dc(NULL);
			return I_NULL; /* for now, wait for the DC's
					* to settle down
					*/
		}
		
		/* send as a broadcast */
		{
			HA_Message *req = create_request(
				CRM_OP_JOIN_ANNOUNCE, NULL, NULL,
				CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

			send_msg_via_ha(fsa_cluster_conn, req);
		}
	
	} else {
		/* Delay announce until we have finished local startup */
		crm_warn("Delaying announce until local startup is complete");
		return I_NULL;
	}
	
	return I_NULL;
}


static int query_call_id = 0;

/*	 A_CL_JOIN_REQUEST	*/
/* aka. accept the welcome offer */
enum crmd_fsa_input
do_cl_join_offer_respond(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
	const char *welcome_from = cl_get_string(input->msg, F_CRM_HOST_FROM);
	
#if 0
	if(we are sick) {
		log error ;

		/* save the request for later? */
		return I_NULL;
	} 
#endif

	crm_debug("Accepting join offer: join-%s",
		  cl_get_string(input->msg, F_CRM_JOIN_ID));
	
	/* we only ever want the last one */
	if(query_call_id > 0) {
		crm_debug("Cancelling previous join query: %d", query_call_id);
		remove_cib_op_callback(query_call_id, FALSE);
		query_call_id = 0;
	}

	if(fsa_our_dc == NULL) {
		update_dc(input->msg);
		
	} else if(safe_str_neq(welcome_from, fsa_our_dc)) {
		/* dont do anything until DC's sort themselves out */
		crm_err("Expected a welcome from %s, but %s replied",
			fsa_our_dc, welcome_from);

		return I_NULL;
	}

	CRM_DEV_ASSERT(input != NULL);
	query_call_id = fsa_cib_conn->cmds->query(
		fsa_cib_conn, NULL, NULL, cib_scope_local);
	add_cib_op_callback(
		query_call_id, TRUE,
		copy_ha_msg_input(input), join_query_callback);
	crm_debug("Registered join query callback: %d", query_call_id);

	register_fsa_action(A_DC_TIMER_STOP);
	return I_NULL;
}

void
join_query_callback(const HA_Message *msg, int call_id, int rc,
		    crm_data_t *output, void *user_data)
{
	crm_data_t *local_cib = NULL;
	ha_msg_input_t *input = user_data;
	crm_data_t *generation = create_xml_node(
		NULL, XML_CIB_TAG_GENERATION_TUPPLE);

	CRM_DEV_ASSERT(input != NULL);

	query_call_id = 0;
	
	if(rc == cib_ok) {
		local_cib = find_xml_node(output, XML_TAG_CIB, TRUE);
	}
	
	if(local_cib != NULL) {
		HA_Message *reply = NULL;
		const char *join_id = ha_msg_value(input->msg, F_CRM_JOIN_ID);
		crm_debug("Respond to join offer join-%s", join_id);
		crm_debug("Acknowledging %s as our DC",
			  cl_get_string(input->msg, F_CRM_HOST_FROM));
		copy_in_properties(generation, local_cib);

		reply = create_request(
			CRM_OP_JOIN_REQUEST, generation, fsa_our_dc,
			CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

		ha_msg_add(reply, F_CRM_JOIN_ID, join_id);

		send_msg_via_ha(fsa_cluster_conn, reply);

	} else {
		crm_err("Could not retrieve Generation to attach to our"
			" join acknowledgement: %s", cib_error2string(rc));
		register_fsa_error_adv(
			C_FSA_INTERNAL, I_ERROR, NULL, NULL, __FUNCTION__);
	}
	
	delete_ha_msg_input(input);
	free_xml(generation);
}

/*	A_CL_JOIN_RESULT	*/
/* aka. this is notification that we have (or have not) been accepted */
enum crmd_fsa_input
do_cl_join_finalize_respond(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	crm_data_t *tmp1      = NULL;
	gboolean   was_nack   = TRUE;
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);

	int join_id = -1;
	const char *op           = cl_get_string(input->msg,F_CRM_TASK);
	const char *ack_nack     = cl_get_string(input->msg,CRM_OP_JOIN_ACKNAK);
	const char *welcome_from = cl_get_string(input->msg,F_CRM_HOST_FROM);
	
	if(safe_str_neq(op, CRM_OP_JOIN_ACKNAK)) {
		crm_debug_2("Ignoring op=%s message", op);
		return I_NULL;
	}
	
	/* calculate if it was an ack or a nack */
	if(crm_is_true(ack_nack)) {
		was_nack = FALSE;
	}

	ha_msg_value_int(input->msg, F_CRM_JOIN_ID, &join_id);
	
	if(was_nack) {
		crm_err("Join join-%d with %s failed.  NACK'd", join_id, welcome_from);
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
		return I_NULL;
	}

	if(AM_I_DC == FALSE && safe_str_eq(welcome_from, fsa_our_uname)) {
		crm_warn("Discarding our own welcome - we're no longer the DC");
		return I_NULL;
		
	} else if(fsa_our_dc == NULL) {
		update_dc(input->msg);
	} 	

	/* send our status section to the DC */
	crm_debug("Confirming join join-%d: %s",
		  join_id, cl_get_string(input->msg, F_CRM_TASK));
	crm_debug_2("Discovering local LRM status");
	tmp1 = do_lrm_query(TRUE);
	if(tmp1 != NULL) {
		HA_Message *reply = create_request(
			CRM_OP_JOIN_CONFIRM, tmp1, fsa_our_dc,
			CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);
		ha_msg_add_int(reply, F_CRM_JOIN_ID, join_id);
		
		crm_debug("join-%d: Join complete.  Sending local LRM status.",
			join_id);
		send_msg_via_ha(fsa_cluster_conn, reply);
		if(AM_I_DC == FALSE) {
 			register_fsa_input_adv(cause, I_NOT_DC, NULL,
 					       A_NOTHING, TRUE, __FUNCTION__);
		}
		free_xml(tmp1);
		
	} else {
		crm_err("Could send our LRM state to the DC");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
	}

	return I_NULL;
}
