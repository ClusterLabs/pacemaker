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

/*	A_CL_JOIN_QUERY		*/
/* is there a DC out there? */
enum crmd_fsa_input
do_cl_join_query(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	HA_Message *req = create_request(CRM_OP_ANNOUNCE, NULL, NULL,
					 CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);
	
	send_msg_via_ha(fsa_cluster_conn, req);

	/* ok, this is complete garbage
	 *
	 * what seems to happen is that this message is sent, but does not
	 *   arrive at the DC until the next message is sent (which happens to
	 *   an election vote - since no-one answered this one)
	 *
	 * worse is that without the sleep() below, all three messages show
	 *   up at the same time (12 seconds after the above message is sent)
	 *
	 * so for now I'll send a no-op
	 */
	sleep(2);
	
	req = create_request(CRM_OP_NOOP, NULL, NULL,
			     CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);
	
	send_msg_via_ha(fsa_cluster_conn, req);
	
	return I_NULL;
}


/*	 A_CL_JOIN_ANNOUNCE	*/

/* this is kind of a workaround for the the fact that we may not be around
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

		if(hb_from == NULL) {
			crm_err("Failed to determin origin of hb message");
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
			return I_NULL;
		}

		if(fsa_our_dc == NULL) {
			crm_info("Set DC to %s", hb_from);
			fsa_our_dc = crm_strdup(hb_from);

		} else if(safe_str_eq(hb_from, fsa_our_dc)) {
			reannounce_count++;
			if(fsa_join_reannouce > 0
			   && reannounce_count < fsa_join_reannouce) {
				crm_warn("Already announced to %s", hb_from);
				return I_NULL;
			}
			crm_warn("Re-announcing ourselves to %s (%d times)",
				 hb_from, reannounce_count);
			
		} else {
			crm_warn("We announced ourselves to %s, but are"
				 " now receiving DC Heartbeats from %s",
				 fsa_our_dc, hb_from);
			/* reset the fsa_our_dc to NULL */
			crm_warn("Resetting our DC to NULL after DC_HB"
				 " from unrecognised node.");
			crm_free(fsa_our_dc);
			fsa_our_dc = NULL;
			return I_NULL; /* for now, wait for the DC's
					* to settle down
					*/
		}
		
		reannounce_count = 0;
		/* send as a broadcast */
		{
			HA_Message *req = create_request(
			CRM_OP_ANNOUNCE, NULL, NULL,
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


/*	 A_CL_JOIN_REQUEST	*/

/* aka. accept the welcome offer */
enum crmd_fsa_input
do_cl_join_request(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	crm_data_t *tmp1;
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
	const char *welcome_from = cl_get_string(input->msg, F_CRM_HOST_FROM);
	HA_Message *reply = NULL;
	
#if 0
	if(we are sick) {
		log error ;

		/* save the request for later? */
		return I_NULL;
	} 
#endif
	if(fsa_our_dc == NULL) {
		crm_info("Set DC to %s", welcome_from);
		fsa_our_dc = crm_strdup(welcome_from);

	} else if(safe_str_neq(welcome_from, fsa_our_dc)) {
		/* dont do anything until DC's sort themselves out */
		crm_err("Expected a welcome from %s, but %s replied",
			fsa_our_dc, welcome_from);

		return I_NULL;
	}

	/* include our CIB generation tuple */
	tmp1 = cib_get_generation(fsa_cib_conn);
	if(tmp1 != NULL) {
		reply = create_reply(input->msg, tmp1);
		send_msg_via_ha(fsa_cluster_conn, reply);
		free_xml(tmp1);
	
		return I_NULL;
	}
	register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
	return I_NULL;
}

/*	A_CL_JOIN_RESULT	*/
/* aka. this is notification that we have (or have not) been accepted */
enum crmd_fsa_input
do_cl_join_result(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	gboolean   was_nack   = TRUE;
	crm_data_t *tmp1       = NULL;
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
	const char *ack_nack     = cl_get_string(input->msg, CRM_OP_JOINACK);
	const char *welcome_from = cl_get_string(input->msg, F_CRM_HOST_FROM);
	const char *type = cl_get_string(input->msg, F_SUBTYPE);

	if(safe_str_eq(type, XML_ATTR_RESPONSE)) {
		crm_verbose("Ignoring result.");
		crm_log_message(LOG_VERBOSE, input->msg);
		return I_NULL;
	}
	
	/* calculate if it was an ack or a nack */
	if(crm_is_true(ack_nack)) {
		was_nack = FALSE;
	}
	
	if(was_nack) {
		crm_err("Join with %s failed.  NACK'd", welcome_from);
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
		return I_NULL;
	}

	if(AM_I_DC == FALSE && safe_str_eq(welcome_from, fsa_our_uname)) {
		crm_warn("Discarding our own welcome - we're no longer the DC");
		return I_NULL;
		
	} else if(g_hash_table_lookup(
			  fsa_membership_copy->members, welcome_from) == NULL){
		crm_warn("Discarding welcome from %s."
			 "  They are no longer part of the cluster",
			 welcome_from);
		return I_NULL;
		
	} else if(fsa_our_dc == NULL) {
		crm_info("Set DC to %s", welcome_from);
		fsa_our_dc = crm_strdup(welcome_from);
	} 	

	/* send our status section to the DC */
	crm_devel("Discovering local LRM status");
	tmp1 = do_lrm_query(TRUE);
	if(tmp1 != NULL) {
		HA_Message *reply = create_reply(input->msg, tmp1);
		crm_devel("Sending local LRM status");
		send_msg_via_ha(fsa_cluster_conn, reply);
		
		free_xml(tmp1);

		if(AM_I_DC == FALSE) {
			register_fsa_input(cause, I_NOT_DC, NULL);
		}
		
	} else {
		crm_err("Could send our LRM state to the DC");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
	}

	return I_NULL;
}
