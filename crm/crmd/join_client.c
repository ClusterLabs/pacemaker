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



/*	 A_CL_JOIN_ANNOUNCE	*/

/* this is kind of a workaround for the the fact that we may not be around
 * or are otherwise unable to reply when the DC sends out A_WELCOME_ALL
 */
enum crmd_fsa_input
do_cl_join_announce(long long action,
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
	if(cur_state != S_PENDING) {
		crm_warn("Do not announce ourselves in state %s",
			 fsa_state2string(cur_state));
		return I_NULL;
	}

	if(AM_I_OPERATIONAL) {
		const char *hb_from = xmlGetProp(msg, XML_ATTR_HOSTFROM);

		if(hb_from == NULL) {
			crm_err("Failed to determin origin of hb message");
			return I_FAIL;
		}

		if(fsa_our_dc == NULL) {
			fsa_our_dc = hb_from;

		} else if(safe_str_eq(hb_from, fsa_our_dc)) {
			crm_debug("Already announced to %s", hb_from);
			return I_NULL;

		} else {
			crm_warn("We announced ourselves to %s, but are"
				 " now receiving DC Heartbeats from %s",
				 fsa_our_dc, hb_from);
			/* reset the fsa_our_dc to NULL */
			fsa_our_dc = NULL;
			return I_NULL; /* for now, wait for the DC's
					* to settle down
					*/
		}
		send_request(NULL, NULL, CRM_OP_ANNOUNCE,
			     hb_from, CRM_SYSTEM_DC, NULL);
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
	    void *data)
{
	xmlNodePtr tmp1;
	xmlNodePtr welcome = (xmlNodePtr)data;

	const char *welcome_from = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
	
#if 0
	if(we are sick) {
		log error ;
		return I_NULL;
	} 
#endif
	if(fsa_our_dc == NULL) {
		fsa_our_dc = welcome_from;

	} else if(safe_str_neq(welcome_from, fsa_our_dc)) {
		/* dont do anything until DC's sort themselves out */
		crm_err("Expected a welcome from %s, but %s replied",
			fsa_our_dc, welcome_from);

		return I_NULL;
	}

	/* include our CIB generation tuple */
	tmp1 = cib_get_generation();
	send_ha_reply(fsa_cluster_conn, welcome, tmp1);
	free_xml(tmp1);
	
	return I_NULL;
}

/*	A_CL_JOIN_RESULT	*/
/* aka. this is notification that we have (or have not) been accepted */
enum crmd_fsa_input
do_cl_join_result(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	gboolean   was_nack      = TRUE;
	xmlNodePtr welcome       = (xmlNodePtr)data;
	xmlNodePtr tmp1          = find_xml_node(welcome, XML_TAG_OPTIONS);
	const char *ack_nack     = xmlGetProp(tmp1, CRM_OP_JOINACK);
	const char *welcome_from = xmlGetProp(welcome, XML_ATTR_HOSTFROM);
	xmlNodePtr tmp2          = NULL;

	/* calculate if it was an ack or a nack */
	if(safe_str_eq(ack_nack, XML_BOOLEAN_TRUE)) {
		was_nack = FALSE;
	}
	
	if(was_nack) {
		crm_err("Join with %s failed.  NACK'd", welcome_from);
		return I_ERROR;
	}
	
	/* send our status section to the DC */
	tmp1 = do_lrm_query(TRUE);
	if(tmp1 != NULL) {
		tmp2 = create_cib_fragment(tmp1, NULL);

		send_ha_reply(fsa_cluster_conn, welcome, tmp2);

		free_xml(tmp2);
		free_xml(tmp1);
	}
	
	return I_SUCCESS;
}
