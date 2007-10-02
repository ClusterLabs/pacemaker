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

/* put these first so that uuid_t is defined without conflicts */
#include <lha_internal.h>
#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

#include <clplumbing/GSource.h>
#include <string.h>

#include <heartbeat.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/cluster.h>
#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_callbacks.h>


void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

void crmd_ccm_msg_callback(
    oc_ed_t event, void *cookie, size_t size, const void *data);

void ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data);
void check_dead_member(const char *uname, GHashTable *members);
void reap_dead_ccm_nodes(gpointer key, gpointer value, gpointer user_data);

#define CCM_EVENT_DETAIL 0
#define CCM_EVENT_DETAIL_PARTIAL 0

oc_ev_t *fsa_ev_token;
int num_ccm_register_fails = 0;
int max_ccm_register_fails = 30;

extern GHashTable *voted;

struct update_data_s
{
		const char *state;
		const char *caller;
		crm_data_t *updates;
		gboolean    overwrite_join;
};

void reap_dead_ccm_nodes(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    check_dead_member(node->uname, NULL);
}

void
check_dead_member(const char *uname, GHashTable *members)
{
	CRM_CHECK(uname != NULL, return);
	if(members != NULL && g_hash_table_lookup(members, uname) != NULL) {
		crm_err("%s didnt really leave the membership!", uname);
		return;
	}

	erase_node_from_join(uname);
	if(voted != NULL) {
		g_hash_table_remove(voted, uname);
	}
	
	if(safe_str_eq(fsa_our_uname, uname)) {
		crm_err("We're not part of the cluster anymore");
	}
	
	if(AM_I_DC == FALSE && safe_str_eq(uname, fsa_our_dc)) {
		crm_warn("Our DC node (%s) left the cluster", uname);
		register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
	}
}

void
ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data)
{
	crm_data_t *tmp1 = NULL;
	const char *join = NULL;
	const char *peer_online = NULL;
	crm_node_t *node = value;
	struct update_data_s* data = (struct update_data_s*)user_data;

	data->state = XML_BOOLEAN_NO;
	if(safe_str_eq(node->state, CRM_NODE_ACTIVE)) {
	    data->state = XML_BOOLEAN_YES;
	}
	
	crm_debug_2("Updating %s: %s (overwrite=%s)",
		    node->uname, data->state,
		    data->overwrite_join?"true":"false");

	peer_online = g_hash_table_lookup(crmd_peer_state, node->uname);
	
	if(data->overwrite_join) {
		if(safe_str_neq(peer_online, ONLINESTATUS)) {
			join  = CRMD_JOINSTATE_DOWN;
			
		} else {
			const char *peer_member = g_hash_table_lookup(
				confirmed_nodes, node->uname);
			if(peer_member != NULL) {
				join = CRMD_JOINSTATE_MEMBER;
			} else {
				join = CRMD_JOINSTATE_PENDING;
			}
		}
	}
	
	tmp1 = create_node_state(node->uname, NULL, data->state, peer_online,
				 join, NULL, FALSE, data->caller);

	add_node_copy(data->updates, tmp1);
	free_xml(tmp1);
}

/*	 A_CCM_CONNECT	*/
enum crmd_fsa_input
do_ccm_control(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		fsa_data_t *msg_data)
{	
	if(action & A_CCM_DISCONNECT){
		set_bit_inplace(fsa_input_register, R_CCM_DISCONNECTED);
		crm_membership_destroy();
#ifndef WITH_NATIVE_AIS
		oc_ev_unregister(fsa_ev_token);
#endif
	}

	if(action & A_CCM_CONNECT) {
#ifdef WITH_NATIVE_AIS
		crm_membership_init();
#else
		int      ret;
		int	 fsa_ev_fd; 
		gboolean did_fail = FALSE;
		crm_membership_init();
		crm_debug_3("Registering with CCM");
		clear_bit_inplace(fsa_input_register, R_CCM_DISCONNECTED);
		ret = oc_ev_register(&fsa_ev_token);
		if (ret != 0) {
			crm_warn("CCM registration failed");
			did_fail = TRUE;
		}

		if(did_fail == FALSE) {
			crm_debug_3("Setting up CCM callbacks");
			ret = oc_ev_set_callback(fsa_ev_token, OC_EV_MEMB_CLASS,
						 crmd_ccm_msg_callback, NULL);
			if (ret != 0) {
				crm_warn("CCM callback not set");
				did_fail = TRUE;
			}
		}
		if(did_fail == FALSE) {
			oc_ev_special(fsa_ev_token, OC_EV_MEMB_CLASS, 0/*don't care*/);
			
			crm_debug_3("Activating CCM token");
			ret = oc_ev_activate(fsa_ev_token, &fsa_ev_fd);
			if (ret != 0){
				crm_warn("CCM Activation failed");
				did_fail = TRUE;
			}
		}

		if(did_fail) {
			num_ccm_register_fails++;
			oc_ev_unregister(fsa_ev_token);
			
			if(num_ccm_register_fails < max_ccm_register_fails) {
				crm_warn("CCM Connection failed"
					 " %d times (%d max)",
					 num_ccm_register_fails,
					 max_ccm_register_fails);
				
				crm_timer_start(wait_timer);
				crmd_fsa_stall(NULL);
				return I_NULL;
				
			} else {
				crm_err("CCM Activation failed %d (max) times",
					num_ccm_register_fails);
				register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
				return I_NULL;
			}
		}
		

		crm_info("CCM connection established..."
			 " waiting for first callback");

		G_main_add_fd(G_PRIORITY_HIGH, fsa_ev_fd, FALSE, ccm_dispatch,
			      fsa_ev_token, default_ipc_connection_destroy);
		
#endif
	}

	if(action & ~(A_CCM_CONNECT|A_CCM_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
	
	return I_NULL;
}


#ifdef WITH_NATIVE_AIS
enum crmd_fsa_input do_ccm_update_cache(
    long long action, enum crmd_fsa_cause cause, enum crmd_fsa_state cur_state,
    enum crmd_fsa_input current_input, fsa_data_t *msg_data)
{
    return I_NULL;
}


enum crmd_fsa_input do_ccm_event(
    long long action, enum crmd_fsa_cause cause, enum crmd_fsa_state cur_state,
    enum crmd_fsa_input current_input, fsa_data_t *msg_data)
{
    return I_NULL;
}

#else

/*	 A_CCM_EVENT	*/
enum crmd_fsa_input
do_ccm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	enum crmd_fsa_input return_input = I_NULL;
	oc_ed_t event;
	const oc_ev_membership_t *oc = NULL;
	struct crmd_ccm_data_s *ccm_data = fsa_typed_data(fsa_dt_ccm);
	
	if(ccm_data == NULL) {
		crm_err("No data provided to FSA function");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;

	} else if(msg_data->fsa_cause != C_CCM_CALLBACK) {
		crm_err("FSA function called in response to incorect input");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}

	event = ccm_data->event;
	oc = ccm_data->oc;
	
	ccm_event_detail(oc, event);

	if (OC_EV_MS_EVICTED == event) {
		/* todo: drop back to S_PENDING instead */
		/* get out... NOW!
		 *
		 * go via the error recovery process so that HA will
		 *    restart us if required
		 */
		register_fsa_error(cause, I_ERROR, msg_data->data);
		return I_NULL;
	}	
	
	return return_input;
}

/*	 A_CCM_UPDATE_CACHE	*/
/*
 * Take the opportunity to update the node status in the CIB as well
 */
enum crmd_fsa_input
do_ccm_update_cache(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	enum crmd_fsa_input next_input = I_NULL;
	unsigned int	lpc;
	int		offset;
	GHashTable *members = NULL;
	oc_ed_t event;
	const oc_ev_membership_t *oc = NULL;
	oc_node_list_t *tmp = NULL, *membership_copy = NULL;
	struct crmd_ccm_data_s *ccm_data = fsa_typed_data(fsa_dt_ccm);
	HA_Message *no_op = NULL;
	
	if(ccm_data == NULL) {
		crm_err("No data provided to FSA function");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}

	event = ccm_data->event;
	oc = ccm_data->oc;

	if(crm_membership_seq > oc->m_instance) {
		crm_debug("Ignoring superceeded %s CCM event %d - we had %d", 
			  ccm_event_name(event), oc->m_instance,
			  crm_membership_seq);
		return I_NULL;
	}
	
	crm_membership_seq = oc->m_instance;
	crm_debug("Updating cache after CCM event %d (%s).", 
		  oc->m_instance, ccm_event_name(event));
	
	crm_debug_2("instance=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
		    "new_idx=%d, old_idx=%d",
		    oc->m_instance,
		    oc->m_n_member, oc->m_n_in, oc->m_n_out,
		    oc->m_memb_idx, oc->m_in_idx, oc->m_out_idx);
		
	crm_debug_3("Copying dead members");

	/*--*-- Recently Dead Member Nodes --*--*/
	offset = oc->m_out_idx;
	for(lpc=0; lpc < membership_copy->m_out; lpc++) {
	    update_ccm_node(fsa_cluster_conn, oc, offset+lpc, CRM_NODE_LOST);
	}

	crm_debug_3("Copying members");
	
	/*--*-- All Member Nodes --*--*/
	offset = oc->m_memb_idx;
	for(lpc=0; lpc < membership_copy->m_n_member; lpc++) {
	    update_ccm_node(fsa_cluster_conn, oc, offset+lpc, CRM_NODE_ACTIVE);
	}

	if(event == OC_EV_MS_EVICTED) {
	    update_ccm_node(fsa_cluster_conn, oc, offset+lpc, CRM_NODE_EVICTED);
	}

	g_hash_table_foreach(crm_membership_cache, reap_dead_ccm_nodes, NULL);

	crm_debug("Updated membership cache with %d (%d new, %d lost) members",
		  oc->m_n_memb, oc->m_n_in, oc->m_n_out);

	set_bit_inplace(fsa_input_register, R_CCM_DATA);

	if(cur_state != S_STOPPING) {
		crm_debug_3("Updating the CIB from CCM cache");
		do_update_cib_nodes(FALSE, __FUNCTION__);
	}

	/* Membership changed, remind everyone we're here.
	 * This will aid detection of duplicate DCs
	 */
	no_op = create_request(
		CRM_OP_NOOP, NULL, NULL, CRM_SYSTEM_CRMD,
		AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD, NULL);
	send_msg_via_ha(fsa_cluster_conn, no_op);

	return next_input;
}

void
ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event)
{
	int lpc;
	gboolean member = FALSE;
	member = FALSE;

	crm_debug_2("-----------------------");
	crm_info("%s: trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
		 "new_idx=%d, old_idx=%d",
		 ccm_event_name(event),
		 oc->m_instance,
		 oc->m_n_member,
		 oc->m_n_in,
		 oc->m_n_out,
		 oc->m_memb_idx,
		 oc->m_in_idx,
		 oc->m_out_idx);
	
#if !CCM_EVENT_DETAIL_PARTIAL
	for(lpc=0; lpc < oc->m_n_member; lpc++) {
		crm_info("\tCURRENT: %s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_memb_idx+lpc].node_uname,
		       oc->m_array[oc->m_memb_idx+lpc].node_id,
		       oc->m_array[oc->m_memb_idx+lpc].node_born_on);

		if(safe_str_eq(fsa_our_uname,
			       oc->m_array[oc->m_memb_idx+lpc].node_uname)) {
			member = TRUE;
		}
	}
	if (member == FALSE) {
		crm_warn("MY NODE IS NOT IN CCM THE MEMBERSHIP LIST");
	}
#endif
	for(lpc=0; lpc<(int)oc->m_n_in; lpc++) {
		crm_info("\tNEW:     %s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_in_idx+lpc].node_uname,
		       oc->m_array[oc->m_in_idx+lpc].node_id,
		       oc->m_array[oc->m_in_idx+lpc].node_born_on);
	}
	
	for(lpc=0; lpc<(int)oc->m_n_out; lpc++) {
		crm_info("\tLOST:    %s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_out_idx+lpc].node_uname,
		       oc->m_array[oc->m_out_idx+lpc].node_id,
		       oc->m_array[oc->m_out_idx+lpc].node_born_on);
	}
	
	crm_debug_2("-----------------------");
	
}

#endif

static void
ccm_node_update_complete(const HA_Message *msg, int call_id, int rc,
			 crm_data_t *output, void *user_data)
{
	fsa_data_t *msg_data = NULL;
	
	if(rc == cib_ok) {
		crm_debug("Node update %d complete", call_id);

	} else {
		crm_err("Node update %d failed", call_id);
		crm_log_message(LOG_DEBUG, msg);
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}
}

void
do_update_cib_nodes(gboolean overwrite, const char *caller)
{
	int call_id = 0;
	int call_options = cib_scope_local|cib_quorum_override;
	struct update_data_s update_data;
	crm_data_t *fragment = NULL;

	if(crm_membership_cache == NULL) {
		/* We got a replace notification before being connected to
		 *   the CCM.
		 * So there is no need to update the local CIB with our values
		 *   - since we have none.
		 */
		return;
	}
	
	fragment = create_xml_node(NULL, XML_CIB_TAG_STATUS);

	update_data.caller = caller;
	update_data.updates = fragment;
	update_data.overwrite_join = overwrite;

	if(overwrite == FALSE) {
		call_options = call_options|cib_inhibit_bcast;
		crm_debug_2("Inhibiting bcast for membership updates");
	}

	g_hash_table_foreach(crm_membership_cache, ghash_update_cib_node, &update_data);

	fsa_cib_update(XML_CIB_TAG_STATUS, fragment, call_options, call_id);
	add_cib_op_callback(call_id, FALSE, NULL, ccm_node_update_complete);

	free_xml(fragment);
}
