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
#include <crm_internal.h>
#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

#include <clplumbing/GSource.h>
#include <string.h>

#include <heartbeat.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_callbacks.h>


void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

int register_with_ccm(ll_cluster_t *hb_cluster);

void msg_ccm_join(const HA_Message *msg, void *foo);

void crmd_ccm_msg_callback(oc_ed_t event,
			     void *cookie,
			     size_t size,
			     const void *data);

void ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data);

#define CCM_EVENT_DETAIL 0
#define CCM_EVENT_DETAIL_PARTIAL 0

oc_ev_t *fsa_ev_token;
int current_ccm_membership_id = 0;
int num_ccm_register_fails = 0;
int max_ccm_register_fails = 30;

/*	 A_CCM_CONNECT	*/
void
do_ccm_control(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		fsa_data_t *msg_data)
{
	int      ret;
 	int	 fsa_ev_fd; 
	gboolean did_fail = FALSE;
	
	if(action & A_CCM_DISCONNECT){
		set_bit_inplace(fsa_input_register, R_CCM_DISCONNECTED);
		oc_ev_unregister(fsa_ev_token);
	}

	if(action & A_CCM_CONNECT) {
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
				return;
				
			} else {
				crm_err("CCM Activation failed %d (max) times",
					num_ccm_register_fails);
				register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
				return;
			}
		}
		

		crm_info("CCM connection established..."
			 " waiting for first callback");

		G_main_add_fd(G_PRIORITY_HIGH, fsa_ev_fd, FALSE, ccm_dispatch,
			      fsa_ev_token, default_ipc_connection_destroy);
		
	}

	if(action & ~(A_CCM_CONNECT|A_CCM_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
}

extern GHashTable *voted;

/*	 A_CCM_EVENT	*/
void
do_ccm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	oc_ed_t event;
	const oc_ev_membership_t *oc = NULL;
	struct crmd_ccm_data_s *ccm_data = fsa_typed_data(fsa_dt_ccm);
	
	if(ccm_data == NULL) {
		crm_err("No data provided to FSA function");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return;

	} else if(msg_data->fsa_cause != C_CCM_CALLBACK) {
		crm_err("FSA function called in response to incorect input");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return;
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
		return;
	}	
}

static void
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

/*	 A_CCM_UPDATE_CACHE	*/
/*
 * Take the opportunity to update the node status in the CIB as well
 */
void
do_ccm_update_cache(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	unsigned int	lpc;
	int		offset;
	GHashTable *members = NULL;
	oc_ed_t event;
	const oc_ev_membership_t *oc = NULL;
	oc_node_list_t *tmp = NULL, *membership_copy = NULL;
	struct crmd_ccm_data_s *ccm_data = fsa_typed_data(fsa_dt_ccm);
	HA_Message *no_op = create_request(
		CRM_OP_NOOP, NULL, NULL, CRM_SYSTEM_CRMD,
		AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD, NULL);
	
	if(ccm_data == NULL) {
		crm_err("No data provided to FSA function");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		send_msg_via_ha(fsa_cluster_conn, no_op);
		return;
	}

	event = ccm_data->event;
	oc = ccm_data->oc;

	if(current_ccm_membership_id > oc->m_instance) {
		crm_debug("Ignoring superceeded %s CCM event %d - we had %d", 
			  ccm_event_name(event), oc->m_instance,
			  current_ccm_membership_id);
		return;
	}
	
	current_ccm_membership_id = oc->m_instance;
	crm_debug("Updating cache after CCM event %d (%s).", 
		  oc->m_instance, ccm_event_name(event));
	
	crm_debug_2("instance=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
		  "new_idx=%d, old_idx=%d",
		  oc->m_instance,
		  oc->m_n_member,
		  oc->m_n_in,
		  oc->m_n_out,
		  oc->m_memb_idx,
		  oc->m_in_idx,
		  oc->m_out_idx);
#define ALAN_DEBUG 1
#ifdef ALAN_DEBUG
	{
		/*
		 *	Size	(Size + 2) / 2
		 *
		 *	3	(3+2)/2	= 5 / 2 = 2
		 *	4	(4+2)/2	= 6 / 2 = 3
		 *	5	(5+2)/2	= 7 / 2 = 3
		 *	6	(6+2)/2	= 8 / 2 = 4
		 *	7	(7+2)/2	= 9 / 2 = 4
		 */
		unsigned int		clsize = (oc->m_out_idx - oc->m_n_member);
		unsigned int		plsize = (clsize + 2)/2;
		gboolean	plurality = (oc->m_n_member >= plsize);
		gboolean	Q = ccm_have_quorum(event);

		if(clsize == 2) {
			if (!Q) {
				crm_err("2 nodes w/o quorum");
			}
			
		} else if(Q && !plurality) {
			crm_err("Quorum w/o plurality (%d/%d nodes)",
				oc->m_n_member, clsize);
		} else if(plurality && !Q) {
			crm_err("Plurality w/o Quorum (%d/%d nodes)",
				oc->m_n_member, clsize);
		} else {
			crm_debug_2("Quorum(%s) and plurality (%d/%d) agree.",
				    Q?"true":"false", oc->m_n_member, clsize);
		}
		
	}
#endif
		
	crm_malloc0(membership_copy, sizeof(oc_node_list_t));
	membership_copy->id = oc->m_instance;
	membership_copy->last_event = event;

	crm_debug_3("Copying members");

	/*--*-- All Member Nodes --*--*/
	offset = oc->m_memb_idx;
	membership_copy->members_size = oc->m_n_member;

	if(membership_copy->members_size > 0) {
		membership_copy->members =
			g_hash_table_new(g_str_hash, g_str_equal);
		members = membership_copy->members;
		
		for(lpc=0; lpc < membership_copy->members_size; lpc++) {
			oc_node_t *member = NULL;
			CRM_CHECK(oc->m_array[offset+lpc].node_uname != NULL,
				  continue);

			crm_malloc0(member, sizeof(oc_node_t));

			member->node_id = oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				crm_strdup(oc->m_array[offset+lpc].node_uname);
			g_hash_table_insert(
				members, member->node_uname, member);	
		}
		
	} else {
		membership_copy->members = NULL;
	}
	
	crm_debug_3("Copying new members");

	/*--*-- New Member Nodes --*--*/
	offset = oc->m_in_idx;
	membership_copy->new_members_size = oc->m_n_in;

	if(membership_copy->new_members_size > 0) {
		membership_copy->new_members =
			g_hash_table_new(g_str_hash, g_str_equal);
		members = membership_copy->new_members;
		
		for(lpc=0; lpc < membership_copy->new_members_size; lpc++) {
			oc_node_t *member = NULL;
			CRM_CHECK(oc->m_array[offset+lpc].node_uname != NULL,
				  continue);

			crm_malloc0(member, sizeof(oc_node_t));

			member->node_id = oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				crm_strdup(oc->m_array[offset+lpc].node_uname);

			g_hash_table_insert(
				members, member->node_uname, member);	

			g_hash_table_insert(members, member->node_uname, member);
		}

	} else {
		membership_copy->new_members = NULL;
	}
	
	crm_debug_3("Copying dead members");

	/*--*-- Recently Dead Member Nodes --*--*/
	offset = oc->m_out_idx;
	membership_copy->dead_members_size = oc->m_n_out;
	if(membership_copy->dead_members_size > 0) {
		membership_copy->dead_members =
			g_hash_table_new(g_str_hash, g_str_equal);

		members = membership_copy->dead_members;

		for(lpc=0; lpc < membership_copy->dead_members_size; lpc++) {
			oc_node_t *member = NULL;
			CRM_CHECK(oc->m_array[offset+lpc].node_uname != NULL,
				  continue);

			crm_malloc0(member, sizeof(oc_node_t));

			member->node_id = oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				crm_strdup(oc->m_array[offset+lpc].node_uname);

			g_hash_table_insert(members, member->node_uname, member);
			check_dead_member(
				member->node_uname, membership_copy->members);
			
		}
	} else {
		membership_copy->dead_members = NULL;
	}

	tmp = fsa_membership_copy;
	fsa_membership_copy = membership_copy;
	crm_debug_2("Updated membership cache with %d (%d new, %d lost) members",
		    g_hash_table_size(fsa_membership_copy->members),
		    g_hash_table_size(fsa_membership_copy->new_members),
		    g_hash_table_size(fsa_membership_copy->dead_members));

	free_ccm_cache(tmp);
	
	set_bit_inplace(fsa_input_register, R_CCM_DATA);

	if(cur_state != S_STOPPING) {
		crm_debug_3("Updating the CIB from CCM cache");
		do_update_cib_nodes(FALSE, __FUNCTION__);
	}

	/* Membership changed, remind everyone we're here.
	 * This will aid detection of duplicate DCs
	 */
	send_msg_via_ha(fsa_cluster_conn, no_op);
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

int
register_with_ccm(ll_cluster_t *hb_cluster)
{
	return 0;
}

void 
msg_ccm_join(const HA_Message *msg, void *foo)
{
	
	crm_debug_2("###### Received ccm_join message...");
	if (msg != NULL)
	{
		crm_debug_2("[type=%s]",
			    ha_msg_value(msg, F_TYPE));
		crm_debug_2("[orig=%s]",
			    ha_msg_value(msg, F_ORIG));
		crm_debug_2("[to=%s]",
			    ha_msg_value(msg, F_TO));
		crm_debug_2("[status=%s]",
			    ha_msg_value(msg, F_STATUS));
		crm_debug_2("[info=%s]",
			    ha_msg_value(msg, F_COMMENT));
		crm_debug_2("[rsc_hold=%s]",
			    ha_msg_value(msg, F_RESOURCES));
		crm_debug_2("[stable=%s]",
			    ha_msg_value(msg, F_ISSTABLE));
		crm_debug_2("[rtype=%s]",
			    ha_msg_value(msg, F_RTYPE));
		crm_debug_2("[ts=%s]",
			    ha_msg_value(msg, F_TIME));
		crm_debug_2("[seq=%s]",
			    ha_msg_value(msg, F_SEQ));
		crm_debug_2("[generation=%s]",
			    ha_msg_value(msg, F_HBGENERATION));
		/*      crm_debug_2("[=%s]", ha_msg_value(msg, F_)); */
	}
	return;
}

struct update_data_s
{
		const char *state;
		const char *caller;
		crm_data_t *updates;
		gboolean    overwrite_join;
};

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

	if(fsa_membership_copy == NULL) {
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

	/* dead nodes */
	update_data.state = XML_BOOLEAN_NO;
	if(fsa_membership_copy->dead_members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->dead_members,
				     ghash_update_cib_node, &update_data);
	}		
	
	/* live nodes */
	update_data.state = XML_BOOLEAN_YES;
	if(fsa_membership_copy->members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->members,
				     ghash_update_cib_node, &update_data);
	}

	fsa_cib_update(XML_CIB_TAG_STATUS, fragment, call_options, call_id);
	
	add_cib_op_callback(call_id, FALSE, NULL, ccm_node_update_complete);
	free_xml(fragment);
}

void
ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data)
{
	crm_data_t *tmp1 = NULL;
	const char *join = NULL;
	const char *peer_online = NULL;
	const char *node_uname = (const char*)key;
	struct update_data_s* data = (struct update_data_s*)user_data;

	crm_debug_2("Updating %s: %s (overwrite=%s)",
		    node_uname, data->state,
		    data->overwrite_join?"true":"false");

	peer_online = g_hash_table_lookup(crmd_peer_state, node_uname);
	
	if(data->overwrite_join) {
		if(safe_str_neq(peer_online, ONLINESTATUS)) {
			join  = CRMD_JOINSTATE_DOWN;
			
		} else {
			const char *peer_member = g_hash_table_lookup(
				confirmed_nodes, node_uname);
			if(peer_member != NULL) {
				join = CRMD_JOINSTATE_MEMBER;
			} else {
				join = CRMD_JOINSTATE_PENDING;
			}
		}
	}
	
	tmp1 = create_node_state(node_uname, NULL, data->state, peer_online,
				 join, NULL, FALSE, data->caller);

	add_node_copy(data->updates, tmp1);
	free_xml(tmp1);
}


