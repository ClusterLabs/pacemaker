/* $Id: ccm.c,v 1.64 2005/04/08 16:46:26 andrew Exp $ */
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
#include <portability.h>
#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

#include <clplumbing/GSource.h>
#include <string.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crmd_messages.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_callbacks.h>

#include <crm/dmalloc_wrapper.h>

void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

int register_with_ccm(ll_cluster_t *hb_cluster);

void msg_ccm_join(const HA_Message *msg, void *foo);

void crmd_ccm_msg_callback(oc_ed_t event,
			     void *cookie,
			     size_t size,
			     const void *data);

gboolean ghash_node_clfree(gpointer key, gpointer value, gpointer user_data);
void ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data);

#define CCM_EVENT_DETAIL 0
#define CCM_EVENT_DETAIL_PARTIAL 1

oc_ev_t *fsa_ev_token;
int num_ccm_register_fails = 0;
int max_ccm_register_fails = 30;

/*	 A_CCM_CONNECT	*/
enum crmd_fsa_input
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
		oc_ev_unregister(fsa_ev_token);
	}

	if(action & A_CCM_CONNECT) {
		crm_devel("Registering with CCM");
		ret = oc_ev_register(&fsa_ev_token);
		if (ret != 0) {
			crm_warn("CCM registration failed");
			did_fail = TRUE;
		}

		if(did_fail == FALSE) {
			crm_devel("Setting up CCM callbacks");
			ret = oc_ev_set_callback(fsa_ev_token, OC_EV_MEMB_CLASS,
						 crmd_ccm_msg_callback, NULL);
			if (ret != 0) {
				crm_warn("CCM callback not set");
				did_fail = TRUE;
			}
		}
		if(did_fail == FALSE) {
			oc_ev_special(fsa_ev_token, OC_EV_MEMB_CLASS, 0/*don't care*/);
			
			crm_devel("Activating CCM token");
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
				crmd_fsa_stall();
				return I_NULL;
				
			} else {
				crm_err("CCM Activation failed %d (max) times",
					num_ccm_register_fails);
				register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
				return I_NULL;
			}
		}
		

		crm_info("CCM Activation passed... all set to go!");

/* GFDSource* */
		G_main_add_fd(G_PRIORITY_LOW, fsa_ev_fd, FALSE, ccm_dispatch,
			      fsa_ev_token,
			      default_ipc_connection_destroy);
		
	}

	if(action & ~(A_CCM_CONNECT|A_CCM_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
	
	return I_NULL;
}


/*	 A_CCM_EVENT	*/
enum crmd_fsa_input
do_ccm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	enum crmd_fsa_input return_input = I_NULL;
	oc_ed_t *event = NULL;
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
	
	crm_info("event=%s", 
	       *event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       *event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       *event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       *event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");
	
	if(CCM_EVENT_DETAIL) {
		ccm_event_detail(oc, *event);
	}

	if (OC_EV_MS_EVICTED == *event) {
		/* todo: drop back to S_PENDING instead */
		/* get out... NOW!
		 *
		 * go via the error recovery process so that HA will
		 *    restart us if required
		 */
		register_fsa_error(cause, I_ERROR, msg_data->data);
		return I_NULL;
	}
	
	
	/* My understanding is that we will never get both
	 * node leaving *and* node joining callbacks at the
	 * same time.
	 *
	 * This logic would need to change if this is not
	 * the case
	 */
	
	if(oc->m_n_out != 0) {
		unsigned lpc = 0;
		int offset = oc->m_out_idx;
		for(lpc=0; lpc < oc->m_n_out; lpc++) {
			crm_data_t *node_state = NULL;
			
			const char *uname = oc->m_array[offset+lpc].node_uname;
			
			crm_info("Node %s has left the cluster,"
				 " updating the CIB.", uname);

			if(uname == NULL) {
				crm_err("CCM node had no name");
				continue;
				
			} else if(safe_str_eq(uname, fsa_our_dc)) {
				/* did our DC leave us */
				register_fsa_input(cause, I_ELECTION, NULL);

			} else if(AM_I_DC) {
				node_state = create_node_state(
					NULL, uname, NULL,
					XML_BOOLEAN_NO, NULL, NULL, NULL);
				
				update_local_cib(
					create_cib_fragment(node_state, NULL));
				free_xml(node_state);
			}
		}
		
	} else if(oc->m_n_in !=0) {
		/* delay the I_NODE_JOIN until they acknowledge our
		 * DC status and send us their CIB
		 */
	} else {
		CRM_DEV_ASSERT(oc->m_n_in != 0 || oc->m_n_out != 0);
		crm_warn("So why are we here?  What CCM event happened?");
	}

	return return_input;
}

/*	 A_CCM_UPDATE_CACHE	*/
/*
 * Take the opportunity to update the node status in the CIB as well
 *  (but only if we are the DC)
 */
enum crmd_fsa_input
do_ccm_update_cache(long long action,
		    enum crmd_fsa_cause cause,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    fsa_data_t *msg_data)
{
	enum crmd_fsa_input next_input = I_NULL;
	int lpc, offset;
	GHashTable *members = NULL;
	oc_ed_t *event = NULL;
	const oc_ev_membership_t *oc = NULL;
	oc_node_list_t *tmp = NULL, *membership_copy = NULL;
	struct crmd_ccm_data_s *ccm_data = fsa_typed_data(fsa_dt_ccm);

	if(ccm_data == NULL) {
		crm_err("No data provided to FSA function");
		register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
		return I_NULL;
	}

	event = ccm_data->event;
	oc = ccm_data->oc;

	crm_info("Updating CCM cache after a \"%s\" event.", 
	       *event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       *event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       *event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       *event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");

	crm_debug("instace=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
		  "new_idx=%d, old_idx=%d",
		  oc->m_instance,
		  oc->m_n_member,
		  oc->m_n_in,
		  oc->m_n_out,
		  oc->m_memb_idx,
		  oc->m_in_idx,
		  oc->m_out_idx);

	crm_malloc(membership_copy, sizeof(oc_node_list_t));

	if(membership_copy == NULL) {
		crm_crit("Couldnt create membership copy - out of memory");
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
		return I_NULL;
	}

	membership_copy->last_event = *event;

	crm_devel("Copying members");

	/*--*-- All Member Nodes --*--*/
	offset = oc->m_memb_idx;
	membership_copy->members_size = oc->m_n_member;

	if(membership_copy->members_size > 0) {
		membership_copy->members =
			g_hash_table_new(g_str_hash, g_str_equal);
		members = membership_copy->members;
		
		for(lpc=0; lpc < membership_copy->members_size; lpc++) {
			oc_node_t *member = NULL;
			crm_devel("Copying member %d", lpc);
			crm_malloc(member, sizeof(oc_node_t));
			
			if(member == NULL) {
				continue;
			}

			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname = NULL;
			if(oc->m_array[offset+lpc].node_uname != NULL) {
				member->node_uname =
					crm_strdup(oc->m_array[offset+lpc].node_uname);
			} else {
				crm_err("Node %d had a NULL uname",
					member->node_id);
			}
			g_hash_table_insert(
				members, member->node_uname, member);	
		}
		
	} else {
		membership_copy->members = NULL;
	}
	
	crm_devel("Copying new members");

	/*--*-- New Member Nodes --*--*/
	offset = oc->m_in_idx;
	membership_copy->new_members_size = oc->m_n_in;

	if(membership_copy->new_members_size > 0) {
		membership_copy->new_members =
			g_hash_table_new(g_str_hash, g_str_equal);
		members = membership_copy->new_members;
		
		for(lpc=0; lpc < membership_copy->new_members_size; lpc++) {
			oc_node_t *member = NULL;
			crm_malloc(member, sizeof(oc_node_t));

			if(member == NULL) {
				continue;
			}
			
			member->node_uname = NULL;
			member->node_id = oc->m_array[offset+lpc].node_id;
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;

			if(oc->m_array[offset+lpc].node_uname != NULL) {
				member->node_uname =
					crm_strdup(oc->m_array[offset+lpc].node_uname);
			} else {
				crm_err("Node %d had a NULL uname",
					member->node_id);
			}
			g_hash_table_insert(
				members, member->node_uname, member);	

			g_hash_table_insert(members, member->node_uname, member);
		}

	} else {
		membership_copy->new_members = NULL;
	}
	
	crm_devel("Copying dead members");

	/*--*-- Recently Dead Member Nodes --*--*/
	offset = oc->m_out_idx;
	membership_copy->dead_members_size = oc->m_n_out;
	if(membership_copy->dead_members_size > 0) {
		membership_copy->dead_members =
			g_hash_table_new(g_str_hash, g_str_equal);

		members = membership_copy->dead_members;

		for(lpc=0; lpc < membership_copy->dead_members_size; lpc++) {
			oc_node_t *member = NULL;
			crm_malloc(member, sizeof(oc_node_t));

			if(member == NULL) {
				continue;
			}
			
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname = NULL;
			if(oc->m_array[offset+lpc].node_uname != NULL) {
				member->node_uname =
					crm_strdup(oc->m_array[offset+lpc].node_uname);
			} else {
				crm_err("Node %d had a NULL uname",
					member->node_id);
			}
			g_hash_table_insert(
				members, member->node_uname, member);	

			g_hash_table_insert(members, member->node_uname, member);
		}

	} else {
		membership_copy->dead_members = NULL;
	}

	crm_devel("Replacing old copies");
	tmp = fsa_membership_copy;
	fsa_membership_copy = membership_copy;

	/* Free the old copy */
	if(tmp != NULL) {
		if(tmp->members != NULL)
			g_hash_table_foreach_remove(
				tmp->members, ghash_node_clfree, NULL);
		if(tmp->new_members != NULL)
			g_hash_table_foreach_remove(
				tmp->new_members, ghash_node_clfree, NULL);
		if(tmp->dead_members != NULL)
			g_hash_table_foreach_remove(
				tmp->dead_members, ghash_node_clfree, NULL);
		crm_free(tmp);
	}
	crm_devel("Free'd old copies");

	if(AM_I_DC) {
		/* should be sufficient for only the DC to do this */
		crm_data_t *foo = NULL;
		HA_Message *no_op = NULL;
		
		crm_devel("Updating the CIB");
		foo = do_update_cib_nodes(NULL, FALSE);
		free_xml(foo);

		/* Membership changed, remind everyone we're here.
		 * This will aid detection of duplicate DCs
		 */
		no_op = create_request(CRM_OP_NOOP, NULL, NULL,
				       CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);
	
		send_msg_via_ha(fsa_cluster_conn, no_op);
	}
	
	set_bit_inplace(fsa_input_register, R_CCM_DATA);
	
	return next_input;
}

void
ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event)
{
	int lpc;
	gboolean member = FALSE;

	crm_info("-----------------------");
	crm_debug("trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
	       "new_idx=%d, old_idx=%d",
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
#endif
	if (member == FALSE) {
		crm_warn("MY NODE IS NOT IN CCM THE MEMBERSHIP LIST");
	}
	
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
		if(fsa_our_uname != NULL
		   && 0 == strcmp(fsa_our_uname,
			     oc->m_array[oc->m_out_idx+lpc].node_uname)) {
			crm_err("We're not part of the cluster anymore");
		}
	}
	
	crm_info("-----------------------");
	
}

int
register_with_ccm(ll_cluster_t *hb_cluster)
{
	return 0;
}

void 
msg_ccm_join(const HA_Message *msg, void *foo)
{
	
	crm_verbose("###### Received ccm_join message...");
	if (msg != NULL)
	{
		crm_verbose("[type=%s]",
			    ha_msg_value(msg, F_TYPE));
		crm_verbose("[orig=%s]",
			    ha_msg_value(msg, F_ORIG));
		crm_verbose("[to=%s]",
			    ha_msg_value(msg, F_TO));
		crm_verbose("[status=%s]",
			    ha_msg_value(msg, F_STATUS));
		crm_verbose("[info=%s]",
			    ha_msg_value(msg, F_COMMENT));
		crm_verbose("[rsc_hold=%s]",
			    ha_msg_value(msg, F_RESOURCES));
		crm_verbose("[stable=%s]",
			    ha_msg_value(msg, F_ISSTABLE));
		crm_verbose("[rtype=%s]",
			    ha_msg_value(msg, F_RTYPE));
		crm_verbose("[ts=%s]",
			    ha_msg_value(msg, F_TIME));
		crm_verbose("[seq=%s]",
			    ha_msg_value(msg, F_SEQ));
		crm_verbose("[generation=%s]",
			    ha_msg_value(msg, F_HBGENERATION));
		/*      crm_verbose("[=%s]", ha_msg_value(msg, F_)); */
	}
	return;
}

struct update_data_s
{
		crm_data_t *updates;
		const char *state;
		const char *join;
};

crm_data_t*
do_update_cib_nodes(crm_data_t *updates, gboolean overwrite)
{
	struct update_data_s update_data;
	crm_data_t *fragment = updates;
	crm_data_t *tmp = NULL;
	
	if(updates == NULL) {
		fragment = create_cib_fragment(NULL, NULL);
	}

	tmp = find_xml_node(fragment, XML_TAG_CIB, TRUE);
	tmp = get_object_root(XML_CIB_TAG_STATUS, tmp);
	CRM_DEV_ASSERT(tmp != NULL);
	
	update_data.updates = tmp;

	update_data.state = XML_BOOLEAN_NO;
	update_data.join  = CRMD_JOINSTATE_DOWN;
	if(fsa_membership_copy->dead_members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->dead_members,
				     ghash_update_cib_node, &update_data);
	}
	
	update_data.state = XML_BOOLEAN_YES;
	update_data.join  = NULL;
	if(overwrite) {
		update_data.join = CRMD_JOINSTATE_PENDING;
	}
	
	if(fsa_membership_copy->members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->members,
				     ghash_update_cib_node, &update_data);
	}

	/* this is most likely overkill...
	 *
	 * make *sure* that the join status of nodes entering the ccm list
	 *  is reset
	 *
	update_data.join = CRMD_JOINSTATE_PENDING;
	if(fsa_membership_copy->new_members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->new_members,
				     ghash_update_cib_node, &update_data);
	}
*/
	if(update_data.updates != NULL) {
		update_local_cib(fragment);
	}

	/* so it can be freed */
	return fragment;

}

void
ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data)
{
	crm_data_t *tmp1 = NULL;
	const char *node_uname = (const char*)key;
	struct update_data_s* data = (struct update_data_s*)user_data;
	const char *state = data->join;

	crm_verbose("%s processing %s (%s)",
		  __FUNCTION__, node_uname, data->state);

	tmp1 = create_node_state(node_uname, node_uname,
				 NULL, data->state, NULL, state, NULL);

	add_node_copy(data->updates, tmp1);
	free_xml(tmp1);
}

gboolean
ghash_node_clfree(gpointer key, gpointer value, gpointer user_data)
{
	/* value->node_uname is free'd as "key" */
	if(key != NULL) {
		crm_free(key);
	}
	if(value != NULL) {
		crm_free(value);
	}
	return TRUE;
}
