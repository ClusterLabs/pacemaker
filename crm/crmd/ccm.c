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

#include <crm/dmalloc_wrapper.h>

void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

int register_with_ccm(ll_cluster_t *hb_cluster);

void msg_ccm_join(const struct ha_msg *msg, void *foo);

void crmd_ccm_input_callback(oc_ed_t event,
			     void *cookie,
			     size_t size,
			     const void *data);

void ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event);
gboolean ccm_dispatch(int fd, gpointer user_data);

gboolean ghash_node_clfree(gpointer key, gpointer value, gpointer user_data);
void ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data);

#define CCM_EVENT_DETAIL 1
oc_ev_t *fsa_ev_token;

/*	 A_CCM_CONNECT	*/
enum crmd_fsa_input
do_ccm_control(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	int      ret;
 	int	 fsa_ev_fd; 
    
	FNIN();

	if(action & A_CCM_DISCONNECT){
		oc_ev_unregister(fsa_ev_token);

	}

	if(action & A_CCM_CONNECT) {
		
		crm_info("Registering with CCM");
		oc_ev_register(&fsa_ev_token);
		
		crm_info("Setting up CCM callbacks");
		oc_ev_set_callback(fsa_ev_token, OC_EV_MEMB_CLASS,
				   crmd_ccm_input_callback,
				   NULL);

		oc_ev_special(fsa_ev_token, OC_EV_MEMB_CLASS, 0/*don't care*/);
		
		crm_info("Activating CCM token");
		ret = oc_ev_activate(fsa_ev_token, &fsa_ev_fd);
		if (ret){
			crm_info("CCM Activation failed... unregistering");
			oc_ev_unregister(fsa_ev_token);
			return(I_FAIL);
		}
		crm_info("CCM Activation passed... all set to go!");

//GFDSource*
		G_main_add_fd(G_PRIORITY_LOW, fsa_ev_fd, FALSE, ccm_dispatch,
			      fsa_ev_token,
			      default_ipc_input_destroy);
		
	}

	if(action & ~(A_CCM_CONNECT|A_CCM_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
	
	FNRET(I_NULL);
}


/*	 A_CCM_EVENT	*/
enum crmd_fsa_input
do_ccm_event(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	enum crmd_fsa_input return_input = I_NULL;
	const oc_ev_membership_t *oc = ((struct ccm_data *)data)->oc;
	oc_ed_t event = *((struct ccm_data *)data)->event;

	FNIN();

	crm_info("event=%s", 
	       event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");
	
	if(CCM_EVENT_DETAIL) {
		ccm_event_detail(oc, event);
	}

	if (OC_EV_MS_EVICTED == event) {
		/* get out... NOW! */
		return_input = I_SHUTDOWN;

	}
	
	if(return_input == I_SHUTDOWN) {
		; /* ignore everything, the new DC will handle it */
	} else {
		/* My understanding is that we will never get both
		 * node leaving *and* node joining callbacks at the
		 * same time.
		 *
		 * This logic would need to change if this is not
		 * the case
		 */

		if(oc->m_n_out !=0) {
			return_input = I_NODE_LEFT;

		} else if(oc->m_n_in !=0) {
			/* delay the I_NODE_JOIN until they acknowledge our
			 * DC status and send us their CIB
			 */
			return_input = I_NULL;
		} else {
			crm_warn("So why are we here?  What CCM event happened?");
		}
	}

	FNRET(return_input);
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
		    void *data)
{
	enum crmd_fsa_input next_input = I_NULL;
	int lpc, offset;
	GHashTable *members = NULL;
	oc_ed_t event = *((struct ccm_data *)data)->event;
	const oc_ev_membership_t *oc = ((struct ccm_data *)data)->oc;

	oc_node_list_t *tmp = NULL, *membership_copy = (oc_node_list_t *)
		crm_malloc(sizeof(oc_node_list_t));

	FNIN();

	crm_info("Updating CCM cache after a \"%s\" event.", 
	       event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");

	/*--*-- All Member Nodes --*--*/
	offset = oc->m_memb_idx;
	membership_copy->members_size = oc->m_n_member;

	if(membership_copy->members_size > 0) {
		membership_copy->members =
			g_hash_table_new(g_str_hash, g_str_equal);
		members = membership_copy->members;
		
		for(lpc=0; lpc < membership_copy->members_size; lpc++) {
			oc_node_t *member = (oc_node_t *)
				crm_malloc(sizeof(oc_node_t));
			
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				crm_strdup(oc->m_array[offset+lpc].node_uname);

			g_hash_table_insert(members, member->node_uname, member);	
		}
		
	} else {
		membership_copy->members = NULL;
	}
	
	/*--*-- New Member Nodes --*--*/
	offset = oc->m_in_idx;
	membership_copy->new_members_size = oc->m_n_in;

	if(membership_copy->new_members_size > 0) {
		membership_copy->new_members =
			g_hash_table_new(g_str_hash, g_str_equal);
		members = membership_copy->new_members;
		
		for(lpc=0; lpc < membership_copy->new_members_size; lpc++) {
			oc_node_t *member = (oc_node_t *)
				crm_malloc(sizeof(oc_node_t));
			
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;

			member->node_uname =
				crm_strdup(oc->m_array[offset+lpc].node_uname);

			g_hash_table_insert(members, member->node_uname, member);
		}

	} else {
		membership_copy->new_members = NULL;
	}
	
	/*--*-- Recently Dead Member Nodes --*--*/
	offset = oc->m_out_idx;
	membership_copy->dead_members_size = oc->m_n_out;
	if(membership_copy->dead_members_size > 0) {
		membership_copy->dead_members =
			g_hash_table_new(g_str_hash, g_str_equal);

		members = membership_copy->dead_members;

		for(lpc=0; lpc < membership_copy->dead_members_size; lpc++) {
			oc_node_t *member = (oc_node_t *)
				crm_malloc(sizeof(oc_node_t));
			
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				crm_strdup(oc->m_array[offset+lpc].node_uname);

			g_hash_table_insert(members, member->node_uname, member);
		}

	} else {
		membership_copy->dead_members = NULL;
	}

	tmp = fsa_membership_copy;
	fsa_membership_copy = membership_copy;

	if(AM_I_DC) {
		// should be sufficient for only the DC to do this
		free_xml(do_update_cib_nodes(NULL, FALSE));
	}
	
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
	
	FNRET(next_input);
}

void
ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event)
{
	int member_id = -1;
	gboolean member = FALSE;
	int lpc;
	int node_list_size;

	crm_info("trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
	       "new_idx=%d, old_idx=%d",
	       oc->m_instance,
	       oc->m_n_member,
	       oc->m_n_in,
	       oc->m_n_out,
	       oc->m_memb_idx,
	       oc->m_in_idx,
	       oc->m_out_idx);
	
	crm_info("NODES IN THE PRIMARY MEMBERSHIP");
	
	node_list_size = oc->m_n_member;
	for(lpc=0; lpc<node_list_size; lpc++) {
		crm_info("\t%s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_memb_idx+lpc].node_uname,
		       oc->m_array[oc->m_memb_idx+lpc].node_id,
		       oc->m_array[oc->m_memb_idx+lpc].node_born_on);

		crm_verbose("%s ? %s", fsa_our_uname,
			  oc->m_array[oc->m_memb_idx+lpc].node_uname);
		if(safe_str_eq(fsa_our_uname,
			       oc->m_array[oc->m_memb_idx+lpc].node_uname)) {
			member = TRUE;
			member_id = oc->m_array[oc->m_memb_idx+lpc].node_id;
		}
	}
	
	if (member == FALSE) {
		crm_warn("MY NODE IS NOT IN CCM THE MEMBERSHIP LIST");
	} else {
		crm_info("MY NODE ID IS %d", member_id);
	}
	
	
	crm_info("NEW MEMBERS");
	if (oc->m_n_in==0) 
		crm_info("\tNONE");
	
	for(lpc=0; lpc<oc->m_n_in; lpc++) {
		crm_info("\t%s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_in_idx+lpc].node_uname,
		       oc->m_array[oc->m_in_idx+lpc].node_id,
		       oc->m_array[oc->m_in_idx+lpc].node_born_on);
	}
	
	crm_info("MEMBERS LOST");
	if (oc->m_n_out==0) 
		crm_info("\tNONE");
	
	for(lpc=0; lpc<oc->m_n_out; lpc++) {
		crm_info("\t%s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_out_idx+lpc].node_uname,
		       oc->m_array[oc->m_out_idx+lpc].node_id,
		       oc->m_array[oc->m_out_idx+lpc].node_born_on);
		if(fsa_our_uname != NULL
		   && strcmp(fsa_our_uname,
			     oc->m_array[oc->m_memb_idx+lpc].node_uname)) {
			crm_err("We're not part of the cluster anymore");
		}
	}
	
	crm_info("-----------------------");
	
}

int
register_with_ccm(ll_cluster_t *hb_cluster)
{
	FNRET(0);
}

gboolean ccm_dispatch(int fd, gpointer user_data)
{
	oc_ev_t *ccm_token = (oc_ev_t*)user_data;
	oc_ev_handle_event(ccm_token);
	return TRUE;
}


void 
crmd_ccm_input_callback(oc_ed_t event,
			void *cookie,
			size_t size,
			const void *data)
{
	struct ccm_data *event_data = NULL;
	
	FNIN();

	if(data != NULL) {
		event_data = (struct ccm_data *)
			crm_malloc(sizeof(struct ccm_data));
		
		event_data->event = &event;
		event_data->oc = (const oc_ev_membership_t *)data;
		
		s_crmd_fsa(C_CCM_CALLBACK, I_CCM_EVENT, (void*)event_data);
		
		event_data->event = NULL;
		event_data->oc = NULL;

		crm_free(event_data);

	} else {
		crm_info("CCM Callback with NULL data... "
		       "I dont /think/ this is bad");
	}
	
	oc_ev_callback_done(cookie);
	
	FNOUT();
}

void 
msg_ccm_join(const struct ha_msg *msg, void *foo)
{
	FNIN();
	crm_verbose("\n###### Recieved ccm_join message...");
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
		//      crm_verbose("[=%s]", ha_msg_value(msg, F_));
	}
	FNOUT();
}

struct update_data_s
{
		xmlNodePtr updates;
		const char *state;
		const char *join;
};

xmlNodePtr
do_update_cib_nodes(xmlNodePtr updates, gboolean overwrite)
{
	
	struct update_data_s update_data;
	update_data.updates = updates;
	
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
		xmlNodePtr fragment =
			create_cib_fragment(update_data.updates, NULL);

		store_request(NULL, fragment,
			      CRM_OP_UPDATE, CRM_SYSTEM_DCIB);
		
		free_xml(fragment);
	}
	
	return update_data.updates;

}

void
ghash_update_cib_node(gpointer key, gpointer value, gpointer user_data)
{
	xmlNodePtr tmp1 = NULL;
	const char *node_uname = (const char*)key;
	struct update_data_s* data = (struct update_data_s*)user_data;
	const char *state = data->join;

	crm_verbose("%s processing %s (%s)",
		  __FUNCTION__, node_uname, data->state);

	if(state != NULL
	   && safe_str_eq(fsa_our_uname, node_uname)) {
		/* the DC is always a member */
		state = CRMD_JOINSTATE_MEMBER;
	} 

	tmp1 = create_node_state(node_uname, data->state, NULL, state);

	if(data->updates == NULL) {
		crm_verbose("Creating first update");
		data->updates = tmp1;
	} else {
		xmlAddNextSibling(data->updates, tmp1);
	}

}

gboolean
ghash_node_clfree(gpointer key, gpointer value, gpointer user_data)
{
	// value->node_uname is free'd as "key"
	if(key != NULL) {
		crm_free(key);
	}
	if(value != NULL) {
		crm_free(value);
	}
	return TRUE;
}
