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

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>

void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

#include <clplumbing/GSource.h>
#include <crm/common/ipcutils.h>
#include <crm/common/xmlutils.h>
#include <crmd_messages.h>
#include <string.h>
#include <crm/dmalloc_wrapper.h>

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
/* 	fd_set   rset; */
 	int	 fsa_ev_fd; 
    
	FNIN();

	if(action & A_CCM_DISCONNECT){
		oc_ev_unregister(fsa_ev_token);

	}

	if(action & A_CCM_CONNECT) {
		
		cl_log(LOG_INFO, "Registering with CCM");
		oc_ev_register(&fsa_ev_token);
		
		cl_log(LOG_INFO, "Setting up CCM callbacks");
		oc_ev_set_callback(fsa_ev_token, OC_EV_MEMB_CLASS,
				   crmd_ccm_input_callback,
				   NULL);

		oc_ev_special(fsa_ev_token, OC_EV_MEMB_CLASS, 0/*don't care*/);
		
		cl_log(LOG_INFO, "Activating CCM token");
		ret = oc_ev_activate(fsa_ev_token, &fsa_ev_fd);
		if (ret){
			cl_log(LOG_INFO, "CCM Activation failed... unregistering");
			oc_ev_unregister(fsa_ev_token);
			return(I_FAIL);
		}
		cl_log(LOG_INFO, "CCM Activation passed... all set to go!");

/* 		FD_ZERO(&rset); */
/* 		FD_SET(fsa_ev_fd, &rset); */
		
//GFDSource*
		G_main_add_fd(G_PRIORITY_LOW, fsa_ev_fd, FALSE, ccm_dispatch,
			      fsa_ev_token,
			      default_ipc_input_destroy);
		
	}

	if(action & ~(A_CCM_CONNECT|A_CCM_DISCONNECT)) {
		cl_log(LOG_ERR, "Unexpected action %s in %s",
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

	cl_log(LOG_INFO,"event=%s", 
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
			cl_log(LOG_INFO,
			       "So why are we here?  What CCM event happened?");
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
		cl_malloc(sizeof(oc_node_list_t));

	FNIN();

	cl_log(LOG_INFO,"Updating CCM cache after a \"%s\" event.", 
	       event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");

	/*--*-- All Member Nodes --*--*/
	offset = oc->m_memb_idx;
	membership_copy->members_size = oc->m_n_member;

	if(membership_copy->members_size > 0) {
		membership_copy->members = g_hash_table_new(g_str_hash, g_direct_equal);
		members = membership_copy->members;
		
		for(lpc=0; lpc < membership_copy->members_size; lpc++) {
			oc_node_t *member = (oc_node_t *)cl_malloc(sizeof(oc_node_t));
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				cl_strdup(oc->m_array[offset+lpc].node_uname);
			
		}
	} else {
		membership_copy->members = NULL;
	}
	
	/*--*-- New Member Nodes --*--*/
	offset = oc->m_in_idx;
	membership_copy->new_members_size = oc->m_n_in;

	if(membership_copy->new_members_size > 0) {
		membership_copy->new_members = g_hash_table_new(g_str_hash, g_direct_equal);
		members = membership_copy->new_members;
		
		for(lpc=0; lpc < membership_copy->new_members_size; lpc++) {
			oc_node_t *member = (oc_node_t *)cl_malloc(sizeof(oc_node_t));
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;

			member->node_uname =
				cl_strdup(oc->m_array[offset+lpc].node_uname);

			g_hash_table_insert(members, member->node_uname, member);
			
		}

	} else {
		membership_copy->new_members = NULL;
	}
	
	/*--*-- Recently Dead Member Nodes --*--*/
	offset = oc->m_out_idx;
	membership_copy->dead_members_size = oc->m_n_out;
	if(membership_copy->dead_members_size > 0) {
		membership_copy->dead_members = g_hash_table_new(g_str_hash, g_direct_equal);
		members = membership_copy->dead_members;

		for(lpc=0; lpc < membership_copy->dead_members_size; lpc++) {
			oc_node_t *member = (oc_node_t *)cl_malloc(sizeof(oc_node_t));
			member->node_id =
				oc->m_array[offset+lpc].node_id;
			
			member->node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
			member->node_uname =
				cl_strdup(oc->m_array[offset+lpc].node_uname);

		}
	} else {
		membership_copy->dead_members = NULL;
	}

	if(AM_I_DC) {
		// should be sufficient for only the DC to do this
		free_xml(do_update_cib_nodes(NULL));
	}
	
	tmp = fsa_membership_copy;
	fsa_membership_copy = membership_copy;

	/* Free the old copy */
	if(tmp != NULL) {
		if(tmp->members != NULL)
			g_hash_table_foreach_remove (tmp->members, ghash_node_clfree, NULL);
		if(tmp->new_members != NULL)
			g_hash_table_foreach_remove (tmp->new_members, ghash_node_clfree, NULL);
		if(tmp->dead_members != NULL)
			g_hash_table_foreach_remove (tmp->dead_members, ghash_node_clfree, NULL);
		cl_free(tmp);
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

	cl_log(LOG_INFO,"trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
	       "new_idx=%d, old_idx=%d",
	       oc->m_instance,
	       oc->m_n_member,
	       oc->m_n_in,
	       oc->m_n_out,
	       oc->m_memb_idx,
	       oc->m_in_idx,
	       oc->m_out_idx);
	
	cl_log(LOG_INFO, "NODES IN THE PRIMARY MEMBERSHIP");
	
	node_list_size = oc->m_n_member;
	for(lpc=0; lpc<node_list_size; lpc++) {
		cl_log(LOG_INFO,"\t%s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_memb_idx+lpc].node_uname,
		       oc->m_array[oc->m_memb_idx+lpc].node_id,
		       oc->m_array[oc->m_memb_idx+lpc].node_born_on);

		if(fsa_our_uname != NULL
		   && strcmp(fsa_our_uname, oc->m_array[oc->m_memb_idx+lpc].node_uname)) {
			member = TRUE;
			member_id = oc->m_array[oc->m_memb_idx+lpc].node_id;
		}
	}
	
	if (member == FALSE) {
		cl_log(LOG_WARNING,
		       "MY NODE IS NOT IN CCM THE MEMBERSHIP LIST");
	} else {
		cl_log(LOG_INFO, "MY NODE ID IS %d", member_id);
	}
	
	
	cl_log(LOG_INFO, "NEW MEMBERS");
	if (oc->m_n_in==0) 
		cl_log(LOG_INFO, "\tNONE");
	
	for(lpc=0; lpc<oc->m_n_in; lpc++) {
		cl_log(LOG_INFO,"\t%s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_in_idx+lpc].node_uname,
		       oc->m_array[oc->m_in_idx+lpc].node_id,
		       oc->m_array[oc->m_in_idx+lpc].node_born_on);
	}
	
	cl_log(LOG_INFO, "MEMBERS LOST");
	if (oc->m_n_out==0) 
		cl_log(LOG_INFO, "\tNONE");
	
	for(lpc=0; lpc<oc->m_n_out; lpc++) {
		cl_log(LOG_INFO,"\t%s [nodeid=%d, born=%d]",
		       oc->m_array[oc->m_out_idx+lpc].node_uname,
		       oc->m_array[oc->m_out_idx+lpc].node_id,
		       oc->m_array[oc->m_out_idx+lpc].node_born_on);
		if(fsa_our_uname != NULL
		   && strcmp(fsa_our_uname, oc->m_array[oc->m_memb_idx+lpc].node_uname)) {
			cl_log(LOG_ERR,
			       "We're not part of the cluster anymore");
		}
	}
	
	cl_log(LOG_INFO, "-----------------------");
	
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
			cl_malloc(sizeof(struct ccm_data));
		
		event_data->event = &event;
		event_data->oc = (const oc_ev_membership_t *)data;
		
		s_crmd_fsa(C_CCM_CALLBACK, I_CCM_EVENT, (void*)event_data);
		
		event_data->event = NULL;
		event_data->oc = NULL;

		cl_free(event_data);

	} else {
		cl_log(LOG_INFO, "CCM Callback with NULL data... "
		       "I dont /think/ this is bad");
	}
	
	oc_ev_callback_done(cookie);
	
	FNOUT();
}

void 
msg_ccm_join(const struct ha_msg *msg, void *foo)
{
	FNIN();
	cl_log(LOG_INFO, "\n###### Recieved ccm_join message...");
	if (msg != NULL)
	{
		cl_log(LOG_INFO,
		       "[type=%s]",
		       ha_msg_value(msg, F_TYPE));
		cl_log(LOG_INFO,
		       "[orig=%s]",
		       ha_msg_value(msg, F_ORIG));
		cl_log(LOG_INFO,
		       "[to=%s]",
		       ha_msg_value(msg, F_TO));
		cl_log(LOG_INFO,
		       "[status=%s]",
		       ha_msg_value(msg, F_STATUS));
		cl_log(LOG_INFO,
		       "[info=%s]",
		       ha_msg_value(msg, F_COMMENT));
		cl_log(LOG_INFO,
		       "[rsc_hold=%s]",
		       ha_msg_value(msg, F_RESOURCES));
		cl_log(LOG_INFO,
		       "[stable=%s]",
		       ha_msg_value(msg, F_ISSTABLE));
		cl_log(LOG_INFO,
		       "[rtype=%s]",
		       ha_msg_value(msg, F_RTYPE));
		cl_log(LOG_INFO,
		       "[ts=%s]",
		       ha_msg_value(msg, F_TIME));
		cl_log(LOG_INFO,
		       "[seq=%s]",
		       ha_msg_value(msg, F_SEQ));
		cl_log(LOG_INFO,
		       "[generation=%s]",
		       ha_msg_value(msg, F_HBGENERATION));
		//      cl_log(LOG_INFO, "[=%s]", ha_msg_value(msg, F_));
	}
	FNOUT();
}

struct update_data_s
{
		xmlNodePtr updates;
		const char *state;
};

xmlNodePtr
do_update_cib_nodes(xmlNodePtr updates)
{
	
	struct update_data_s update_data;
	update_data.updates = updates;
	
	CRM_DEBUG("Processing the \"down\" list");
	update_data.state = "down";
	if(fsa_membership_copy->dead_members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->dead_members,
				     ghash_update_cib_node, &update_data);
	}
	
	CRM_DEBUG("Processing the \"in_ccm (old)\" list");
	update_data.state = "in_ccm";
	if(fsa_membership_copy->members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->members,
				     ghash_update_cib_node, &update_data);
	}
	
	CRM_DEBUG("Processing the \"in_ccm (new)\" list");
	if(fsa_membership_copy->new_members != NULL) {
		g_hash_table_foreach(fsa_membership_copy->new_members,
				     ghash_update_cib_node, &update_data);
	}

	if(update_data.updates != NULL) {
		xmlNodePtr fragment = create_cib_fragment(update_data.updates, NULL);
		
		send_request(NULL, fragment, CRM_OPERATION_UPDATE,
			     NULL, CRM_SYSTEM_DCIB, NULL);
		
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

	CRM_DEBUG("%s processing %s (%s)", __FUNCTION__, node_uname, data->state);
	
	if(safe_str_eq(fsa_our_uname, node_uname)) {
		// dont change ourselves
		return;
	}

	tmp1 = create_node_state(node_uname, data->state, NULL, NULL);
	if(data->updates == NULL) {
		data->updates = tmp1;
	} else {
		data->updates = xmlAddSibling(data->updates, tmp1);
	}	
}

gboolean
ghash_node_clfree(gpointer key, gpointer value, gpointer user_data)
{
	// value->node_uname is free'd as "key"
	if(key != NULL) {
		cl_free(key);
	}
	if(value != NULL) {
		cl_free(value);
	}
	return TRUE;
}
