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
#include <crm/common/crm.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
/* #include <crmd.h> */
/* #include <crm/common/crmutils.h> */

void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

#include <ocf/oc_event.h>
#include <ocf/oc_membership.h>

int register_with_ccm(ll_cluster_t *hb_cluster);
void crmd_ccm_input_callback(oc_ed_t event, void *cookie, size_t size, const void *data);
void ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event);
void msg_ccm_join(const struct ha_msg *msg, void *foo);



static oc_ev_t   * fsa_ev_token;     // for CCM comms
static int	   fsa_ev_fd;     // for CCM comms

#define CCM_EVENT_DETAIL 1

/*	 A_CCM_CONNECT	*/
enum crmd_fsa_input
do_ccm_register(long long action,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	int registered = 0;
	
	FNIN();
	// or pass the cluster in through "void *data"?
	registered = register_with_ccm(fsa_cluster_connection);

	if(registered == 0)
		FNRET(I_NULL);
	
	FNRET(I_FAIL);
}


/*	 A_CCM_EVENT	*/
enum crmd_fsa_input
do_ccm_event(long long action,
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
			;
			/* so what happened??  why are we here? */
		}
	}
	FNRET(return_input);
}

/*	 A_CCM_UPDATE_CACHE	*/
enum crmd_fsa_input
do_ccm_update_cache(long long action,
		    enum crmd_fsa_state cur_state,
		    enum crmd_fsa_input current_input,
		    void *data)
{
	int lpc, offset;
	oc_node_t *members = NULL;
	oc_ed_t event = *((struct ccm_data *)data)->event;
	const oc_ev_membership_t *oc = ((struct ccm_data *)data)->oc;

	oc_node_list_t *tmp = NULL, *membership_copy = (oc_node_list_t *)
		ha_malloc(sizeof(oc_node_list_t));

	FNIN();

	cl_log(LOG_INFO,"Updating CCM cache after a \"%s\" event.", 
	       event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");

	if(CCM_EVENT_DETAIL) {
		ccm_event_detail(oc, event);
	}

	/*--*-- All Member Nodes --*--*/
	offset = oc->m_memb_idx;
	membership_copy->members_size = oc->m_n_member;


	CRM_DEBUG2("Number of members: %d", membership_copy->members_size);
	
	if(membership_copy->members_size > 0) {
		int size = membership_copy->members_size;
		size = size * sizeof(oc_node_t);
		CRM_DEBUG2("Allocing %d", size);
		membership_copy->members = (oc_node_t *)ha_malloc(size);

		members = membership_copy->members;
		
		for(lpc=0; lpc < membership_copy->members_size; lpc++) {
			members[lpc].node_id =
				oc->m_array[offset+lpc].node_id;
			
			members[lpc].node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
#ifdef CCM_UNAME
			members[lpc].node_uname =
				ha_strdup(oc->m_array[offset+lpc].node_uname);
#endif	
		}
	}
	

	/*--*-- New Member Nodes --*--*/
	offset = oc->m_n_in;
	membership_copy->new_members_size = oc->m_n_in;

	CRM_DEBUG2("Number of new members: %d", membership_copy->new_members_size);
	if(membership_copy->new_members_size > 0) {
		int size = membership_copy->new_members_size;
		size = size * sizeof(oc_node_t);

		CRM_DEBUG2("Allocing %d", size);
		
		membership_copy->new_members = (oc_node_t *)ha_malloc(size);
		
		members = membership_copy->new_members;
		
		for(lpc=0; lpc < membership_copy->new_members_size; lpc++) {
			members[lpc].node_id =
				oc->m_array[offset+lpc].node_id;
			
			members[lpc].node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
#ifdef CCM_UNAME
			members[lpc].node_uname =
				ha_strdup(oc->m_array[offset+lpc].node_uname);
#endif	
			
		}
	}
	

	/*--*-- Recently Dead Member Nodes --*--*/
	offset = oc->m_n_out;
	membership_copy->dead_members_size = oc->m_n_out;
	if(membership_copy->dead_members_size > 0) {
		int size = membership_copy->dead_members_size;
		size = size * sizeof(oc_node_t);
		membership_copy->dead_members = (oc_node_t *)ha_malloc(size);
		
		members = membership_copy->new_members;
		
		for(lpc=0; lpc < membership_copy->dead_members_size; lpc++) {
			members[lpc].node_id =
				oc->m_array[offset+lpc].node_id;
			
			members[lpc].node_born_on =
				oc->m_array[offset+lpc].node_born_on;
			
#ifdef CCM_UNAME
			members[lpc].node_uname =
				ha_strdup(oc->m_array[offset+lpc].node_uname);
#endif			
		}
	}
	
	tmp = fsa_membership_copy;
	fsa_membership_copy = membership_copy;

	/* Free the old copy */
	if(tmp != NULL) {
		if(tmp->members != NULL)
			ha_free(tmp->members);
		if(tmp->new_members != NULL)
			ha_free(tmp->new_members);
		if(tmp->dead_members != NULL)
			ha_free(tmp->dead_members);
		ha_free(tmp);
	}
	
	FNRET(I_NULL);
}

void
ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event)
{
	int member_id = -1;
	gboolean member = FALSE;
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
	
	int lpc;
	int node_list_size = oc->m_n_member;
	for(lpc=0; lpc<node_list_size; lpc++) {
		cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
		       oc->m_array[oc->m_memb_idx+lpc].node_id,
		       oc->m_array[oc->m_memb_idx+lpc].node_born_on);
		if (oc_ev_is_my_nodeid(fsa_ev_token, &(oc->m_array[lpc]))) {
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
		cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
		       oc->m_array[oc->m_in_idx+lpc].node_id,
		       oc->m_array[oc->m_in_idx+lpc].node_born_on);
	}
	
	cl_log(LOG_INFO, "MEMBERS LOST");
	if (oc->m_n_out==0) 
		cl_log(LOG_INFO, "\tNONE");
	
	for(lpc=0; lpc<oc->m_n_out; lpc++) {
		cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
		       oc->m_array[oc->m_out_idx+lpc].node_id,
		       oc->m_array[oc->m_out_idx+lpc].node_born_on);
		if (oc_ev_is_my_nodeid(fsa_ev_token, &(oc->m_array[lpc]))) {
			cl_log(LOG_ERR,
			       "We're not part of the cluster anymore");
		}
	}
	
	cl_log(LOG_INFO, "-----------------------");
	
}

int
register_with_ccm(ll_cluster_t *hb_cluster)
{
    int ret;
    fd_set rset;
    
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
		return(1);
    }
    cl_log(LOG_INFO, "CCM Activation passed... all set to go!");
    
    FD_ZERO(&rset);
    FD_SET(fsa_ev_fd, &rset);
    
    if (oc_ev_handle_event(fsa_ev_token)){
		cl_log(LOG_ERR,"CCM Activation: terminating");
		return(1);
    }
    
    cl_log(LOG_INFO, "Sign up for \"ccmjoin\" messages");
    if (hb_cluster->llc_ops->set_msg_callback(
			hb_cluster,
			"ccmjoin",
			msg_ccm_join,
			hb_cluster) != HA_OK)
    {
		cl_log(LOG_ERR, "Cannot set msg_ipfail_join callback");
    }
    
    FNRET(0);
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
			ha_malloc(sizeof(struct ccm_data));
		
		event_data->event = &event;
		event_data->oc = (const oc_ev_membership_t *)data;
		
		s_crmd_fsa(C_CCM_CALLBACK, I_CCM_EVENT, (void*)event_data);
		
		event_data->event = NULL;
		event_data->oc = NULL;

		ha_free(event_data);
	} else {
		cl_log(LOG_INFO, "CCM Callback with NULL data... "
		       "I dont think this is bad");
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

