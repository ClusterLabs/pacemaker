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

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <ocf/oc_event.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmlutils.h>

#include <crm/dmalloc_wrapper.h>


gboolean dc_election_in_progress = FALSE;
gboolean i_am_dc = FALSE;
int      is_cluster_member = 0;
oc_ev_t *ev_token = NULL;    // for CCM comms
int	 my_ev_fd = -1;     // for CCM comms

ll_cluster_t *hb_cluster = NULL;
GHashTable   *pending_remote_replies = NULL;
GHashTable   *ipc_clients = NULL;
const char   *our_uname = NULL;

gboolean have_lrmd = FALSE;
gboolean have_pe = FALSE;
gboolean have_te = FALSE;

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlutils.h>
#include <glib.h>
#include <crmd.h>

void send_msg_via_ha(xmlNodePtr action, const char *dest_node);
void send_msg_via_ipc(xmlNodePtr action, const char *sys);

void process_message(xmlNodePtr root_xml_node,
		     gboolean originated_locally,
		     const char *src_node_name);

gboolean relay_message(xmlNodePtr action,
		       gboolean originated_locally,
		       const char *host_from);

gboolean crm_dc_process_message(xmlNodePtr whole_message,
				xmlNodePtr action,
				const char *host_from,
				const char *sys_from,
				const char *sys_to,
				const char *op,
				gboolean dc_mode);

gboolean add_pending_outgoing_reply(const char *originating_node_name,
				    const char *crm_msg_reference,
				    const char *sys_to,
				    const char *sys_from);

char *find_destination_host(xmlNodePtr xml_root_node,
			    const char *crm_msg_reference,
			    const char *sys_from,
			    int is_request);

gboolean crmd_authorize_message(xmlNodePtr root_xml_node,
				IPC_Message *client_msg,
				crmd_client_t *curr_client);

gboolean
crmd_client_connect(IPC_Channel *client_channel, gpointer user_data)
{
	FNIN();
	// assign the client to be something, or put in a hashtable
	CRM_DEBUG("A client tried to connect... and there was much rejoicing.");


	if (client_channel == NULL) {
		cl_log(LOG_ERR, "Channel was NULL");
	} else if (client_channel->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "Channel was disconnected");
	} else {
		crmd_client_t *blank_client =
			(crmd_client_t *)ha_malloc(sizeof(crmd_client_t));
	
		if (blank_client == NULL) {
			cl_log(LOG_ERR,
			       "Could not allocate memory for a blank crmd_client_t");
			FNRET(FALSE);
		}
	
		blank_client->client_channel = client_channel;
		blank_client->sub_sys = NULL;
		blank_client->uid = NULL;
		blank_client->table_key = NULL;
	
		CRM_DEBUG("Adding IPC Channel to main thread.");
		blank_client->client_source =
			G_main_add_IPC_Channel(G_PRIORITY_LOW,
					       client_channel,
					       FALSE, 
					       crmd_ipc_input_callback,
					       blank_client,  // passed to crmd_ipc_input_dispatch
					       default_ipc_input_destroy);
	}
    
	FNRET(TRUE);
}


gboolean
crmd_authorize_message(xmlNodePtr root_xml_node,
		       IPC_Message *client_msg,
		       crmd_client_t *curr_client)
{
	// check the best case first
	const char *sys_from   = xmlGetProp(root_xml_node,
					    XML_MSG_ATTR_SYSFROM);
	char *uid = NULL;
	char *client_name = NULL;
	char *major_version = NULL;
	char *minor_version = NULL;

	gpointer table_key = NULL;
	
	FNIN();

	if (sys_from != NULL) {
		gboolean can_reply = FALSE; // no-one has registered with this id
		if (g_hash_table_lookup (ipc_clients, sys_from) != NULL)
			can_reply = TRUE;  // reply can be routed

		CRM_DEBUG2("Message reply would%s be able to be routed.",
			   can_reply?"":" not");
		FNRET(can_reply);
	}

	// otherwise, check if it was a hello message

	cl_log(LOG_INFO,
	       "recieved client join msg: %s",
	       (char*)client_msg->msg_body);

	gboolean result = process_hello_message(client_msg,
						&uid,
						&client_name,
						&major_version,
						&minor_version);

	if (result == TRUE) {
		// check version
		int mav = atoi(major_version);
		int miv = atoi(minor_version);
		if (mav < 0 || miv < 0) {
			cl_log(LOG_ERR,
			       "Client version (%d:%d) is not acceptable",
			       mav,
			       miv);
			result = FALSE;
		}
		ha_free(major_version);
		ha_free(minor_version);
	}

	if (result == TRUE) {
		/* if we already have one of those clients
		 * only applies to lrm, crm etc.  not admin clients
		 */
		if (strcmp(CRM_SYSTEM_LRMD, client_name) == 0) {
			result = !have_lrmd;
			have_lrmd = TRUE;
		} else if (strcmp(CRM_SYSTEM_PENGINE, client_name) == 0) {
			result = !have_te;
			have_te = TRUE;
		} else if (strcmp(CRM_SYSTEM_TENGINE, client_name) == 0) {
			result = !have_te;
			have_pe = TRUE;
		} else
			table_key =
				(gpointer)generate_hash_key(client_name,
							    uid);
	}

	if(table_key == NULL)
		table_key = (gpointer)ha_strdup(client_name);

	if (result == TRUE) {
		CRM_DEBUG2("Accepted client %s", (char*)table_key);

		curr_client->table_key = table_key;
		curr_client->sub_sys = ha_strdup(client_name);
		curr_client->uid = ha_strdup(uid);
	
		g_hash_table_insert (ipc_clients,
				     table_key,
				     curr_client->client_channel);
	} else
		CRM_DEBUG("Rejected client logon request");


	if(uid != NULL) ha_free(uid);
	if(client_name != NULL) ha_free(client_name);
	
	FNRET(result);
}

void
crmd_ha_input_callback(const struct ha_msg* msg, void* private_data)
{
	FNIN();
	cl_log(LOG_DEBUG,
	       "processing HA message (%s from %s)",
	       ha_msg_value(msg, F_SEQ), ha_msg_value(msg, F_ORIG));
	
	xmlNodePtr root_xml_node = find_xml_in_hamessage(msg);
	process_message(root_xml_node, FALSE, ha_msg_value(msg, F_ORIG));
	free_xml(root_xml_node);
	FNOUT();
}

/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */
gboolean
crmd_ipc_input_callback(IPC_Channel *client, gpointer user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	IPC_Message *msg = NULL;
	gboolean hack_return_good = TRUE;
	crmd_client_t *curr_client = (crmd_client_t*)user_data;

	FNIN();
	CRM_DEBUG2("processing IPC message from %s",
		   curr_client->table_key);

	while(client->ops->is_message_pending(client)) {
		if (client->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (client->ops->recv(client, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!hack_return_good);
		}
		if (msg == NULL) {
			CRM_DEBUG("No message this time");
			continue;
		}

		lpc++;
		buffer = (char*)msg->msg_body;
		CRM_DEBUG2("Got xml [text=%s]", buffer);
	
		xmlNodePtr root_xml_node =
			find_xml_in_ipcmessage(msg, FALSE);
		if (root_xml_node != NULL) {
			if (crmd_authorize_message(root_xml_node,
						   msg,
						   curr_client)) {
				CRM_DEBUG("Message authorized, about to relay");
				process_message(root_xml_node, TRUE, NULL);
			} else
				CRM_DEBUG("Message not authorized");
		} else {
			cl_log(LOG_INFO,
			       "IPC Message was not valid... discarding message.");
		}
		free_xml(root_xml_node);
		msg->msg_done(msg);
	}

	CRM_DEBUG2("Processed %d messages", lpc);
    
	if (client->ch_status == IPC_DISCONNECT)
	{
		cl_log(LOG_INFO,
		       "received HUP from %s",
		       curr_client->table_key);
		if (curr_client != NULL) {
			
			if (curr_client->sub_sys == NULL)
				CRM_DEBUG("Client had not registered with us yet");
			else if (strcmp(CRM_SYSTEM_LRMD,
					curr_client->sub_sys) == 0)
				have_lrmd = FALSE;
			else if (strcmp(CRM_SYSTEM_PENGINE,
					curr_client->sub_sys) == 0)
				have_te = FALSE;
			else if (strcmp(CRM_SYSTEM_TENGINE,
					curr_client->sub_sys) == 0)
				have_pe = FALSE;

			if (curr_client->table_key != NULL) {
				/*
				 * Key is destroyed below: curr_client->table_key
				 * Value is cleaned up by G_main_del_IPC_Channel
				 */
				g_hash_table_remove(
					ipc_clients,
					curr_client->table_key);
			}


			if(curr_client->client_source != NULL) {
				gboolean det =
					G_main_del_IPC_Channel(curr_client->client_source);
			
				CRM_DEBUG2("crm_client was %s detached",
					   det?"successfully":"not");
			}
			
			ha_free(curr_client->table_key);
			ha_free(curr_client->sub_sys);
			ha_free(curr_client->uid);
			ha_free(curr_client);
		}
		CRM_DEBUG("this client has now left the building.");
		FNRET(!hack_return_good);
	}
    
	FNRET(hack_return_good);
}


void 
crmd_ccm_input_callback(oc_ed_t event,
			void *cookie,
			size_t size,
			const void *data)
{
	FNIN();
	(void)_ha_msg_h_Id; // keep the compiler happy

	const oc_ev_membership_t *oc = (const oc_ev_membership_t *)data;
    
	cl_log(LOG_INFO,"event=%s", 
	       event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
	       event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
	       event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
	       event==OC_EV_MS_EVICTED?"EVICTED":
	       "NO QUORUM MEMBERSHIP");
    
	if (OC_EV_MS_EVICTED == event) {
		oc_ev_callback_done(cookie);
		FNOUT();
	}
    
	cl_log(LOG_INFO,"trans=%d, nodes=%d, new=%d, lost=%d n_idx=%d, "
	       "new_idx=%d, old_idx=%d",
	       oc->m_instance,
	       oc->m_n_member,
	       oc->m_n_in,
	       oc->m_n_out,
	       oc->m_memb_idx,
	       oc->m_in_idx,
	       oc->m_out_idx);
    
	dc_election_in_progress = TRUE;
	is_cluster_member=0;
	i_am_dc=FALSE;
	cl_log(LOG_INFO, "NODES IN THE PRIMARY MEMBERSHIP");
    
	int lpc;
	int node_list_size = oc->m_n_member;
	for(lpc=0; lpc<node_list_size; lpc++)
	{
		cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
		       oc->m_array[oc->m_memb_idx+lpc].node_id,
		       oc->m_array[oc->m_memb_idx+lpc].node_born_on);
		if (oc_ev_is_my_nodeid(ev_token, &(oc->m_array[lpc])))
		{
			cl_log(LOG_INFO,
			       "MY NODE ID IS %d",
			       oc->m_array[oc->m_memb_idx+lpc].node_id);
			is_cluster_member = TRUE;
			if (lpc == 0)
				i_am_dc=TRUE;
			break;
		}
	}
    
	if (lpc == node_list_size)
	{
		is_cluster_member = FALSE;
		cl_log(LOG_WARNING,"MY NODE IS NOT IN CCM THE MEMBERSHIP LIST");
	}
	
	if (is_cluster_member)
	{
		cl_log(LOG_INFO,"MY NODE IS A MEMBER OF THE MEMBERSHIP LIST");
		if (i_am_dc) {
			cl_log(LOG_INFO,
			       "MY NODE IS THE DESIGNATED CONTROLLER OF THE MEMBERSHIP LIST");
		}
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
	}

	cl_log(LOG_INFO, "-----------------------");
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

void
process_message(xmlNodePtr root_xml_node,
		gboolean originated_locally,
		const char *src_node_name)
{
	const char *crm_msg_reference = xmlGetProp(root_xml_node,
						   XML_MSG_ATTR_REFERENCE);
	const char *sys_from = xmlGetProp(root_xml_node,
					  XML_MSG_ATTR_SYSFROM);
	const char *sys_to   = xmlGetProp(root_xml_node,
					  XML_MSG_ATTR_SYSTO);
	const char *op       = NULL;
	xmlNodePtr action = NULL;
	gboolean processing_complete = FALSE;

	FNIN();

	if (root_xml_node == NULL)
	{
		cl_log(LOG_INFO, "Message was not valid... discarding message.");
		FNOUT();
	}
    

	// try passing the buck first
	processing_complete = relay_message(root_xml_node,
					    originated_locally,
					    src_node_name);

	/* if that doesn't work, the message is *definitly* for us
	 * (where us == dc||crmd)
	 */
	if (processing_complete == FALSE) {
		gboolean dc_mode = FALSE;
		action = validate_crm_message(root_xml_node,
					      NULL,
					      NULL,
					      NULL);
		op = xmlGetProp(action, XML_CRM_ATTR_OP);  

		if (strcmp(CRM_SYSTEM_DC, sys_to) == 0) {
			dc_mode = TRUE;
			op = xmlGetProp(action, XML_DC_ATTR_OP);
		}

		if (op == NULL) {
			cl_log(LOG_ERR,
			       "Invalid XML message.  "
			       "No value %s operation for specified in (%s).",
			       dc_mode?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD,
			       root_xml_node->name); 
		} else {
			processing_complete =
				crm_dc_process_message(root_xml_node,
						       action,
						       src_node_name,
						       sys_from,
						       sys_to,
						       op,
						       dc_mode);
		}
		
	}

	if (processing_complete != TRUE)
		cl_log(LOG_ERR, "Did not know what to do with message "
		       "(crm_msg_reference=%s)", crm_msg_reference);
	else
		CRM_DEBUG2("Processing complete for message (crm_msg_reference=%s)",
			   crm_msg_reference);

	FNOUT();
}


gboolean
relay_message(xmlNodePtr xml_relay_message,
	      gboolean originated_locally,
	      const char *host_from)
{
	const char *crm_msg_reference  = xmlGetProp(xml_relay_message,
						    XML_MSG_ATTR_REFERENCE);
	const char *sys_from   = xmlGetProp(xml_relay_message,
					    XML_MSG_ATTR_SYSFROM);
	const char *host_to    = xmlGetProp(xml_relay_message,
					    XML_MSG_ATTR_HOSTTO);
	const char *sys_to     = xmlGetProp(xml_relay_message,
					    XML_MSG_ATTR_SYSTO);
	const char *type       = xmlGetProp(xml_relay_message,
					    XML_MSG_ATTR_MSGTYPE);
	char *dest_node = NULL;

	int is_for_dc  = 0;
	int is_for_crm = 0;
	int is_request = 0;
	int is_local   = 0;
	gboolean processing_complete = FALSE;
	
	FNIN();

	if (sys_to == NULL || crm_msg_reference == NULL || type == NULL) {
		cl_log(LOG_DEBUG,
		       "relay_message: Invalid message, (%s, %s, %s) discarding.",
		       sys_to, crm_msg_reference, type);
		FNRET(TRUE); // Discard.  Should have been picked up by now anyway
	}
    
	is_for_dc  = (strcmp(CRM_SYSTEM_DC, sys_to) == 0);
	is_for_crm = (strcmp(CRM_SYSTEM_CRMD, sys_to) == 0);
	is_request = (strcmp("request", type) == 0);
	is_local   = (host_to == NULL
		      || strlen(host_to) == 0
		      || strcmp(our_uname, host_to) == 0);

	CRM_DEBUG("relaying message");
	CRM_DEBUG2("originated locally %d", originated_locally);
	CRM_DEBUG2("is dc %d", is_for_dc);
	CRM_DEBUG2("is crm %d", is_for_crm);
	CRM_DEBUG2("is request %d", is_request);
	CRM_DEBUG2("is local %d", is_local);
	CRM_DEBUG2("our host [%s]", our_uname);
	CRM_DEBUG2("dest host [%s]", host_to);
    
	if (is_request == 1 && is_for_dc == 0 && originated_locally == FALSE) {
		/* save host/crm_msg_reference in routing table
		 * so that responses will be directed appropriately
		 */
		CRM_DEBUG("Generating key to look up hash table with");
		gpointer action_ref =
			(gpointer)generate_hash_key(crm_msg_reference, sys_to);
		CRM_DEBUG2("key (%s)", (char*)action_ref);

		if(g_hash_table_lookup(pending_remote_replies, action_ref) == NULL){
			CRM_DEBUG2(
				"Updating crm_msg_reference table for %s",
				host_from);
			gpointer value =
				(gpointer)generate_hash_value(host_from,
							      sys_from);
			CRM_DEBUG2("value (%s)", (char*)value);
			g_hash_table_insert (pending_remote_replies,
					     action_ref,
					     value);
			/* remove from the table based on FIFO or a timed sweep
			 *    or something
			 *
			 * cleanup_crm_msg_referenceTable();
			 */
		} else {
			cl_log(LOG_INFO,
			       "Already processing a message with crm_msg_reference "
			       "number (%s) for sub-system (%s)... discarding message.",
			       crm_msg_reference, sys_to);
			processing_complete = TRUE;
		}
	}

	if (is_for_dc) {
		// only forward dc messages if they originated locally
		if (originated_locally && i_am_dc == FALSE) {
			// DC Messages are always broadcast
			send_msg_via_ha(xml_relay_message, NULL);
			processing_complete = TRUE;
		} else if (i_am_dc == FALSE) {
			processing_complete = TRUE;  // ignore
		}
	} else if (is_local) {
		if (!is_for_crm) {
			send_msg_via_ipc(xml_relay_message, sys_to);
			processing_complete = TRUE;
		}
	} else {
		dest_node = find_destination_host(xml_relay_message,
						  crm_msg_reference,
						  sys_from,
						  is_request);
		send_msg_via_ha(xml_relay_message, dest_node);
		processing_complete = TRUE;
	}

	FNRET(processing_complete);
}

gboolean
crm_dc_process_message(xmlNodePtr whole_message,
		       xmlNodePtr action,
		       const char *host_from,
		       const char *sys_from,
		       const char *sys_to,
		       const char *op,
		       gboolean dc_mode)
{
	FNIN();
	gboolean processing_complete = FALSE;
	xmlNodePtr wrapper = NULL, ping = NULL;
    
	if (dc_mode)
	{
		CRM_DEBUG("Processing DC specific actions");	    
		// DC specific actions
		if (strcmp("cib_op", op) == 0)
		{
			xmlNodePtr cib_req =
				find_xml_node(action, XML_REQ_TAG_CIB);
	    
			wrapper = create_forward(whole_message,
						 cib_req,
						 "cib");
			relay_message(wrapper, TRUE, host_from);
			processing_complete = TRUE;
			free_xml(wrapper);
		}
	
		CRM_DEBUG("Finished processing DC specific actions");
	}
    
	if (processing_complete == FALSE)
	{
		CRM_DEBUG("Processing common DC/CRMd actions");
	
		xmlNodePtr response = NULL;
		if (strcmp("ping", op) == 0)
		{
			// eventually do some stuff to figure out if we *are* ok
			ping = createPingAnswerFragment(sys_to, "ok");

			if (dc_mode)
				response = create_xml_node(NULL,
							   XML_RESP_TAG_DC);
			else response = create_xml_node(NULL,
							XML_RESP_TAG_CRM);
			xmlAddChild(response, ping);
	    
			wrapper = create_reply(whole_message, response);
			relay_message(wrapper, TRUE, host_from);
			processing_complete = TRUE;
			free_xml(wrapper);
		}
		else if (strcmp("ping_deep", op) == 0)
		{
			// eventually do some stuff to figure out if we *are* ok
			ping = createPingAnswerFragment(sys_to, "ok");

			if (dc_mode)
				response = create_xml_node(NULL,
							   XML_RESP_TAG_DC);
			else
				response = create_xml_node(NULL,
							   XML_RESP_TAG_CRM);
			xmlAddChild(response, ping);
	    
			wrapper = create_reply(whole_message, response);
			relay_message(wrapper, TRUE, host_from);
			free_xml(wrapper);

			/* Now pass the ping request on to all subsystems for them
			 *  to reply to individually.
			 *
			 * Basically this means we are pushing the complexity back
			 *  on to the client.  Therefore it is the client that must
			 *  decide, based on the results it recieves, if all
			 *  subsystems are alive.
			 *
			 * ... Unless we choose another method, other than IPC 
			 *  message/response, of pinging locally.
			 */
			wrapper = create_forward(whole_message,
						 action,
						 CRM_SYSTEM_CIB);
			relay_message(wrapper, TRUE, host_from);
			free_xml(wrapper);

			wrapper =
				create_forward(whole_message,
					       action,
					       CRM_SYSTEM_LRMD);
			relay_message(wrapper, TRUE, host_from);
			free_xml(wrapper);

			wrapper =
				create_forward(whole_message,
					       action,
					       CRM_SYSTEM_PENGINE);
			relay_message(wrapper, TRUE, host_from);
			free_xml(wrapper);

			wrapper =
				create_forward(whole_message, action, CRM_SYSTEM_TENGINE);
			relay_message(wrapper, TRUE, host_from);
			free_xml(wrapper);

			processing_complete = TRUE;
		} else {
                        // else we dont know anything about it
			cl_log(LOG_ERR,
			       "The specified operation (%s) is not (yet?) supported\n",
			       op);
		}
	
		CRM_DEBUG("Finished processing common DC/CRMd actions");
	}
	FNRET(processing_complete);
}



void
send_msg_via_ha(xmlNodePtr action, const char *dest_node)
//, const char *sys_to, const char *dest_node)
{
	FNIN();
	if (action == NULL) FNOUT();

	if (validate_crm_message(action, NULL, NULL, NULL) == NULL)
	{
		cl_log(LOG_ERR,
		       "Relay message to (%s) via HA was invalid, ignoring",
		       dest_node);
		FNOUT();
	}
	CRM_DEBUG2("Relaying message to (%s) via HA", dest_node);
	set_xml_property_copy(action, XML_MSG_ATTR_HOSTTO, dest_node);
	send_xmlha_message(hb_cluster, action);
	FNOUT();
}


void
send_msg_via_ipc(xmlNodePtr action, const char *sys)
{
	FNIN();
	cl_log(LOG_DEBUG, "relaying msg to sub_sys=%s via IPC", sys);

	IPC_Channel *client_channel =
		(IPC_Channel*)g_hash_table_lookup (ipc_clients, sys);

	if (client_channel != NULL) {
		cl_log(LOG_DEBUG, "Sending message via channel %s.", sys);
		send_xmlipc_message(client_channel, action);
	} else {
		cl_log(LOG_INFO,
		       "Unknown Sub-system (%s)... discarding message.",
		       sys);
		FNOUT();
	}    
}


// return value is an indication that processing should continue
gboolean
add_pending_outgoing_reply(const char *originating_node_name,
			   const char *crm_msg_reference,
			   const char *sys_to,
			   const char *sys_from)
{
	FNIN();
    
	CRM_DEBUG2("Updating crm_msg_reference table for %s",
		   originating_node_name);
	CRM_DEBUG("Generating key to look up hash table with");

	gpointer action_ref = (gpointer)generate_hash_key(crm_msg_reference,
							  sys_to);
	CRM_DEBUG2("key (%s)", (char*)action_ref);
	if (g_hash_table_lookup (pending_remote_replies, action_ref) != NULL)
	{
		cl_log(LOG_INFO,
		       "Already processing a message with crm_msg_reference "
		       "number (%s) for sub-system (%s)... discarding message.",
		       crm_msg_reference, sys_to);
		FNRET(FALSE);
	}
	gpointer value = (gpointer)generate_hash_value(originating_node_name,
						       sys_from);
	CRM_DEBUG2("value (%s)", (char*)value);
	g_hash_table_insert (pending_remote_replies, action_ref, value);
	// remove from the table based on FIFO or a timed sweep or something
	// cleanup_crm_msg_referenceTable();

	FNRET(TRUE);
}

		
char *
find_destination_host(xmlNodePtr xml_root_node,
		      const char *crm_msg_reference,
		      const char *sys_from,
		      int is_request)
{
	char *dest_node = NULL, *sys_to = NULL;
	FNIN();
    
	if (is_request == 0)
	{
		gpointer destination = NULL;
		CRM_DEBUG("Generating key to look up destination hash table with");
		gpointer action_ref =
			(gpointer)generate_hash_key(
				crm_msg_reference,
				sys_from);
		CRM_DEBUG2("Created key (%s)", (char*)action_ref);
		destination = g_hash_table_lookup (pending_remote_replies,
						   action_ref);
		CRM_DEBUG2("Looked up hash table and found value (%s)",
			   (char*)destination);
	
		if (destination == NULL)
		{
			cl_log(LOG_INFO,
			       "Dont know anything about a message with "
			       "crm_msg_reference number (%s) from sub-system (%s)..."
			       " discarding response.",
			       crm_msg_reference, sys_from);
			FNRET(NULL);// should be discarded instead?
		}
		CRM_DEBUG("Decoding destination");
		if (decode_hash_value(destination, &dest_node, &sys_to))
		{
			CRM_DEBUG3("Decoded destination (%s, %s)",
				   dest_node,
				   sys_to);
			set_xml_property_copy(xml_root_node,
					      XML_MSG_ATTR_SYSTO,
					      sys_to);
			CRM_DEBUG3("setting (%s=%s) on HA message",
				   XML_MSG_ATTR_SYSTO, sys_to);
		}
		else
		{
			cl_log(LOG_INFO,
			       "Could not decode hash value (%s)... "
			       "Discarding message.",
			       (char*)destination);
		}
	}
	FNRET(dest_node);
	//return dest_node;
}
