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
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <ocf/oc_event.h>

#define IS_DAEMON   1
#define REGISTER_HA 1
#define IPC_COMMS   1
#define REALTIME_SUPPORT
#define APPHB_SUPPORT

#define APPNAME_LEN 256

gboolean i_am_dc = FALSE;
int i_am_in = 0;
oc_ev_t *ev_token;    // for CCM comms
int	my_ev_fd;     // for CCM comms

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlutils.h>
#include <glib.h>

extern GHashTable   *pending_actions;
extern IPC_Channel  *cib;
extern ll_cluster_t *hb_fd;

extern const char* daemon_name;// = "crmd";
void my_ms_events(oc_ed_t event, void *cookie, size_t size, const void *data);

void send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg);
gboolean waitCh_client_connect(IPC_Channel *newclient, gpointer user_data);
void clntCh_input_destroy(gpointer );
void waitCh_input_destroy(gpointer user_data);
gboolean tickle_apphb(gpointer data);
void msg_ccm_join(const struct ha_msg *msg, void *foo);
void ha_crm_msg_callback(const struct ha_msg* msg, void* private_data);
gboolean crm_clntCh_input_dispatch(IPC_Channel *client, gpointer user_data);

char *generate_hash_key(const char *reference, const char *sys);
char *generate_hash_value(const char *src_node, const char *src_subsys);
gboolean decode_hash_value(gpointer value, char **node, char **subsys);

void relay_ipc_to_ha(xmlNodePtr action);
void relay_ha_to_ipc(xmlNodePtr action, const char *sys, const char *src_node_name);
void process_message(xmlNodePtr root_xml_node, gboolean from_ipc, const char *src_node_name);
gboolean updateReferenceTable(xmlNodePtr root_xml_node, const char *src_node_name);


gboolean
waitCh_client_connect(IPC_Channel *newclient, gpointer user_data)
{
    // assign the client to be something, or put in a hashtable

    cl_log(LOG_DEBUG, "A client tried to connect");

    IPC_Message *client_msg = (IPC_Message *)user_data;
    cl_log(LOG_INFO, "recieved client join msg: %s", (char*)client_msg->msg_body);


    IPC_Message        *ack_msg;
    char	       str[256];
    snprintf(str, sizeof(str)-1, "I see you have joined us... %d", 1);

    ack_msg = create_simple_message(str, newclient);
    send_ipc_message(newclient, ack_msg);
    
    G_main_add_IPC_Channel(G_PRIORITY_LOW,
			   newclient,
			   FALSE, 
			   crm_clntCh_input_dispatch,
			   newclient, 
			   clntCh_input_destroy);
    return TRUE;
}



void 
my_ms_events(oc_ed_t event, void *cookie, 
		size_t size, const void *data)
{
    (void)_ha_msg_h_Id; // keep the compiler happy

    const oc_ev_membership_t *oc = (const oc_ev_membership_t *)data;
	uint i;

 	cl_log(LOG_INFO,"event=%s", 
			event==OC_EV_MS_NEW_MEMBERSHIP?"NEW MEMBERSHIP":
		        event==OC_EV_MS_NOT_PRIMARY?"NOT PRIMARY":
			event==OC_EV_MS_PRIMARY_RESTORED?"PRIMARY RESTORED":
			event==OC_EV_MS_EVICTED?"EVICTED":
			      "NO QUORUM MEMBERSHIP");

	if(OC_EV_MS_EVICTED == event) {
		oc_ev_callback_done(cookie);
		return;
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

	i_am_in=0;
	i_am_dc=FALSE;
	cl_log(LOG_INFO, "NODES IN THE PRIMARY MEMBERSHIP");
	
	int node_list_size = oc->m_n_member;
	
	for(i=0; i<node_list_size; i++) {
	  cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
		 oc->m_array[oc->m_memb_idx+i].node_id,
		 oc->m_array[oc->m_memb_idx+i].node_born_on);
	  if(oc_ev_is_my_nodeid(ev_token, &(oc->m_array[i])))
	    {
	      cl_log(LOG_INFO,"MY NODE ID IS %d", oc->m_array[oc->m_memb_idx+i].node_id);
	      i_am_in=1;
	      if(i == 0)
		i_am_dc=TRUE;
	    }
	}

	if(i_am_in) {
	  cl_log(LOG_INFO,"MY NODE IS A MEMBER OF THE MEMBERSHIP LIST");
	  if(i_am_dc) {
	    cl_log(LOG_INFO,"MY NODE IS THE DESIGNATED CONTROLLER OF THE MEMBERSHIP LIST");
	  }
	}

	cl_log(LOG_INFO, "NEW MEMBERS");
	if(oc->m_n_in==0) 
	  cl_log(LOG_INFO, "\tNONE");
	for(i=0; i<oc->m_n_in; i++) {
	  cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
		 oc->m_array[oc->m_in_idx+i].node_id,
		 oc->m_array[oc->m_in_idx+i].node_born_on);
	}
	cl_log(LOG_INFO, "MEMBERS LOST");
	if(oc->m_n_out==0) 
		cl_log(LOG_INFO, "\tNONE");
	for(i=0; i<oc->m_n_out; i++) {
		cl_log(LOG_INFO,"\tnodeid=%d, born=%d",
			oc->m_array[oc->m_out_idx+i].node_id,
			oc->m_array[oc->m_out_idx+i].node_born_on);
	}
	cl_log(LOG_INFO, "-----------------------");
	oc_ev_callback_done(cookie);
}


void 
msg_ccm_join(const struct ha_msg *msg, void *foo)
{
  cl_log(LOG_INFO, "\n###### Recieved ccm_join message...");
  if(msg != NULL)
    {
      cl_log(LOG_INFO, "[type=%s]", ha_msg_value(msg, F_TYPE));
      cl_log(LOG_INFO, "[orig=%s]", ha_msg_value(msg, F_ORIG));
      cl_log(LOG_INFO, "[to=%s]", ha_msg_value(msg, F_TO));
      cl_log(LOG_INFO, "[status=%s]", ha_msg_value(msg, F_STATUS));
      cl_log(LOG_INFO, "[info=%s]", ha_msg_value(msg, F_COMMENT));
      cl_log(LOG_INFO, "[rsc_hold=%s]", ha_msg_value(msg, F_RESOURCES));
      cl_log(LOG_INFO, "[stable=%s]", ha_msg_value(msg, F_ISSTABLE));
      cl_log(LOG_INFO, "[rtype=%s]", ha_msg_value(msg, F_RTYPE));
      cl_log(LOG_INFO, "[ts=%s]", ha_msg_value(msg, F_TIME));
      cl_log(LOG_INFO, "[seq=%s]", ha_msg_value(msg, F_SEQ));
      cl_log(LOG_INFO, "[generation=%s]", ha_msg_value(msg, F_HBGENERATION));
      //      cl_log(LOG_INFO, "[=%s]", ha_msg_value(msg, F_));
    }
}

char *
generate_hash_key(const char *reference, const char *sys)
{
    int ref_len = strlen(sys) + strlen(reference) + 2;
    char *hash_key = (char*)ha_malloc(sizeof(char)*(ref_len));
    sprintf(hash_key, "%s_%s", sys, reference);
    hash_key[ref_len-1] = '\0';
    cl_log(LOG_INFO, "created hash key: (%s)", hash_key);
    return hash_key;
}

char *
generate_hash_value(const char *src_node, const char *src_subsys)
{
    if(src_node == NULL || src_subsys == NULL) return NULL;
    int ref_len = strlen(src_subsys) + 1;
    if(strcmp("dc", src_subsys) == 0)
    {
	char *subsys = (char*)ha_malloc(sizeof(char)* ref_len);
	strncpy(subsys, src_subsys, strlen(src_subsys));
	subsys[strlen(src_subsys)] ='\0';
	return subsys;
    }
    
    ref_len += strlen(src_node)+1;
    char *hash_value = (char*)ha_malloc(sizeof(char)*(ref_len));
    sprintf(hash_value, "%s_%s", src_node, src_subsys);
    hash_value[ref_len-1] = '\0';// i want to make sure it is null terminated

    cl_log(LOG_INFO, "created hash value: (%s)", hash_value);
    return hash_value;
}

gboolean
decode_hash_value(gpointer value, char **node, char **subsys)
{
    char *char_value = (char*)value;
    int value_len = strlen(char_value);
    
    cl_log(LOG_INFO, "Decoding hash value: (%s:%d)", char_value, value_len);
    	
    if(strcmp("dc", (char*)value) == 0) 
    {
	*node = NULL;
	*subsys = (char*)ha_malloc(sizeof(char)* (value_len+1));
	strncpy(*subsys, char_value, value_len);
	(*subsys)[value_len] ='\0';
	cl_log(LOG_INFO, "Decoded value: (%s:%d)", *subsys, strlen(*subsys));
	return TRUE;
    }
    else if(char_value != NULL)
    {
	if(decodeNVpair(char_value, '_', node, subsys))
	    return TRUE;
	else
	{
	    *node = NULL;
	    *subsys = NULL;
	    return FALSE;
	}
    }
    // do the real decoding bit
    return FALSE;
}

void
ha_crm_msg_callback(const struct ha_msg* msg, void* private_data)
{
    cl_log(LOG_DEBUG, "ha_crm_msg_callback: processing HA message (%s from %s)", ha_msg_value(msg, F_SEQ), ha_msg_value(msg, F_ORIG));
    xmlNodePtr root_xml_node = validate_and_decode_hamessage(msg);
    process_message(root_xml_node, FALSE, ha_msg_value(msg, F_ORIG));
}

void
process_message(xmlNodePtr root_xml_node, gboolean from_ipc, const char *src_node_name)
{
    xmlNodePtr action = validate_crm_message(root_xml_node, NULL, NULL);
    if(root_xml_node == NULL)
    {
	cl_log(LOG_INFO, "Message was not valid... discarding message.");
	return;
    }

    const char *src_sys   = xmlGetProp(root_xml_node, XML_MSG_ATTR_SRCSUBSYS);
    const char *dest_sys  = xmlGetProp(root_xml_node, XML_MSG_ATTR_SUBSYS);
    const char *reference = xmlGetProp(root_xml_node, XML_MSG_ATTR_REFERENCE);

    /* check the message is for us...
     *   ie. for the DC and we are it
     *       or it was specifically addressed to us.
     */

    const char *tag = XML_RESP_TAG_CRM;    
    const char *op = NULL;

    // Try to avoid even more string comparisions
    int crm_dc_other = 0;
    if(i_am_dc && strcmp("dc", dest_sys) == 0)
    {
	crm_dc_other = 1;
	tag = XML_RESP_TAG_DC;
	op = xmlGetProp(root_xml_node, XML_DC_ATTR_OP);
	if(op == NULL)
	{
	    cl_log(LOG_ERR, "Invalid XML message.  No value for (%s) specified in (%s).", XML_DC_ATTR_OP, root_xml_node->name); 
	    return;
	}
    }
    else if(strcmp("crm", dest_sys) == 0)
    {
	crm_dc_other = 2;
	op = xmlGetProp(action, XML_CRM_ATTR_OP);
	if(op == NULL)
	{
	    cl_log(LOG_ERR, "Invalid XML message.  No value for (%s) specified in (%s).", XML_CRM_ATTR_OP, root_xml_node->name); 
	    return;
	}
    }
    else if(dest_sys[0] != 'd') crm_dc_other = 3;

    xmlNodePtr response = NULL, wrapper = NULL;;
    switch(crm_dc_other)
    {
	case 1:
	    // DC specific actions

	    // fall through and do the things common to the DC and the CRMd
	case 2:
	    // DC/CRM actions
	    if(strcmp("ping", op) == 0)
	    {
		// eventually do some stuff to figure out if we *are* ok
		xmlNodePtr ping = createPingAnswerFragment(dest_sys, NULL, "ok");
		wrapper = createIpcMessage(reference, dest_sys, NULL, ping, FALSE);
		response = createCrmMsg(reference, dest_sys, src_sys, wrapper, FALSE);
		send_xmlha_message(hb_fd, response, src_node_name, NULL);
	    }
	    else if(strcmp("ping_deep", op) == 0)
	    {
		// eventually do some stuff to figure out if we *are* ok
		xmlNodePtr ping = createPingAnswerFragment(dest_sys, NULL, "ok");
		wrapper = createIpcMessage(reference, dest_sys, NULL, ping, FALSE);
		response = createCrmMsg(reference, dest_sys, src_sys, wrapper, FALSE);
		send_xmlha_message(hb_fd, response, src_node_name, NULL);

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
		const char *local_sub_sys = "lrmd";

		ping = createPingRequest(reference, dest_sys, local_sub_sys);
		relay_ha_to_ipc(ping, local_sub_sys, src_node_name);

		local_sub_sys = "cib";
		cl_log(LOG_DEBUG, "Building Ping Request");
		ping = createPingRequest(reference, src_sys, local_sub_sys);
		wrapper = createCrmMsg(reference, src_sys, local_sub_sys, ping, TRUE);
		cl_log(LOG_DEBUG, "Sending Ping Request");
		relay_ha_to_ipc(wrapper, local_sub_sys, src_node_name);
		cl_log(LOG_DEBUG, "Sent Ping Request");
		//   ...
	    }
	    // else if dc action, skip
	    else
	    {
		cl_log(LOG_ERR, "The specified operation (%s) is not (yet?) supported\n", op);
	    }
	    
	    cl_log(LOG_DEBUG, "The (%s) Received and processed message.", dest_sys);
	    break;
	case 3:
	    /* forward the request to the correct sub-system, making a note of where
	     * the reply should go if it was a request
	     */
	    if(from_ipc)
		relay_ipc_to_ha(root_xml_node);		    
	    else
		relay_ha_to_ipc(root_xml_node, dest_sys, src_node_name);
	    break;
	case 0:
	    // it was for the DC but that isnt us
	    cl_log(LOG_DEBUG, "Received a message for the DC, but that isnt us.");
	default:
	    cl_log(LOG_ERR, "Unknown CRM state.");
	    break;
    }
}

// return value is an indication that processing should continue
gboolean
updateReferenceTable(xmlNodePtr root_xml_node, const char *originating_node_name)
{
    
    CRM_DEBUG2("Updating reference table for %s", originating_node_name);
    if(root_xml_node == NULL) return FALSE;


    
    CRM_DEBUG("Generating key to look up hash table with");

    
    if(originating_node_name == NULL) return TRUE; // local request
    const char *type      = xmlGetProp(root_xml_node, XML_MSG_ATTR_MSGTYPE);

    CRM_DEBUG2("Type (%s)", type);
    if(type == NULL)
    {
	CRM_DEBUG2("type was null!!! xml=[%s]", dump_xml(root_xml_node));
	return FALSE;
    }
    else if(strcmp("request", type) != 0) return TRUE;
    
    const char *originating_sys   = xmlGetProp(root_xml_node, XML_MSG_ATTR_SRCSUBSYS);
    const char *dest_sys  = xmlGetProp(root_xml_node, XML_MSG_ATTR_SUBSYS);
    const char *reference = xmlGetProp(root_xml_node, XML_MSG_ATTR_REFERENCE);

    gpointer action_ref = (gpointer)generate_hash_key(reference, dest_sys);
    CRM_DEBUG2("key (%s)", (char*)action_ref);
    if(g_hash_table_lookup (pending_actions, action_ref) != NULL)
    {
	cl_log(LOG_INFO,
	       "Already processing a message with reference number (%s) for sub-system (%s)... discarding message.",
	       reference, dest_sys);
	return FALSE;
    }
    gpointer value = (gpointer)generate_hash_value(originating_node_name, originating_sys);
    CRM_DEBUG2("value (%s)", (char*)action_ref);
    g_hash_table_insert (pending_actions, action_ref, value);
    // remove from the table based on FIFO or a timed sweep or something
    // cleanup_referenceTable();

    return TRUE;
}


gboolean
crm_clntCh_input_dispatch(IPC_Channel *client, 
	      gpointer        user_data)
{
	cl_log(LOG_DEBUG, "crm_clntCh_input_dispatch: processing IPC message");
	if(client->ch_status == IPC_DISCONNECT)
	{
	    cl_log(LOG_INFO, "clntCh_input_dispatch: received HUP");
// client_delete(client);
// do some equiv instead
	    return FALSE;
	}

	xmlNodePtr root_xml_node = validate_and_decode_ipcmessage(client);
	if(root_xml_node == NULL)
	{
	    cl_log(LOG_INFO, "IPC Message was not valid... discarding message.");
	    return TRUE;
	}
	cl_log(LOG_DEBUG, "crm_clntCh_input_dispatch: about to relay message");
	
	process_message(root_xml_node, TRUE, NULL);
	    
	return TRUE; /* TOBEDONE */
}

void
relay_ipc_to_ha(xmlNodePtr action)
{
    if(action == NULL) return;
    const char *type = xmlGetProp(action, XML_MSG_ATTR_MSGTYPE);
    const char *from = xmlGetProp(action, XML_MSG_ATTR_SRCSUBSYS);
    const char *to = xmlGetProp(action, XML_MSG_ATTR_SUBSYS);
    const char *reference = xmlGetProp(action, XML_MSG_ATTR_REFERENCE);

    gpointer destination = NULL;
    cl_log(LOG_DEBUG, "relaying msg (type=%s, ref=%s, from=%s) to HA", type, reference, from);
    if(strcmp("response", type) == 0)
    {
	CRM_DEBUG("Generating key to look up hash table with");
	gpointer action_ref = (gpointer)generate_hash_key(reference, from);
	CRM_DEBUG2("Created key (%s)", (char*)action_ref);
	destination = g_hash_table_lookup (pending_actions, action_ref);
	CRM_DEBUG2("Looked up hash tabel and found value (%s)", (char*)destination);
	
	if(destination == NULL)
	{
	    cl_log(LOG_INFO,
		   "Dont know anything about a message with reference number (%s) for sub-system (%s)... discarding response.",
		   reference, to);
	    return;
	}
    }

    if(validate_crm_message(action, NULL, NULL) == NULL)
    {
	cl_log(LOG_ERR, "Message to relay from (%s) to (%s) via heartbeat was invalid, ignoring", from, to);
	return;
    }
    
    char *dest_node, *dest_sys;
    CRM_DEBUG("Decoding destination");
    if(decode_hash_value(destination, &dest_node, &dest_sys))
    {
	CRM_DEBUG3("Decoded destination (%s, %s)", dest_node, dest_sys);
	xmlSetProp(action, XML_MSG_ATTR_SUBSYS, dest_sys);
	cl_log(LOG_DEBUG, "setting (%s=%s) on HA message", XML_MSG_ATTR_SUBSYS, dest_sys);
	send_xmlha_message(hb_fd, action, dest_node, NULL);
    }
    else
    {
	cl_log(LOG_INFO, "Could not decode hash value (%s)... Discarding message.", (char*)destination);
    }
    
//    g_hash_table_remove (pending_actions, action_ref);  // see note in updateReferenceTable()
}


void
relay_ha_to_ipc(xmlNodePtr action, const char *sys, const char *originating_node_name)
{
    cl_log(LOG_DEBUG, "relaying msg to sub_sys=%s via IPC", sys);

    updateReferenceTable(action, originating_node_name); // so that responses will be directed appropriately
    
    if(strcmp("cib", sys) == 0)
    {
	cl_log(LOG_DEBUG, "Sending message to the CIB.");
	send_xmlipc_message(cib, action);
    }
    else
    {
	cl_log(LOG_INFO, "Unknown Sub-system (%s)... discarding message.", sys);
	return;
    }    
}


