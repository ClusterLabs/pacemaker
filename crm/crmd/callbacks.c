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
#include <crm/crm.h>
#include <string.h>
#include <crmd_fsa.h>
#include <libxml/tree.h>

#include <heartbeat.h>

#include <hb_api.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>

#include <crm/dmalloc_wrapper.h>

FILE *msg_in_strm = NULL;

xmlNodePtr find_xml_in_hamessage(const struct ha_msg* msg);

void
crmd_ha_input_callback(const struct ha_msg* msg, void* private_data)
{
	const char *from = ha_msg_value(msg, F_ORIG);
	const char *to = NULL;
	xmlNodePtr root_xml_node;

	FNIN();

#ifdef MSG_LOG
	if(msg_in_strm == NULL) {
		msg_in_strm = fopen("/tmp/inbound.log", "w");
	}
#endif

	if(from == NULL || strcmp(from, fsa_our_uname) == 0) {
#ifdef MSG_LOG
		fprintf(msg_in_strm,
			"Discarded message [F_SEQ=%s] from ourselves.\n",
			ha_msg_value(msg, F_SEQ));
#endif
		FNOUT();
	}
	
#ifdef MSG_LOG
	fprintf(msg_in_strm, "[%s (%s:%s)]\t%s\n",
		from,
		ha_msg_value(msg, F_SEQ),
		ha_msg_value(msg, F_TYPE),
		ha_msg_value(msg, "xml")
		);
	fflush(msg_in_strm);
#endif

	root_xml_node = find_xml_in_hamessage(msg);
	to = xmlGetProp(root_xml_node, XML_ATTR_HOSTTO);
	
	if(to != NULL && strlen(to) > 0 && strcmp(to, fsa_our_uname) != 0) {
#ifdef MSG_LOG
		fprintf(msg_in_strm,
			"Discarding message [F_SEQ=%s] for someone else.",
			ha_msg_value(msg, F_SEQ));
#endif
		FNOUT();
	}

	set_xml_property_copy(root_xml_node, XML_ATTR_HOSTFROM, from);
	s_crmd_fsa(C_HA_MESSAGE, I_ROUTER, root_xml_node);

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
	xmlNodePtr root_xml_node;
	crmd_client_t *curr_client = (crmd_client_t*)user_data;

	FNIN();
	CRM_DEBUG("Processing IPC message from %s",
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
			cl_log(LOG_WARNING, "No message this time");
			continue;
		}

		lpc++;
		buffer = (char*)msg->msg_body;
		CRM_DEBUG("Processing xml from %s [text=%s]",
			   curr_client->table_key, buffer);
	
		root_xml_node =
			find_xml_in_ipcmessage(msg, FALSE);
		if (root_xml_node != NULL) {

			if (crmd_authorize_message(root_xml_node,
						   msg,
						   curr_client)) {
				s_crmd_fsa(C_IPC_MESSAGE,
					   I_ROUTER,
					   root_xml_node);
			}
		} else {
			cl_log(LOG_INFO,
			       "IPC Message was not valid... discarding.");
		}
		free_xml(root_xml_node);
		msg->msg_done(msg);
		
		msg = NULL;
		buffer = NULL;
		root_xml_node = NULL;
	}

	CRM_DEBUG("Processed %d messages", lpc);
    
	if (client->ch_status == IPC_DISCONNECT)
	{
		cl_log(LOG_INFO,
		       "received HUP from %s",
		       curr_client->table_key);
		if (curr_client != NULL) {
			struct crm_subsystem_s *the_subsystem = NULL;
			
			if (curr_client->sub_sys == NULL) {
				cl_log(LOG_WARNING,
				       "Client hadn't registered with us yet");

			} else if (strcmp(CRM_SYSTEM_PENGINE,
					  curr_client->sub_sys) == 0) {
				the_subsystem = pe_subsystem;

			} else if (strcmp(CRM_SYSTEM_TENGINE,
					  curr_client->sub_sys) == 0) {
				the_subsystem = te_subsystem;

			} else if (strcmp(CRM_SYSTEM_CIB,
					  curr_client->sub_sys) == 0){
				the_subsystem = cib_subsystem;
			}
			

			if(the_subsystem != NULL) {
				cleanup_subsystem(the_subsystem);
			} // else that was a transient client
			
			if (curr_client->table_key != NULL) {
				/*
				 * Key is destroyed below:
				 *	curr_client->table_key
				 * Value is cleaned up by:
				 *	G_main_del_IPC_Channel
				 */
				g_hash_table_remove(
					ipc_clients, curr_client->table_key);
			}


			if(curr_client->client_source != NULL) {
				gboolean det = G_main_del_IPC_Channel(
					curr_client->client_source);
			
				CRM_DEBUG("crm_client was %s detached",
					   det?"successfully":"not");
			}
			
			crm_free(curr_client->table_key);
			crm_free(curr_client->sub_sys);
			crm_free(curr_client->uuid);
			crm_free(curr_client);
		}
		FNRET(!hack_return_good);
	}
    
	FNRET(hack_return_good);
}


void
lrm_op_callback (lrm_op_t* op)
{
	s_crmd_fsa(C_LRM_OP_CALLBACK, I_LRM_EVENT, op);
}

void
lrm_monitor_callback (lrm_mon_t* monitor)
{
	s_crmd_fsa(C_LRM_MONITOR_CALLBACK, I_LRM_EVENT, monitor);
}

void
CrmdClientStatus(const char * node, const char * client,
		 const char * status, void * private)
{
	const char    *join = NULL;
	const char   *extra = NULL;
	xmlNodePtr   update = NULL;
	xmlNodePtr fragment = NULL;

	if(safe_str_eq(status, JOINSTATUS)){
		status = ONLINESTATUS;
		extra  = XML_CIB_ATTR_CLEAR_SHUTDOWN;

	} else if(safe_str_eq(status, LEAVESTATUS)){
		status = OFFLINESTATUS;
		join   = CRMD_JOINSTATE_DOWN;
		extra  = XML_CIB_ATTR_CLEAR_SHUTDOWN;
	}
	
	cl_log(LOG_NOTICE,
	       "Status update: Client %s/%s now has status [%s]\n",
	       node, client, status);

	if(AM_I_DC) {
		update = create_node_state(node, NULL, status, join);

		if(extra != NULL) {
			set_xml_property_copy(update, extra, XML_BOOLEAN_TRUE);
		}
		
		fragment = create_cib_fragment(update, NULL);
		store_request(NULL, fragment,
			      CRM_OP_UPDATE, CRM_SYSTEM_DCIB);
		
		free_xml(fragment);
		free_xml(update);

		s_crmd_fsa(C_CRMD_STATUS_CALLBACK, I_NULL, NULL);
		
	} else {
		cl_log(LOG_ERR, "Got client status callback in non-DC mode");
	}
}


xmlNodePtr
find_xml_in_hamessage(const struct ha_msg* msg)
{
	const char *xml;
   	xmlDocPtr doc;
	xmlNodePtr root;

	FNIN();
	if (msg == NULL) {
		cl_log(LOG_INFO,
		       "**** ha_crm_msg_callback called on a NULL message");
		FNRET(NULL);
	}

#if 0
	cl_log(LOG_DEBUG, "[F_TYPE=%s]", ha_msg_value(msg, F_TYPE));
	cl_log(LOG_DEBUG, "[F_ORIG=%s]", ha_msg_value(msg, F_ORIG));
	cl_log(LOG_DEBUG, "[F_TO=%s]", ha_msg_value(msg, F_TO));
	cl_log(LOG_DEBUG, "[F_COMMENT=%s]", ha_msg_value(msg, F_COMMENT));
	cl_log(LOG_DEBUG, "[F_XML=%s]", ha_msg_value(msg, "xml"));
//    cl_log(LOG_DEBUG, "[F_=%s]", ha_msg_value(ha_msg, F_));
#endif
	
	if (strcmp("CRM", ha_msg_value(msg, F_TYPE)) != 0) {
		cl_log(LOG_INFO, "Received a (%s) message by mistake.",
		       ha_msg_value(msg, F_TYPE));
		FNRET(NULL);
	}
	xml = ha_msg_value(msg, "xml");
	if (xml == NULL) {
		cl_log(LOG_INFO, "No XML attached to this message.");
		FNRET(NULL);
	}
	doc = xmlParseMemory(xml, strlen(xml));
	if (doc == NULL) {
		cl_log(LOG_INFO, "XML Buffer was not valid.");
		FNRET(NULL);
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
		cl_log(LOG_INFO, "Root node was NULL.");
		FNRET(NULL);
	}
	FNRET(root);
}
