/* $Id: ipc.c,v 1.1 2004/06/02 11:45:28 andrew Exp $ */
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>


#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include <crm/common/ipc.h>
#include <crm/msg_xml.h>


#include <crm/dmalloc_wrapper.h>

IPC_Message *create_simple_message(char *text, IPC_Channel *ch);
gboolean send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg);


gboolean 
send_xmlipc_message(IPC_Channel *ipc_client, xmlNodePtr msg)
{
	int log_level = LOG_DEBUG;
	char *xml_message = NULL;
	IPC_Message *cib_dump = NULL;
	gboolean res;
	FNIN();

	xml_message = dump_xml(msg);
	
	cib_dump =
		create_simple_message(xml_message, ipc_client);
	res = send_ipc_message(ipc_client, cib_dump);
	crm_free(xml_message);

	if(res == FALSE) {
		log_level = LOG_ERR;
	}
	
	cl_log(log_level,
	       "Sending IPC message (ref=%s) to %s@%s %s.",
	       xmlGetProp(msg, XML_ATTR_REFERENCE), 
	       xmlGetProp(msg, XML_ATTR_SYSTO),
	       xmlGetProp(msg, XML_ATTR_HOSTTO),
	       res?"succeeded":"failed");
	
	FNRET(res);
}


gboolean 
send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg)
{
	int lpc = 0;
	gboolean all_is_good = TRUE;
	FNIN();

	if (msg == NULL) {
		cl_log(LOG_WARNING, "cant send NULL message");
		all_is_good = FALSE;
	}
	else if (msg->msg_len <= 0) {
		cl_log(LOG_WARNING, "cant send 0 sized message");
		all_is_good = FALSE;
	}
	else if (msg->msg_len > MAXDATASIZE) {
		cl_log(LOG_WARNING, "cant send msg... too big");
		all_is_good = FALSE;
	}
    
/*     CRM_DEBUG("Sending message: %s", (char*)msg->msg_body); */
	CRM_DEBUG("Message is%s valid to send", all_is_good?"":" not");

	if (ipc_client == NULL) {
		all_is_good = FALSE;
	}
	CRM_DEBUG("IPC Client is%s set.", all_is_good?"":" not");
	if (all_is_good) {		
		while(lpc++ < MAX_IPC_FAIL
		      && ipc_client->ops->send(ipc_client, msg) == IPC_FAIL)
		{
			cl_log(LOG_WARNING, "ipc channel blocked");
			cl_shortsleep();
		}
	}
	
	if (lpc == MAX_IPC_FAIL) {
		cl_log(LOG_ERR,
		       "Could not send IPC, message.  Channel is dead.");
		all_is_good = FALSE;
	}

	FNRET(all_is_good);
}

IPC_Message *
create_simple_message(char *text, IPC_Channel *ch)
{
	//    char	       str[256];
	IPC_Message        *ack_msg = NULL;

	FNIN();
	if (text == NULL) FNRET(NULL);

	ack_msg = (IPC_Message *)crm_malloc(sizeof(IPC_Message));
    
	ack_msg->msg_private = NULL;
	ack_msg->msg_done    = NULL;
	ack_msg->msg_body    = text;
	ack_msg->msg_ch      = ch;

	ack_msg->msg_len = strlen(text)+1;
    
	FNRET(ack_msg);
}


xmlNodePtr
find_xml_in_ipcmessage(IPC_Message *msg, gboolean do_free)
{
	char *buffer = NULL;
	xmlDocPtr doc;
	xmlNodePtr root;

	FNIN();
	if (msg == NULL) {
		CRM_NOTE("IPC Message was empty...");
		FNRET(NULL);
	}

	buffer = (char*)msg->msg_body;
	doc = xmlParseMemory(buffer, strlen(buffer));

	if (do_free) msg->msg_done(msg);

	if (doc == NULL) {
		cl_log(LOG_INFO,
		       "IPC Message did not contain an XML buffer...");
		FNRET(NULL);
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
		cl_log(LOG_INFO, "Root node was NULL.");
		FNRET(NULL);
	}
	FNRET(root);
}



void
default_ipc_input_destroy(gpointer user_data)
{
	FNIN();
	FNOUT();
}


IPC_Channel *
init_client_ipc_comms(const char *child,
		      gboolean (*dispatch)(IPC_Channel* source_data
					   ,gpointer    user_data),
		      crmd_client_t *client_data)
{
	IPC_Channel *ch;
	GHashTable * attrs;
	GCHSource *the_source = NULL;
	void *callback_data = client_data;
	static char 	path[] = IPC_PATH_ATTR;
	char *commpath = NULL;
	int local_socket_len = 2; // 2 = '/' + '\0'

	FNIN();
	local_socket_len += strlen(child);
	local_socket_len += strlen(WORKING_DIR);

	commpath = (char*)crm_malloc(sizeof(char)*local_socket_len);
	sprintf(commpath, WORKING_DIR "/%s", child);
	commpath[local_socket_len - 1] = '\0';
    
	cl_log(LOG_DEBUG, "Attempting to talk on: %s", commpath);

	attrs = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(attrs, path, commpath);

	ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
	g_hash_table_destroy(attrs);

	if (ch == NULL) {
		cl_log(LOG_CRIT,
		       "Could not access channel on: %s",
		       commpath);
		
	} else if (ch->ops->initiate_connection(ch) != IPC_OK) {
		cl_log(LOG_CRIT, "Could not init comms on: %s", commpath);
		FNRET(NULL);
	}

	if(callback_data == NULL)
		callback_data = ch;

	ch->ops->set_recv_qlen(ch, 100);
	ch->ops->set_send_qlen(ch, 100);

	the_source = G_main_add_IPC_Channel(G_PRIORITY_LOW,
					    ch,
					    FALSE, 
					    dispatch,
					    callback_data, 
					    default_ipc_input_destroy);

	cl_log(LOG_DEBUG, "Processing of %s complete", commpath);

	FNRET(ch);
}


/*
 * This method adds a copy of xml_response_data
 */
gboolean
send_ipc_request(IPC_Channel *ipc_channel,
		 xmlNodePtr msg_options, xmlNodePtr msg_data, 
		 const char *host_to, const char *sys_to,
		 const char *sys_from, const char *uuid_from,
		 const char *crm_msg_reference)
{
	gboolean was_sent = FALSE;
	xmlNodePtr request = NULL;
	FNIN();

	request = create_request(msg_options, msg_data,
				 host_to, sys_to,
				 sys_from, uuid_from,
				 crm_msg_reference);

//	xml_message_debug(request, "Final request...");

	was_sent = send_xmlipc_message(ipc_channel, request);

	free_xml(request);

	FNRET(was_sent);
}


/*
 * This method adds a copy of xml_response_data
 */
gboolean
send_ipc_reply(IPC_Channel *ipc_channel,
	       xmlNodePtr xml_request,
	       xmlNodePtr xml_response_data)
{
	gboolean was_sent = FALSE;
	xmlNodePtr reply;
	FNIN();

	reply = create_reply(xml_request, xml_response_data);

//	xml_message_debug(reply, "Final reply...");

	if (reply != NULL) {
		was_sent = send_xmlipc_message(ipc_channel, reply);
		free_xml(reply);
	}
	FNRET(was_sent);
}


gboolean
subsystem_input_dispatch(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	IPC_Message *msg = NULL;
	gboolean all_is_well = TRUE;
	xmlNodePtr root_xml_node = NULL;
	const char *sys_to;
	const char *type;

	
	FNIN();

	while(sender->ops->is_message_pending(sender)) {
		if (sender->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (sender->ops->recv(sender, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!all_is_well);
		}
		if (msg == NULL) {
			cl_log(LOG_ERR, "No message this time");
			continue;
		}

		lpc++;


		buffer = (char*)msg->msg_body;
		root_xml_node = string2xml(buffer);

		sys_to= xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
		type  = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
		if (root_xml_node == NULL) {
			cl_log(LOG_ERR, "Root node was NULL!!");

		} else if(sys_to == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_SYSTO);
			
		} else if(type == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_MSGTYPE);
			
		} else {
			gboolean (*process_function)
				(xmlNodePtr msg, IPC_Channel *sender) = NULL;
			process_function = user_data;
			
			if(process_function(root_xml_node, sender) == FALSE) {
				cl_log(LOG_WARNING,
				       "Received a message destined for %s"
				       " by mistake", sys_to);
			}
			
		}

		free_xml(root_xml_node);
		root_xml_node = NULL;
		
		msg->msg_done(msg);
		msg = NULL;
	}

	// clean up after a break
	if(msg != NULL)
		msg->msg_done(msg);

	if(root_xml_node != NULL)
		free_xml(root_xml_node);

	CRM_DEBUG("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "The server has left us: Shutting down...NOW");

		exit(1); // shutdown properly later
		
		FNRET(!all_is_well);
	}
	FNRET(all_is_well);
}
