/* $Id: ipc.c,v 1.6 2004/09/04 10:41:55 andrew Exp $ */
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
#include <sys/param.h>

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
	

	xml_message = dump_xml_formatted(msg);
	
	cib_dump =
		create_simple_message(xml_message, ipc_client);
	res = send_ipc_message(ipc_client, cib_dump);
	crm_free(xml_message);

	if(res == FALSE) {
		log_level = LOG_ERR;
	}
	
	do_crm_log(log_level, __FUNCTION__,
	       "Sending IPC message (ref=%s) to %s@%s %s.",
	       xmlGetProp(msg, XML_ATTR_REFERENCE), 
	       xmlGetProp(msg, XML_ATTR_SYSTO),
	       xmlGetProp(msg, XML_ATTR_HOSTTO),
	       res?"succeeded":"failed");
	
	return res;
}


gboolean 
send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg)
{
	int lpc = 0;
	gboolean all_is_good = TRUE;
	

	if (msg == NULL) {
		crm_err("cant send NULL message");
		all_is_good = FALSE;
	}
	else if (msg->msg_len <= 0) {
		crm_err("cant send 0 sized message");
		all_is_good = FALSE;
	}
	else if (msg->msg_len > MAXDATASIZE) {
		crm_err("cant send msg... too big");
		all_is_good = FALSE;
	}
    
	crm_trace("Sending message: %s", (char*)msg->msg_body); 
	crm_verbose("Message is%s valid to send", all_is_good?"":" not");

	if (ipc_client == NULL) {
		all_is_good = FALSE;
	}
	crm_verbose("IPC Client is%s set.", all_is_good?"":" not");
	if (all_is_good) {		
		while(lpc++ < MAX_IPC_FAIL
		      && ipc_client->ops->send(ipc_client, msg) == IPC_FAIL)
		{
			crm_err("ipc channel blocked");
			cl_shortsleep();
		}
	}
	
	if (lpc == MAX_IPC_FAIL) {
		crm_err("Could not send IPC, message.  Channel is dead.");
		all_is_good = FALSE;
	}

	return all_is_good;
}

IPC_Message *
create_simple_message(char *text, IPC_Channel *ch)
{
	/*    char	       str[256]; */
	IPC_Message        *ack_msg = NULL;

	
	if (text == NULL) return NULL;

	ack_msg = (IPC_Message *)crm_malloc(sizeof(IPC_Message));
    
	ack_msg->msg_private = NULL;
	ack_msg->msg_done    = NULL;
	ack_msg->msg_body    = text;
	ack_msg->msg_ch      = ch;

	ack_msg->msg_len = strlen(text)+1;
    
	return ack_msg;
}


xmlNodePtr
find_xml_in_ipcmessage(IPC_Message *msg, gboolean do_free)
{
	char *buffer = NULL;
	xmlDocPtr doc;
	xmlNodePtr root;

	
	if (msg == NULL) {
		crm_trace("IPC Message was empty...");
		return NULL;
	}

	buffer = (char*)msg->msg_body;
	doc = xmlParseMemory(buffer, strlen(buffer));

	if (do_free) msg->msg_done(msg);

	if (doc == NULL) {
		crm_info("IPC Message did not contain an XML buffer...");
		return NULL;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
		crm_info("Root node was NULL.");
		return NULL;
	}
	return root;
}



void
default_ipc_input_destroy(gpointer user_data)
{
	
	return;
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
	int local_socket_len = 2; /* 2 = '/' + '\0' */

	
	local_socket_len += strlen(child);
	local_socket_len += strlen(WORKING_DIR);

	commpath = (char*)crm_malloc(sizeof(char)*local_socket_len);
	sprintf(commpath, WORKING_DIR "/%s", child);
	commpath[local_socket_len - 1] = '\0';
    
	crm_debug("Attempting to talk on: %s", commpath);

	attrs = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(attrs, path, commpath);

	ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
	g_hash_table_destroy(attrs);

	if (ch == NULL) {
		crm_crit("Could not access channel on: %s", commpath);
		
	} else if (ch->ops->initiate_connection(ch) != IPC_OK) {
		crm_crit("Could not init comms on: %s", commpath);
		return NULL;
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

	crm_debug("Processing of %s complete", commpath);

	return ch;
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
	

	request = create_request(msg_options, msg_data,
				 host_to, sys_to,
				 sys_from, uuid_from,
				 crm_msg_reference);

	was_sent = send_xmlipc_message(ipc_channel, request);

	free_xml(request);

	return was_sent;
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
	

	reply = create_reply(xml_request, xml_response_data);

	if (reply != NULL) {
		was_sent = send_xmlipc_message(ipc_channel, reply);
		free_xml(reply);
	}
	return was_sent;
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

	
	

	while(sender->ops->is_message_pending(sender)) {
		if (sender->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (sender->ops->recv(sender, &msg) != IPC_OK) {
			perror("Receive failure:");
			return !all_is_well;
		}
		if (msg == NULL) {
			crm_err("No message this time");
			continue;
		}

		lpc++;


		buffer = (char*)msg->msg_body;
		root_xml_node = string2xml(buffer);

		sys_to= xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
		type  = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
		if (root_xml_node == NULL) {
			crm_err("Root node was NULL!!");

		} else if(sys_to == NULL) {
			crm_err("Value of %s was NULL!!",
			       XML_ATTR_SYSTO);
			
		} else if(type == NULL) {
			crm_err("Value of %s was NULL!!",
			       XML_ATTR_MSGTYPE);
			
		} else {
			gboolean (*process_function)
				(xmlNodePtr msg, IPC_Channel *sender) = NULL;
			process_function = user_data;
			
			if(process_function(root_xml_node, sender) == FALSE) {
				crm_warn("Received a message destined for %s"
					 " by mistake", sys_to);
			}
			
		}

		free_xml(root_xml_node);
		root_xml_node = NULL;
		
		msg->msg_done(msg);
		msg = NULL;
	}

	/* clean up after a break */
	if(msg != NULL)
		msg->msg_done(msg);

	if(root_xml_node != NULL)
		free_xml(root_xml_node);

	crm_verbose("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		crm_err("The server has left us: Shutting down...NOW");

		exit(1); /* shutdown properly later */
		
		return !all_is_well;
	}
	return all_is_well;
}
