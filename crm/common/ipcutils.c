/* $Id: ipcutils.c,v 1.26 2004/05/18 14:26:45 andrew Exp $ */
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

#include <hb_api.h>
#include <ha_msg.h>

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

//#include <time.h> // for getNow()

#include <ipcutils.h>
/* 
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>
*/
#include <xmlutils.h>
#include <msgutils.h>
#include <crm/msg_xml.h>


#include <crm/dmalloc_wrapper.h>

FILE *msg_out_strm = NULL;

IPC_Message *create_simple_message(char *text, IPC_Channel *ch);


void
LinkStatus(const char * node, const char * lnk,
	   const char * status ,void * private)
{
	// put something here
}

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
	cl_free(xml_message);

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
send_xmlha_message(ll_cluster_t *hb_fd, xmlNodePtr root)
{
	int xml_len          = -1;
	int send_result      = -1;
	char *xml_text       = NULL;
	const char *host_to  = NULL;
	const char *sys_to   = NULL;
	struct ha_msg *msg   = NULL;
	gboolean all_is_good = TRUE;
	gboolean broadcast   = FALSE;
	int log_level        = LOG_DEBUG;

	xmlNodePtr opts = find_xml_node(root, XML_TAG_OPTIONS);
	const char *op  = xmlGetProp(opts, XML_ATTR_OP);

#ifdef MSG_LOG
	char *msg_text = NULL;
#endif

	FNIN();
    
	if (root == NULL) {
		cl_log(LOG_ERR, "Attempt to send NULL Message via HA failed.");
		all_is_good = FALSE;
	}

	host_to = xmlGetProp(root, XML_ATTR_HOSTTO);
	sys_to = xmlGetProp(root, XML_ATTR_SYSTO);
	
	if (sys_to != NULL && strcmp("dc", sys_to) == 0) {
		cl_log(LOG_INFO,
		       "Resetting the value of %s to null from %s",
		       XML_ATTR_HOSTTO, host_to);
//		xmlSetProp(root, XML_ATTR_HOSTTO, "");
	}
	
	if (all_is_good) {
		msg = ha_msg_new(4); 
		ha_msg_add(msg, F_TYPE, "CRM");
		ha_msg_add(msg, F_COMMENT, "A CRM xml message");
		xml_text = dump_xml(root);
		xml_len = strlen(xml_text);
		
		if (xml_text == NULL || xml_len <= 0) {
			cl_log(LOG_ERR,
			       "Failed sending an invalid XML Message via HA");
			all_is_good = FALSE;
			xml_message_debug(root, "Bad message was");
			
		} else {
			if(ha_msg_add(msg, "xml", xml_text) == HA_FAIL) {
				cl_log(LOG_ERR,
				       "Could not add xml to HA message");
				all_is_good = FALSE;
			}
		}
	}

	if (all_is_good) {
		if (sys_to == NULL || strlen(sys_to) == 0)
		{
			cl_log(LOG_ERR,
			       "You did not specify a destination sub-system"
			       " for this message.");
			all_is_good = FALSE;
		}
	}


	/* There are a number of messages may not need to be ordered.
	 * At a later point perhaps we should detect them and send them
	 *  as unordered messages.
	 */
	if (all_is_good) {
		if (host_to == NULL
		    || strlen(host_to) == 0
		    || strcmp("dc", sys_to) == 0) {
			broadcast = TRUE;
			send_result =
				hb_fd->llc_ops->send_ordered_clustermsg(hb_fd, msg);
		}
		else {
			send_result =
				hb_fd->llc_ops->send_ordered_nodemsg(hb_fd, msg, host_to);
		}
		
		if(send_result != HA_OK) all_is_good = FALSE;
		
	}
	
	if(all_is_good == FALSE) {
		log_level = LOG_ERR;
	}

	if(log_level == LOG_ERR
	   || (safe_str_neq(op, CRM_OPERATION_HBEAT))) {
		cl_log(log_level,
		       "Sending %s HA message (ref=%s, len=%d) to %s@%s %s.",
		       broadcast?"broadcast":"directed",
		       xmlGetProp(root, XML_ATTR_REFERENCE), xml_len,
		       sys_to, host_to==NULL?"<all>":host_to,
		       all_is_good?"succeeded":"failed");
	}
	
#ifdef MSG_LOG
	msg_text = dump_xml(root);
	if(msg_out_strm == NULL) {
		msg_out_strm = fopen("/tmp/outbound.log", "w");
	}
	fprintf(msg_out_strm, "[%d HA (%s:%d)]\t%s\n",
		all_is_good,
		xmlGetProp(root, XML_ATTR_REFERENCE),
		send_result,
		msg_text);
	
	fflush(msg_out_strm);
	cl_free(msg_text);
	if(msg != NULL) {
		ha_msg_del(msg);
	}
#endif
		
	FNRET(all_is_good);
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

	ack_msg = (IPC_Message *)cl_malloc(sizeof(IPC_Message));
    
	ack_msg->msg_private = NULL;
	ack_msg->msg_done    = NULL;
	ack_msg->msg_body    = text;
	ack_msg->msg_ch      = ch;

	ack_msg->msg_len = strlen(text)+1;
    
	FNRET(ack_msg);
}

gboolean
default_ipc_input_dispatch(IPC_Channel *client, gpointer user_data)
{
	xmlNodePtr root;
	xmlNodePtr options;
	IPC_Message *msg = NULL;
	const char *op;
	
	FNIN();
	msg = get_ipc_message(client);
	if (msg) {
		root = find_xml_in_ipcmessage(msg, TRUE);
		validate_crm_message(root, NULL, NULL, NULL);
		options = find_xml_node(root, XML_TAG_OPTIONS);
		op = xmlGetProp(options, XML_ATTR_OP);
		if(op != NULL && strcmp(op, "quit") == 0) {
			cl_log(LOG_WARNING,
			       "The CRMd has asked us to exit... complying");
			exit(0);
		}
		

	} else if (client->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "The server has left us: Shutting down...NOW");

		exit(1); /* Server disconnects should be fatal,
			  * but I will do it a little more gracefully :)
			  */
		FNRET(FALSE); /* This conection is hosed */
	}
	
	FNRET(TRUE); /* TOBEDONE */
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

xmlNodePtr
find_xml_in_ipcmessage(IPC_Message *msg, gboolean do_free)
{
	char *buffer = NULL;
	xmlDocPtr doc;
	xmlNodePtr root;

	FNIN();
	if (msg == NULL) {
		CRM_DEBUG("IPC Message was empty...");
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

int
init_server_ipc_comms(
	const char *child,
	gboolean (*channel_client_connect)(IPC_Channel *newclient,
					   gpointer user_data),
	void (*channel_input_destroy)(gpointer user_data))
{
	/* the clients wait channel is the other source of events.
	 * This source delivers the clients connection events.
	 * listen to this source at a relatively lower priority.
	 */
    
	char    commpath[SOCKET_LEN];
	IPC_WaitConnection *wait_ch;

	FNIN();
	sprintf(commpath, WORKING_DIR "/%s", child);

	wait_ch = wait_channel_init(commpath);

	if (wait_ch == NULL) FNRET(1);
	G_main_add_IPC_WaitConnection(G_PRIORITY_LOW,
				      wait_ch,
				      NULL,
				      FALSE,
				      channel_client_connect,
				      wait_ch, // user data passed to ??
				      channel_input_destroy);

	cl_log(LOG_DEBUG, "Listening on: %s", commpath);

	FNRET(0);
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

	commpath = (char*)cl_malloc(sizeof(char)*local_socket_len);
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


IPC_WaitConnection *
wait_channel_init(char daemonsocket[])
{
	IPC_WaitConnection *wait_ch;
	mode_t mask;
	char path[] = IPC_PATH_ATTR;
	GHashTable * attrs;

	FNIN();
	attrs = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(attrs, path, daemonsocket);
    
	mask = umask(0);
	wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
	if (wait_ch == NULL) {
		cl_perror("Can't create wait channel of type %s",
			  IPC_ANYTYPE);
		exit(1);
	}
	mask = umask(mask);
    
	g_hash_table_destroy(attrs);
    
	FNRET(wait_ch);
}

IPC_Message *
get_ipc_message(IPC_Channel *a_channel)
{
	IPC_Message *msg = NULL;

	FNIN();
	if(a_channel->ops->is_message_pending(a_channel) == TRUE) {
		if (a_channel->ch_status == IPC_DISCONNECT) {
			/* The pending message was IPC_DISCONNECT */
			cl_log(LOG_INFO, "get_ipc_message: received HUP");
			FNRET(msg);
		}
		if(a_channel->ops->recv(a_channel, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(msg);
		}
		cl_log(LOG_INFO, "Got message [body=%s]",
		       (char*)msg->msg_body);
	}
	FNRET(msg);
}

