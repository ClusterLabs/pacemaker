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
#include <crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

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

#include <time.h> // for getNow()

#include <ipcutils.h>
#include <xmlutils.h>
#include <msgutils.h>
#include <xmltags.h>

#define APPNAME_LEN 256

// this will come from whoever links with us, so any number of places.
extern const char* daemon_name;// = "crmd";


IPC_Message *get_ipc_message(IPC_Channel *client);


void
LinkStatus(const char * node, const char * lnk, const char * status ,void * private)
{
    // put something here
}

void 
send_xmlipc_message(IPC_Channel *ipc_client, xmlNodePtr msg)
{
    CRM_DEBUG("Attempting to send XML IPC Message.");
    char *xml_message = dump_xml(msg);
    CRM_DEBUG("Dumped XML for IPC Message.");
    IPC_Message *cib_dump = create_simple_message(xml_message, ipc_client);
    CRM_DEBUG("Created IPC Message.");
    send_ipc_message(ipc_client, cib_dump);
    CRM_DEBUG("Sent IPC Message.");
}


void send_xmlha_message(ll_cluster_t *hb_fd, xmlNodePtr root, const char *node, const char *ha_client)
{
    CRM_DEBUG("Attempting to send XML HA Message.");

    if(root == NULL)
    {
	cl_log(LOG_INFO, "Attempt to send a NULL Message via HA failed.");
	return;
    }
    
    
    struct ha_msg *msg = ha_msg_new(4); 
    ha_msg_add(msg, F_TYPE, "CRM");
/*     ha_msg_add(msg, F_ORIG, "here"); */
/*     ha_msg_add(msg, F_TO, "there"); */

    if(ha_client != NULL)
	ha_msg_add(msg, F_TOID, ha_client);
    else if(strcmp("admin", xmlGetProp(root, XML_MSG_ATTR_SUBSYS)) == 0)
	ha_msg_add(msg, F_TOID, "crmadmin");
    // else???
	
    ha_msg_add(msg, F_COMMENT, "A CRM xml message");
    CRM_DEBUG("Dumping XML into HA Message.");
    char *xml_text = dump_xml(root);

    CRM_DEBUG("delete me - 1.");

    if(xml_text == NULL)
    {
	cl_log(LOG_INFO, "Attempt to send an invalid XML Message via HA failed.");
	return;
    }
    
    ha_msg_add(msg, "xml", xml_text);

    CRM_DEBUG("Sending HA Message.");
    
    if(node == NULL)
	hb_fd->llc_ops->sendclustermsg(hb_fd, msg);
    else
	hb_fd->llc_ops->sendnodemsg(hb_fd, msg, node);
//    ha_msg_del(msg);
    CRM_DEBUG("Sent HA Message.");
}
		    

void 
send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg)
{
    CRM_DEBUG("Processing IPC message");
    (void)_ha_msg_h_Id; /* Make the compiler happy */
    if (msg->msg_len <= 0)
    {
	cl_log(LOG_WARNING, "cant send 0 sized message");
	return;
    }
    else if(msg->msg_len > MAXDATASIZE)
    {
	cl_log(LOG_WARNING, "cant send msg... too big");
	return;
    }
    
    // comment out soon
    CRM_DEBUG2("Sending message: %s", (char*)msg->msg_body);
    CRM_DEBUG("Message ok to send");

    if(ipc_client == NULL)
    {
	cl_log(LOG_ERR, "IPC Client was NULL, cant send message");
	return;
    }
    
    
    while(ipc_client->ops->send(ipc_client, msg) == IPC_FAIL){
	cl_log(LOG_WARNING, "ipc channel blocked");
	cl_shortsleep();
    }
    CRM_DEBUG("Message sent");
    return;
}

IPC_Message *
create_simple_message(char *text, IPC_Channel *ch)
{
    if(text == NULL) return NULL;

//    char	       str[256];
    IPC_Message        *ack_msg = NULL;

    ack_msg = (IPC_Message *)ha_malloc(sizeof(IPC_Message));
    
    ack_msg->msg_private = NULL;
    ack_msg->msg_done    = NULL;
    ack_msg->msg_body    = text;
    ack_msg->msg_ch      = ch;

    ack_msg->msg_len = strlen(text)+1;
    
    return ack_msg;
}

gboolean
default_ipc_input_dispatch(IPC_Channel *client, 
	      gpointer        user_data)
{
    CRM_DEBUG("default_ipc_input_dispatch: default processing of IPC messages");
    if(client->ch_status == IPC_DISCONNECT)
    {
	cl_log(LOG_INFO, "default_ipc_input_dispatch: received HUP");
// client_delete(client);
// do some equiv instead
	return FALSE;
    }
    else
    {
	xmlNodePtr root = validate_and_decode_ipcmessage(client);
	validate_crm_message(root, NULL, NULL);
/* 	    IPC_Message *msg = get_ipc_message(client); */
	
/* 	    char *buffer = (char*)msg->msg_body; */
/* 	    xmlDocPtr doc = xmlParseMemory(buffer, strlen(buffer)); */
/* 	    if(doc == NULL) */
/* 	    { */
/* 		cl_log(LOG_INFO, "Message did not contain an XML buffer..."); */
/* 		return TRUE; */
/* 	    } */

/* 	    cl_log(LOG_DEBUG, "Recieved XML message with (version=%s)", xmlGetProp(doc->children, XML_ATTR_VERSION)); */
/* 	    cl_log(LOG_DEBUG, "Recieved XML message with (subsys=%s)" , xmlGetProp(doc->children, XML_MSG_ATTR_SUBSYS)); */
/* 	    cl_log(LOG_DEBUG, "Recieved XML message with (type=%s)"   , xmlGetProp(doc->children, XML_MSG_ATTR_MSGTYPE)); */
/* 	    cl_log(LOG_DEBUG, "Recieved XML message with (ref=%s)"    , xmlGetProp(doc->children, XML_MSG_ATTR_REFERENCE)); */
	    
    }
    
    return TRUE; /* TOBEDONE */
}

xmlNodePtr
validate_and_decode_hamessage(const struct ha_msg* msg)
{
    
    if(msg == NULL)
    {
	cl_log(LOG_INFO, "**** ha_crm_msg_callback called on a NULL message");
	return NULL;
    }

    if(1)
    {
	cl_log(LOG_DEBUG, "[F_TYPE=%s]", ha_msg_value(msg, F_TYPE));
	cl_log(LOG_DEBUG, "[F_ORIG=%s]", ha_msg_value(msg, F_ORIG));
	cl_log(LOG_DEBUG, "[F_TO=%s]", ha_msg_value(msg, F_TO));
	cl_log(LOG_DEBUG, "[F_COMMENT=%s]", ha_msg_value(msg, F_COMMENT));
	cl_log(LOG_DEBUG, "[F_XML=%s]", ha_msg_value(msg, "xml"));
//    cl_log(LOG_DEBUG, "[F_=%s]", ha_msg_value(ha_msg, F_));
    }
    if(strcmp("CRM", ha_msg_value(msg, F_TYPE)) != 0)
    {
	cl_log(LOG_INFO, "Received a (%s) message by mistake.", ha_msg_value(msg, F_TYPE));
	return NULL;
    }
    const char *xml = ha_msg_value(msg, "xml");
    if(xml == NULL)
    {
	cl_log(LOG_INFO, "No XML attached to this message.");
	return NULL;
    }
    
    xmlDocPtr doc = xmlParseMemory(xml, strlen(xml));
    if(doc == NULL)
    {
	cl_log(LOG_INFO, "XML Buffer was not valid.");
	return NULL;
    }


    xmlNodePtr root = xmlDocGetRootElement(doc);
    if(root == NULL)
    {
	cl_log(LOG_INFO, "Root node was NULL.");
	return NULL;
    }
    return root;
}

xmlNodePtr
validate_and_decode_ipcmessage(IPC_Channel *client)
{
    IPC_Message *msg = NULL;
    if(client->ops->is_message_pending(client) == TRUE)
    {
	if(client->ops->recv(client, &msg) != IPC_OK)
	{
	    perror("Receive failure:");
	    return FALSE;
	}
	cl_log(LOG_INFO, "Got message [body=%s]", (char*)msg->msg_body);
    }

    char *buffer = (char*)msg->msg_body;
    xmlDocPtr doc = xmlParseMemory(buffer, strlen(buffer));
    msg->msg_done(msg);

    if(doc == NULL)
    {
	cl_log(LOG_INFO, "IPC Message did not contain an XML buffer...");
	return NULL;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if(root == NULL)
    {
	cl_log(LOG_INFO, "Root node was NULL.");
	return NULL;
    }
    return root;
}


IPC_Message *
get_ipc_message(IPC_Channel *client)
{
    IPC_Message *msg = NULL;
    if(client->ops->is_message_pending(client) == TRUE)
    {
//		cl_log(LOG_INFO, "dispatch:received a message");
	
	if(client->ops->recv(client, &msg) != IPC_OK)
	{
	    perror("Receive failure:");
	    return FALSE;
	}
	cl_log(LOG_INFO, "Got message [body=%s]", (char*)msg->msg_body);
	//msg->msg_done(msg);
    }
    return msg;
}


void
default_ipc_input_destroy(gpointer user_data)
{
	cl_log(LOG_INFO, "default_ipc_input_destroy:received HUP");
	return;
}

void
init_server_ipc_comms(const char *child,
		      gboolean (*channel_client_connect)(IPC_Channel *newclient, gpointer user_data),
		      void (*channel_input_destroy)(gpointer user_data))
{

    CRM_DEBUG("Init IPC Comms");

    /* the clients wait channel is the other source of events.
     * This source delivers the clients connection events.
     * listen to this source at a relatively lower priority.
     */
    
    char    commpath[FIFO_LEN];
    sprintf(commpath, WORKING_DIR "/%s.fifo", child);

    IPC_WaitConnection *wait_ch;

    wait_ch = wait_channel_init(commpath);

    G_main_add_IPC_WaitConnection(G_PRIORITY_LOW,
				  wait_ch,
				  NULL,
				  FALSE,
				  channel_client_connect,
				  wait_ch,
				  channel_input_destroy);

    cl_log(LOG_DEBUG, "Listening on: %s", commpath);

    
/*     if (!usenormalpoll) { */
 	g_main_set_poll_func(cl_glibpoll);
 	ipc_set_pollfunc(cl_poll); 
/*     } */
    
}

struct IPC_CHANNEL *
init_client_ipc_comms(const char *child,
		      gboolean (*dispatch)(IPC_Channel* source_data
					   ,gpointer    user_data))
{
    struct IPC_CHANNEL *ch;
    GHashTable * attrs;
    static char 	path[] = IPC_PATH_ATTR;
    char    commpath[FIFO_LEN];
    sprintf(commpath, WORKING_DIR "/%s.fifo", child);

    cl_log(LOG_DEBUG, "Attempting to talk on: %s", commpath);

    attrs = g_hash_table_new(g_str_hash,g_str_equal);
    g_hash_table_insert(attrs, path, commpath);
//    ch = ipc_channel_constructor(IPC_DOMAIN_SOCKET, attrs);
    ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
    g_hash_table_destroy(attrs);

    if (ch == NULL)
    {
	cl_log(LOG_CRIT, "Could not access channel on: %s", commpath);
    }
    else if(ch->ops->initiate_connection(ch) != IPC_OK)
    {
	cl_log(LOG_CRIT, "Could not init comms on: %s", commpath);
	return NULL;
    }

    G_main_add_IPC_Channel(G_PRIORITY_LOW,
			   ch,
			   FALSE, 
			   dispatch,
			   ch, 
			   default_ipc_input_destroy);
    
    // do some error reporting
    return ch;
}


IPC_WaitConnection *
wait_channel_init(char daemonfifo[])
{
    IPC_WaitConnection *wait_ch;
    mode_t mask;
    char path[] = IPC_PATH_ATTR;
//    char domainsocket[] = IPC_DOMAIN_SOCKET;
    
    GHashTable * attrs = g_hash_table_new(g_str_hash,g_str_equal);
    g_hash_table_insert(attrs, path, daemonfifo);
    
    mask = umask(0);
    wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
    if (wait_ch == NULL){
	cl_perror("Can't create wait channel of type %s", IPC_ANYTYPE);
	exit(1);
    }
    mask = umask(mask);
    
    g_hash_table_destroy(attrs);
    
    return wait_ch;
}



