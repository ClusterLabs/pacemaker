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
/* #include <apphb.h> */

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
#include <libxml/tree.h>

#define REPLACE

#include <crm/common/ipcutils.h>
#include <crm/common/crmutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <cibprimatives.h>
#include <crm/common/xmlutils.h>
#include <crm/common/msgutils.h>
#include <cibio.h>

/* gboolean waitCh_client_connect(IPC_Channel *newclient, gpointer user_data); */
int updateCibStatus(xmlNodePtr cib, const char *res_id, const char *instanceNum, const char *node_id, const char *status);
int addNodeToResource(xmlNodePtr cib, const char *res_id, const char *node_id, const char *weight);

cibConstraint *createInternalConstraint(const char *res_id_1, const char *instance, const char *node_id, const char *expires);
cibConstraint *createSimpleConstraint(const char *id, const char *type, const char *res_id_1, const char *res_id_2);
cibConstraint *createVariableConstraint(const char *id, const char *type, const char *res_id_1,
					const char *var_name, const char *var_value);
gboolean cib_clntCh_input_dispatch(IPC_Channel *client, gpointer user_data);

extern xmlNodePtr processCibRequest(xmlNodePtr command);

gboolean
waitCh_client_connect(IPC_Channel *newclient, gpointer user_data)
{
    // assign the client to be something, or put in a hashtable

    CRM_DEBUG("A client tried to connect");

    IPC_Message *client_msg = (IPC_Message *)user_data;
    cl_log(LOG_INFO, "recieved client join msg: %s", (char*)client_msg->msg_body);


    IPC_Message        *ack_msg;
    char	       str[256];
    snprintf(str, sizeof(str)-1, "I see you have joined us... %s", daemon_name);

    ack_msg = create_simple_message(str, newclient);
    send_ipc_message(newclient, ack_msg);
    
    G_main_add_IPC_Channel(G_PRIORITY_LOW,
			   newclient,
			   FALSE, 
			   cib_clntCh_input_dispatch,
			   newclient, 
			   clntCh_input_destroy);
    return TRUE;
}

gboolean
cib_clntCh_input_dispatch(IPC_Channel *client, 
	      gpointer        user_data)
{
    if(client->ch_status == IPC_DISCONNECT)
    {
	cl_log(LOG_INFO, "cib_clntCh_input_dispatch: received HUP");
// client_delete(client);
// do some equiv instead
	return FALSE;
    }
    else
    {
	IPC_Message *msg = NULL;
	if(client->ops->is_message_pending(client) == TRUE)
	{
	    if(client->ops->recv(client, &msg) != IPC_OK)
	    {
		perror("Receive failure:");
		return TRUE;
	    }
	    cl_log(LOG_DEBUG, "Got message [body=%s]", (char*)msg->msg_body);
	}
	if(msg == NULL)
	{
	    CRM_DEBUG("#### No message this time...");
	    return TRUE;
	}
	
	char *buffer = (char*)msg->msg_body;
	cl_log(LOG_DEBUG, "Got xml [text=%s]", buffer);
	xmlInitParser(); // docs say only do this once, but in their code they do it every time!
	xmlDocPtr doc = xmlParseMemory(buffer, strlen(buffer));
	CRM_DEBUG("Finished parsing buffer as XML");
	if(doc == NULL)
	{
	    cl_log(LOG_INFO, "XML Buffer was not valid...\n Buffer: (%s)", buffer);
	    return TRUE;
	}
	else
	{
	    CRM_DEBUG("About to interrogate xml");
	    xmlNodePtr root_xml_node = xmlDocGetRootElement(doc);
	    CRM_DEBUG("Got the root element");
	    
	    xmlNodePtr msg_xml_node = validate_crm_message(root_xml_node,
							   "cib",
							   XML_MSG_TAG_REQUEST);

	    if(msg_xml_node != NULL)
	    {
		CRM_DEBUG("The message is good, processing");
		xmlNodePtr answer = processCibRequest(msg_xml_node);
		CRM_DEBUG("Directing reply");
		const char *src_sys   = xmlGetProp(root_xml_node, XML_MSG_ATTR_SRCSUBSYS);
		xmlSetProp(answer, XML_MSG_ATTR_SUBSYS, src_sys);
		CRM_DEBUG("Sending reply");
		send_xmlipc_message(client, answer);
	    }
	    else if(root_xml_node != NULL)
		cl_log(LOG_INFO, "Received a message for (%s) by mistake", xmlGetProp(root_xml_node, XML_MSG_ATTR_SUBSYS));
	    else
		cl_log(LOG_INFO, "Root node was NULL!!");
	}
	msg->msg_done(msg);
    }	
    return TRUE;
}


int
addNodeToResource(xmlNodePtr cib, const char *res_id, const char *node_id, const char *weight)
{
    xmlNodePtr resource = findResource(cib, res_id);
    if(resource != NULL)
    {
	if(findHaNode(cib, node_id) == NULL)
	{
	    cl_log(LOG_CRIT, XML_CIB_TAG_NODE " (%s) does not exist, cannot be added to " XML_CIB_TAG_RESOURCE " (%s).", node_id, res_id);	
	    return -1;
	}

	CRM_DEBUG3("Attempting to add allowed " XML_CIB_TAG_NODE " (%s) to " XML_CIB_TAG_RESOURCE " (%s).", node_id, res_id);
	xmlNodePtr node_entry = findEntity(resource, "node", node_id, FALSE);
	if(node_entry == NULL)
	    node_entry = xmlNewChild(resource, NULL, "node", NULL);
	else
	    CRM_DEBUG3("Allowed " XML_CIB_TAG_NODE " (%s) already present for " XML_CIB_TAG_RESOURCE " (%s), updating.", node_id, res_id);
	
	xmlSetProp(node_entry, XML_ATTR_ID, node_id);
	xmlSetProp(node_entry, XML_CIB_ATTR_WEIGHT, weight);
	xmlSetProp(node_entry, XML_ATTR_TSTAMP, getNow());
    }
    else
    {
	cl_log(LOG_CRIT, XML_CIB_TAG_RESOURCE " (%s) does not exist, cannot add allowed " XML_CIB_TAG_NODE" (%s).", res_id, node_id);
	return -2;
    }
    return 0;
}


int
updateCibStatus(xmlNodePtr cib, const char *res_id, const char *instanceNum, const char *node_id, const char *status)
{
    CRM_DEBUG4("Update: " XML_CIB_TAG_STATE " (%s:%s)@(%s).", res_id, instanceNum, node_id);
    xmlNodePtr resource = findResource(cib, res_id);
    if(resource != NULL)
    {
	CRM_DEBUG4("Attempting to set allocated " XML_CIB_TAG_NODE " for " XML_CIB_TAG_RESOURCE " (%s:%s) to (%s).", res_id, instanceNum, node_id);
	xmlNodePtr node = findHaNode(cib, node_id);

	if(node == NULL)
	{
	    cl_log(LOG_CRIT, XML_CIB_TAG_NODE " (%s) does not exist, cannot assign " XML_CIB_TAG_RESOURCE " (%s:%s) to it in the status list.",
		   node_id,
		   res_id,
		   instanceNum);
	    return -1;
	}

	/* this could probable be optimized to update the status entry directly instead of creating a new one and doing
	 *   the update with that... but for now, lets make it work.
	 */
	cibStatus *new_status = newStatus(res_id, node_id, instanceNum);
	xmlSetProp(new_status, XML_CIB_ATTR_MAXINSTANCE, xmlGetProp(resource, XML_CIB_ATTR_MAXINSTANCE));
	xmlSetProp(new_status, XML_CIB_ATTR_RESSTATUS, status);
	// TODO: set the source of the info
	//new_status.source = "nodeX";

	updateStatus(cib, new_status);
    }
    else
    {
	cl_log(LOG_CRIT, XML_CIB_TAG_RESOURCE " (%s) does not exist, cannot add it to the " XML_CIB_TAG_STATUS " list.", res_id);
	return -2;
    }
    return 0;
}

cibConstraint *
createInternalConstraint(const char *res_id_1, const char *instance, const char *node_id, const char *expires)
{
    char *id = (char*)ha_malloc(256*(sizeof(char)));
    sprintf(id, "failed-%s-%s-%s", node_id, res_id_1, instance);
    
    cibConstraint *new_con = newConstraint(id);

    xmlSetProp(new_con, XML_CIB_ATTR_CONTYPE, CIB_VAL_CONTYPE_BLOCK);
    xmlSetProp(new_con, XML_CIB_ATTR_RESID1, res_id_1);
    xmlSetProp(new_con, XML_CIB_ATTR_CLEAR, expires);

    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_TAG_NVPAIR);			
    xmlSetProp(node_entry, XML_ATTR_ID, "blockHost");
//			xmlSetProp(node_entry, XML_CIB_ATTR_VARTYPE, subtype);
    xmlSetProp(node_entry, XML_CIB_ATTR_VARVALUE, node_id);
    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
    xmlAddChild(new_con, node_entry);
    
    return new_con;
}

cibConstraint *
createSimpleConstraint(const char *id, const char *type, const char *res_id_1, const char *res_id_2)
{
    cibConstraint *new_con = newConstraint(id);

    xmlSetProp(new_con, XML_CIB_ATTR_CONTYPE, type);
    xmlSetProp(new_con, XML_CIB_ATTR_RESID1, res_id_1);
    xmlSetProp(new_con, XML_CIB_ATTR_RESID2, res_id_2);

    return new_con;
}

cibConstraint *
createVariableConstraint(const char *id, const char *type, const char *res_id_1,
			 const char *var_name, const char *var_value)
{
    cibConstraint *new_con = newConstraint(id);

    xmlSetProp(new_con, XML_CIB_ATTR_CONTYPE, type);
    xmlSetProp(new_con, XML_CIB_ATTR_RESID1, res_id_1);

    xmlNodePtr node_entry = xmlNewNode(NULL, XML_CIB_TAG_NVPAIR);			
    xmlSetProp(node_entry, XML_ATTR_ID, var_name);
//			xmlSetProp(node_entry, XML_CIB_ATTR_VARTYPE, subtype);
    xmlSetProp(node_entry, XML_CIB_ATTR_VARVALUE, var_value);
    xmlSetProp(node_entry, XML_CIB_ATTR_ACTION, "add");
    xmlAddChild(new_con, node_entry);

    return new_con;
}


int
test(void)
{
    (void)_ha_msg_h_Id;
    
    xmlNodePtr cib = NULL;
    cib = readCibXmlFile(CIB_FILENAME);
    
    updateHaNode(cib,newHaNode("node1", CIB_VAL_NODETYPE_NODE));
    updateHaNode(cib,newHaNode("node2", CIB_VAL_NODETYPE_NODE));
    updateHaNode(cib,newHaNode("node3", CIB_VAL_NODETYPE_PING));
    updateHaNode(cib,newHaNode("node4", CIB_VAL_NODETYPE_NODE));

    updateResource(cib, newResource("res1", "apache", "my web site", "1"));
    updateResource(cib, newResource("res2", "drbd", "data for apache", "2"));
    updateResource(cib, newResource("res3", "dhcp", "dhcp", "1"));
     
    addNodeToResource(cib, "res2", "node1", "10");
    addNodeToResource(cib, "res2", "node2", "100");
    addNodeToResource(cib, "res2", "node3", "5");

    addNodeToResource(cib, "res1", "node2", "20");

    addNodeToResource(cib, "res3", "node2", "-1");
    addNodeToResource(cib, "res3", "node4", "10");
    
    updateConstraint(cib, createSimpleConstraint("con1", CIB_VAL_CONTYPE_AFTER, "res1", "res2"));
    updateConstraint(cib, createVariableConstraint("con2", CIB_VAL_CONTYPE_VAR, "res1",
						   "KERNEL_RELEASE", "2.4.20-gentoo-r9"));

    updateCibStatus(cib, "res2", "1", "node1", CIB_VAL_RESSTATUS_STARTING);
    updateCibStatus(cib, "res3", "1", "node4", CIB_VAL_RESSTATUS_RUNNING);
    activateCibXml(cib);
    
    updateCibStatus(cib, "res2", "1", "node1", CIB_VAL_RESSTATUS_FAILED);
    updateConstraint(cib, createInternalConstraint("res2", "1", "node1", CIB_VAL_CLEARON_STONITH));
    updateCibStatus(cib, "res2", "1", "node3", CIB_VAL_RESSTATUS_RUNNING);
    updateCibStatus(cib, "res2", "2", "node1", CIB_VAL_RESSTATUS_STARTING);
    updateCibStatus(cib, "res1", "1", "node1", CIB_VAL_RESSTATUS_STARTING);

    updateHaNode(cib,newHaNode("node2", CIB_VAL_NODETYPE_PING));
    updateResource(cib, newResource("res2", "drbd", "apache data", "2"));

    activateCibXml(cib);
    
    return 0;
}
