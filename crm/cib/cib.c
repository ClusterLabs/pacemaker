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
#include <cib.h>
#include <cibmessages.h>

#include <crm/dmalloc_wrapper.h>

int updateCibStatus(xmlNodePtr cib,
		    const char *res_id,
		    const char *instanceNum,
		    const char *node_id,
		    const char *status);

int add_xmlnode_to_cibToResource(xmlNodePtr cib,
				 const char *res_id,
				 const char *node_id,
				 const char *weight);

cibConstraint *createInternalConstraint(const char *res_id_1,
					const char *instance,
					const char *node_id,
					const char *expires);

cibConstraint *createSimpleConstraint(const char *id,
				      const char *type,
				      const char *res_id_1,
				      const char *res_id_2);

cibConstraint *createVariableConstraint(const char *id,
					const char *type,
					const char *res_id_1,
					const char *var_name,
					const char *var_value);

// from cibmessages.c
extern xmlNodePtr processCibRequest(xmlNodePtr command);

gboolean
cib_client_connect(IPC_Channel *newclient, gpointer user_data)
{
	CRM_DEBUG("A client tried to connect");

	IPC_Message *client_msg = (IPC_Message *)user_data;
	cl_log(LOG_INFO,
	       "recieved client join msg: %s",
	       (char*)client_msg->msg_body);

	if (newclient != NULL)
		G_main_add_IPC_Channel(G_PRIORITY_LOW,
				       newclient,
				       FALSE, 
				       cib_input_dispatch,
				       newclient, 
				       default_ipc_input_destroy);
	FNRET(TRUE);
}

gboolean
cib_input_dispatch(IPC_Channel *client, gpointer user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	xmlDocPtr doc = NULL;
	IPC_Message *msg = NULL;
	gboolean hack_return_good = TRUE;
	xmlNodePtr msg_xml_node = NULL, answer = NULL, root_xml_node = NULL;
	
	FNIN();
		
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
			cl_log(LOG_ERR, "No message this time");
			continue;
		}

		lpc++;
		CRM_DEBUG2("Got message [body=%s]", (char*)msg->msg_body);

		/* the docs say only do this once, but in their code
		 * they do it every time!
		 */
		xmlInitParser();

		buffer = (char*)msg->msg_body;
		cl_log(LOG_DEBUG, "Got xml [text=%s]", buffer);
		doc = xmlParseMemory(buffer, strlen(buffer));
		msg->msg_done(msg);

		CRM_DEBUG("Finished parsing buffer as XML");
		if (doc != NULL) {
			CRM_DEBUG("About to interrogate xml");
			root_xml_node = xmlDocGetRootElement(doc);
			CRM_DEBUG("Got the root element");
			
			msg_xml_node =
				validate_crm_message(root_xml_node,
						     CRM_SYSTEM_CIB,
						     NULL,
						     XML_MSG_TAG_REQUEST);
	
			if (msg_xml_node != NULL) {
				answer = processCibRequest(msg_xml_node);
				if (send_ipc_reply(
					    client,
					    root_xml_node,
					    answer) == FALSE)
					cl_log(LOG_WARNING,
					       "Cib answer could not be sent");
#if BUG
				/* currently we get a segfault here */
				if(answer != NULL)
					free_xml(answer);
#endif			
			} else if (root_xml_node != NULL)
				cl_log(LOG_INFO,
				       "Received a message destined for (%s) "
				       "by mistake",
				       xmlGetProp(root_xml_node,
						  XML_MSG_ATTR_SYSTO));
			else
				cl_log(LOG_INFO, "Root node was NULL!!");

			free_xml(root_xml_node);
		} else {
			cl_log(LOG_INFO,
			       "XML Buffer was not valid...\n Buffer: (%s)",
			       buffer);
		}
	}
	
	CRM_DEBUG2("Processed %d messages", lpc);
	if (client->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_INFO, "the client has left us: received HUP");
		FNRET(!hack_return_good);
	}
	FNRET(hack_return_good);
}


int
add_xmlnode_to_cibToResource(xmlNodePtr cib,
			     const char *res_id,
			     const char *node_id,
			     const char *weight)
{
	xmlNodePtr resource = NULL, node_entry = NULL;
	resource = findResource(cib, res_id);
	if (resource != NULL)
	{
		if (findHaNode(cib, node_id) == NULL)
		{
			cl_log(LOG_CRIT,
			       "Node (%s) does not exist, cannot be added "
			       "to Resource (%s).", node_id, res_id);	
			FNRET(-1);
		}

		CRM_DEBUG3("Attempting to add allowed " XML_CIB_TAG_NODE
			   " (%s) to " XML_CIB_TAG_RESOURCE " (%s).",
			   node_id, res_id);
	
		node_entry = find_entity(resource, "node", node_id, FALSE);
		if (node_entry == NULL)
			node_entry = create_xml_node(resource, "node");
		else
			CRM_DEBUG3("Allowed node (%s) already present for "
				   XML_CIB_TAG_RESOURCE " (%s), updating.",
				   node_id, res_id);
	
		set_xml_property_copy(node_entry,
				      XML_ATTR_ID,
				      node_id);
		set_xml_property_copy(node_entry,
				      XML_CIB_ATTR_WEIGHT,
				      weight);
		set_node_tstamp(node_entry);
	}
	else
	{
		cl_log(LOG_CRIT,
		       "%s (%s) does not exist, cannot add allowed %s (%s)",
		       XML_CIB_TAG_RESOURCE,
		       res_id,
		       XML_CIB_TAG_NODE,
		       node_id);
		FNRET(-2);
	}
	FNRET(0);
}

int
updateCibStatus(xmlNodePtr cib,
		const char *res_id,
		const char *instanceNum,
		const char *node_id,
		const char *status)
{
	CRM_DEBUG4("Update: " XML_CIB_TAG_STATE " (%s:%s)@(%s).",
		   res_id, instanceNum, node_id);
	xmlNodePtr resource = findResource(cib, res_id);
	if (resource != NULL)
	{
		CRM_DEBUG4("Attempting to set allocated " XML_CIB_TAG_NODE
			   " for " XML_CIB_TAG_RESOURCE " (%s:%s) to (%s).",
			   res_id, instanceNum, node_id);
		xmlNodePtr node = findHaNode(cib, node_id);

		if (node == NULL)
		{
			cl_log(LOG_CRIT,
			       "Node (%s) does not exist, cannot assign "
			       "Resource (%s:%s) to it in the status list.",
			       node_id, res_id, instanceNum);
			FNRET(-1);
		}

		/* this could probable be optimized to update the status
		 *   entry directly instead of creating a new one and doing
		 *   the update with that... but for now, lets make it work.
		 */
		cibStatus *new_status =
			newStatus(res_id, node_id, instanceNum);
		set_xml_property_copy(new_status,
				      XML_CIB_ATTR_MAXINSTANCE,
				      xmlGetProp(resource,
						 XML_CIB_ATTR_MAXINSTANCE));
		set_xml_property_copy(new_status,
				      XML_CIB_ATTR_RESSTATUS,
				      status);
		// TODO: set the source of the info
		//new_status.source = "nodeX";

		updateStatus(cib, new_status);
	}
	else
	{
		cl_log(LOG_CRIT,
		       XML_CIB_TAG_RESOURCE
		       " (%s) does not exist, cannot add it to the status list.",
		       res_id);
		FNRET(-2);
	}
	FNRET(0);
}

cibConstraint *
createInternalConstraint(const char *res_id_1,
			 const char *instance,
			 const char *node_id,
			 const char *expires)
{
	char *id = (char*)ha_malloc(256*(sizeof(char)));
	sprintf(id, "failed-%s-%s-%s", node_id, res_id_1, instance);
    
	cibConstraint *new_con = newConstraint(id);

	set_xml_property_copy(new_con,
			      XML_CIB_ATTR_CONTYPE,
			      CIB_VAL_CONTYPE_BLOCK);
	set_xml_property_copy(new_con,
			      XML_CIB_ATTR_RESID1,
			      res_id_1);
	set_xml_property_copy(new_con,
			      XML_CIB_ATTR_CLEAR,
			      expires);

	xmlNodePtr node_entry = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
	set_xml_property_copy(node_entry, XML_ATTR_ID, "blockHost");
	set_xml_property_copy(node_entry, XML_CIB_ATTR_VARVALUE, node_id);
	set_xml_property_copy(node_entry, XML_CIB_ATTR_ACTION, "add");
	xmlAddChild(new_con, node_entry);
    
	FNRET(new_con);
}

cibConstraint *
createSimpleConstraint(const char *id,
		       const char *type,
		       const char *res_id_1,
		       const char *res_id_2)
{
	cibConstraint *new_con = newConstraint(id);

	set_xml_property_copy(new_con, XML_CIB_ATTR_CONTYPE, type);
	set_xml_property_copy(new_con, XML_CIB_ATTR_RESID1, res_id_1);
	set_xml_property_copy(new_con, XML_CIB_ATTR_RESID2, res_id_2);

	FNRET(new_con);
}

cibConstraint *
createVariableConstraint(const char *id,
			 const char *type,
			 const char *res_id_1,
			 const char *var_name,
			 const char *var_value)
{
	cibConstraint *new_con = newConstraint(id);

	set_xml_property_copy(new_con, XML_CIB_ATTR_CONTYPE, type);
	set_xml_property_copy(new_con, XML_CIB_ATTR_RESID1, res_id_1);

	xmlNodePtr node_entry = create_xml_node(NULL, XML_CIB_TAG_NVPAIR);
	set_xml_property_copy(node_entry, XML_ATTR_ID, var_name);
	set_xml_property_copy(node_entry, XML_CIB_ATTR_VARVALUE, var_value);
	set_xml_property_copy(node_entry, XML_CIB_ATTR_ACTION, "add");
	xmlAddChild(new_con, node_entry);

	FNRET(new_con);
}


int
test(void)
{
	(void)_ha_msg_h_Id;
	FNRET(0);
}
