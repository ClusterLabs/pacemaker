/* $Id: cib.c,v 1.12 2004/02/26 12:58:57 andrew Exp $ */
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
cib_msg_callback(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	xmlDocPtr doc = NULL;
	IPC_Message *msg = NULL;
	gboolean all_is_well = TRUE;
	xmlNodePtr answer = NULL, root_xml_node = NULL;
	
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
		CRM_DEBUG2("Got message [body=%s]", (char*)msg->msg_body);

		/* the docs say only do this once, but in their code
		 * they do it every time!
		 */
//		xmlInitParser();

		buffer = (char*)msg->msg_body;
		cl_log(LOG_DEBUG, "[text=%s]", buffer);
		doc = xmlParseMemory(ha_strdup(buffer), strlen(buffer));

		CRM_DEBUG("Finished parsing buffer as XML");
		if(doc == NULL) {
			cl_log(LOG_INFO,
			       "XML Buffer was not valid...\n Buffer: (%s)",
			       buffer);
		}

		CRM_DEBUG("About to interrogate xml");
		root_xml_node = xmlDocGetRootElement(doc);
		CRM_DEBUG("Got the root element");
		
		const char *sys_to = xmlGetProp(root_xml_node, XML_ATTR_SYSTO);

		if (root_xml_node == NULL) {
			cl_log(LOG_WARNING, "Root node was NULL!!");

		} else if (strcmp(sys_to, CRM_SYSTEM_CIB) != 0
			&& strcmp(sys_to, CRM_SYSTEM_DCIB) != 0) {
			
			cl_log(LOG_WARNING,
			       "Received a message destined for %s by mistake",
			       sys_to);

		} else {

			answer = processCibRequest(root_xml_node);
			
			if (send_ipc_reply(sender,
					   root_xml_node,
					   answer) == FALSE)
				
				cl_log(LOG_WARNING,
				       "Cib answer could not be sent");
		}
		
		if(answer != NULL)
			free_xml(answer);
		
		msg->msg_done(msg);
		msg = NULL;
	}

	// clean up after a break
	if(msg != NULL)
		msg->msg_done(msg);

	if(root_xml_node != NULL)
		free_xml(root_xml_node);

	
	CRM_DEBUG2("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_INFO, "the sender has left us: received HUP");
		FNRET(!all_is_well);
	}
	FNRET(all_is_well);
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
	FNRET(0);
}
