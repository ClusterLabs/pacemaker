/* $Id: cib.c,v 1.18 2004/03/19 10:43:42 andrew Exp $ */
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

		/* the docs say only do this once, but in their code
		 * they do it every time!
		 */
//		xmlInitParser();

		buffer = (char*)msg->msg_body;
		cl_log(LOG_DEBUG, "Message %d [text=%s]", lpc, buffer);
		doc = xmlParseMemory(ha_strdup(buffer), strlen(buffer));

		if(doc == NULL) {
			cl_log(LOG_INFO,
			       "XML Buffer was not valid...\n Buffer: (%s)",
			       buffer);
		}

		root_xml_node = xmlDocGetRootElement(doc);

		const char *sys_to= xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
		const char *type  = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
		if (root_xml_node == NULL) {
			cl_log(LOG_ERR, "Root node was NULL!!");

		} else if(sys_to == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_SYSTO);
			
		} else if(type == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_MSGTYPE);
			
		} else if(strcmp(type, XML_ATTR_REQUEST) != 0) {
			cl_log(LOG_INFO,
			       "Message was a response not a request."
			       "  Discarding");
		} else if (strcmp(sys_to, CRM_SYSTEM_CIB) == 0
			|| strcmp(sys_to, CRM_SYSTEM_DCIB) == 0) {

			answer = processCibRequest(root_xml_node);

			if (send_ipc_reply(sender,root_xml_node,answer)==FALSE)
				cl_log(LOG_WARNING,
				       "Cib answer could not be sent");
		} else {
			cl_log(LOG_WARNING,
			       "Received a message destined for %s by mistake",
			       sys_to);
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
		cl_log(LOG_ERR, "The server has left us: Shutting down...NOW");

		exit(1); // shutdown properly later
		
		FNRET(!all_is_well);
	}
	FNRET(all_is_well);
}

