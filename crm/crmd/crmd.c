/* $Id: crmd.c,v 1.14 2004/02/29 20:48:02 andrew Exp $ */
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
#include <clplumbing/GSource.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <ocf/oc_event.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmlutils.h>

#include <crmd_fsa.h>



gboolean dc_election_in_progress = FALSE;
gboolean i_am_dc = FALSE;
int      is_cluster_member = 0;

ll_cluster_t *hb_cluster = NULL;
GHashTable   *pending_remote_replies = NULL;
GHashTable   *ipc_clients = NULL;

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/msgutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlutils.h>
#include <glib.h>
#include <crmd.h>

#include <crm/dmalloc_wrapper.h>

void send_msg_via_ha(xmlNodePtr action, const char *dest_node);
void send_msg_via_ipc(xmlNodePtr action, const char *sys);

void process_message(xmlNodePtr root_xml_node,
		     gboolean originated_locally,
		     const char *src_node_name);

gboolean relay_message(xmlNodePtr action,
		       gboolean originated_locally,
		       const char *host_from);

gboolean crm_dc_process_message(xmlNodePtr whole_message,
				xmlNodePtr action,
				const char *host_from,
				const char *sys_from,
				const char *sys_to,
				const char *op,
				gboolean dc_mode);

gboolean add_pending_outgoing_reply(const char *originating_node_name,
				    const char *crm_msg_reference,
				    const char *sys_to,
				    const char *sys_from);

char *find_destination_host(xmlNodePtr xml_root_node,
			    const char *crm_msg_reference,
			    const char *sys_from,
			    int is_request);



char *
find_destination_host(xmlNodePtr xml_root_node,
		      const char *crm_msg_reference,
		      const char *sys_from,
		      int is_request)
{
	char *dest_node = NULL, *sys_to = NULL;
	FNIN();
    
	if (is_request == 0)
	{
		gpointer destination = NULL;
		CRM_DEBUG("Generating key to look up destination hash table with");
		gpointer action_ref =
			(gpointer)generate_hash_key(
				crm_msg_reference,
				sys_from);
		CRM_DEBUG2("Created key (%s)", (char*)action_ref);
		destination = g_hash_table_lookup (pending_remote_replies,
						   action_ref);
		CRM_DEBUG2("Looked up hash table and found value (%s)",
			   (char*)destination);
	
		if (destination == NULL)
		{
			cl_log(LOG_INFO,
			       "Dont know anything about a message with "
			       "crm_msg_reference number (%s) from sub-system (%s)..."
			       " discarding response.",
			       crm_msg_reference, sys_from);
			FNRET(NULL);// should be discarded instead?
		}
		CRM_DEBUG("Decoding destination");
		if (decode_hash_value(destination, &dest_node, &sys_to))
		{
			CRM_DEBUG3("Decoded destination (%s, %s)",
				   dest_node,
				   sys_to);
			set_xml_property_copy(xml_root_node,
					      XML_ATTR_SYSTO,
					      sys_to);
			CRM_DEBUG3("setting (%s=%s) on HA message",
				   XML_ATTR_SYSTO, sys_to);
		}
		else
		{
			cl_log(LOG_INFO,
			       "Could not decode hash value (%s)... "
			       "Discarding message.",
			       (char*)destination);
		}
	}
	FNRET(dest_node);
	//return dest_node;
}
