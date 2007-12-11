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

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>

#include <clplumbing/cl_log.h>
#include <ha_msg.h>

#include <time.h> 

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>
#include "stack.h"


HA_Message *create_common_message(
	HA_Message *original_request, crm_data_t *xml_response_data);

gboolean crm_cluster_connect(
    char **our_uname, char **our_uuid,
    void *dispatch, void *destroy, ll_cluster_t **hb_conn) {
    if(hb_conn != NULL) {
	*hb_conn = NULL;
    }
    
#if SUPPORT_AIS
    if(is_openais_cluster()) {
	crm_peer_init();
	return init_ais_connection(dispatch, destroy, our_uuid, our_uname);
    }
#endif
    
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {	
	CRM_ASSERT(hb_conn != NULL);

	if(*hb_conn == NULL) {
	    *hb_conn = ll_cluster_new("heartbeat");
	}
	heartbeat_cluster = *hb_conn;

	/* make sure we are disconnected first */
	heartbeat_cluster->llc_ops->signoff(heartbeat_cluster, FALSE);

	return register_heartbeat_conn(
	    heartbeat_cluster, our_uuid, our_uname, dispatch, destroy);
    }
#endif
    return FALSE;
}

gboolean send_cluster_message(
    const char *node, enum crm_ais_msg_types service, HA_Message *data, gboolean ordered) {

#if SUPPORT_AIS
    if(is_openais_cluster()) {
	return send_ais_message(data, FALSE, node, service);
    }
#endif
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
	return send_ha_message(heartbeat_cluster, data, node, ordered);
    }
#endif
    return FALSE;
}

crm_data_t*
createPingAnswerFragment(const char *from, const char *status)
{
	crm_data_t *ping = NULL;
	
	
	ping = create_xml_node(NULL, XML_CRM_TAG_PING);
	
	crm_xml_add(ping, XML_PING_ATTR_STATUS, status);
	crm_xml_add(ping, XML_PING_ATTR_SYSFROM, from);

	return ping;
}
