/* $Id: msgutils.h,v 1.10 2004/03/24 09:59:05 andrew Exp $ */
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
#ifndef MSG_UTILS__H
#define MSG_UTILS__H

#include <libxml/tree.h>
#include <clplumbing/ipc.h>
#include <hb_api.h>

extern const char *generateReference(const char *custom1, const char *custom2);

extern xmlNodePtr validate_crm_message(xmlNodePtr root,
				       const char *sys,
				       const char *uuid,
				       const char *msg_type);

extern xmlNodePtr createPingAnswerFragment(const char *from,
					   const char *status);

extern xmlNodePtr createPingRequest(const char *crm_msg_reference,
				    const char *to);

gboolean decodeNVpair(const char *srcstring,
		      char separator,
		      char **name,
		      char **value);

extern void send_hello_message(IPC_Channel *ipc_client,
			       const char *uuid,
			       const char *client_name,
			       const char *major_version,
			       const char *minor_version);
extern gboolean process_hello_message(IPC_Message *hello_message,
				      char **uuid,
				      char **client_name,
				      char **major_version,
				      char **minor_version);

extern gboolean forward_ipc_request(IPC_Channel *ipc_channel,
				    xmlNodePtr xml_request,
				    xmlNodePtr xml_response_data,
				    const char *sys_to,
				    const char *sys_from);
extern gboolean
send_ipc_request(IPC_Channel *ipc_channel,
		 xmlNodePtr xml_options, xmlNodePtr xml_data,
		 const char *host_to, const char *sys_to,
		 const char *sys_from, const char *uuid_from,
		 const char *crm_msg_reference);

extern gboolean
send_ha_request(ll_cluster_t *hb_fd,
		xmlNodePtr xml_options, xmlNodePtr xml_data,
		const char *host_to, const char *sys_to,
		const char *sys_from, const char *uuid_from,
		const char *crm_msg_reference);

extern gboolean send_ha_reply(ll_cluster_t *hb_cluster,
			      xmlNodePtr xml_request,
			      xmlNodePtr xml_response_data);

extern gboolean send_ipc_reply(IPC_Channel *ipc_channel,
			       xmlNodePtr xml_request,
			       xmlNodePtr xml_response_data);

extern xmlNodePtr create_forward(xmlNodePtr xml_request,
				 xmlNodePtr xml_response_data,
				 const char *sys_to);

extern xmlNodePtr createCrmMsg(xmlNodePtr data,
			       gboolean is_request);

extern xmlNodePtr create_reply(xmlNodePtr xml_request,
			       xmlNodePtr xml_response_data);

extern char *generate_hash_key(const char *crm_msg_reference,
			       const char *sys);

extern char *generate_hash_value(const char *src_node,
				 const char *src_subsys);

extern gboolean decode_hash_value(gpointer value,
				  char **node,
				  char **subsys);

extern xmlNodePtr
create_request(xmlNodePtr xml_options, xmlNodePtr xml_data,
	       const char *host_to, const char *sys_to,
	       const char *sys_from, const char *uuid_from,
	       const char *crm_msg_reference);

#endif
