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

extern const char *generateReference(void);
extern gboolean conditional_add_failure(xmlNodePtr failed, xmlNodePtr target, int operation, int return_code);
extern xmlNodePtr validate_crm_message(xmlNodePtr root, const char *sys, const char *uid, const char *msg_type);
extern xmlNodePtr createPingAnswerFragment(const char *from, const char *status);
extern xmlNodePtr createPingRequest(const char *reference, const char *to);
/* extern xmlNodePtr createCrmMsg(const char *reference, */
/* 			       const char *dest_subsystem, */
/* 			       const char *src_subsystem, */
/* 			       xmlNodePtr data, */
/* 			       gboolean is_request); */
/* extern xmlNodePtr createIpcMessage(const char *reference, */
/* 				   const char *from, */
/* 				   const char *to, */
/* 				   xmlNodePtr data, */
/* 				   gboolean is_request); */
gboolean decodeNVpair(const char *srcstring, char separator, char **name, char **value);

extern void
send_hello_message(IPC_Channel *ipc_client,
		   const char *uid,
		   const char *client_name,
		   const char *major_version,
		   const char *minor_version);
extern gboolean
process_hello_message(IPC_Message *hello_message,
		      char **uid,
		      char **client_name,
		      char **major_version,
		      char **minor_version);

extern gboolean
send_ipc_request(IPC_Channel *ipc_channel, xmlNodePtr xml_msg_node,
		 const char *host_to, const char *sys_to,
		 const char *sys_from, const char *uid_from,
		 const char *reference);
extern gboolean send_ha_request(void);
extern gboolean send_ha_reply(ll_cluster_t *hb_cluster, xmlNodePtr xml_request, xmlNodePtr xml_response_data);
extern gboolean send_ipc_reply(IPC_Channel *ipc_channel, xmlNodePtr xml_request, xmlNodePtr xml_response_data);
extern xmlNodePtr create_forward(xmlNodePtr xml_request, xmlNodePtr xml_response_data, const char *sys_to);
extern xmlNodePtr createCrmMsg(xmlNodePtr data, gboolean is_request);
extern xmlNodePtr create_reply(xmlNodePtr xml_request, xmlNodePtr xml_response_data);
//xmlNodePtr createIpcMessage(const char *reference, const char *from, const char *to, xmlNodePtr data, gboolean is_request);

extern char *generate_hash_key(const char *reference, const char *sys);
extern char *generate_hash_value(const char *src_node, const char *src_subsys);
extern gboolean decode_hash_value(gpointer value, char **node, char **subsys);

#endif
