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
#ifndef CRM_COMMON_IPC__H
#define CRM_COMMON_IPC__H

#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>

#include <crm/common/xml.h>
#include <crm/common/msg.h>

typedef struct crmd_client_s 
{
		char *sub_sys;
		char *uuid;
		char *table_key;
		IPC_Channel *client_channel;
		GCHSource *client_source;
} crmd_client_t;

extern gboolean send_ipc_message(IPC_Channel *ipc_client, HA_Message *msg);

extern void default_ipc_connection_destroy(gpointer user_data);

extern int init_server_ipc_comms(
	char *channel_name,
	gboolean (*channel_client_connect)(
		IPC_Channel *newclient, gpointer user_data),
	void (*channel_connection_destroy)(gpointer user_data));

extern GCHSource *init_client_ipc_comms(
	const char *channel_name,
	gboolean (*dispatch)(
		IPC_Channel* source_data, gpointer user_data),
	void *client_data, IPC_Channel **ch);

extern IPC_Channel *init_client_ipc_comms_nodispatch(const char *channel_name);

extern gboolean subsystem_msg_dispatch(IPC_Channel *sender, void *user_data);

extern IPC_WaitConnection *wait_channel_init(char daemonsocket[]);

extern gboolean is_ipc_empty(IPC_Channel *ch);


extern crm_data_t *createPingRequest(const char *crm_msg_reference,
				     const char *to);

extern HA_Message *validate_crm_message(HA_Message *msg,
				       const char *sys,
				       const char *uuid,
				       const char *msg_type);

extern void send_hello_message(IPC_Channel *ipc_client,
			       const char *uuid,
			       const char *client_name,
			       const char *major_version,
			       const char *minor_version);

#define create_reply(request, xml_response_data) create_reply_adv(request, xml_response_data, __FUNCTION__);
extern HA_Message *create_reply_adv(HA_Message *request, crm_data_t *xml_response_data, const char *origin);

#define create_request(task, xml_data, host_to, sys_to, sys_from, uuid_from) create_request_adv(task, xml_data, host_to, sys_to, sys_from, uuid_from, __FUNCTION__)

extern HA_Message *create_request_adv(
	const char *task, crm_data_t *xml_data, const char *host_to,
	const char *sys_to, const char *sys_from, const char *uuid_from,
	const char *origin);


typedef struct ha_msg_input_s 
{
		HA_Message *msg;
		crm_data_t *xml;
		
} ha_msg_input_t;

extern ha_msg_input_t *new_ipc_msg_input(IPC_Message *orig);
extern ha_msg_input_t *new_ha_msg_input(const HA_Message *orig);
extern void delete_ha_msg_input(ha_msg_input_t *orig);


#endif
