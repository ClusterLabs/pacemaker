/* $Id: msg.h,v 1.3 2005/01/18 20:33:04 andrew Exp $ */
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
#ifndef CRM_COMMON_MSG__H
#define CRM_COMMON_MSG__H

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <clplumbing/ipc.h>

typedef struct ha_msg HA_Message;

extern HA_Message *validate_crm_message(HA_Message *msg,
				       const char *sys,
				       const char *uuid,
				       const char *msg_type);

extern xmlNodePtr createPingAnswerFragment(const char *from,
					   const char *status);

extern xmlNodePtr createPingRequest(const char *crm_msg_reference,
				    const char *to);

extern void send_hello_message(IPC_Channel *ipc_client,
			       const char *uuid,
			       const char *client_name,
			       const char *major_version,
			       const char *minor_version);

extern gboolean process_hello_message(xmlNodePtr hello,
				      char **uuid,
				      char **client_name,
				      char **major_version,
				      char **minor_version);

extern gboolean send_ipc_reply(
	IPC_Channel *ipc_channel, HA_Message *request, xmlNodePtr xml_response_data);

extern HA_Message *create_reply(HA_Message *request, xmlNodePtr xml_response_data);

extern HA_Message *create_request(
	const char *task, xmlNodePtr xml_data, const char *host_to,
	const char *sys_to, const char *sys_from, const char *uuid_from);

typedef struct ha_msg_input_s 
{
		HA_Message *msg;
		xmlNodePtr xml;
		
} ha_msg_input_t;

extern ha_msg_input_t *new_ipc_msg_input(IPC_Message *orig);
extern ha_msg_input_t *new_ha_msg_input(const HA_Message *orig);
extern void delete_ha_msg_input(ha_msg_input_t *orig);


#endif
