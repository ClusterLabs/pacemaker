/* $Id: ipc.h,v 1.1 2004/06/02 11:40:50 andrew Exp $ */
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

#include <xml.h>
#include <msg.h>

typedef struct _crmd_client 
{
		char *sub_sys;
		char *uuid;
		char *table_key;
		IPC_Channel *client_channel;
		GCHSource *client_source;
} crmd_client_t;

extern gboolean send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg);

extern void default_ipc_input_destroy(gpointer user_data);

extern xmlNodePtr find_xml_in_ipcmessage(IPC_Message *msg,
					 gboolean do_free);

extern gboolean send_xmlipc_message(IPC_Channel *ipc_client,
				    xmlNodePtr msg);

extern IPC_Channel *init_client_ipc_comms(
	const char *child,
	gboolean (*dispatch)(IPC_Channel* source_data, gpointer user_data),
	crmd_client_t *user_data);

extern gboolean subsystem_input_dispatch(IPC_Channel *sender, void *user_data);

#endif

