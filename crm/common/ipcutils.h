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
#ifndef IPCUTILS_H
#define IPCUTILS_H

#include <libxml/tree.h>
extern void LinkStatus(const char * node, const char * lnk, const char * status ,void * private);

extern IPC_Message *create_simple_message(char *text, IPC_Channel *ch);
extern void send_ipc_message(IPC_Channel *ipc_client, IPC_Message *msg);
//extern gboolean default_client_connect(IPC_Channel *newclient, gpointer user_data);
extern gboolean default_ipc_input_dispatch(IPC_Channel *, gpointer);
extern void default_ipc_input_destroy(gpointer user_data);
extern void
init_server_ipc_comms(const char *child,
		      gboolean (*channel_client_connect)(IPC_Channel *newclient, gpointer user_data),
		      void (*channel_input_destroy)(gpointer user_data));
extern IPC_Channel *
init_client_ipc_comms(const char *child,
		      gboolean (*dispatch)(IPC_Channel* source_data, gpointer user_data));
extern IPC_WaitConnection *wait_channel_init(char daemonfifo[]);
extern IPC_Message *get_ipc_message(IPC_Channel *client);
extern char* getNow(void);
extern void send_xmlipc_message(IPC_Channel *ipc_client, xmlNodePtr msg);
extern char *dump_xml(xmlNodePtr msg);
extern void send_xmlha_message(ll_cluster_t *hb_fd, xmlNodePtr root, const char *node, const char *ha_client);
extern char *dump_xml_node(xmlNodePtr msg, gboolean whole_doc);

extern xmlNodePtr validate_and_decode_hamessage(const struct ha_msg* msg);
extern xmlNodePtr validate_and_decode_ipcmessage(IPC_Channel *client);

 
#endif

