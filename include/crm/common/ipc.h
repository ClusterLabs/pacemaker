/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMMON_IPC__H
#  define CRM_COMMON_IPC__H

#  include <clplumbing/ipc.h>
#  include <clplumbing/GSource.h>

#  include <crm/common/xml.h>
#  include <crm/common/msg.h>

typedef struct crmd_client_s {
    char *sub_sys;
    char *uuid;
    char *table_key;
    char *user;
    IPC_Channel *client_channel;
    GCHSource *client_source;
} crmd_client_t;

extern gboolean send_ipc_message(IPC_Channel * ipc_client, xmlNode * msg);

extern void default_ipc_connection_destroy(gpointer user_data);

extern int init_server_ipc_comms(char *channel_name,
                                 gboolean(*channel_client_connect) (IPC_Channel * newclient,
                                                                    gpointer user_data),
                                 void (*channel_connection_destroy) (gpointer user_data));

extern GCHSource *init_client_ipc_comms(const char *channel_name,
                                        gboolean(*dispatch) (IPC_Channel * source_data,
                                                             gpointer user_data), void *client_data,
                                        IPC_Channel ** ch);

extern IPC_Channel *init_client_ipc_comms_nodispatch(const char *channel_name);

extern gboolean subsystem_msg_dispatch(IPC_Channel * sender, void *user_data);

extern IPC_WaitConnection *wait_channel_init(char daemonsocket[]);

extern gboolean is_ipc_empty(IPC_Channel * ch);

extern xmlNode *createPingRequest(const char *crm_msg_reference, const char *to);

extern xmlNode *validate_crm_message(xmlNode * msg,
                                     const char *sys, const char *uuid, const char *msg_type);

extern void send_hello_message(IPC_Channel * ipc_client,
                               const char *uuid,
                               const char *client_name,
                               const char *major_version, const char *minor_version);

#  define create_reply(request, xml_response_data) create_reply_adv(request, xml_response_data, __FUNCTION__);
extern xmlNode *create_reply_adv(xmlNode * request, xmlNode * xml_response_data,
                                 const char *origin);

#  define create_request(task, xml_data, host_to, sys_to, sys_from, uuid_from) create_request_adv(task, xml_data, host_to, sys_to, sys_from, uuid_from, __FUNCTION__)

extern xmlNode *create_request_adv(const char *task, xmlNode * xml_data, const char *host_to,
                                   const char *sys_to, const char *sys_from, const char *uuid_from,
                                   const char *origin);

typedef struct ha_msg_input_s {
    xmlNode *msg;
    xmlNode *xml;

} ha_msg_input_t;

extern ha_msg_input_t *new_ha_msg_input(xmlNode * orig);
extern void delete_ha_msg_input(ha_msg_input_t * orig);
extern xmlNode *xmlfromIPC(IPC_Channel * ch, int timeout);


/* Libqb based IPC */

#include <qb/qbipcs.h>
ssize_t crm_ipcs_send(qb_ipcs_connection_t *c, xmlNode *msg, gboolean event);
xmlNode *crm_ipcs_recv(qb_ipcs_connection_t *c, void *data, size_t size);
int crm_ipcs_client_pid(qb_ipcs_connection_t *c);
void crm_ipcs_send_ack(qb_ipcs_connection_t *c, const char *tag, const char *function, int line);

#include <qb/qbipcc.h>
typedef struct crm_ipc_s crm_ipc_t;

crm_ipc_t *crm_ipc_new(const char *name, size_t max_size);
bool crm_ipc_connect(crm_ipc_t *client);
void crm_ipc_close(crm_ipc_t *client);
void crm_ipc_destroy(crm_ipc_t *client);

int crm_ipc_send(crm_ipc_t *client, xmlNode *message, xmlNode **reply, int32_t ms_timeout);

int crm_ipc_get_fd(crm_ipc_t *client);
bool crm_ipc_connected(crm_ipc_t *client);
int crm_ipc_ready(crm_ipc_t *client);
long crm_ipc_read(crm_ipc_t *client);
const char *crm_ipc_buffer(crm_ipc_t *client);
const char *crm_ipc_name(crm_ipc_t *client);




#endif
