/*
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
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

/**
 * \file
 * \brief Wrappers for and extensions to libqb IPC
 * \ingroup core
 */

#  include <crm/common/xml.h>

/* clplumbing based IPC */

#  define create_reply(request, xml_response_data) create_reply_adv(request, xml_response_data, __FUNCTION__);
xmlNode *create_reply_adv(xmlNode * request, xmlNode * xml_response_data, const char *origin);

#  define create_request(task, xml_data, host_to, sys_to, sys_from, uuid_from) create_request_adv(task, xml_data, host_to, sys_to, sys_from, uuid_from, __FUNCTION__)

xmlNode *create_request_adv(const char *task, xmlNode * xml_data, const char *host_to,
                            const char *sys_to, const char *sys_from, const char *uuid_from,
                            const char *origin);

/* *INDENT-OFF* */
enum crm_ipc_flags
{
    crm_ipc_flags_none      = 0x00000000,

    crm_ipc_compressed      = 0x00000001, /* Message has been compressed */

    crm_ipc_proxied         = 0x00000100, /* _ALL_ replies to proxied connections need to be sent as events */
    crm_ipc_client_response = 0x00000200, /* A Response is expected in reply */

    /* These options are just options for crm_ipcs_sendv() */
    crm_ipc_server_event    = 0x00010000, /* Send an Event instead of a Response */
    crm_ipc_server_free     = 0x00020000, /* Free the iovec after sending */

    crm_ipc_server_info     = 0x00100000, /* Log failures as LOG_INFO */
    crm_ipc_server_error    = 0x00200000, /* Log failures as LOG_ERR */
};
/* *INDENT-ON* */

#  include <qb/qbipcc.h>
typedef struct crm_ipc_s crm_ipc_t;

crm_ipc_t *crm_ipc_new(const char *name, size_t max_size);
bool crm_ipc_connect(crm_ipc_t * client);
void crm_ipc_close(crm_ipc_t * client);
void crm_ipc_destroy(crm_ipc_t * client);

int crm_ipc_send(crm_ipc_t * client, xmlNode * message, enum crm_ipc_flags flags,
                 int32_t ms_timeout, xmlNode ** reply);

int crm_ipc_get_fd(crm_ipc_t * client);
bool crm_ipc_connected(crm_ipc_t * client);
int crm_ipc_ready(crm_ipc_t * client);
long crm_ipc_read(crm_ipc_t * client);
const char *crm_ipc_buffer(crm_ipc_t * client);
const char *crm_ipc_name(crm_ipc_t * client);

/* Utils */
xmlNode *create_hello_message(const char *uuid, const char *client_name,
                              const char *major_version, const char *minor_version);

#endif
