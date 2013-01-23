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
#ifndef CRM_COMMON_IPCS__H
#  define CRM_COMMON_IPCS__H

#include <qb/qbipcs.h>
#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif

typedef struct mainloop_io_s mainloop_io_t;

enum client_type
{
        client_type_ipc = 1,
        client_type_tcp = 2,
#ifdef HAVE_GNUTLS_GNUTLS_H
        client_type_tls = 3,
#endif
};

struct crm_client_s
{
        uint pid;

        uid_t uid;
        gid_t gid;

        char *id;
        char *name;
        char *user;

        long long options;
        
        int request_id;
        GList *pending;
        void *userdata;

        /* Depending on the value of kind, only some of the following
         * will be populated/valid
         */
        enum client_type kind;

/* CIB specific */
        char *callback_id;

        /* IPC */
        qb_ipcs_connection_t *ipcs;

        /* TCP / TLS */
        char *recv_buf;
        bool  remote_auth;
        int   remote_auth_timeout;
        mainloop_io_t *remote;

        /* TLS */
#ifdef HAVE_GNUTLS_GNUTLS_H
        gnutls_session *session;
        gboolean handshake_complete;
#else
        void *session;
#endif
};

enum crm_ipc_server_flags
{
    crm_ipc_server_none  = 0x0000,
    crm_ipc_server_event = 0x0001, /* Send an Event instead of a Response */ 

    crm_ipc_server_info  = 0x0010, /* Log failures as LOG_INFO */ 
    crm_ipc_server_error = 0x0020, /* Log failures as LOG_ERR */
};

extern GHashTable *client_connections;

typedef struct crm_client_s crm_client_t;

void crm_client_init(void);
void crm_client_cleanup(void);

crm_client_t *crm_client_get(qb_ipcs_connection_t *c);
crm_client_t *crm_client_get_by_id(const char *id);
const char *crm_client_name(crm_client_t *c);

crm_client_t *crm_client_new(qb_ipcs_connection_t *c, uid_t uid, gid_t gid);
void crm_client_destroy(crm_client_t *c);

void crm_ipcs_send_ack(crm_client_t *c, uint32_t request, const char *tag, const char *function, int line);
ssize_t crm_ipcs_send(crm_client_t *c, uint32_t request, xmlNode *message, enum crm_ipc_server_flags flags);
xmlNode *crm_ipcs_recv(crm_client_t *c, void *data, size_t size, uint32_t *id, uint32_t *flags);

int crm_ipcs_client_pid(qb_ipcs_connection_t *c);

#endif
