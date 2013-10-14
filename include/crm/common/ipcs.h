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

#  include <qb/qbipcs.h>
#  ifdef HAVE_GNUTLS_GNUTLS_H
#    undef KEYFILE
#    include <gnutls/gnutls.h>
#  endif

#  include <crm/common/ipc.h>
#  include <crm/common/mainloop.h>

typedef struct crm_client_s crm_client_t;

enum client_type {
    CRM_CLIENT_IPC = 1,
    CRM_CLIENT_TCP = 2,
#  ifdef HAVE_GNUTLS_GNUTLS_H
    CRM_CLIENT_TLS = 3,
#  endif
};

struct crm_remote_s {
    /* Shared */
    char *buffer;
    size_t buffer_size;
    size_t buffer_offset;
    int auth_timeout;
    int tcp_socket;
    mainloop_io_t *source;

    /* CIB-only */
    bool authenticated;
    char *token;

    /* TLS only */
#  ifdef HAVE_GNUTLS_GNUTLS_H
    gnutls_session_t *tls_session;
    bool tls_handshake_complete;
#  endif
};

enum crm_client_flags
{
    crm_client_flag_have_events = 0x00001, /* ipc_proxy code only */
};

struct crm_client_s {
    uint pid;

    uid_t uid;
    gid_t gid;

    char *id;
    char *name;
    char *user;

    long long options;

    int request_id;
    uint32_t flags;
    void *userdata;

    int event_timer;
    GList *event_queue;

    /* Depending on the value of kind, only some of the following
     * will be populated/valid
     */
    enum client_type kind;

    qb_ipcs_connection_t *ipcs; /* IPC */

    struct crm_remote_s *remote;        /* TCP/TLS */
};

extern GHashTable *client_connections;

void crm_client_init(void);
void crm_client_cleanup(void);

crm_client_t *crm_client_get(qb_ipcs_connection_t * c);
crm_client_t *crm_client_get_by_id(const char *id);
const char *crm_client_name(crm_client_t * c);

crm_client_t *crm_client_new(qb_ipcs_connection_t * c, uid_t uid, gid_t gid);
void crm_client_destroy(crm_client_t * c);
void crm_client_disconnect_all(qb_ipcs_service_t *s);

void crm_ipcs_send_ack(crm_client_t * c, uint32_t request, uint32_t flags,
                       const char *tag, const char *function, int line);

/* when max_send_size is 0, default ipc buffer size is used */
ssize_t crm_ipc_prepare(uint32_t request, xmlNode * message, struct iovec **result, int32_t max_send_size);
ssize_t crm_ipcs_send(crm_client_t * c, uint32_t request, xmlNode * message, enum crm_ipc_flags flags);
ssize_t crm_ipcs_sendv(crm_client_t * c, struct iovec *iov, enum crm_ipc_flags flags);
xmlNode *crm_ipcs_recv(crm_client_t * c, void *data, size_t size, uint32_t * id, uint32_t * flags);

int crm_ipcs_client_pid(qb_ipcs_connection_t * c);

#endif
