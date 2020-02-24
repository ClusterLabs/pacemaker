/*
 * Copyright 2013-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_COMMON_IPCS__H
#  define CRM_COMMON_IPCS__H

#ifdef __cplusplus
extern "C" {
#endif

#  include <stdbool.h>
#  include <qb/qbipcs.h>
#  ifdef HAVE_GNUTLS_GNUTLS_H
#    undef KEYFILE
#    include <gnutls/gnutls.h>
#  endif

#  include <crm/common/ipc.h>
#  include <crm/common/mainloop.h>

typedef struct pcmk__client_s pcmk__client_t;

enum pcmk__client_type {
    PCMK__CLIENT_IPC = 1,
    PCMK__CLIENT_TCP = 2,
#  ifdef HAVE_GNUTLS_GNUTLS_H
    PCMK__CLIENT_TLS = 3,
#  endif
};

struct pcmk__remote_s {
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

enum pcmk__client_flags {
    pcmk__client_proxied    = 0x00001, /* ipc_proxy code only */
    pcmk__client_privileged = 0x00002, /* root or cluster user */
};

struct pcmk__client_s {
    uint pid;

    uid_t uid;
    gid_t gid;

    char *id;
    char *name;
    char *user;

    /* Provided for server use (not used by library) */
    /* @TODO merge options, flags, and kind (reserving lower bits for server) */
    long long options;

    int request_id;
    uint32_t flags;
    void *userdata;

    int event_timer;
    GQueue *event_queue;

    /* Depending on the value of kind, only some of the following
     * will be populated/valid
     */
    enum pcmk__client_type kind;

    qb_ipcs_connection_t *ipcs; /* IPC */

    struct pcmk__remote_s *remote;        /* TCP/TLS */

    unsigned int queue_backlog; /* IPC queue length after last flush */
    unsigned int queue_max;     /* Evict client whose queue grows this big */
};

guint pcmk__ipc_client_count(void);
void pcmk__foreach_ipc_client(GHFunc func, gpointer user_data);
void pcmk__foreach_ipc_client_remove(GHRFunc func, gpointer user_data);

void pcmk__client_cleanup(void);

pcmk__client_t *pcmk__find_client(qb_ipcs_connection_t *c);
pcmk__client_t *pcmk__find_client_by_id(const char *id);
const char *pcmk__client_name(pcmk__client_t *c);
const char *pcmk__client_type_str(enum pcmk__client_type client_type);

pcmk__client_t *pcmk__new_unauth_client(void *key);
pcmk__client_t *pcmk__new_client(qb_ipcs_connection_t *c, uid_t uid, gid_t gid);
void pcmk__free_client(pcmk__client_t *c);
void pcmk__drop_all_clients(qb_ipcs_service_t *s);
bool pcmk__set_client_queue_max(pcmk__client_t *client, const char *qmax);

void pcmk__ipc_send_ack_as(const char *function, int line, pcmk__client_t *c,
                           uint32_t request, uint32_t flags, const char *tag);
#define pcmk__ipc_send_ack(c, req, flags, tag) \
    pcmk__ipc_send_ack_as(__FUNCTION__, __LINE__, (c), (req), (flags), (tag))

int pcmk__ipc_prepare_iov(uint32_t request, xmlNode *message,
                          uint32_t max_send_size,
                          struct iovec **result, ssize_t *bytes);
int pcmk__ipc_send_xml(pcmk__client_t *c, uint32_t request, xmlNode *message,
                       uint32_t flags);
int pcmk__ipc_send_iov(pcmk__client_t *c, struct iovec *iov, uint32_t flags);
xmlNode *pcmk__client_data2xml(pcmk__client_t *c, void *data,
                               uint32_t *id, uint32_t *flags);

int pcmk__client_pid(qb_ipcs_connection_t *c);

#ifdef __cplusplus
}
#endif

#endif
