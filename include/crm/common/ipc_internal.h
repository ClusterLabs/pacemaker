/*
 * Copyright 2013-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <ipc_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_IPC_INTERNAL__H
#define PCMK__CRM_COMMON_IPC_INTERNAL__H

#include <stdbool.h>                // bool
#include <stdint.h>                 // uint32_t, uint64_t, UINT64_C()
#include <sys/uio.h>                // struct iovec
#include <sys/types.h>              // uid_t, gid_t, pid_t, size_t

#include <glib.h>                   // guint, gpointer, GQueue, ...
#include <libxml/tree.h>            // xmlNode
#include <qb/qbipcs.h>              // qb_ipcs_connection_t, ...

#include <crm_config.h>             // HAVE_GETPEEREID
#include <crm/crm.h>                    // crm_system_name
#include <crm/common/ipc.h>
#include <crm/common/ipc_controld.h>    // pcmk_controld_api_reply
#include <crm/common/ipc_pacemakerd.h>  // pcmk_pacemakerd_{api_reply,state}
#include <crm/common/remote_internal.h> // pcmk__remote_t

#ifdef __cplusplus
extern "C" {
#endif

/* denotes "non yieldable PID" on FreeBSD, or actual PID1 in scenarios that
   require a delicate handling anyway (socket-based activation with systemd);
   we can be reasonably sure that this PID is never possessed by the actual
   child daemon, as it gets taken either by the proper init, or by pacemakerd
   itself (i.e. this precludes anything else); note that value of zero
   is meant to carry "unset" meaning, and better not to bet on/conditionalize
   over signedness of pid_t */
#define PCMK__SPECIAL_PID  1

// Timeout (in seconds) to use for IPC client sends, reply waits, etc.
#define PCMK__IPC_TIMEOUT 120

#if defined(HAVE_GETPEEREID)
/* on FreeBSD, we don't want to expose "non-yieldable PID" (leading to
   "IPC liveness check only") as its nominal representation, which could
   cause confusion -- this is unambiguous as long as there's no
   socket-based activation like with systemd (very improbable) */
#define PCMK__SPECIAL_PID_AS_0(p)  (((p) == PCMK__SPECIAL_PID) ? 0 : (p))
#else
#define PCMK__SPECIAL_PID_AS_0(p)  (p)
#endif

/*!
 * \internal
 * \brief Check the authenticity and liveness of the process via IPC end-point
 *
 * When IPC daemon under given IPC end-point (name) detected, its authenticity
 * is verified by the means of comparing against provided referential UID and
 * GID, and the result of this check can be deduced from the return value.
 * As an exception, referential UID of 0 (~ root) satisfies arbitrary
 * detected daemon's credentials.
 *
 * \param[in]  name    IPC name to base the search on
 * \param[in]  refuid  referential UID to check against
 * \param[in]  refgid  referential GID to check against
 * \param[out] gotpid  to optionally store obtained PID of the found process
 *                     upon returning 1 or -2
 *                     (not available on FreeBSD, special value of 1,
 *                     see PCMK__SPECIAL_PID, used instead, and the caller
 *                     is required to special case this value respectively)
 *
 * \return Standard Pacemaker return code
 *
 * \note Return codes of particular interest include pcmk_rc_ipc_unresponsive
 *       indicating that no trace of IPC liveness was detected, and
 *       pcmk_rc_ipc_unauthorized indicating that the IPC endpoint is blocked by
 *       an unauthorized process.
 * \note This function emits a log message for return codes other than
 *       pcmk_rc_ok and pcmk_rc_ipc_unresponsive, and when there isn't a perfect
 *       match in respect to \p reguid and/or \p refgid, for a possible
 *       least privilege principle violation.
 *
 * \see crm_ipc_is_authentic_process
 */
int pcmk__ipc_is_authentic_process_active(const char *name, uid_t refuid,
                                          gid_t refgid, pid_t *gotpid);

int pcmk__connect_generic_ipc(crm_ipc_t *ipc);
int pcmk__ipc_fd(crm_ipc_t *ipc, int *fd);
int pcmk__connect_ipc(pcmk_ipc_api_t *api, enum pcmk_ipc_dispatch dispatch_type,
                      int attempts);
int pcmk__connect_ipc_retry_conrefused(pcmk_ipc_api_t *api,
                                       enum pcmk_ipc_dispatch dispatch_type,
                                       int attempts);
/*
 * Server-related
 */

enum pcmk__client_flags {
    // Lower 32 bits are reserved for server (not library) use

    // Next 8 bits are reserved for client type (sort of a cheap enum)

    //! Client uses plain IPC
    pcmk__client_ipc                    = (UINT64_C(1) << 32),

    //! Client uses TCP connection
    pcmk__client_tcp                    = (UINT64_C(1) << 33),

    //! Client uses TCP with TLS
    pcmk__client_tls                    = (UINT64_C(1) << 34),

    // The rest are client attributes

    //! Client IPC is proxied
    pcmk__client_proxied                = (UINT64_C(1) << 40),

    //! Client is run by root or cluster user
    pcmk__client_privileged             = (UINT64_C(1) << 41),

    //! Local client to be proxied
    pcmk__client_to_proxy               = (UINT64_C(1) << 42),

    /*!
     * \brief Client IPC connection accepted
     *
     * Used only for remote CIB connections via \c PCMK_XA_REMOTE_TLS_PORT.
     */
    pcmk__client_authenticated          = (UINT64_C(1) << 43),

    //! Client TLS handshake is complete
    pcmk__client_tls_handshake_complete = (UINT64_C(1) << 44),
};

#define PCMK__CLIENT_TYPE(client) ((client)->flags & UINT64_C(0xff00000000))

typedef struct {
    unsigned int pid;

    char *id;
    char *name;
    char *user;
    uint64_t flags; // Group of pcmk__client_flags

    int request_id;
    void *userdata;

    int event_timer;
    GQueue *event_queue;

    /* Buffer used to store a multipart IPC message when we are building it
     * up over multiple reads.
     */
    GByteArray *buffer;

    /* Depending on the client type, only some of the following will be
     * populated/valid. @TODO Maybe convert to a union.
     */

    qb_ipcs_connection_t *ipcs; /* IPC */

    pcmk__remote_t *remote;     /* TCP/TLS */

    unsigned int queue_backlog; /* IPC queue length after last flush */
    unsigned int queue_max;     /* Evict client whose queue grows this big */
} pcmk__client_t;

#define pcmk__set_client_flags(client, flags_to_set) do {               \
        (client)->flags = pcmk__set_flags_as(__func__, __LINE__,        \
            LOG_TRACE,                                                  \
            "Client", pcmk__client_name(client),                        \
            (client)->flags, (flags_to_set), #flags_to_set);            \
    } while (0)

#define pcmk__clear_client_flags(client, flags_to_clear) do {           \
        (client)->flags = pcmk__clear_flags_as(__func__, __LINE__,      \
            LOG_TRACE,                                                  \
            "Client", pcmk__client_name(client),                        \
            (client)->flags, (flags_to_clear), #flags_to_clear);        \
    } while (0)

#define pcmk__set_ipc_flags(ipc_flags, ipc_name, flags_to_set) do {         \
        ipc_flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,       \
                                       "IPC", (ipc_name),                   \
                                       (ipc_flags), (flags_to_set),         \
                                       #flags_to_set);                      \
    } while (0)

#define pcmk__clear_ipc_flags(ipc_flags, ipc_name, flags_to_clear) do {     \
        ipc_flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                         "IPC", (ipc_name),                 \
                                         (ipc_flags), (flags_to_clear),     \
                                         #flags_to_clear);                  \
    } while (0)

guint pcmk__ipc_client_count(void);
void pcmk__foreach_ipc_client(GHFunc func, gpointer user_data);

void pcmk__client_cleanup(void);

pcmk__client_t *pcmk__find_client(const qb_ipcs_connection_t *c);
pcmk__client_t *pcmk__find_client_by_id(const char *id);
const char *pcmk__client_name(const pcmk__client_t *c);
const char *pcmk__client_type_str(uint64_t client_type);

pcmk__client_t *pcmk__new_unauth_client(void *key);
pcmk__client_t *pcmk__new_client(qb_ipcs_connection_t *c, uid_t uid, gid_t gid);
void pcmk__free_client(pcmk__client_t *c);
void pcmk__drop_all_clients(qb_ipcs_service_t *s);
void pcmk__set_client_queue_max(pcmk__client_t *client, const char *qmax);

xmlNode *pcmk__ipc_create_ack_as(const char *function, int line, uint32_t flags,
                                 const char *ver, crm_exit_t status);
#define pcmk__ipc_create_ack(flags, ver, st) \
    pcmk__ipc_create_ack_as(__func__, __LINE__, (flags), (ver), (st))

int pcmk__ipc_send_ack_as(const char *function, int line, pcmk__client_t *c,
                          uint32_t request, uint32_t flags, const char *tag,
                          const char *ver, crm_exit_t status);
#define pcmk__ipc_send_ack(c, req, flags, tag, ver, st) \
    pcmk__ipc_send_ack_as(__func__, __LINE__, (c), (req), (flags), (tag), (ver), (st))

int pcmk__ipc_prepare_iov(uint32_t request, const GString *message,
                          uint16_t index, struct iovec **result, ssize_t *bytes);
int pcmk__ipc_send_xml(pcmk__client_t *c, uint32_t request,
                       const xmlNode *message, uint32_t flags);
int pcmk__ipc_send_iov(pcmk__client_t *c, struct iovec *iov, uint32_t flags);
void pcmk__ipc_free_client_buffer(crm_ipc_t *client);
int pcmk__ipc_msg_append(GByteArray **buffer, guint8 *data);
xmlNode *pcmk__client_data2xml(pcmk__client_t *c, uint32_t *id, uint32_t *flags);

int pcmk__client_pid(qb_ipcs_connection_t *c);

void pcmk__serve_attrd_ipc(qb_ipcs_service_t **ipcs,
                           struct qb_ipcs_service_handlers *cb);
void pcmk__serve_execd_ipc(qb_ipcs_service_t **ipcs,
                           struct qb_ipcs_service_handlers *cb);
void pcmk__serve_fenced_ipc(qb_ipcs_service_t **ipcs,
                            struct qb_ipcs_service_handlers *cb);
void pcmk__serve_pacemakerd_ipc(qb_ipcs_service_t **ipcs,
                                struct qb_ipcs_service_handlers *cb);
void pcmk__serve_schedulerd_ipc(qb_ipcs_service_t **ipcs,
                                struct qb_ipcs_service_handlers *cb);
qb_ipcs_service_t *pcmk__serve_controld_ipc(struct qb_ipcs_service_handlers *cb);

void pcmk__serve_based_ipc(qb_ipcs_service_t **ipcs_ro,
                           qb_ipcs_service_t **ipcs_rw,
                           qb_ipcs_service_t **ipcs_shm,
                           struct qb_ipcs_service_handlers *ro_cb,
                           struct qb_ipcs_service_handlers *rw_cb);

void pcmk__stop_based_ipc(qb_ipcs_service_t *ipcs_ro,
        qb_ipcs_service_t *ipcs_rw,
        qb_ipcs_service_t *ipcs_shm);

static inline const char *
pcmk__ipc_sys_name(const char *ipc_name, const char *fallback)
{
    return ipc_name ? ipc_name : ((crm_system_name ? crm_system_name : fallback));
}

const char *pcmk__pcmkd_state_enum2friendly(enum pcmk_pacemakerd_state state);

const char *pcmk__controld_api_reply2str(enum pcmk_controld_api_reply reply);
const char *pcmk__pcmkd_api_reply2str(enum pcmk_pacemakerd_api_reply reply);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_INTERNAL__H
