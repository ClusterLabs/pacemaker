/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_COMMON_IPC__H
#  define CRM_COMMON_IPC__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to libqb IPC
 * \ingroup core
 */

#include <sys/uio.h>
#include <qb/qbipcc.h>
#include <crm/common/xml.h>

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
    crm_ipc_proxied_relay_response = 0x00040000, /* all replies to proxied connections are sent as events, this flag preserves whether the event should be treated as an actual event, or a response.*/

    crm_ipc_server_info     = 0x00100000, /* Log failures as LOG_INFO */
    crm_ipc_server_error    = 0x00200000, /* Log failures as LOG_ERR */
};
/* *INDENT-ON* */

typedef struct crm_ipc_s crm_ipc_t;

crm_ipc_t *crm_ipc_new(const char *name, size_t max_size);
bool crm_ipc_connect(crm_ipc_t * client);
void crm_ipc_close(crm_ipc_t * client);
void crm_ipc_destroy(crm_ipc_t * client);
void pcmk_free_ipc_event(struct iovec *event);

int crm_ipc_send(crm_ipc_t * client, xmlNode * message, enum crm_ipc_flags flags,
                 int32_t ms_timeout, xmlNode ** reply);

int crm_ipc_get_fd(crm_ipc_t * client);
bool crm_ipc_connected(crm_ipc_t * client);
int crm_ipc_ready(crm_ipc_t * client);
long crm_ipc_read(crm_ipc_t * client);
const char *crm_ipc_buffer(crm_ipc_t * client);
uint32_t crm_ipc_buffer_flags(crm_ipc_t * client);
const char *crm_ipc_name(crm_ipc_t * client);
unsigned int crm_ipc_default_buffer_size(void);

/*!
 * \brief Check the authenticity of the IPC socket peer process
 *
 * If everything goes well, peer's authenticity is verified by the means
 * of comparing against provided referential UID and GID (either satisfies),
 * and the result of this check can be deduced from the return value.
 * As an exception, detected UID of 0 ("root") satisfies arbitrary
 * provided referential daemon's credentials.
 *
 * \param[in]  sock    IPC related, connected Unix socket to check peer of
 * \param[in]  refuid  referential UID to check against
 * \param[in]  refgid  referential GID to check against
 * \param[out] gotpid  to optionally store obtained PID of the peer
 *                     (not available on FreeBSD, special value of 1
 *                     used instead, and the caller is required to
 *                     special case this value respectively)
 * \param[out] gotuid  to optionally store obtained UID of the peer
 * \param[out] gotgid  to optionally store obtained GID of the peer
 *
 * \return 0 if IPC related socket's peer is not authentic given the
 *         referential credentials (see above), 1 if it is,
 *         negative value on error (generally expressing -errno unless
 *         it was zero even on nonhappy path, -pcmk_err_generic is
 *         returned then; no message is directly emitted)
 *
 * \note While this function is tolerant on what constitutes authorized
 *       IPC daemon process (its effective user matches UID=0 or \p refuid,
 *       or at least its group matches \p refroup), either or both (in case
 *       of UID=0) mismatches on the expected credentials of such peer
 *       process \e shall be investigated at the caller when value of 1
 *       gets returned there, since higher-than-expected privileges in
 *       respect to the expected/intended credentials possibly violate
 *       the least privilege principle and may pose an additional risk
 *       (i.e. such accidental inconsistency shall be eventually fixed).
 */
int crm_ipc_is_authentic_process(int sock, uid_t refuid, gid_t refgid,
                                 pid_t *gotpid, uid_t *gotuid, gid_t *gotgid);

/* Utils */
xmlNode *create_hello_message(const char *uuid, const char *client_name,
                              const char *major_version, const char *minor_version);

#ifdef __cplusplus
}
#endif

#endif
