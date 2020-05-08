/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#if defined(US_AUTH_PEERCRED_UCRED) || defined(US_AUTH_PEERCRED_SOCKPEERCRED)
#  ifdef US_AUTH_PEERCRED_UCRED
#    ifndef _GNU_SOURCE
#      define _GNU_SOURCE
#    endif
#  endif
#  include <sys/socket.h>
#elif defined(US_AUTH_GETPEERUCRED)
#  include <ucred.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <bzlib.h>

#include <crm/crm.h>   /* indirectly: pcmk_err_generic */
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include "crmcommon_private.h"

struct crm_ipc_s {
    struct pollfd pfd;
    unsigned int max_buf_size; // maximum bytes we can send or receive over IPC
    unsigned int buf_size;     // size of allocated buffer
    int msg_size;
    int need_reply;
    char *buffer;
    char *name;
    qb_ipcc_connection_t *ipc;
};

crm_ipc_t *
crm_ipc_new(const char *name, size_t max_size)
{
    crm_ipc_t *client = NULL;

    client = calloc(1, sizeof(crm_ipc_t));

    client->name = strdup(name);
    client->buf_size = pcmk__ipc_buffer_size(max_size);
    client->buffer = malloc(client->buf_size);

    /* Clients initiating connection pick the max buf size */
    client->max_buf_size = client->buf_size;

    client->pfd.fd = -1;
    client->pfd.events = POLLIN;
    client->pfd.revents = 0;

    return client;
}

/*!
 * \brief Establish an IPC connection to a Pacemaker component
 *
 * \param[in] client  Connection instance obtained from crm_ipc_new()
 *
 * \return TRUE on success, FALSE otherwise (in which case errno will be set;
 *         specifically, in case of discovering the remote side is not
 *         authentic, its value is set to ECONNABORTED).
 */
bool
crm_ipc_connect(crm_ipc_t * client)
{
    uid_t cl_uid = 0;
    gid_t cl_gid = 0;
    pid_t found_pid = 0; uid_t found_uid = 0; gid_t found_gid = 0;
    int rv;

    client->need_reply = FALSE;
    client->ipc = qb_ipcc_connect(client->name, client->buf_size);

    if (client->ipc == NULL) {
        crm_debug("Could not establish %s connection: %s (%d)", client->name, pcmk_strerror(errno), errno);
        return FALSE;
    }

    client->pfd.fd = crm_ipc_get_fd(client);
    if (client->pfd.fd < 0) {
        rv = errno;
        /* message already omitted */
        crm_ipc_close(client);
        errno = rv;
        return FALSE;
    }

    rv = pcmk_daemon_user(&cl_uid, &cl_gid);
    if (rv < 0) {
        /* message already omitted */
        crm_ipc_close(client);
        errno = -rv;
        return FALSE;
    }

    if (!(rv = crm_ipc_is_authentic_process(client->pfd.fd, cl_uid, cl_gid,
                                            &found_pid, &found_uid,
                                            &found_gid))) {
        crm_err("Daemon (IPC %s) is not authentic:"
                " process %lld (uid: %lld, gid: %lld)",
                client->name,  (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        crm_ipc_close(client);
        errno = ECONNABORTED;
        return FALSE;

    } else if (rv < 0) {
        errno = -rv;
        crm_perror(LOG_ERR, "Could not verify authenticity of daemon (IPC %s)",
                   client->name);
        crm_ipc_close(client);
        errno = -rv;
        return FALSE;
    }

    qb_ipcc_context_set(client->ipc, client);

#ifdef HAVE_IPCS_GET_BUFFER_SIZE
    client->max_buf_size = qb_ipcc_get_buffer_size(client->ipc);
    if (client->max_buf_size > client->buf_size) {
        free(client->buffer);
        client->buffer = calloc(1, client->max_buf_size);
        client->buf_size = client->max_buf_size;
    }
#endif

    return TRUE;
}

void
crm_ipc_close(crm_ipc_t * client)
{
    if (client) {
        crm_trace("Disconnecting %s IPC connection %p (%p)", client->name, client, client->ipc);

        if (client->ipc) {
            qb_ipcc_connection_t *ipc = client->ipc;

            client->ipc = NULL;
            qb_ipcc_disconnect(ipc);
        }
    }
}

void
crm_ipc_destroy(crm_ipc_t * client)
{
    if (client) {
        if (client->ipc && qb_ipcc_is_connected(client->ipc)) {
            crm_notice("Destroying an active IPC connection to %s", client->name);
            /* The next line is basically unsafe
             *
             * If this connection was attached to mainloop and mainloop is active,
             *   the 'disconnected' callback will end up back here and we'll end
             *   up free'ing the memory twice - something that can still happen
             *   even without this if we destroy a connection and it closes before
             *   we call exit
             */
            /* crm_ipc_close(client); */
        }
        crm_trace("Destroying IPC connection to %s: %p", client->name, client);
        free(client->buffer);
        free(client->name);
        free(client);
    }
}

int
crm_ipc_get_fd(crm_ipc_t * client)
{
    int fd = 0;

    if (client && client->ipc && (qb_ipcc_fd_get(client->ipc, &fd) == 0)) {
        return fd;
    }
    errno = EINVAL;
    crm_perror(LOG_ERR, "Could not obtain file IPC descriptor for %s",
               (client? client->name : "unspecified client"));
    return -errno;
}

bool
crm_ipc_connected(crm_ipc_t * client)
{
    bool rc = FALSE;

    if (client == NULL) {
        crm_trace("No client");
        return FALSE;

    } else if (client->ipc == NULL) {
        crm_trace("No connection");
        return FALSE;

    } else if (client->pfd.fd < 0) {
        crm_trace("Bad descriptor");
        return FALSE;
    }

    rc = qb_ipcc_is_connected(client->ipc);
    if (rc == FALSE) {
        client->pfd.fd = -EINVAL;
    }
    return rc;
}

/*!
 * \brief Check whether an IPC connection is ready to be read
 *
 * \param[in] client  Connection to check
 *
 * \return Positive value if ready to be read, 0 if not ready, -errno on error
 */
int
crm_ipc_ready(crm_ipc_t *client)
{
    int rc;

    CRM_ASSERT(client != NULL);

    if (crm_ipc_connected(client) == FALSE) {
        return -ENOTCONN;
    }

    client->pfd.revents = 0;
    rc = poll(&(client->pfd), 1, 0);
    return (rc < 0)? -errno : rc;
}

// \return Standard Pacemaker return code
static int
crm_ipc_decompress(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = (pcmk__ipc_header_t *)(void*)client->buffer;

    if (header->size_compressed) {
        int rc = 0;
        unsigned int size_u = 1 + header->size_uncompressed;
        /* never let buf size fall below our max size required for ipc reads. */
        unsigned int new_buf_size = QB_MAX((sizeof(pcmk__ipc_header_t) + size_u), client->max_buf_size);
        char *uncompressed = calloc(1, new_buf_size);

        crm_trace("Decompressing message data %u bytes into %u bytes",
                 header->size_compressed, size_u);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed + sizeof(pcmk__ipc_header_t), &size_u,
                                        client->buffer + sizeof(pcmk__ipc_header_t), header->size_compressed, 1, 0);

        if (rc != BZ_OK) {
            crm_err("Decompression failed: %s " CRM_XS " bzerror=%d",
                    bz2_strerror(rc), rc);
            free(uncompressed);
            return EILSEQ;
        }

        /*
         * This assert no longer holds true.  For an identical msg, some clients may
         * require compression, and others may not. If that same msg (event) is sent
         * to multiple clients, it could result in some clients receiving a compressed
         * msg even though compression was not explicitly required for them.
         *
         * CRM_ASSERT((header->size_uncompressed + sizeof(pcmk__ipc_header_t)) >= ipc_buffer_max);
         */
        CRM_ASSERT(size_u == header->size_uncompressed);

        memcpy(uncompressed, client->buffer, sizeof(pcmk__ipc_header_t));       /* Preserve the header */
        header = (pcmk__ipc_header_t *)(void*)uncompressed;

        free(client->buffer);
        client->buf_size = new_buf_size;
        client->buffer = uncompressed;
    }

    CRM_ASSERT(client->buffer[sizeof(pcmk__ipc_header_t) + header->size_uncompressed - 1] == 0);
    return pcmk_rc_ok;
}

long
crm_ipc_read(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = NULL;

    CRM_ASSERT(client != NULL);
    CRM_ASSERT(client->ipc != NULL);
    CRM_ASSERT(client->buffer != NULL);

    client->buffer[0] = 0;
    client->msg_size = qb_ipcc_event_recv(client->ipc, client->buffer,
                                          client->buf_size, 0);
    if (client->msg_size >= 0) {
        int rc = crm_ipc_decompress(client);

        if (rc != pcmk_rc_ok) {
            return pcmk_rc2legacy(rc);
        }

        header = (pcmk__ipc_header_t *)(void*)client->buffer;
        if (!pcmk__valid_ipc_header(header)) {
            return -EBADMSG;
        }

        crm_trace("Received %s event %d, size=%u, rc=%d, text: %.100s",
                  client->name, header->qb.id, header->qb.size, client->msg_size,
                  client->buffer + sizeof(pcmk__ipc_header_t));

    } else {
        crm_trace("No message from %s received: %s", client->name, pcmk_strerror(client->msg_size));
    }

    if (crm_ipc_connected(client) == FALSE || client->msg_size == -ENOTCONN) {
        crm_err("Connection to %s failed", client->name);
    }

    if (header) {
        /* Data excluding the header */
        return header->size_uncompressed;
    }
    return -ENOMSG;
}

const char *
crm_ipc_buffer(crm_ipc_t * client)
{
    CRM_ASSERT(client != NULL);
    return client->buffer + sizeof(pcmk__ipc_header_t);
}

uint32_t
crm_ipc_buffer_flags(crm_ipc_t * client)
{
    pcmk__ipc_header_t *header = NULL;

    CRM_ASSERT(client != NULL);
    if (client->buffer == NULL) {
        return 0;
    }

    header = (pcmk__ipc_header_t *)(void*)client->buffer;
    return header->flags;
}

const char *
crm_ipc_name(crm_ipc_t * client)
{
    CRM_ASSERT(client != NULL);
    return client->name;
}

// \return Standard Pacemaker return code
static int
internal_ipc_get_reply(crm_ipc_t *client, int request_id, int ms_timeout,
                       ssize_t *bytes)
{
    time_t timeout = time(NULL) + 1 + (ms_timeout / 1000);
    int rc = pcmk_rc_ok;

    /* get the reply */
    crm_trace("client %s waiting on reply to msg id %d", client->name, request_id);
    do {

        *bytes = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, 1000);
        if (*bytes > 0) {
            pcmk__ipc_header_t *hdr = NULL;

            rc = crm_ipc_decompress(client);
            if (rc != pcmk_rc_ok) {
                return rc;
            }

            hdr = (pcmk__ipc_header_t *)(void*)client->buffer;
            if (hdr->qb.id == request_id) {
                /* Got it */
                break;
            } else if (hdr->qb.id < request_id) {
                xmlNode *bad = string2xml(crm_ipc_buffer(client));

                crm_err("Discarding old reply %d (need %d)", hdr->qb.id, request_id);
                crm_log_xml_notice(bad, "OldIpcReply");

            } else {
                xmlNode *bad = string2xml(crm_ipc_buffer(client));

                crm_err("Discarding newer reply %d (need %d)", hdr->qb.id, request_id);
                crm_log_xml_notice(bad, "ImpossibleReply");
                CRM_ASSERT(hdr->qb.id <= request_id);
            }
        } else if (crm_ipc_connected(client) == FALSE) {
            crm_err("Server disconnected client %s while waiting for msg id %d", client->name,
                    request_id);
            break;
        }

    } while (time(NULL) < timeout);

    if (*bytes < 0) {
        rc = (int) -*bytes; // System errno
    }
    return rc;
}

/*!
 * \brief Send an IPC XML message
 *
 * \param[in]  client      Connection to IPC server
 * \param[in]  message     XML message to send
 * \param[in]  flags       Bitmask of crm_ipc_flags
 * \param[in]  ms_timeout  Give up if not sent within this much time
 *                         (5 seconds if 0, or no timeout if negative)
 * \param[out] reply       Reply from server (or NULL if none)
 *
 * \return Negative errno on error, otherwise size of reply received in bytes
 *         if reply was needed, otherwise number of bytes sent
 */
int
crm_ipc_send(crm_ipc_t * client, xmlNode * message, enum crm_ipc_flags flags, int32_t ms_timeout,
             xmlNode ** reply)
{
    int rc = 0;
    ssize_t qb_rc = 0;
    ssize_t bytes = 0;
    struct iovec *iov;
    static uint32_t id = 0;
    static int factor = 8;
    pcmk__ipc_header_t *header;

    if (client == NULL) {
        crm_notice("Can't send IPC request without connection (bug?): %.100s",
                   message);
        return -ENOTCONN;

    } else if (crm_ipc_connected(client) == FALSE) {
        /* Don't even bother */
        crm_notice("Can't send IPC request to %s: Connection closed",
                   client->name);
        return -ENOTCONN;
    }

    if (ms_timeout == 0) {
        ms_timeout = 5000;
    }

    if (client->need_reply) {
        qb_rc = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, ms_timeout);
        if (qb_rc < 0) {
            crm_warn("Sending IPC to %s disabled until pending reply received",
                     client->name);
            return -EALREADY;

        } else {
            crm_notice("Sending IPC to %s re-enabled after pending reply received",
                       client->name);
            client->need_reply = FALSE;
        }
    }

    id++;
    CRM_LOG_ASSERT(id != 0); /* Crude wrap-around detection */
    rc = pcmk__ipc_prepare_iov(id, message, client->max_buf_size, &iov, &bytes);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't prepare IPC request to %s: %s " CRM_XS " rc=%d",
                 client->name, pcmk_rc_str(rc), rc);
        return pcmk_rc2legacy(rc);
    }

    header = iov[0].iov_base;
    header->flags |= flags;

    if(is_set(flags, crm_ipc_proxied)) {
        /* Don't look for a synchronous response */
        clear_bit(flags, crm_ipc_client_response);
    }

    if(header->size_compressed) {
        if(factor < 10 && (client->max_buf_size / 10) < (bytes / factor)) {
            crm_notice("Compressed message exceeds %d0%% of configured IPC "
                       "limit (%u bytes); consider setting PCMK_ipc_buffer to "
                       "%u or higher",
                       factor, client->max_buf_size, 2 * client->max_buf_size);
            factor++;
        }
    }

    crm_trace("Sending %s IPC request %d of %u bytes using %dms timeout",
              client->name, header->qb.id, header->qb.size, ms_timeout);

    if (ms_timeout > 0 || is_not_set(flags, crm_ipc_client_response)) {

        time_t timeout = time(NULL) + 1 + (ms_timeout / 1000);

        do {
            /* @TODO Is this check really needed? Won't qb_ipcc_sendv() return
             * an error if it's not connected?
             */
            if (!crm_ipc_connected(client)) {
                goto send_cleanup;
            }

            qb_rc = qb_ipcc_sendv(client->ipc, iov, 2);
        } while ((qb_rc == -EAGAIN) && (time(NULL) < timeout));

        rc = (int) qb_rc; // Negative of system errno, or bytes sent
        if (qb_rc <= 0) {
            goto send_cleanup;

        } else if (is_not_set(flags, crm_ipc_client_response)) {
            crm_trace("Not waiting for reply to %s IPC request %d",
                      client->name, header->qb.id);
            goto send_cleanup;
        }

        rc = internal_ipc_get_reply(client, header->qb.id, ms_timeout, &bytes);
        if (rc != pcmk_rc_ok) {
            /* We didn't get the reply in time, so disable future sends for now.
             * The only alternative would be to close the connection since we
             * don't know how to detect and discard out-of-sequence replies.
             *
             * @TODO Implement out-of-sequence detection
             */
            client->need_reply = TRUE;
        }
        rc = (int) bytes; // Negative system errno, or size of reply received

    } else {
        // No timeout, and client response needed
        do {
            qb_rc = qb_ipcc_sendv_recv(client->ipc, iov, 2, client->buffer,
                                       client->buf_size, -1);
        } while ((qb_rc == -EAGAIN) && crm_ipc_connected(client));
        rc = (int) qb_rc; // Negative system errno, or size of reply received
    }

    if (rc > 0) {
        pcmk__ipc_header_t *hdr = (pcmk__ipc_header_t *)(void*)client->buffer;

        crm_trace("Received %d-byte reply %d to %s IPC %d: %.100s",
                  rc, hdr->qb.id, client->name, header->qb.id,
                  crm_ipc_buffer(client));

        if (reply) {
            *reply = string2xml(crm_ipc_buffer(client));
        }

    } else {
        crm_trace("No reply to %s IPC %d: rc=%d",
                  client->name, header->qb.id, rc);
    }

  send_cleanup:
    if (crm_ipc_connected(client) == FALSE) {
        crm_notice("Couldn't send %s IPC request %d: Connection closed "
                   CRM_XS " rc=%d", client->name, header->qb.id, rc);

    } else if (rc == -ETIMEDOUT) {
        crm_warn("%s IPC request %d failed: %s after %dms " CRM_XS " rc=%d",
                 client->name, header->qb.id, pcmk_strerror(rc), ms_timeout,
                 rc);
        crm_write_blackbox(0, NULL);

    } else if (rc <= 0) {
        crm_warn("%s IPC request %d failed: %s " CRM_XS " rc=%d",
                 client->name, header->qb.id,
                 ((rc == 0)? "No bytes sent" : pcmk_strerror(rc)), rc);
    }

    pcmk_free_ipc_event(iov);
    return rc;
}

int
crm_ipc_is_authentic_process(int sock, uid_t refuid, gid_t refgid,
                             pid_t *gotpid, uid_t *gotuid, gid_t *gotgid) {
    int ret = 0;
    pid_t found_pid = 0; uid_t found_uid = 0; gid_t found_gid = 0;
#if defined(US_AUTH_PEERCRED_UCRED)
    struct ucred ucred;
    socklen_t ucred_len = sizeof(ucred);

    if (!getsockopt(sock, SOL_SOCKET, SO_PEERCRED,
                    &ucred, &ucred_len)
                && ucred_len == sizeof(ucred)) {
        found_pid = ucred.pid; found_uid = ucred.uid; found_gid = ucred.gid;

#elif defined(US_AUTH_PEERCRED_SOCKPEERCRED)
    struct sockpeercred sockpeercred;
    socklen_t sockpeercred_len = sizeof(sockpeercred);

    if (!getsockopt(sock, SOL_SOCKET, SO_PEERCRED,
                    &sockpeercred, &sockpeercred_len)
                && sockpeercred_len == sizeof(sockpeercred_len)) {
        found_pid = sockpeercred.pid;
        found_uid = sockpeercred.uid; found_gid = sockpeercred.gid;

#elif defined(US_AUTH_GETPEEREID)
    if (!getpeereid(sock, &found_uid, &found_gid)) {
        found_pid = PCMK__SPECIAL_PID;  /* cannot obtain PID (FreeBSD) */

#elif defined(US_AUTH_GETPEERUCRED)
    ucred_t *ucred;
    if (!getpeerucred(sock, &ucred)) {
        errno = 0;
        found_pid = ucred_getpid(ucred);
        found_uid = ucred_geteuid(ucred); found_gid = ucred_getegid(ucred);
        ret = -errno;
        ucred_free(ucred);
        if (ret) {
            return (ret < 0) ? ret : -pcmk_err_generic;
        }

#else
#  error "No way to authenticate a Unix socket peer"
    errno = 0;
    if (0) {
#endif
        if (gotpid != NULL) {
            *gotpid = found_pid;
        }
        if (gotuid != NULL) {
            *gotuid = found_uid;
        }
        if (gotgid != NULL) {
            *gotgid = found_gid;
        }
        ret = (found_uid == 0 || found_uid == refuid || found_gid == refgid);
    } else {
        ret = (errno > 0) ? -errno : -pcmk_err_generic;
    }

    return ret;
}

int
pcmk__ipc_is_authentic_process_active(const char *name, uid_t refuid,
                                      gid_t refgid, pid_t *gotpid)
{
    static char last_asked_name[PATH_MAX / 2] = "";  /* log spam prevention */
    int fd;
    int rc = pcmk_rc_ipc_unresponsive;
    int auth_rc = 0;
    int32_t qb_rc;
    pid_t found_pid = 0; uid_t found_uid = 0; gid_t found_gid = 0;
    qb_ipcc_connection_t *c;

    c = qb_ipcc_connect(name, 0);
    if (c == NULL) {
        crm_info("Could not connect to %s IPC: %s", name, strerror(errno));
        rc = pcmk_rc_ipc_unresponsive;
        goto bail;
    }

    qb_rc = qb_ipcc_fd_get(c, &fd);
    if (qb_rc != 0) {
        rc = (int) -qb_rc; // System errno
        crm_err("Could not get fd from %s IPC: %s " CRM_XS " rc=%d",
                name, pcmk_rc_str(rc), rc);
        goto bail;
    }

    auth_rc = crm_ipc_is_authentic_process(fd, refuid, refgid, &found_pid,
                                           &found_uid, &found_gid);
    if (auth_rc < 0) {
        rc = pcmk_legacy2rc(auth_rc);
        crm_err("Could not get peer credentials from %s IPC: %s "
                CRM_XS " rc=%d", name, pcmk_rc_str(rc), rc);
        goto bail;
    }

    if (gotpid != NULL) {
        *gotpid = found_pid;
    }

    if (auth_rc == 0) {
        crm_err("Daemon (IPC %s) effectively blocked with unauthorized"
                " process %lld (uid: %lld, gid: %lld)",
                name, (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        rc = pcmk_rc_ipc_unauthorized;
        goto bail;
    }

    rc = pcmk_rc_ok;
    if ((found_uid != refuid || found_gid != refgid)
            && strncmp(last_asked_name, name, sizeof(last_asked_name))) {
        if ((found_uid == 0) && (refuid != 0)) {
            crm_warn("Daemon (IPC %s) runs as root, whereas the expected"
                     " credentials are %lld:%lld, hazard of violating"
                     " the least privilege principle",
                     name, (long long) refuid, (long long) refgid);
        } else {
            crm_notice("Daemon (IPC %s) runs as %lld:%lld, whereas the"
                       " expected credentials are %lld:%lld, which may"
                       " mean a different set of privileges than expected",
                       name, (long long) found_uid, (long long) found_gid,
                       (long long) refuid, (long long) refgid);
        }
        memccpy(last_asked_name, name, '\0', sizeof(last_asked_name));
    }

bail:
    if (c != NULL) {
        qb_ipcc_disconnect(c);
    }
    return rc;
}

xmlNode *
create_hello_message(const char *uuid,
                     const char *client_name, const char *major_version, const char *minor_version)
{
    xmlNode *hello_node = NULL;
    xmlNode *hello = NULL;

    if (pcmk__str_empty(uuid) || pcmk__str_empty(client_name)
        || pcmk__str_empty(major_version) || pcmk__str_empty(minor_version)) {
        crm_err("Could not create IPC hello message from %s (UUID %s): "
                "missing information",
                client_name? client_name : "unknown client",
                uuid? uuid : "unknown");
        return NULL;
    }

    hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
    if (hello_node == NULL) {
        crm_err("Could not create IPC hello message from %s (UUID %s): "
                "Message data creation failed", client_name, uuid);
        return NULL;
    }

    crm_xml_add(hello_node, "major_version", major_version);
    crm_xml_add(hello_node, "minor_version", minor_version);
    crm_xml_add(hello_node, "client_name", client_name);
    crm_xml_add(hello_node, "client_uuid", uuid);

    hello = create_request(CRM_OP_HELLO, hello_node, NULL, NULL, client_name, uuid);
    if (hello == NULL) {
        crm_err("Could not create IPC hello message from %s (UUID %s): "
                "Request creation failed", client_name, uuid);
        return NULL;
    }
    free_xml(hello_node);

    crm_trace("Created hello message from %s (UUID %s)", client_name, uuid);
    return hello;
}
