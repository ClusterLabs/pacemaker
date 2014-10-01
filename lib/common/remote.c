/*
 * Copyright (c) 2008 Andrew Beekhof
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include <crm_internal.h>
#include <crm/crm.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>

#include <bzlib.h>

#include <crm/common/ipcs.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>

const int psk_tls_kx_order[] = {
    GNUTLS_KX_DHE_PSK,
    GNUTLS_KX_PSK,
};

const int anon_tls_kx_order[] = {
    GNUTLS_KX_ANON_DH,
    GNUTLS_KX_DHE_RSA,
    GNUTLS_KX_DHE_DSS,
    GNUTLS_KX_RSA,
    0
};
#endif

/* Swab macros from linux/swab.h */
#ifdef HAVE_LINUX_SWAB_H
#  include <linux/swab.h>
#else
/*
 * casts are necessary for constants, because we never know how for sure
 * how U/UL/ULL map to __u16, __u32, __u64. At least not in a portable way.
 */
#define __swab16(x) ((uint16_t)(                                      \
        (((uint16_t)(x) & (uint16_t)0x00ffU) << 8) |                  \
        (((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))

#define __swab32(x) ((uint32_t)(                                      \
        (((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) |            \
        (((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) |            \
        (((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) |            \
        (((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#define __swab64(x) ((uint64_t)(                                      \
        (((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) |   \
        (((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) |   \
        (((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) |   \
        (((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) |   \
        (((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) |   \
        (((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) |   \
        (((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) |   \
        (((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56)))
#endif

#define REMOTE_MSG_VERSION 1
#define ENDIAN_LOCAL 0xBADADBBD

struct crm_remote_header_v0 
{
    uint32_t endian;    /* Detect messages from hosts with different endian-ness */
    uint32_t version;
    uint64_t id;
    uint64_t flags;
    uint32_t size_total;
    uint32_t payload_offset;
    uint32_t payload_compressed;
    uint32_t payload_uncompressed;

        /* New fields get added here */

} __attribute__ ((packed));

static struct crm_remote_header_v0 *
crm_remote_header(crm_remote_t * remote)
{
    struct crm_remote_header_v0 *header = (struct crm_remote_header_v0 *)remote->buffer;
    if(remote->buffer_offset < sizeof(struct crm_remote_header_v0)) {
        return NULL;

    } else if(header->endian != ENDIAN_LOCAL) {
        uint32_t endian = __swab32(header->endian);

        CRM_LOG_ASSERT(endian == ENDIAN_LOCAL);
        if(endian != ENDIAN_LOCAL) {
            crm_err("Invalid message detected, endian mismatch: %lx is neither %lx nor the swab'd %lx",
                    ENDIAN_LOCAL, header->endian, endian);
            return NULL;
        }

        header->id = __swab64(header->id);
        header->flags = __swab64(header->flags);
        header->endian = __swab32(header->endian);

        header->version = __swab32(header->version);
        header->size_total = __swab32(header->size_total);
        header->payload_offset = __swab32(header->payload_offset);
        header->payload_compressed = __swab32(header->payload_compressed);
        header->payload_uncompressed = __swab32(header->payload_uncompressed);
    }

    return header;
}

#ifdef HAVE_GNUTLS_GNUTLS_H

int
crm_initiate_client_tls_handshake(crm_remote_t * remote, int timeout_ms)
{
    int rc = 0;
    int pollrc = 0;
    time_t start = time(NULL);

    do {
        rc = gnutls_handshake(*remote->tls_session);
        if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
            pollrc = crm_remote_ready(remote, 1000);
            if (pollrc < 0) {
                /* poll returned error, there is no hope */
                rc = -1;
            }
        }

    } while (((time(NULL) - start) < (timeout_ms / 1000)) &&
             (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN));

    if (rc < 0) {
        crm_trace("gnutls_handshake() failed with %d", rc);
    }
    return rc;
}

void *
crm_create_anon_tls_session(int csock, int type /* GNUTLS_SERVER, GNUTLS_CLIENT */ ,
                            void *credentials)
{
    gnutls_session_t *session = gnutls_malloc(sizeof(gnutls_session_t));

    gnutls_init(session, type);
#  ifdef HAVE_GNUTLS_PRIORITY_SET_DIRECT
/*      http://www.manpagez.com/info/gnutls/gnutls-2.10.4/gnutls_81.php#Echo-Server-with-anonymous-authentication */
    gnutls_priority_set_direct(*session, "NORMAL:+ANON-DH", NULL);
/*	gnutls_priority_set_direct (*session, "NONE:+VERS-TLS-ALL:+CIPHER-ALL:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ANON-DH", NULL); */
#  else
    gnutls_set_default_priority(*session);
    gnutls_kx_set_priority(*session, anon_tls_kx_order);
#  endif
    gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t) GINT_TO_POINTER(csock));
    switch (type) {
        case GNUTLS_SERVER:
            gnutls_credentials_set(*session, GNUTLS_CRD_ANON,
                                   (gnutls_anon_server_credentials_t) credentials);
            break;
        case GNUTLS_CLIENT:
            gnutls_credentials_set(*session, GNUTLS_CRD_ANON,
                                   (gnutls_anon_client_credentials_t) credentials);
            break;
    }

    return session;
}

void *
create_psk_tls_session(int csock, int type /* GNUTLS_SERVER, GNUTLS_CLIENT */ , void *credentials)
{
    gnutls_session_t *session = gnutls_malloc(sizeof(gnutls_session_t));

    gnutls_init(session, type);
#  ifdef HAVE_GNUTLS_PRIORITY_SET_DIRECT
    gnutls_priority_set_direct(*session, "NORMAL:+DHE-PSK:+PSK", NULL);
#  else
    gnutls_set_default_priority(*session);
    gnutls_kx_set_priority(*session, psk_tls_kx_order);
#  endif
    gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t) GINT_TO_POINTER(csock));
    switch (type) {
        case GNUTLS_SERVER:
            gnutls_credentials_set(*session, GNUTLS_CRD_PSK,
                                   (gnutls_psk_server_credentials_t) credentials);
            break;
        case GNUTLS_CLIENT:
            gnutls_credentials_set(*session, GNUTLS_CRD_PSK,
                                   (gnutls_psk_client_credentials_t) credentials);
            break;
    }

    return session;
}

static int
crm_send_tls(gnutls_session_t * session, const char *buf, size_t len)
{
    const char *unsent = buf;
    int rc = 0;
    int total_send;

    if (buf == NULL) {
        return -1;
    }

    total_send = len;
    crm_trace("Message size: %d", len);

    while (TRUE) {
        rc = gnutls_record_send(*session, unsent, len);

        if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
            crm_debug("Retry");

        } else if (rc < 0) {
            crm_err("Connection terminated rc = %d", rc);
            break;

        } else if (rc < len) {
            crm_debug("Only sent %d of %d bytes", rc, len);
            len -= rc;
            unsent += rc;
        } else {
            crm_debug("Sent %d bytes", rc);
            break;
        }
    }

    return rc < 0 ? rc : total_send;
}
#endif

static int
crm_send_plaintext(int sock, const char *buf, size_t len)
{

    int rc = 0;
    const char *unsent = buf;
    int total_send;

    if (buf == NULL) {
        return -1;
    }
    total_send = len;

    crm_trace("Message on socket %d: size=%d", sock, len);
  retry:
    rc = write(sock, unsent, len);
    if (rc < 0) {
        switch (errno) {
            case EINTR:
            case EAGAIN:
                crm_trace("Retry");
                goto retry;
            default:
                crm_perror(LOG_ERR, "Could only write %d of the remaining %d bytes", rc, (int)len);
                break;
        }

    } else if (rc < len) {
        crm_trace("Only sent %d of %d remaining bytes", rc, len);
        len -= rc;
        unsent += rc;
        goto retry;

    } else {
        crm_trace("Sent %d bytes: %.100s", rc, buf);
    }

    return rc < 0 ? rc : total_send;

}

static int
crm_remote_sendv(crm_remote_t * remote, struct iovec * iov, int iovs)
{
    int lpc = 0;
    int rc = -ESOCKTNOSUPPORT;

    for(; lpc < iovs; lpc++) {
        if (remote->tcp_socket) {
            rc = crm_send_plaintext(remote->tcp_socket, iov[lpc].iov_base, iov[lpc].iov_len);
#ifdef HAVE_GNUTLS_GNUTLS_H

        } else if (remote->tls_session) {
            rc = crm_send_tls(remote->tls_session, iov[lpc].iov_base, iov[lpc].iov_len);
#endif
        } else {
            crm_err("Unsupported connection type");
        }
    }
    return rc;
}

int
crm_remote_send(crm_remote_t * remote, xmlNode * msg)
{
    int rc = -1;
    static uint64_t id = 0;
    char *xml_text = dump_xml_unformatted(msg);

    struct iovec iov[2];
    struct crm_remote_header_v0 *header;

    if (xml_text == NULL) {
        crm_err("Invalid XML, can not send msg");
        return -1;
    }

    header = calloc(1, sizeof(struct crm_remote_header_v0));
    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(struct crm_remote_header_v0);

    iov[1].iov_base = xml_text;
    iov[1].iov_len = 1 + strlen(xml_text);

    id++;
    header->id = id;
    header->endian = ENDIAN_LOCAL;
    header->version = REMOTE_MSG_VERSION;
    header->payload_offset = iov[0].iov_len;
    header->payload_uncompressed = iov[1].iov_len;
    header->size_total = iov[0].iov_len + iov[1].iov_len;

    crm_trace("Sending len[0]=%d, start=%x\n",
              (int)iov[0].iov_len, *(int*)(void*)xml_text);
    rc = crm_remote_sendv(remote, iov, 2);
    if (rc < 0) {
        crm_err("Failed to send remote msg, rc = %d", rc);
    }

    free(iov[0].iov_base);
    free(iov[1].iov_base);
    return rc;
}


/*!
 * \internal
 * \brief handles the recv buffer and parsing out msgs.
 * \note new_data is owned by this function once it is passed in.
 */
xmlNode *
crm_remote_parse_buffer(crm_remote_t * remote)
{
    xmlNode *xml = NULL;
    struct crm_remote_header_v0 *header = crm_remote_header(remote);

    if (remote->buffer == NULL || header == NULL) {
        return NULL;
    }

    /* take ownership of the buffer */
    remote->buffer_offset = 0;

    /* Support compression on the receiving end now, in case we ever want to add it later */
    if (header->payload_compressed) {
        int rc = 0;
        unsigned int size_u = 1 + header->payload_uncompressed;
        char *uncompressed = calloc(1, header->payload_offset + size_u);

        crm_trace("Decompressing message data %d bytes into %d bytes",
                 header->payload_compressed, size_u);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed + header->payload_offset, &size_u,
                                        remote->buffer + header->payload_offset,
                                        header->payload_compressed, 1, 0);

        if (rc != BZ_OK && header->version > REMOTE_MSG_VERSION) {
            crm_warn("Couldn't decompress v%d message, we only understand v%d",
                     header->version, REMOTE_MSG_VERSION);
            free(uncompressed);
            return NULL;

        } else if (rc != BZ_OK) {
            crm_err("Decompression failed: %s (%d)", bz2_strerror(rc), rc);
            free(uncompressed);
            return NULL;
        }

        CRM_ASSERT(size_u == header->payload_uncompressed);

        memcpy(uncompressed, remote->buffer, header->payload_offset);       /* Preserve the header */
        remote->buffer_size = header->payload_offset + size_u;

        free(remote->buffer);
        remote->buffer = uncompressed;
        header = crm_remote_header(remote);
    }

    CRM_LOG_ASSERT(remote->buffer[sizeof(struct crm_remote_header_v0) + header->payload_uncompressed - 1] == 0);

    xml = string2xml(remote->buffer + header->payload_offset);
    if (xml == NULL && header->version > REMOTE_MSG_VERSION) {
        crm_warn("Couldn't parse v%d message, we only understand v%d",
                 header->version, REMOTE_MSG_VERSION);

    } else if (xml == NULL) {
        crm_err("Couldn't parse: '%.120s'", remote->buffer + header->payload_offset);
    }

    return xml;
}

/*!
 * \internal
 * \brief Determine if a remote session has data to read
 *
 * \retval 0, timeout occured.
 * \retval positive, data is ready to be read
 * \retval negative, session has ended
 */
int
crm_remote_ready(crm_remote_t * remote, int timeout /* ms */ )
{
    struct pollfd fds = { 0, };
    int sock = 0;
    int rc = 0;
    time_t start;

    if (remote->tcp_socket) {
        sock = remote->tcp_socket;
#ifdef HAVE_GNUTLS_GNUTLS_H
    } else if (remote->tls_session) {
        void *sock_ptr = gnutls_transport_get_ptr(*remote->tls_session);

        sock = GPOINTER_TO_INT(sock_ptr);
#endif
    } else {
        crm_err("Unsupported connection type");
    }

    if (sock <= 0) {
        crm_trace("No longer connected");
        return -ENOTCONN;
    }

    start = time(NULL);
    errno = 0;
    do {
        fds.fd = sock;
        fds.events = POLLIN;

        /* If we got an EINTR while polling, and we have a
         * specific timeout we are trying to honor, attempt
         * to adjust the timeout to the closest second. */
        if (errno == EINTR && (timeout > 0)) {
            timeout = timeout - ((time(NULL) - start) * 1000);
            if (timeout < 1000) {
                timeout = 1000;
            }
        }

        rc = poll(&fds, 1, timeout);
    } while (rc < 0 && errno == EINTR);

    return rc;
}


/*!
 * \internal
 * \brief Read bytes off non blocking remote connection.
 *
 * \note only use with NON-Blocking sockets. Should only be used after polling socket.
 *       This function will return once max_size is met, the socket read buffer
 *       is empty, or an error is encountered.
 *
 * \retval number of bytes received
 */
static size_t
crm_remote_recv_once(crm_remote_t * remote)
{
    int rc = 0;
    size_t read_len = sizeof(struct crm_remote_header_v0);
    struct crm_remote_header_v0 *header = crm_remote_header(remote);

    if(header) {
        /* Stop at the end of the current message */
        read_len = header->size_total;
    }

    /* automatically grow the buffer when needed */
    if(remote->buffer_size < read_len) {
           remote->buffer_size = 2 * read_len;
        crm_trace("Expanding buffer to %u bytes", remote->buffer_size);

        remote->buffer = realloc(remote->buffer, remote->buffer_size + 1);
        CRM_ASSERT(remote->buffer != NULL);
    }

    if (remote->tcp_socket) {
        errno = 0;
        rc = read(remote->tcp_socket,
                  remote->buffer + remote->buffer_offset,
                  remote->buffer_size - remote->buffer_offset);
        if(rc < 0) {
            rc = -errno;
        }

#ifdef HAVE_GNUTLS_GNUTLS_H
    } else if (remote->tls_session) {
        rc = gnutls_record_recv(*(remote->tls_session),
                                remote->buffer + remote->buffer_offset,
                                remote->buffer_size - remote->buffer_offset);
        if (rc == GNUTLS_E_INTERRUPTED) {
            rc = -EINTR;
        } else if (rc == GNUTLS_E_AGAIN) {
            rc = -EAGAIN;
        } else if (rc < 0) {
            crm_debug("TLS receive failed: %s (%d)", gnutls_strerror(rc), rc);
            rc = -pcmk_err_generic;
        }
#endif
    } else {
        crm_err("Unsupported connection type");
        return -ESOCKTNOSUPPORT;
    }

    /* process any errors. */
    if (rc > 0) {
        remote->buffer_offset += rc;
        /* always null terminate buffer, the +1 to alloc always allows for this. */
        remote->buffer[remote->buffer_offset] = '\0';
        crm_trace("Received %u more bytes, %u total", rc, remote->buffer_offset);

    } else if (rc == -EINTR || rc == -EAGAIN) {
        crm_trace("non-blocking, exiting read: %s (%d)", pcmk_strerror(rc), rc);

    } else if (rc == 0) {
        crm_debug("EOF encoutered after %u bytes", remote->buffer_offset);
        return -ENOTCONN;

    } else {
        crm_debug("Error receiving message after %u bytes: %s (%d)",
                  remote->buffer_offset, pcmk_strerror(rc), rc);
        return -ENOTCONN;
    }

    header = crm_remote_header(remote);
    if(header) {
        if(remote->buffer_offset < header->size_total) {
            crm_trace("Read less than the advertised length: %u < %u bytes",
                      remote->buffer_offset, header->size_total);
        } else {
            crm_trace("Read full message of %u bytes", remote->buffer_offset);
            return remote->buffer_offset;
        }
    }

    return -EAGAIN;
}

/*!
 * \internal
 * \brief Read data off the socket until at least one full message is present or timeout occures.
 * \retval TRUE message read
 * \retval FALSE full message not read
 */

gboolean
crm_remote_recv(crm_remote_t * remote, int total_timeout /*ms */ , int *disconnected)
{
    int rc;
    time_t start = time(NULL);
    int remaining_timeout = 0;

    if (total_timeout == 0) {
        total_timeout = 10000;
    } else if (total_timeout < 0) {
        total_timeout = 60000;
    }
    *disconnected = 0;

    remaining_timeout = total_timeout;
    while ((remaining_timeout > 0) && !(*disconnected)) {

        /* read some more off the tls buffer if we still have time left. */
        crm_trace("waiting to receive remote msg, starting timeout %d, remaining_timeout %d",
                  total_timeout, remaining_timeout);
        rc = crm_remote_ready(remote, remaining_timeout);

        if (rc == 0) {
            crm_err("poll timed out (%d ms) while waiting to receive msg", remaining_timeout);
            return FALSE;

        } else if(rc < 0) {
            crm_debug("poll() failed: %s (%d)", pcmk_strerror(rc), rc);

        } else {
            rc = crm_remote_recv_once(remote);
            if(rc > 0) {
                return TRUE;
            } else if (rc < 0) {
                crm_debug("recv() failed: %s (%d)", pcmk_strerror(rc), rc);
            }
        }

        if(rc == -ENOTCONN) {
            *disconnected = 1;
            return FALSE;
        }

        remaining_timeout = remaining_timeout - ((time(NULL) - start) * 1000);
    }

    return FALSE;
}

struct tcp_async_cb_data {
    gboolean success;
    int sock;
    void *userdata;
    void (*callback) (void *userdata, int sock);
    int timeout;                /*ms */
    time_t start;
};

static gboolean
check_connect_finished(gpointer userdata)
{
    struct tcp_async_cb_data *cb_data = userdata;
    int rc = 0;
    int sock = cb_data->sock;
    int error = 0;

    fd_set rset, wset;
    socklen_t len = sizeof(error);
    struct timeval ts = { 0, };

    if (cb_data->success == TRUE) {
        goto dispatch_done;
    }

    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    wset = rset;

    crm_trace("fd %d: checking to see if connect finished", sock);
    rc = select(sock + 1, &rset, &wset, NULL, &ts);

    if (rc < 0) {
        rc = errno;
        if ((errno == EINPROGRESS) || (errno == EAGAIN)) {
            /* reschedule if there is still time left */
            if ((time(NULL) - cb_data->start) < (cb_data->timeout / 1000)) {
                goto reschedule;
            } else {
                rc = -ETIMEDOUT;
            }
        }
        crm_trace("fd %d: select failed %d connect dispatch ", rc);
        goto dispatch_done;
    } else if (rc == 0) {
        if ((time(NULL) - cb_data->start) < (cb_data->timeout / 1000)) {
            goto reschedule;
        }
        crm_debug("fd %d: timeout during select", sock);
        rc = -ETIMEDOUT;
        goto dispatch_done;
    } else {
        crm_trace("fd %d: select returned success", sock);
        rc = 0;
    }

    /* can we read or write to the socket now? */
    if (FD_ISSET(sock, &rset) || FD_ISSET(sock, &wset)) {
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            crm_trace("fd %d: call to getsockopt failed", sock);
            rc = -1;
            goto dispatch_done;
        }

        if (error) {
            crm_trace("fd %d: error returned from getsockopt: %d", sock, error);
            rc = -1;
            goto dispatch_done;
        }
    } else {
        crm_trace("neither read nor write set after select");
        rc = -1;
        goto dispatch_done;
    }

  dispatch_done:
    if (!rc) {
        crm_trace("fd %d: connected", sock);
        /* Success, set the return code to the sock to report to the callback */
        rc = cb_data->sock;
        cb_data->sock = 0;
    } else {
        close(sock);
    }

    if (cb_data->callback) {
        cb_data->callback(cb_data->userdata, rc);
    }
    free(cb_data);
    return FALSE;

  reschedule:

    /* will check again next interval */
    return TRUE;
}

static int
internal_tcp_connect_async(int sock,
                           const struct sockaddr *addr, socklen_t addrlen, int timeout /* ms */ ,
                           int *timer_id, void *userdata, void (*callback) (void *userdata, int sock))
{
    int rc = 0;
    int flag = 0;
    int interval = 500;
    int timer;
    struct tcp_async_cb_data *cb_data = NULL;

    if ((flag = fcntl(sock, F_GETFL)) >= 0) {
        if (fcntl(sock, F_SETFL, flag | O_NONBLOCK) < 0) {
            crm_err("fcntl() write failed");
            return -1;
        }
    }

    rc = connect(sock, addr, addrlen);

    if (rc < 0 && (errno != EINPROGRESS) && (errno != EAGAIN)) {
        return -1;
    }

    cb_data = calloc(1, sizeof(struct tcp_async_cb_data));
    cb_data->userdata = userdata;
    cb_data->callback = callback;
    cb_data->sock = sock;
    cb_data->timeout = timeout;
    cb_data->start = time(NULL);

    if (rc == 0) {
        /* The connect was successful immediately, we still return to mainloop
         * and let this callback get called later. This avoids the user of this api
         * to have to account for the fact the callback could be invoked within this
         * function before returning. */
        cb_data->success = TRUE;
        interval = 1;
    }

    /* Check connect finished is mostly doing a non-block poll on the socket
     * to see if we can read/write to it. Once we can, the connect has completed.
     * This method allows us to connect to the server without blocking mainloop.
     *
     * This is a poor man's way of polling to see when the connection finished.
     * At some point we should figure out a way to use a mainloop fd callback for this.
     * Something about the way mainloop is currently polling prevents this from working at the
     * moment though. */
    crm_trace("fd %d: scheduling to check if connect finished in %dms second", sock, interval);
    timer = g_timeout_add(interval, check_connect_finished, cb_data);
    if (timer_id) {
        *timer_id = timer;
    }

    return 0;
}

static int
internal_tcp_connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
    int flag = 0;
    int rc = connect(sock, addr, addrlen);

    if (rc == 0) {
        if ((flag = fcntl(sock, F_GETFL)) >= 0) {
            if (fcntl(sock, F_SETFL, flag | O_NONBLOCK) < 0) {
                crm_err("fcntl() write failed");
                return -1;
            }
        }
    }

    return rc;
}

/*!
 * \internal
 * \brief tcp connection to server at specified port
 * \retval negative, failed to connect.
 * \retval positive, sock fd
 */
int
crm_remote_tcp_connect_async(const char *host, int port, int timeout, /*ms */
                             int *timer_id, void *userdata, void (*callback) (void *userdata, int sock))
{
    char buffer[256];
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    struct addrinfo hints;
    const char *server = host;
    int ret_ga;
    int sock = -1;

    /* getaddrinfo */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;        /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    crm_debug("Looking up %s", server);
    ret_ga = getaddrinfo(server, NULL, &hints, &res);
    if (ret_ga) {
        crm_err("getaddrinfo: %s", gai_strerror(ret_ga));
        return -1;
    }

    if (!res || !res->ai_addr) {
        crm_err("getaddrinfo failed");
        goto async_cleanup;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        struct sockaddr *addr = rp->ai_addr;

        if (!addr) {
            continue;
        }

        if (rp->ai_canonname) {
            server = res->ai_canonname;
        }
        crm_debug("Got address %s for %s", server, host);

        /* create socket */
        sock = socket(rp->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1) {
            crm_err("Socket creation failed for remote client connection.");
            continue;
        }

        memset(buffer, 0, DIMOF(buffer));
        if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)(void*)addr;

            addr_in->sin6_port = htons(port);
            inet_ntop(addr->sa_family, &addr_in->sin6_addr, buffer, DIMOF(buffer));

        } else {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)(void*)addr;

            addr_in->sin_port = htons(port);
            inet_ntop(addr->sa_family, &addr_in->sin_addr, buffer, DIMOF(buffer));
        }

        crm_info("Attempting to connect to remote server at %s:%d", buffer, port);

        if (callback) {
            if (internal_tcp_connect_async
                (sock, rp->ai_addr, rp->ai_addrlen, timeout, timer_id, userdata, callback) == 0) {
                goto async_cleanup; /* Success for now, we'll hear back later in the callback */
            }

        } else {
            if (internal_tcp_connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
                break;          /* Success */
            }
        }

        close(sock);
        sock = -1;
    }

async_cleanup:

    if (res) {
        freeaddrinfo(res);
    }
    return sock;
}

int
crm_remote_tcp_connect(const char *host, int port)
{
    return crm_remote_tcp_connect_async(host, port, -1, NULL, NULL, NULL);
}
