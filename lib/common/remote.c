/*
 * Copyright 2008-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
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
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>   // PRIx32

#include <glib.h>
#include <bzlib.h>

#include <crm/common/ipc_internal.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/remote_internal.h>
#include <crm/common/tls_internal.h>

#include <gnutls/gnutls.h>

#define REMOTE_MSG_VERSION 1
#define ENDIAN_LOCAL 0xBADADBBD

struct remote_header_v0 {
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

/*!
 * \internal
 * \brief Retrieve remote message header, in local endianness
 *
 * Return a pointer to the header portion of a remote connection's message
 * buffer, converting the header to local endianness if needed.
 *
 * \param[in,out] remote  Remote connection with new message
 *
 * \return Pointer to message header, localized if necessary
 */
static struct remote_header_v0 *
localized_remote_header(pcmk__remote_t *remote)
{
    struct remote_header_v0 *header = NULL;

    if ((remote == NULL) || (remote->buffer == NULL)
        || (remote->buffer_offset < sizeof(struct remote_header_v0))) {

        // Caller error or we haven't received the full header yet
        return NULL;
    }

    header = (struct remote_header_v0 *) remote->buffer;
    if (header->endian != ENDIAN_LOCAL) {
        uint32_t endian_swapped = GUINT32_SWAP_LE_BE(header->endian);

        CRM_CHECK(endian_swapped == ENDIAN_LOCAL,
                  crm_err("Invalid message detected (endian mismatch): local "
                          "magic number %" PRIx32 " matches neither the "
                          "header's magic number %" PRIx32 " nor the "
                          "byte-swapped form %" PRIx32,
                          ENDIAN_LOCAL, header->endian, endian_swapped);
                  return NULL);

        header->endian = endian_swapped;
        header->version = GUINT32_SWAP_LE_BE(header->version);
        header->id = GUINT64_SWAP_LE_BE(header->id);
        header->flags = GUINT64_SWAP_LE_BE(header->flags);
        header->size_total = GUINT32_SWAP_LE_BE(header->size_total);
        header->payload_offset = GUINT32_SWAP_LE_BE(header->payload_offset);
        header->payload_compressed =
            GUINT32_SWAP_LE_BE(header->payload_compressed);
        header->payload_uncompressed =
            GUINT32_SWAP_LE_BE(header->payload_uncompressed);
    }

    // Sanity checks
    if (header->payload_offset != sizeof(struct remote_header_v0)) {
        return NULL;
    }
    if ((header->payload_offset
         + header->payload_compressed
         + header->payload_uncompressed) != header->size_total) {
        return NULL;
    }

    return header;
}

// \return Standard Pacemaker return code
static int
send_tls(gnutls_session_t session, struct iovec *iov)
{
    const char *unsent = iov->iov_base;
    size_t unsent_len = iov->iov_len;
    ssize_t gnutls_rc;

    if (unsent == NULL) {
        return EINVAL;
    }

    crm_trace("Sending TLS message of %zu bytes", unsent_len);

    while (true) {
        gnutls_rc = gnutls_record_send(session, unsent, unsent_len);

        if (gnutls_rc == GNUTLS_E_INTERRUPTED || gnutls_rc == GNUTLS_E_AGAIN) {
            crm_trace("Retrying to send %zu bytes remaining", unsent_len);

        } else if (gnutls_rc < 0) {
            // Caller can log as error if necessary
            crm_info("TLS connection terminated: %s " QB_XS " rc=%zd",
                     gnutls_strerror((int) gnutls_rc), gnutls_rc);
            return ECONNABORTED;

        } else if (gnutls_rc < unsent_len) {
            crm_trace("Sent %zd of %zu bytes remaining", gnutls_rc, unsent_len);
            unsent_len -= gnutls_rc;
            unsent += gnutls_rc;
        } else {
            crm_trace("Sent all %zd bytes remaining", gnutls_rc);
            break;
        }
    }
    return pcmk_rc_ok;
}

// \return Standard Pacemaker return code
static int
send_plaintext(int sock, struct iovec *iov)
{
    const char *unsent = iov->iov_base;
    size_t unsent_len = iov->iov_len;

    if (unsent == NULL) {
        return EINVAL;
    }

    crm_debug("Sending plaintext message of %zu bytes to socket %d",
              unsent_len, sock);
    while (true) {
        ssize_t write_rc = write(sock, unsent, unsent_len);

        if (write_rc < 0) {
            int rc = errno;

            if ((rc == EINTR) || (rc == EAGAIN) || (rc == EWOULDBLOCK)) {
                crm_trace("Retrying to send %zu bytes remaining to socket %d",
                          unsent_len, sock);
                continue;
            }

            // Caller can log as error if necessary
            crm_info("Could not send message: %s " QB_XS " rc=%d socket=%d",
                     pcmk_rc_str(rc), rc, sock);
            return rc;

        } else if (write_rc < unsent_len) {
            crm_trace("Sent %zd of %zu bytes remaining", write_rc, unsent_len);
            unsent += write_rc;
            unsent_len -= write_rc;

        } else {
            crm_trace("Sent all %zd bytes remaining: %.100s",
                      write_rc, (char *) (iov->iov_base));
            return pcmk_rc_ok;
        }
    }
}

// \return Standard Pacemaker return code
static int
remote_send_iovs(pcmk__remote_t *remote, struct iovec *iov, int iovs)
{
    int rc = pcmk_rc_ok;

    for (int lpc = 0; (lpc < iovs) && (rc == pcmk_rc_ok); lpc++) {
        if (remote->tls_session) {
            rc = send_tls(remote->tls_session, &(iov[lpc]));
            continue;
        }
        if (remote->tcp_socket >= 0) {
            rc = send_plaintext(remote->tcp_socket, &(iov[lpc]));
        } else {
            rc = ESOCKTNOSUPPORT;
        }
    }
    return rc;
}

/*!
 * \internal
 * \brief Send an XML message over a Pacemaker Remote connection
 *
 * \param[in,out] remote  Pacemaker Remote connection to use
 * \param[in]     msg     XML to send
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__remote_send_xml(pcmk__remote_t *remote, const xmlNode *msg)
{
    int rc = pcmk_rc_ok;
    static uint64_t id = 0;
    GString *xml_text = NULL;

    struct iovec iov[2];
    struct remote_header_v0 *header;

    CRM_CHECK((remote != NULL) && (msg != NULL), return EINVAL);

    xml_text = g_string_sized_new(1024);
    pcmk__xml_string(msg, 0, xml_text, 0);
    CRM_CHECK(xml_text->len > 0,
              g_string_free(xml_text, TRUE); return EINVAL);

    header = pcmk__assert_alloc(1, sizeof(struct remote_header_v0));

    iov[0].iov_base = header;
    iov[0].iov_len = sizeof(struct remote_header_v0);

    iov[1].iov_len = 1 + xml_text->len;
    iov[1].iov_base = g_string_free(xml_text, FALSE);

    id++;
    header->id = id;
    header->endian = ENDIAN_LOCAL;
    header->version = REMOTE_MSG_VERSION;
    header->payload_offset = iov[0].iov_len;
    header->payload_uncompressed = iov[1].iov_len;
    header->size_total = iov[0].iov_len + iov[1].iov_len;

    rc = remote_send_iovs(remote, iov, 2);
    if (rc != pcmk_rc_ok) {
        crm_err("Could not send remote message: %s " QB_XS " rc=%d",
                pcmk_rc_str(rc), rc);
    }

    free(iov[0].iov_base);
    g_free((gchar *) iov[1].iov_base);
    return rc;
}

/*!
 * \internal
 * \brief Obtain the XML from the currently buffered remote connection message
 *
 * \param[in,out] remote  Remote connection possibly with message available
 *
 * \return Newly allocated XML object corresponding to message data, or NULL
 * \note This effectively removes the message from the connection buffer.
 */
xmlNode *
pcmk__remote_message_xml(pcmk__remote_t *remote)
{
    xmlNode *xml = NULL;
    size_t data_size = 0;
    const char *payload = NULL;
    struct remote_header_v0 *header = localized_remote_header(remote);

    if (header == NULL) {
        return NULL;
    }

    /* Support compression on the receiving end now, in case we ever want to add it later */
    if (header->payload_compressed) {
        int rc = 0;
        unsigned int size_u = 1 + header->payload_uncompressed;
        char *uncompressed =
            pcmk__assert_alloc(1, header->payload_offset + size_u);

        crm_trace("Decompressing message data %d bytes into %d bytes",
                 header->payload_compressed, size_u);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed + header->payload_offset, &size_u,
                                        remote->buffer + header->payload_offset,
                                        header->payload_compressed, 1, 0);
        rc = pcmk__bzlib2rc(rc);

        if (rc != pcmk_rc_ok && header->version > REMOTE_MSG_VERSION) {
            crm_warn("Couldn't decompress v%d message, we only understand v%d",
                     header->version, REMOTE_MSG_VERSION);
            free(uncompressed);
            return NULL;

        } else if (rc != pcmk_rc_ok) {
            crm_err("Decompression failed: %s " QB_XS " rc=%d",
                    pcmk_rc_str(rc), rc);
            free(uncompressed);
            return NULL;
        }

        pcmk__assert(size_u == header->payload_uncompressed);

        memcpy(uncompressed, remote->buffer, header->payload_offset);       /* Preserve the header */
        remote->buffer_size = header->payload_offset + size_u;

        free(remote->buffer);
        remote->buffer = uncompressed;
        header = localized_remote_header(remote);
    }

    /* take ownership of the buffer */
    remote->buffer_offset = 0;

    data_size = (size_t) header->payload_offset + header->payload_uncompressed;

    // Ensure the buffer is as big as it should be
    CRM_CHECK(remote->buffer_size >= data_size, return NULL);

    /* Ensure the buffer is null-terminated (see
     * pcmk__read_available_remote_data()).
     *
     * Note that payload_uncompressed contains the payload size including the
     * null byte (see pcmk__remote_send_xml()).
     */
    CRM_CHECK(remote->buffer[data_size] == '\0', return NULL);

    payload = remote->buffer + header->payload_offset;

    xml = pcmk__xml_parse(payload);
    if (xml == NULL) {
        if (header->version > REMOTE_MSG_VERSION) {
            crm_warn("Couldn't parse v%d message, we only understand v%d",
                     header->version, REMOTE_MSG_VERSION);
        } else {
            crm_err("Couldn't parse: '%.120s'", payload);
        }

    } else {
        crm_log_xml_trace(xml, "[remote msg]");
    }
    return xml;
}

static int
get_remote_socket(const pcmk__remote_t *remote)
{
    if (remote->tls_session != NULL) {
        return pcmk__tls_get_client_sock(remote);
    }
    if (remote->tcp_socket >= 0) {
        return remote->tcp_socket;
    }
    crm_err("Remote connection type undetermined (bug?)");
    return -1;
}

/*!
 * \internal
 * \brief Wait for a remote session to have data to read
 *
 * \param[in] remote      Connection to check
 * \param[in] timeout_ms  Maximum time (in ms) to wait
 *
 * \return Standard Pacemaker return code (of particular interest, pcmk_rc_ok if
 *         there is data ready to be read, and ETIME if there is no data within
 *         the specified timeout)
 */
int
pcmk__remote_ready(const pcmk__remote_t *remote, int timeout_ms)
{
    struct pollfd fds = { 0, };
    int sock = -1;
    int rc = 0;
    time_t start;
    int timeout = timeout_ms;

    sock = get_remote_socket(remote);
    if (sock < 0) {
        crm_trace("No longer connected");
        return ENOTCONN;
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
            timeout = timeout_ms - ((time(NULL) - start) * 1000);
            if (timeout < 1000) {
                timeout = 1000;
            }
        }

        rc = poll(&fds, 1, timeout);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0) {
        return errno;
    }
    return (rc == 0)? ETIME : pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Read bytes from non-blocking remote connection
 *
 * \param[in,out] remote  Remote connection to read
 *
 * \return Standard Pacemaker return code (of particular interest, pcmk_rc_ok if
 *         a full message has been received, or EAGAIN for a partial message)
 * \note Use only with non-blocking sockets after polling the socket.
 * \note This function will return when the socket read buffer is empty or an
 *       error is encountered.
 */
int
pcmk__read_available_remote_data(pcmk__remote_t *remote)
{
    int rc = pcmk_rc_ok;
    size_t read_len = sizeof(struct remote_header_v0);
    struct remote_header_v0 *header = localized_remote_header(remote);
    ssize_t read_rc;

    if(header) {
        /* Stop at the end of the current message */
        read_len = header->size_total;
    }

    /* automatically grow the buffer when needed */
    if(remote->buffer_size < read_len) {
        remote->buffer_size = 2 * read_len;
        crm_trace("Expanding buffer to %zu bytes", remote->buffer_size);
        remote->buffer = pcmk__realloc(remote->buffer, remote->buffer_size + 1);
    }

    if (remote->tls_session) {
        read_rc = gnutls_record_recv(remote->tls_session,
                                     remote->buffer + remote->buffer_offset,
                                     remote->buffer_size - remote->buffer_offset);
        if (read_rc == GNUTLS_E_INTERRUPTED) {
            rc = EINTR;
        } else if (read_rc == GNUTLS_E_AGAIN) {
            rc = EAGAIN;
        } else if (read_rc < 0) {
            crm_debug("TLS receive failed: %s (%zd)",
                      gnutls_strerror((int) read_rc), read_rc);
            rc = EIO;
        }
    } else if (remote->tcp_socket >= 0) {
        read_rc = read(remote->tcp_socket,
                       remote->buffer + remote->buffer_offset,
                       remote->buffer_size - remote->buffer_offset);
        if (read_rc < 0) {
            rc = errno;
        }
    } else {
        crm_err("Remote connection type undetermined (bug?)");
        return ESOCKTNOSUPPORT;
    }

    /* process any errors. */
    if (read_rc > 0) {
        remote->buffer_offset += read_rc;
        /* always null terminate buffer, the +1 to alloc always allows for this. */
        remote->buffer[remote->buffer_offset] = '\0';
        crm_trace("Received %zd more bytes (%zu total)",
                  read_rc, remote->buffer_offset);

    } else if (read_rc == 0) {
        crm_debug("End of remote data encountered after %zu bytes",
                  remote->buffer_offset);
        return ENOTCONN;

    } else if ((rc == EINTR) || (rc == EAGAIN) || (rc == EWOULDBLOCK)) {
        crm_trace("No data available for non-blocking remote read: %s (%d)",
                  pcmk_rc_str(rc), rc);

    } else {
        crm_debug("Error receiving remote data after %zu bytes: %s (%d)",
                  remote->buffer_offset, pcmk_rc_str(rc), rc);
        return ENOTCONN;
    }

    header = localized_remote_header(remote);
    if(header) {
        if(remote->buffer_offset < header->size_total) {
            crm_trace("Read partial remote message (%zu of %" PRIu32 " bytes)",
                      remote->buffer_offset, header->size_total);
        } else {
            crm_trace("Read full remote message of %zu bytes",
                      remote->buffer_offset);
            return pcmk_rc_ok;
        }
    }

    return EAGAIN;
}

/*!
 * \internal
 * \brief Read one message from a remote connection
 *
 * \param[in,out] remote      Remote connection to read
 * \param[in]     timeout_ms  Fail if message not read in this many milliseconds
 *                            (10s will be used if 0, and 60s if negative)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__read_remote_message(pcmk__remote_t *remote, int timeout_ms)
{
    int rc = pcmk_rc_ok;
    time_t start = time(NULL);
    int remaining_timeout = 0;

    if (timeout_ms == 0) {
        timeout_ms = 10000;
    } else if (timeout_ms < 0) {
        timeout_ms = 60000;
    }

    remaining_timeout = timeout_ms;
    while (remaining_timeout > 0) {

        crm_trace("Waiting for remote data (%d ms of %d ms timeout remaining)",
                  remaining_timeout, timeout_ms);
        rc = pcmk__remote_ready(remote, remaining_timeout);

        if (rc == ETIME) {
            crm_err("Timed out (%d ms) while waiting for remote data",
                    remaining_timeout);
            return rc;

        } else if (rc != pcmk_rc_ok) {
            crm_debug("Wait for remote data aborted (will retry): %s "
                      QB_XS " rc=%d", pcmk_rc_str(rc), rc);

        } else {
            rc = pcmk__read_available_remote_data(remote);
            if (rc == pcmk_rc_ok) {
                return rc;
            } else if (rc == EAGAIN) {
                crm_trace("Waiting for more remote data");
            } else {
                crm_debug("Could not receive remote data: %s " QB_XS " rc=%d",
                          pcmk_rc_str(rc), rc);
            }
        }

        // Don't waste time retrying after fatal errors
        if ((rc == ENOTCONN) || (rc == ESOCKTNOSUPPORT)) {
            return rc;
        }

        remaining_timeout = timeout_ms - ((time(NULL) - start) * 1000);
    }
    return ETIME;
}

struct tcp_async_cb_data {
    int sock;
    int timeout_ms;
    time_t start;
    void *userdata;
    void (*callback) (void *userdata, int rc, int sock);
};

// \return TRUE if timer should be rescheduled, FALSE otherwise
static gboolean
check_connect_finished(gpointer userdata)
{
    struct tcp_async_cb_data *cb_data = userdata;
    int rc;

    fd_set rset, wset;
    struct timeval ts = { 0, };

    if (cb_data->start == 0) {
        // Last connect() returned success immediately
        rc = pcmk_rc_ok;
        goto dispatch_done;
    }

    // If the socket is ready for reading or writing, the connect succeeded
    FD_ZERO(&rset);
    FD_SET(cb_data->sock, &rset);
    wset = rset;
    rc = select(cb_data->sock + 1, &rset, &wset, NULL, &ts);

    if (rc < 0) { // select() error
        rc = errno;
        if ((rc == EINTR) || (rc == EAGAIN)) {
            if ((time(NULL) - cb_data->start) < pcmk__timeout_ms2s(cb_data->timeout_ms)) {
                return TRUE; // There is time left, so reschedule timer
            } else {
                rc = ETIMEDOUT;
            }
        }
        crm_trace("Could not check socket %d for connection success: %s (%d)",
                  cb_data->sock, pcmk_rc_str(rc), rc);

    } else if (rc == 0) { // select() timeout
        if ((time(NULL) - cb_data->start) < pcmk__timeout_ms2s(cb_data->timeout_ms)) {
            return TRUE; // There is time left, so reschedule timer
        }
        crm_debug("Timed out while waiting for socket %d connection success",
                  cb_data->sock);
        rc = ETIMEDOUT;

    // select() returned number of file descriptors that are ready

    } else if (FD_ISSET(cb_data->sock, &rset)
               || FD_ISSET(cb_data->sock, &wset)) {

        // The socket is ready; check it for connection errors
        int error = 0;
        socklen_t len = sizeof(error);

        if (getsockopt(cb_data->sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            rc = errno;
            crm_trace("Couldn't check socket %d for connection errors: %s (%d)",
                      cb_data->sock, pcmk_rc_str(rc), rc);
        } else if (error != 0) {
            rc = error;
            crm_trace("Socket %d connected with error: %s (%d)",
                      cb_data->sock, pcmk_rc_str(rc), rc);
        } else {
            rc = pcmk_rc_ok;
        }

    } else { // Should not be possible
        crm_trace("select() succeeded, but socket %d not in resulting "
                  "read/write sets", cb_data->sock);
        rc = EAGAIN;
    }

  dispatch_done:
    if (rc == pcmk_rc_ok) {
        crm_trace("Socket %d is connected", cb_data->sock);
    } else {
        close(cb_data->sock);
        cb_data->sock = -1;
    }

    if (cb_data->callback) {
        cb_data->callback(cb_data->userdata, rc, cb_data->sock);
    }
    free(cb_data);
    return FALSE; // Do not reschedule timer
}

/*!
 * \internal
 * \brief Attempt to connect socket, calling callback when done
 *
 * Set a given socket non-blocking, then attempt to connect to it,
 * retrying periodically until success or a timeout is reached.
 * Call a caller-supplied callback function when completed.
 *
 * \param[in]  sock        Newly created socket
 * \param[in]  addr        Socket address information for connect
 * \param[in]  addrlen     Size of socket address information in bytes
 * \param[in]  timeout_ms  Fail if not connected within this much time
 * \param[out] timer_id    If not NULL, store retry timer ID here
 * \param[in]  userdata    User data to pass to callback
 * \param[in]  callback    Function to call when connection attempt completes
 *
 * \return Standard Pacemaker return code
 */
static int
connect_socket_retry(int sock, const struct sockaddr *addr, socklen_t addrlen,
                     int timeout_ms, int *timer_id, void *userdata,
                     void (*callback) (void *userdata, int rc, int sock))
{
    int rc = 0;
    int interval = 500;
    int timer;
    struct tcp_async_cb_data *cb_data = NULL;

    rc = pcmk__set_nonblocking(sock);
    if (rc != pcmk_rc_ok) {
        crm_warn("Could not set socket non-blocking: %s " QB_XS " rc=%d",
                 pcmk_rc_str(rc), rc);
        return rc;
    }

    rc = connect(sock, addr, addrlen);
    if (rc < 0) {
        rc = errno;
        switch (rc) {
            case EINTR:
            case EINPROGRESS:
            case EAGAIN:
                break;

            default:
                crm_warn("Could not connect socket: %s " QB_XS " rc=%d",
                         pcmk_rc_str(rc), rc);
                return rc;
        }
    }

    cb_data = pcmk__assert_alloc(1, sizeof(struct tcp_async_cb_data));
    cb_data->userdata = userdata;
    cb_data->callback = callback;
    cb_data->sock = sock;
    cb_data->timeout_ms = timeout_ms;

    if (rc == 0) {
        /* The connect was successful immediately, we still return to mainloop
         * and let this callback get called later. This avoids the user of this api
         * to have to account for the fact the callback could be invoked within this
         * function before returning. */
        cb_data->start = 0;
        interval = 1;
    } else {
        cb_data->start = time(NULL);
    }

    /* This timer function does a non-blocking poll on the socket to see if we
     * can use it. Once we can, the connect has completed. This method allows us
     * to connect without blocking the mainloop.
     *
     * @TODO Use a mainloop fd callback for this instead of polling. Something
     *       about the way mainloop is currently polling prevents this from
     *       working at the moment though. (See connect(2) regarding EINPROGRESS
     *       for possible new handling needed.)
     */
    crm_trace("Scheduling check in %dms for whether connect to fd %d finished",
              interval, sock);
    timer = pcmk__create_timer(interval, check_connect_finished, cb_data);
    if (timer_id) {
        *timer_id = timer;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Attempt once to connect socket and set it non-blocking
 *
 * \param[in]  sock        Newly created socket
 * \param[in]  addr        Socket address information for connect
 * \param[in]  addrlen     Size of socket address information in bytes
 *
 * \return Standard Pacemaker return code
 */
static int
connect_socket_once(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
    int rc = connect(sock, addr, addrlen);

    if (rc < 0) {
        rc = errno;
        crm_warn("Could not connect socket: %s " QB_XS " rc=%d",
                 pcmk_rc_str(rc), rc);
        return rc;
    }

    rc = pcmk__set_nonblocking(sock);
    if (rc != pcmk_rc_ok) {
        crm_warn("Could not set socket non-blocking: %s " QB_XS " rc=%d",
                 pcmk_rc_str(rc), rc);
        return rc;
    }

    return pcmk_ok;
}

/*!
 * \internal
 * \brief Connect to server at specified TCP port
 *
 * \param[in]  host        Name of server to connect to
 * \param[in]  port        Server port to connect to
 * \param[in]  timeout_ms  If asynchronous, fail if not connected in this time
 * \param[out] timer_id    If asynchronous and this is non-NULL, retry timer ID
 *                         will be put here (for ease of cancelling by caller)
 * \param[out] sock_fd     Where to store socket file descriptor
 * \param[in]  userdata    If asynchronous, data to pass to callback
 * \param[in]  callback    If NULL, attempt a single synchronous connection,
 *                         otherwise retry asynchronously then call this
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__connect_remote(const char *host, int port, int timeout, int *timer_id,
                     int *sock_fd, void *userdata,
                     void (*callback) (void *userdata, int rc, int sock))
{
    char buffer[INET6_ADDRSTRLEN];
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    struct addrinfo hints;
    const char *server = host;
    int rc;
    int sock = -1;

    CRM_CHECK((host != NULL) && (sock_fd != NULL), return EINVAL);

    // Get host's IP address(es)
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;        /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    rc = getaddrinfo(server, NULL, &hints, &res);
    rc = pcmk__gaierror2rc(rc);

    if (rc != pcmk_rc_ok) {
        crm_err("Unable to get IP address info for %s: %s",
                server, pcmk_rc_str(rc));
        goto async_cleanup;
    }

    if (!res || !res->ai_addr) {
        crm_err("Unable to get IP address info for %s: no result", server);
        rc = ENOTCONN;
        goto async_cleanup;
    }

    // getaddrinfo() returns a list of host's addresses, try them in order
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        struct sockaddr *addr = rp->ai_addr;

        if (!addr) {
            continue;
        }

        if (rp->ai_canonname) {
            server = res->ai_canonname;
        }
        crm_debug("Got canonical name %s for %s", server, host);

        sock = socket(rp->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1) {
            rc = errno;
            crm_warn("Could not create socket for remote connection to %s:%d: "
                     "%s " QB_XS " rc=%d", server, port, pcmk_rc_str(rc), rc);
            continue;
        }

        /* Set port appropriately for address family */
        /* (void*) casts avoid false-positive compiler alignment warnings */
        if (addr->sa_family == AF_INET6) {
            ((struct sockaddr_in6 *)(void*)addr)->sin6_port = htons(port);
        } else {
            ((struct sockaddr_in *)(void*)addr)->sin_port = htons(port);
        }

        memset(buffer, 0, PCMK__NELEM(buffer));
        pcmk__sockaddr2str(addr, buffer);
        crm_info("Attempting remote connection to %s:%d", buffer, port);

        if (callback) {
            if (connect_socket_retry(sock, rp->ai_addr, rp->ai_addrlen, timeout,
                                     timer_id, userdata, callback) == pcmk_rc_ok) {
                goto async_cleanup; /* Success for now, we'll hear back later in the callback */
            }

        } else if (connect_socket_once(sock, rp->ai_addr,
                                       rp->ai_addrlen) == pcmk_rc_ok) {
            break;          /* Success */
        }

        // Connect failed
        close(sock);
        sock = -1;
        rc = ENOTCONN;
    }

async_cleanup:

    if (res) {
        freeaddrinfo(res);
    }
    *sock_fd = sock;
    return rc;
}

/*!
 * \internal
 * \brief Convert an IP address (IPv4 or IPv6) to a string for logging
 *
 * \param[in]  sa  Socket address for IP
 * \param[out] s   Storage for at least INET6_ADDRSTRLEN bytes
 *
 * \note sa The socket address can be a pointer to struct sockaddr_in (IPv4),
 *          struct sockaddr_in6 (IPv6) or struct sockaddr_storage (either),
 *          as long as its sa_family member is set correctly.
 */
void
pcmk__sockaddr2str(const void *sa, char *s)
{
    switch (((const struct sockaddr *) sa)->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((const struct sockaddr_in *) sa)->sin_addr),
                      s, INET6_ADDRSTRLEN);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6,
                      &(((const struct sockaddr_in6 *) sa)->sin6_addr),
                      s, INET6_ADDRSTRLEN);
            break;

        default:
            strcpy(s, "<invalid>");
    }
}

/*!
 * \internal
 * \brief Accept a client connection on a remote server socket
 *
 * \param[in]  ssock  Server socket file descriptor being listened on
 * \param[out] csock  Where to put new client socket's file descriptor
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__accept_remote_connection(int ssock, int *csock)
{
    int rc;
    struct sockaddr_storage addr;
    socklen_t laddr = sizeof(addr);
    char addr_str[INET6_ADDRSTRLEN];
#ifdef TCP_USER_TIMEOUT
    long sbd_timeout = 0;
#endif

    /* accept the connection */
    memset(&addr, 0, sizeof(addr));
    *csock = accept(ssock, (struct sockaddr *)&addr, &laddr);
    if (*csock == -1) {
        rc = errno;
        crm_err("Could not accept remote client connection: %s "
                QB_XS " rc=%d", pcmk_rc_str(rc), rc);
        return rc;
    }
    pcmk__sockaddr2str(&addr, addr_str);
    crm_info("Accepted new remote client connection from %s", addr_str);

    rc = pcmk__set_nonblocking(*csock);
    if (rc != pcmk_rc_ok) {
        crm_err("Could not set socket non-blocking: %s " QB_XS " rc=%d",
                pcmk_rc_str(rc), rc);
        close(*csock);
        *csock = -1;
        return rc;
    }

#ifdef TCP_USER_TIMEOUT
    sbd_timeout = pcmk__get_sbd_watchdog_timeout();
    if (sbd_timeout > 0) {
        // Time to fail and retry before watchdog
        long half = sbd_timeout / 2;
        unsigned int optval = (half <= UINT_MAX)? half : UINT_MAX;

        rc = setsockopt(*csock, SOL_TCP, TCP_USER_TIMEOUT,
                        &optval, sizeof(optval));
        if (rc < 0) {
            rc = errno;
            crm_err("Could not set TCP timeout to %d ms on remote connection: "
                    "%s " QB_XS " rc=%d", optval, pcmk_rc_str(rc), rc);
            close(*csock);
            *csock = -1;
            return rc;
        }
    }
#endif

    return rc;
}

/*!
 * \brief Get the default remote connection TCP port on this host
 *
 * \return Remote connection TCP port number
 */
int
crm_default_remote_port(void)
{
    static int port = 0;

    if (port == 0) {
        const char *env = pcmk__env_option(PCMK__ENV_REMOTE_PORT);

        if (env) {
            errno = 0;
            port = strtol(env, NULL, 10);
            if (errno || (port < 1) || (port > 65535)) {
                crm_warn("Environment variable PCMK_" PCMK__ENV_REMOTE_PORT
                         " has invalid value '%s', using %d instead",
                         env, DEFAULT_REMOTE_PORT);
                port = DEFAULT_REMOTE_PORT;
            }
        } else {
            port = DEFAULT_REMOTE_PORT;
        }
    }
    return port;
}
