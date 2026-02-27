/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <bzlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include "crmcommon_private.h"

/* Evict clients whose event queue grows this large (by default) */
#define PCMK_IPC_DEFAULT_QUEUE_MAX 500

static GHashTable *client_connections = NULL;

/*!
 * \internal
 * \brief Count IPC clients
 *
 * \return Number of active IPC client connections
 */
guint
pcmk__ipc_client_count(void)
{
    return client_connections? g_hash_table_size(client_connections) : 0;
}

/*!
 * \internal
 * \brief Execute a function for each active IPC client connection
 *
 * \param[in]     func       Function to call
 * \param[in,out] user_data  Pointer to pass to function
 *
 * \note The parameters are the same as for g_hash_table_foreach().
 */
void
pcmk__foreach_ipc_client(GHFunc func, gpointer user_data)
{
    if ((func != NULL) && (client_connections != NULL)) {
        g_hash_table_foreach(client_connections, func, user_data);
    }
}

pcmk__client_t *
pcmk__find_client(const qb_ipcs_connection_t *c)
{
    if (client_connections) {
        return g_hash_table_lookup(client_connections, c);
    }

    pcmk__trace("No client found for %p", c);
    return NULL;
}

pcmk__client_t *
pcmk__find_client_by_id(const char *id)
{
    if ((client_connections != NULL) && (id != NULL)) {
        gpointer key;
        pcmk__client_t *client = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, client_connections);
        while (g_hash_table_iter_next(&iter, &key, (gpointer *) & client)) {
            if (strcmp(client->id, id) == 0) {
                return client;
            }
        }
    }
    pcmk__trace("No client found with id='%s'", pcmk__s(id, ""));
    return NULL;
}

/*!
 * \internal
 * \brief Get a client identifier for use in log messages
 *
 * \param[in] c  Client
 *
 * \return Client's name, client's ID, or a string literal, as available
 * \note This is intended to be used in format strings like "client %s".
 */
const char *
pcmk__client_name(const pcmk__client_t *c)
{
    if (c == NULL) {
        return "(unspecified)";

    } else if (c->name != NULL) {
        return c->name;

    } else if (c->id != NULL) {
        return c->id;

    } else {
        return "(unidentified)";
    }
}

void
pcmk__client_cleanup(void)
{
    if (client_connections != NULL) {
        int active = g_hash_table_size(client_connections);

        if (active > 0) {
            pcmk__warn("Exiting with %d active IPC client%s", active,
                       pcmk__plural_s(active));
        }
        g_hash_table_destroy(client_connections);
        client_connections = NULL;
    }
}

void
pcmk__drop_all_clients(qb_ipcs_service_t *service)
{
    qb_ipcs_connection_t *c = NULL;

    if (service == NULL) {
        return;
    }

    c = qb_ipcs_connection_first_get(service);

    while (c != NULL) {
        qb_ipcs_connection_t *last = c;

        c = qb_ipcs_connection_next_get(service, last);

        /* There really shouldn't be anyone connected at this point */
        pcmk__notice("Disconnecting client %p, pid=%d...", last,
                     pcmk__client_pid(last));
        qb_ipcs_disconnect(last);
        qb_ipcs_connection_unref(last);
    }
}

/*!
 * \internal
 * \brief Allocate a new pcmk__client_t object based on an IPC connection
 *
 * \param[in] c           IPC connection (NULL to allocate generic client)
 * \param[in] key         Connection table key (NULL to use sane default)
 * \param[in] uid_client  UID corresponding to c (ignored if c is NULL)
 *
 * \return Pointer to new pcmk__client_t (guaranteed not to be \c NULL)
 */
static pcmk__client_t *
client_from_connection(qb_ipcs_connection_t *c, void *key, uid_t uid_client)
{
    pcmk__client_t *client = pcmk__assert_alloc(1, sizeof(pcmk__client_t));

    if (c) {
        client->user = pcmk__uid2username(uid_client);
        if (client->user == NULL) {
            client->user = pcmk__str_copy("#unprivileged");
            pcmk__err("Unable to enforce ACLs for user ID %d, assuming "
                      "unprivileged",
                      uid_client);
        }
        client->ipcs = c;
        pcmk__set_client_flags(client, pcmk__client_ipc);
        client->pid = pcmk__client_pid(c);
        if (key == NULL) {
            key = c;
        }
    }

    client->id = pcmk__generate_uuid();
    if (key == NULL) {
        key = client->id;
    }
    if (client_connections == NULL) {
        pcmk__trace("Creating IPC client table");
        client_connections = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    g_hash_table_insert(client_connections, key, client);
    return client;
}

/*!
 * \brief Allocate a new pcmk__client_t object and generate its ID
 *
 * \param[in] key  What to use as connections hash table key (NULL to use ID)
 *
 * \return Pointer to new pcmk__client_t (asserts on failure)
 */
pcmk__client_t *
pcmk__new_unauth_client(void *key)
{
    return client_from_connection(NULL, key, 0);
}

pcmk__client_t *
pcmk__new_client(qb_ipcs_connection_t *c, uid_t uid_client, gid_t gid_client)
{
    gid_t uid_cluster = 0;
    gid_t gid_cluster = 0;

    pcmk__client_t *client = NULL;

    CRM_CHECK(c != NULL, return NULL);

    if (pcmk__daemon_user(&uid_cluster, &gid_cluster) != pcmk_rc_ok) {
        static bool need_log = true;

        if (need_log) {
            pcmk__warn("Could not find user and group IDs for user "
                       CRM_DAEMON_USER);
            need_log = false;
        }
    }

    if (uid_client != 0) {
        pcmk__trace("Giving group %u access to new IPC connection",
                    gid_cluster);
        /* Passing -1 to chown(2) means don't change */
        qb_ipcs_connection_auth_set(c, -1, gid_cluster, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    }

    /* TODO: Do our own auth checking, return NULL if unauthorized */
    client = client_from_connection(c, NULL, uid_client);

    if ((uid_client == 0) || (uid_client == uid_cluster)) {
        /* Remember when a connection came from root or hacluster */
        pcmk__set_client_flags(client, pcmk__client_privileged);
    }

    pcmk__debug("New IPC client %s for PID %u with uid %d and gid %d",
                client->id, client->pid, uid_client, gid_client);
    return client;
}

static struct iovec *
pcmk__new_ipc_event(void)
{
    return (struct iovec *) pcmk__assert_alloc(2, sizeof(struct iovec));
}

/*!
 * \brief Free an I/O vector created by pcmk__ipc_prepare_iov()
 *
 * \param[in,out] event  I/O vector to free
 */
void
pcmk_free_ipc_event(struct iovec *event)
{
    if (event != NULL) {
        free(event[0].iov_base);
        free(event[1].iov_base);
        free(event);
    }
}

static void
free_event(gpointer data)
{
    pcmk_free_ipc_event((struct iovec *) data);
}

static void
add_event(pcmk__client_t *c, struct iovec *iov)
{
    if (c->event_queue == NULL) {
        c->event_queue = g_queue_new();
    }
    g_queue_push_tail(c->event_queue, iov);
}

void
pcmk__free_client(pcmk__client_t *c)
{
    if (c == NULL) {
        return;
    }

    if (client_connections) {
        if (c->ipcs) {
            pcmk__trace("Destroying %p/%p (%u remaining)", c, c->ipcs,
                        (g_hash_table_size(client_connections) - 1));
            g_hash_table_remove(client_connections, c->ipcs);

        } else {
            pcmk__trace("Destroying remote connection %p (%u remaining)", c,
                        (g_hash_table_size(client_connections) - 1));
            g_hash_table_remove(client_connections, c->id);
        }
    }

    if (c->event_timer) {
        g_source_remove(c->event_timer);
    }

    if (c->event_queue) {
        pcmk__debug("Destroying %d events", g_queue_get_length(c->event_queue));
        g_queue_free_full(c->event_queue, free_event);
    }

    free(c->id);
    free(c->name);
    free(c->user);

    if (c->buffer != NULL) {
        g_byte_array_free(c->buffer, TRUE);
        c->buffer = NULL;
    }

    if (c->remote) {
        if (c->remote->auth_timeout) {
            g_source_remove(c->remote->auth_timeout);
        }
        if (c->remote->tls_session != NULL) {
            /* @TODO Reduce duplication at callers. Put here everything
             * necessary to tear down and free tls_session.
             */
            gnutls_deinit(c->remote->tls_session);
        }
        free(c->remote->buffer);
        free(c->remote);
    }
    free(c);
}

/*!
 * \internal
 * \brief Raise IPC eviction threshold for a client, if allowed
 *
 * \param[in,out] client     Client to modify
 * \param[in]     qmax       New threshold
 */
void
pcmk__set_client_queue_max(pcmk__client_t *client, const char *qmax)
{
    int rc = pcmk_rc_ok;
    long long qmax_ll = 0LL;
    unsigned int orig_value = 0U;

    CRM_CHECK(client != NULL, return);

    orig_value = client->queue_max;

    if (pcmk__is_set(client->flags, pcmk__client_privileged)) {
        rc = pcmk__scan_ll(qmax, &qmax_ll, 0LL);
        if (rc == pcmk_rc_ok) {
            if ((qmax_ll <= 0LL) || (qmax_ll > UINT_MAX)) {
                rc = ERANGE;
            } else {
                client->queue_max = (unsigned int) qmax_ll;
            }
        }
    } else {
        rc = EACCES;
    }

    if (rc != pcmk_rc_ok) {
        pcmk__info("Could not set IPC threshold for client %s[%u] to %s: %s",
                   pcmk__client_name(client), client->pid,
                   pcmk__s(qmax, "default"), pcmk_rc_str(rc));

    } else if (client->queue_max != orig_value) {
        pcmk__debug("IPC threshold for client %s[%u] is now %u (was %u)",
                    pcmk__client_name(client), client->pid, client->queue_max,
                    orig_value);
    }
}

int
pcmk__client_pid(qb_ipcs_connection_t *c)
{
    struct qb_ipcs_connection_stats stats;

    stats.client_pid = 0;
    qb_ipcs_connection_stats_get(c, &stats, 0);
    return stats.client_pid;
}

/*!
 * \internal
 * \brief Retrieve message XML from data read from client IPC
 *
 * \param[in,out]  c       IPC client connection
 * \param[out]     id      Where to store message ID from libqb header
 * \param[out]     flags   Where to store flags from libqb header
 *
 * \return Message XML on success, NULL otherwise
 */
xmlNode *
pcmk__client_data2xml(pcmk__client_t *c, uint32_t *id, uint32_t *flags)
{
    xmlNode *xml = NULL;
    pcmk__ipc_header_t *header = (void *) c->buffer->data;
    char *text = (char *) header + sizeof(pcmk__ipc_header_t);

    if (!pcmk__valid_ipc_header(header)) {
        return NULL;
    }

    if (id) {
        *id = header->qb.id;
    }

    if (flags) {
        *flags = header->flags;
    }

    if (pcmk__is_set(header->flags, crm_ipc_proxied)) {
        /* Mark this client as being the endpoint of a proxy connection.
         * Proxy connections responses are sent on the event channel, to avoid
         * blocking the controller serving as proxy.
         */
        pcmk__set_client_flags(c, pcmk__client_proxied);
    }

    pcmk__assert(text[header->size - 1] == 0);

    xml = pcmk__xml_parse(text);
    pcmk__log_xml_trace(xml, "[IPC received]");
    return xml;
}

static int crm_ipcs_flush_events(pcmk__client_t *c);

static gboolean
crm_ipcs_flush_events_cb(gpointer data)
{
    pcmk__client_t *c = data;

    c->event_timer = 0;
    crm_ipcs_flush_events(c);
    return FALSE;
}

/*!
 * \internal
 * \brief Add progressive delay before next event queue flush
 *
 * \param[in,out] c          Client connection to add delay to
 * \param[in]     queue_len  Current event queue length
 */
static inline void
delay_next_flush(pcmk__client_t *c, unsigned int queue_len)
{
    /* Delay a maximum of 1.5 seconds */
    guint delay = (queue_len < 5)? (1000 + 100 * queue_len) : 1500;

    c->event_timer = pcmk__create_timer(delay, crm_ipcs_flush_events_cb, c);
}

/*!
 * \internal
 * \brief Send client any messages in its queue
 *
 * \param[in,out] c  Client to flush
 *
 * \return Standard Pacemaker return value
 */
static int
crm_ipcs_flush_events(pcmk__client_t *c)
{
    int rc = pcmk_rc_ok;
    ssize_t qb_rc = 0;
    unsigned int sent = 0;
    unsigned int queue_len = 0;

    if (c == NULL) {
        return rc;
    }

    if (c->event_timer != 0) {
        /* There is already a timer, wait until it goes off */
        pcmk__trace("Timer active for %p - %d", c->ipcs, c->event_timer);
        return rc;
    }

    if (c->event_queue != NULL) {
        queue_len = g_queue_get_length(c->event_queue);
    }

    while (sent < 100) {
        pcmk__ipc_header_t *header = NULL;
        struct iovec *event = NULL;

        if ((c->event_queue == NULL) || g_queue_is_empty(c->event_queue)) {
            break;
        }

        // We don't pop unless send is successful
        event = g_queue_peek_head(c->event_queue);

        /* Retry sending the event up to five times.  If we get -EAGAIN, sleep
         * a very short amount of time (too long here is bad) and try again.
         * If we simply exit the while loop on -EAGAIN, we'll have to wait until
         * the timer fires off again (up to 1.5 seconds - see delay_next_flush)
         * to retry sending the message.
         *
         * In that case, the queue may just continue to grow faster than we are
         * processing it, eventually leading to daemons timing out waiting for
         * replies, which will cause wider failures.
         */
        for (unsigned int retries = 5; retries > 0; retries--) {
            qb_rc = qb_ipcs_event_sendv(c->ipcs, event, 2);

            if (qb_rc >= 0) {
                break;
            }

            if (retries == 1 || qb_rc != -EAGAIN) {
                rc = (int) -qb_rc;
                goto no_more_retries;
            }

            pcmk__sleep_ms(5);
        }

        event = g_queue_pop_head(c->event_queue);

        sent++;
        header = event[0].iov_base;

        pcmk__trace("Event %" PRId32 " to %p[%u] (%zd bytes) sent: %.120s",
                    header->qb.id, c->ipcs, c->pid, qb_rc,
                    (char *) (event[1].iov_base));
        pcmk_free_ipc_event(event);
    }

no_more_retries:
    queue_len -= sent;
    if (sent > 0 || queue_len) {
        pcmk__trace("Sent %u events (%u remaining) for %p[%d]: %s (%zd)", sent,
                    queue_len, c->ipcs, c->pid, pcmk_rc_str(rc), qb_rc);
    }

    if (queue_len == 0) {
        /* Event queue is empty, there is no backlog */
        c->queue_backlog = 0;
        return rc;
    }

    /* Allow clients to briefly fall behind on processing incoming messages,
     * but drop completely unresponsive clients so the connection doesn't
     * consume resources indefinitely.
     */
    if (queue_len > QB_MAX(c->queue_max, PCMK_IPC_DEFAULT_QUEUE_MAX)) {
        /* Don't evict:
         * - Clients with a new backlog.
         * - Clients with a shrinking backlog (the client is processing
         *   messages faster than the server is sending them).
         * - Clients that are pacemaker daemons and have had any messages sent
         *   to them in this flush call (the server is sending messages faster
         *   than the client is processing them, but the client is not dead).
         */
        if ((c->queue_backlog <= 1)
            || (queue_len < c->queue_backlog)
            || ((sent > 0) && (pcmk__parse_server(c->name) != pcmk_ipc_unknown))) {
            pcmk__warn("Client with process ID %u has a backlog of %u messages "
                       QB_XS " %p", c->pid, queue_len, c->ipcs);

        } else {
            pcmk__err("Evicting client with process ID %u due to backlog of %u "
                      "messages " QB_XS " %p",
                      c->pid, queue_len, c->ipcs);
            c->queue_backlog = 0;
            qb_ipcs_disconnect(c->ipcs);
            return rc;
        }
    }

    c->queue_backlog = queue_len;
    delay_next_flush(c, queue_len);

    return rc;
}

/*!
 * \internal
 * \brief Create an I/O vector for sending an IPC XML message
 *
 * If the message is too large to fit into a single buffer, this function will
 * prepare an I/O vector that only holds as much as fits.  The remainder can be
 * prepared in a separate call by keeping a running count of the number of times
 * this function has been called and passing that in for \p index.
 *
 * \param[in]  request Identifier for libqb response header
 * \param[in]  message Message to send
 * \param[in]  index   How many times this function has been called - basically,
 *                     a count of how many chunks of \p message have already
 *                     been sent
 * \param[out] result  Where to store prepared I/O vector - NULL on error
 * \param[out] bytes   Size of prepared data in bytes (includes header)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__ipc_prepare_iov(uint32_t request, const GString *message, uint16_t index,
                      struct iovec **result, ssize_t *bytes)
{
    struct iovec *iov = NULL;
    unsigned int payload_size = 0;
    unsigned int total = 0;
    unsigned int max_send_size = crm_ipc_default_buffer_size();
    unsigned int max_chunk_size = 0;
    size_t offset = 0;
    pcmk__ipc_header_t *header = NULL;
    int rc = pcmk_rc_ok;

    if ((message == NULL) || (result == NULL)) {
        rc = EINVAL;
        goto done;
    }

    header = calloc(1, sizeof(pcmk__ipc_header_t));
    if (header == NULL) {
       rc = ENOMEM;
       goto done;
    }

    *result = NULL;
    iov = pcmk__new_ipc_event();
    iov[0].iov_len = sizeof(pcmk__ipc_header_t);
    iov[0].iov_base = header;

    header->version = PCMK__IPC_VERSION;

    /* We are passed an index, which is basically how many times this function
     * has been called.  This is how we support multi-part IPC messages.  We
     * need to convert that into an offset into the buffer that we want to start
     * reading from.
     *
     * Each call to this function can send max_send_size, but this also includes
     * the header and a null terminator character for the end of the payload.
     * We need to subtract those out here.
     */
    max_chunk_size = max_send_size - iov[0].iov_len - 1;
    offset = index * max_chunk_size;

    /* How much of message is left to send?  This does not include the null
     * terminator character.
     */
    payload_size = message->len - offset;

    /* How much would be transmitted, including the header size and null
     * terminator character for the buffer?
     */
    total = iov[0].iov_len + payload_size + 1;

    if (total >= max_send_size) {
        /* The entire packet is too big to fit in a single buffer.  Calculate
         * how much of it we can send - buffer size, minus header size, minus
         * one for the null terminator.
         */
        payload_size = max_chunk_size;

        header->size = payload_size + 1;

        iov[1].iov_base = strndup(message->str + offset, payload_size);
        if (iov[1].iov_base == NULL) {
            rc = ENOMEM;
            goto done;
        }

        iov[1].iov_len = header->size;
        rc = pcmk_rc_ipc_more;

    } else {
        /* The entire packet fits in a single buffer.  We can copy the entirety
         * of it into the payload.
         */
        header->size = payload_size + 1;

        iov[1].iov_base = pcmk__str_copy(message->str + offset);
        iov[1].iov_len = header->size;
    }

    header->part_id = index;
    header->qb.size = iov[0].iov_len + iov[1].iov_len;
    header->qb.id = (int32_t)request;    /* Replying to a specific request */

    if ((rc == pcmk_rc_ok) && (index != 0)) {
        pcmk__set_ipc_flags(header->flags, "multipart ipc",
                            crm_ipc_multipart | crm_ipc_multipart_end);
    } else if (rc == pcmk_rc_ipc_more) {
        pcmk__set_ipc_flags(header->flags, "multipart ipc",
                            crm_ipc_multipart);
    }

    *result = iov;
    pcmk__assert(header->qb.size > 0);
    if (bytes != NULL) {
        *bytes = header->qb.size;
    }

done:
    if ((rc != pcmk_rc_ok) && (rc != pcmk_rc_ipc_more)) {
        pcmk_free_ipc_event(iov);
    }

    return rc;
}

/* Return the next available ID for a server event.
 *
 * For the parts of a multipart event, all parts should have the same ID as
 * the first part.
 */
static uint32_t
id_for_server_event(pcmk__ipc_header_t *header)
{
    static uint32_t id = 1;

    if (pcmk__is_set(header->flags, crm_ipc_multipart)
        && (header->part_id != 0)) {
        return id;
    } else {
        id++;
        return id;
    }
}

int
pcmk__ipc_send_iov(pcmk__client_t *c, struct iovec *iov, uint32_t flags)
{
    int rc = pcmk_rc_ok;
    pcmk__ipc_header_t *header = iov[0].iov_base;

    /* _ALL_ replies to proxied connections need to be sent as events */
    if (pcmk__is_set(c->flags, pcmk__client_proxied)
        && !pcmk__is_set(flags, crm_ipc_server_event)) {
        /* The proxied flag lets us know this was originally meant to be a
         * response, even though we're sending it over the event channel.
         */
        pcmk__set_ipc_flags(flags, "server event",
                            crm_ipc_server_event|crm_ipc_proxied_relay_response);
    }

    pcmk__set_ipc_flags(header->flags, "server event", flags);
    if (pcmk__is_set(flags, crm_ipc_server_event)) {
        /* Server events don't use an ID, though we do set one in
         * pcmk__ipc_prepare_iov if the event is in response to a particular
         * request.  In that case, we don't want to set a new ID here that
         * overwrites that one.
         *
         * @TODO: Since server event IDs aren't used anywhere, do we really
         * need to set this for any reason other than ease of logging?
         */
        if (header->qb.id == 0) {
            header->qb.id = id_for_server_event(header);
        }

        if (pcmk__is_set(flags, crm_ipc_server_free)) {
            pcmk__trace("Sending the original to %p[%d]", c->ipcs, c->pid);
            add_event(c, iov);

        } else {
            struct iovec *iov_copy = pcmk__new_ipc_event();

            pcmk__trace("Sending a copy to %p[%d]", c->ipcs, c->pid);
            iov_copy[0].iov_len = iov[0].iov_len;
            iov_copy[0].iov_base = malloc(iov[0].iov_len);
            memcpy(iov_copy[0].iov_base, iov[0].iov_base, iov[0].iov_len);

            iov_copy[1].iov_len = iov[1].iov_len;
            iov_copy[1].iov_base = malloc(iov[1].iov_len);
            memcpy(iov_copy[1].iov_base, iov[1].iov_base, iov[1].iov_len);

            add_event(c, iov_copy);
        }

        rc = crm_ipcs_flush_events(c);

    } else {
        ssize_t qb_rc;
        char *part_text = NULL;

        CRM_LOG_ASSERT(header->qb.id != 0);     /* Replying to a specific request */

        if (pcmk__is_set(header->flags, crm_ipc_multipart_end)) {
            part_text = pcmk__assert_asprintf(" (final part %d) ",
                                              header->part_id);
        } else if (pcmk__is_set(header->flags, crm_ipc_multipart)) {
            if (header->part_id == 0) {
                part_text = pcmk__assert_asprintf(" (initial part %d) ",
                                                  header->part_id);
            } else {
                part_text = pcmk__assert_asprintf(" (part %d) ",
                                                  header->part_id);
            }
        } else {
            part_text = pcmk__str_copy(" ");
        }

        qb_rc = qb_ipcs_response_sendv(c->ipcs, iov, 2);
        if (qb_rc < header->qb.size) {
            if (qb_rc < 0) {
                rc = (int) -qb_rc;
            }

            pcmk__notice("Response %" PRId32 "%sto pid %u failed: %s "
                         QB_XS " bytes=%" PRId32 " rc=%zd ipcs=%p",
                         header->qb.id, part_text, c->pid, pcmk_rc_str(rc),
                         header->qb.size, qb_rc, c->ipcs);

        } else {
            pcmk__trace("Response %" PRId32 "%ssent, %zd bytes to %p[%u]",
                        header->qb.id, part_text, qb_rc, c->ipcs, c->pid);
            pcmk__trace("Text = %s", (char *) iov[1].iov_base);
        }

        free(part_text);

        if (pcmk__is_set(flags, crm_ipc_server_free)) {
            pcmk_free_ipc_event(iov);
        }

        crm_ipcs_flush_events(c);
    }

    if ((rc == EPIPE) || (rc == ENOTCONN)) {
        pcmk__trace("Client %p disconnected", c->ipcs);
    }

    return rc;
}

int
pcmk__ipc_send_xml(pcmk__client_t *c, uint32_t request, const xmlNode *message,
                   uint32_t flags)
{
    struct iovec *iov = NULL;
    int rc = pcmk_rc_ok;
    GString *iov_buffer = NULL;
    uint16_t index = 0;
    bool event_or_proxied = false;

    if (c == NULL) {
        return EINVAL;
    }

    iov_buffer = g_string_sized_new(1024);
    pcmk__xml_string(message, 0, iov_buffer, 0);

    /* Testing crm_ipc_server_event is obvious.  pcmk__client_proxied is less
     * obvious.  According to pcmk__ipc_send_iov, replies to proxied connections
     * need to be sent as events.  However, do_local_notify (which calls this
     * function) will clear all flags so we can't go just by crm_ipc_server_event.
     *
     * Changing do_local_notify to check for a proxied connection first results
     * in processes on the Pacemaker Remote node (like cibadmin or crm_mon)
     * timing out when waiting for a reply.
     */
    event_or_proxied = pcmk__is_set(flags, crm_ipc_server_event)
                       || pcmk__is_set(c->flags, pcmk__client_proxied);

    do {
        rc = pcmk__ipc_prepare_iov(request, iov_buffer, index, &iov, NULL);

        switch (rc) {
            case pcmk_rc_ok:
                /* No more chunks to send after this one */
                pcmk__set_ipc_flags(flags, "send data", crm_ipc_server_free);
                rc = pcmk__ipc_send_iov(c, iov, flags);

                if (event_or_proxied) {
                    if (rc == EAGAIN) {
                        /* Return pcmk_rc_ok instead so callers don't have to know
                         * whether they passed an event or not when interpreting
                         * the return code.
                         */
                        rc = pcmk_rc_ok;
                    }
                } else {
                    /* EAGAIN is an error for IPC messages.  We don't have a
                     * send queue for these, so we need to try again.  If there
                     * was some other error, we need to break out of this loop
                     * and report it.
                     *
                     * FIXME: Retry limit for EAGAIN?
                     */
                    if (rc == EAGAIN) {
                        break;
                    }
                }

                goto done;

            case pcmk_rc_ipc_more:
                /* There are more chunks to send after this one */
                pcmk__set_ipc_flags(flags, "send data", crm_ipc_server_free);
                rc = pcmk__ipc_send_iov(c, iov, flags);

                /* Did an error occur during transmission? */
                if (event_or_proxied) {
                    /* EAGAIN is not an error for server events.  The event
                     * will be queued for transmission and we will attempt
                     * sending it again the next time pcmk__ipc_send_iov is
                     * called, or when the crm_ipcs_flush_events_cb happens.
                     */
                    if ((rc != pcmk_rc_ok) && (rc != EAGAIN)) {
                        goto done;
                    }

                    index++;
                    break;

                } else {
                    /* EAGAIN is an error for IPC messages.  We don't have a
                     * send queue for these, so we need to try again.  If there
                     * was some other error, we need to break out of this loop
                     * and report it.
                     *
                     * FIXME: Retry limit for EAGAIN?
                     */
                    if (rc == pcmk_rc_ok) {
                        index++;
                        break;
                    } else if (rc == EAGAIN) {
                        break;
                    } else {
                        goto done;
                    }
                }

            default:
                /* An error occurred during preparation */
                goto done;
        }
    } while (true);

done:
    if ((rc != pcmk_rc_ok) && (rc != EAGAIN)) {
        pcmk__notice("IPC message to pid %u failed: %s " QB_XS " rc=%d", c->pid,
                     pcmk_rc_str(rc), rc);
    }

    g_string_free(iov_buffer, TRUE);
    return rc;
}

/*!
 * \internal
 * \brief Create an acknowledgement with a status code to send to a client
 *
 * \param[in] function  Calling function
 * \param[in] line      Source file line within calling function
 * \param[in] flags     IPC flags to use when sending
 * \param[in] ver       IPC protocol version (can be NULL)
 * \param[in] status    Exit status code to add to ack
 *
 * \return Newly created XML for ack
 *
 * \note The caller is responsible for freeing the return value with
 *       \c pcmk__xml_free().
 */
xmlNode *
pcmk__ipc_create_ack_as(const char *function, int line, uint32_t flags,
                        const char *ver, crm_exit_t status)
{
    xmlNode *ack = NULL;

    if (!pcmk__is_set(flags, crm_ipc_client_response)) {
        return ack;
    }

    ack = pcmk__xe_create(NULL, PCMK__XE_ACK);
    pcmk__xe_set(ack, PCMK_XA_FUNCTION, function);
    pcmk__xe_set_int(ack, PCMK__XA_LINE, line);
    pcmk__xe_set_int(ack, PCMK_XA_STATUS, (int) status);
    pcmk__xe_set(ack, PCMK__XA_IPC_PROTO_VERSION, ver);
    return ack;
}

/*!
 * \internal
 * \brief Send an acknowledgement with a status code to a client
 *
 * \param[in] function  Calling function
 * \param[in] line      Source file line within calling function
 * \param[in] c         Client to send ack to
 * \param[in] request   Request ID being replied to
 * \param[in] flags     IPC flags to use when sending
 * \param[in] ver       IPC protocol version (can be NULL)
 * \param[in] status    Status code to send with acknowledgement
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__ipc_send_ack_as(const char *function, int line, pcmk__client_t *c,
                      uint32_t request, uint32_t flags, const char *ver,
                      crm_exit_t status)
{
    int rc = pcmk_rc_ok;
    xmlNode *ack = pcmk__ipc_create_ack_as(function, line, flags, ver, status);

    if (ack == NULL) {
        return rc;
    }

    pcmk__trace("Ack'ing IPC message from client %s as <" PCMK__XE_ACK
                " status=%d>",
                pcmk__client_name(c), status);
    pcmk__log_xml_trace(ack, "sent-ack");
    c->request_id = 0;
    rc = pcmk__ipc_send_xml(c, request, ack, flags);
    pcmk__xml_free(ack);
    return rc;
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the CIB manager API
 *
 * \param[out] ipcs_ro   New IPC server for read-only CIB manager API
 * \param[out] ipcs_rw   New IPC server for read/write CIB manager API
 * \param[out] ipcs_shm  New IPC server for shared-memory CIB manager API
 * \param[in]  ro_cb     IPC callbacks for read-only API
 * \param[in]  rw_cb     IPC callbacks for read/write and shared-memory APIs
 *
 * \note This function exits fatally on error.
 * \note There is no actual difference between the three IPC endpoints other
 *       than their names.
 */
void pcmk__serve_based_ipc(qb_ipcs_service_t **ipcs_ro,
                           qb_ipcs_service_t **ipcs_rw,
                           qb_ipcs_service_t **ipcs_shm,
                           struct qb_ipcs_service_handlers *ro_cb,
                           struct qb_ipcs_service_handlers *rw_cb)
{
    *ipcs_ro = mainloop_add_ipc_server(PCMK__SERVER_BASED_RO,
                                       QB_IPC_NATIVE, ro_cb);

    *ipcs_rw = mainloop_add_ipc_server(PCMK__SERVER_BASED_RW,
                                       QB_IPC_NATIVE, rw_cb);

    *ipcs_shm = mainloop_add_ipc_server(PCMK__SERVER_BASED_SHM,
                                        QB_IPC_SHM, rw_cb);

    if (*ipcs_ro == NULL || *ipcs_rw == NULL || *ipcs_shm == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(pcmk_ipc_based));
        pcmk__crit("Verify pacemaker and pacemaker_remote are not both "
                   "enabled");
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Destroy IPC servers for the CIB manager API
 *
 * \param[out] ipcs_ro   IPC server for read-only the CIB manager API
 * \param[out] ipcs_rw   IPC server for read/write the CIB manager API
 * \param[out] ipcs_shm  IPC server for shared-memory the CIB manager API
 *
 * \note This is a convenience function for calling qb_ipcs_destroy() for each
 *       argument.
 */
void
pcmk__stop_based_ipc(qb_ipcs_service_t *ipcs_ro,
                     qb_ipcs_service_t *ipcs_rw,
                     qb_ipcs_service_t *ipcs_shm)
{
    qb_ipcs_destroy(ipcs_ro);
    qb_ipcs_destroy(ipcs_rw);
    qb_ipcs_destroy(ipcs_shm);
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the controller API
 *
 * \param[in] cb  IPC callbacks
 *
 * \return Newly created IPC server
 */
qb_ipcs_service_t *
pcmk__serve_controld_ipc(struct qb_ipcs_service_handlers *cb)
{
    return mainloop_add_ipc_server(CRM_SYSTEM_CRMD, QB_IPC_NATIVE, cb);
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the attribute manager API
 *
 * \param[out] ipcs  Where to store newly created IPC server
 * \param[in]  cb    IPC callbacks
 *
 * \note This function exits fatally on error.
 */
void
pcmk__serve_attrd_ipc(qb_ipcs_service_t **ipcs,
                      struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(pcmk__server_ipc_name(pcmk_ipc_attrd),
                                    QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(pcmk_ipc_attrd));
        pcmk__crit("Verify pacemaker and pacemaker_remote are not both "
                   "enabled");
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the executor API
 *
 * \param[out] ipcs  Where to store newly created IPC server
 * \param[in]  cb    IPC callbacks
 *
 * \note This function exits fatally on error.
 */
void
pcmk__serve_execd_ipc(qb_ipcs_service_t **ipcs,
                      struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(pcmk__server_ipc_name(pcmk_ipc_execd),
                                    QB_IPC_SHM, cb);

    if (*ipcs == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(pcmk_ipc_execd));
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the fencer API
 *
 * \param[out] ipcs  Where to store newly created IPC server
 * \param[in]  cb    IPC callbacks
 *
 * \note This function exits fatally on error.
 */
void
pcmk__serve_fenced_ipc(qb_ipcs_service_t **ipcs,
                       struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server_with_prio(pcmk__server_ipc_name(pcmk_ipc_fenced),
                                              QB_IPC_NATIVE, cb, QB_LOOP_HIGH);

    if (*ipcs == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(pcmk_ipc_fenced));
        pcmk__crit("Verify pacemaker and pacemaker_remote are not both "
                   "enabled");
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the pacemakerd API
 *
 * \param[out] ipcs  Where to store newly created IPC server
 * \param[in]  cb    IPC callbacks
 *
 * \note This function exits with CRM_EX_OSERR on error.
 */
void
pcmk__serve_pacemakerd_ipc(qb_ipcs_service_t **ipcs,
                       struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(pcmk__server_ipc_name(pcmk_ipc_pacemakerd),
                                    QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(pcmk_ipc_pacemakerd));
        pcmk__crit("Verify pacemaker and pacemaker_remote are not both "
                   "enabled");
        /* sub-daemons are observed by pacemakerd. Thus we exit CRM_EX_FATAL
         * if we want to prevent pacemakerd from restarting them.
         * With pacemakerd we leave the exit-code shown to e.g. systemd
         * to what it was prior to moving the code here from pacemakerd.c
         */
        crm_exit(CRM_EX_OSERR);
    }
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the scheduler API
 *
 * \param[out] ipcs  Where to store newly created IPC server
 * \param[in]  cb    IPC callbacks
 *
 * \return Newly created IPC server
 * \note This function exits fatally on error.
 */
void
pcmk__serve_schedulerd_ipc(qb_ipcs_service_t **ipcs,
                           struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(pcmk__server_ipc_name(pcmk_ipc_schedulerd),
                                    QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        pcmk__crit("Failed to create %s IPC server; shutting down",
                   pcmk__server_log_name(pcmk_ipc_schedulerd));
        crm_exit(CRM_EX_FATAL);
    }
}
