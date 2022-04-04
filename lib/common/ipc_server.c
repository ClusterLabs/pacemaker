/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <errno.h>
#include <bzlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
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
pcmk__ipc_client_count()
{
    return client_connections? g_hash_table_size(client_connections) : 0;
}

/*!
 * \internal
 * \brief Execute a function for each active IPC client connection
 *
 * \param[in] func       Function to call
 * \param[in] user_data  Pointer to pass to function
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
pcmk__find_client(qb_ipcs_connection_t *c)
{
    if (client_connections) {
        return g_hash_table_lookup(client_connections, c);
    }

    crm_trace("No client found for %p", c);
    return NULL;
}

pcmk__client_t *
pcmk__find_client_by_id(const char *id)
{
    gpointer key;
    pcmk__client_t *client;
    GHashTableIter iter;

    if (client_connections && id) {
        g_hash_table_iter_init(&iter, client_connections);
        while (g_hash_table_iter_next(&iter, &key, (gpointer *) & client)) {
            if (strcmp(client->id, id) == 0) {
                return client;
            }
        }
    }

    crm_trace("No client found with id=%s", id);
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
pcmk__client_name(pcmk__client_t *c)
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

        if (active) {
            crm_err("Exiting with %d active IPC client%s",
                    active, pcmk__plural_s(active));
        }
        g_hash_table_destroy(client_connections); client_connections = NULL;
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
        crm_notice("Disconnecting client %p, pid=%d...",
                   last, pcmk__client_pid(last));
        qb_ipcs_disconnect(last);
        qb_ipcs_connection_unref(last);
    }
}

/*!
 * \internal
 * \brief Allocate a new pcmk__client_t object based on an IPC connection
 *
 * \param[in] c           IPC connection (or NULL to allocate generic client)
 * \param[in] key         Connection table key (or NULL to use sane default)
 * \param[in] uid_client  UID corresponding to c (ignored if c is NULL)
 *
 * \return Pointer to new pcmk__client_t (or NULL on error)
 */
static pcmk__client_t *
client_from_connection(qb_ipcs_connection_t *c, void *key, uid_t uid_client)
{
    pcmk__client_t *client = calloc(1, sizeof(pcmk__client_t));

    if (client == NULL) {
        crm_perror(LOG_ERR, "Allocating client");
        return NULL;
    }

    if (c) {
        client->user = pcmk__uid2username(uid_client);
        if (client->user == NULL) {
            client->user = strdup("#unprivileged");
            CRM_CHECK(client->user != NULL, free(client); return NULL);
            crm_err("Unable to enforce ACLs for user ID %d, assuming unprivileged",
                    uid_client);
        }
        client->ipcs = c;
        pcmk__set_client_flags(client, pcmk__client_ipc);
        client->pid = pcmk__client_pid(c);
        if (key == NULL) {
            key = c;
        }
    }

    client->id = crm_generate_uuid();
    if (client->id == NULL) {
        crm_err("Could not generate UUID for client");
        free(client->user);
        free(client);
        return NULL;
    }
    if (key == NULL) {
        key = client->id;
    }
    if (client_connections == NULL) {
        crm_trace("Creating IPC client table");
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
    pcmk__client_t *client = client_from_connection(NULL, key, 0);

    CRM_ASSERT(client != NULL);
    return client;
}

pcmk__client_t *
pcmk__new_client(qb_ipcs_connection_t *c, uid_t uid_client, gid_t gid_client)
{
    gid_t uid_cluster = 0;
    gid_t gid_cluster = 0;

    pcmk__client_t *client = NULL;

    CRM_CHECK(c != NULL, return NULL);

    if (pcmk_daemon_user(&uid_cluster, &gid_cluster) < 0) {
        static bool need_log = TRUE;

        if (need_log) {
            crm_warn("Could not find user and group IDs for user %s",
                     CRM_DAEMON_USER);
            need_log = FALSE;
        }
    }

    if (uid_client != 0) {
        crm_trace("Giving group %u access to new IPC connection", gid_cluster);
        /* Passing -1 to chown(2) means don't change */
        qb_ipcs_connection_auth_set(c, -1, gid_cluster, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    }

    /* TODO: Do our own auth checking, return NULL if unauthorized */
    client = client_from_connection(c, NULL, uid_client);
    if (client == NULL) {
        return NULL;
    }

    if ((uid_client == 0) || (uid_client == uid_cluster)) {
        /* Remember when a connection came from root or hacluster */
        pcmk__set_client_flags(client, pcmk__client_privileged);
    }

    crm_debug("New IPC client %s for PID %u with uid %d and gid %d",
              client->id, client->pid, uid_client, gid_client);
    return client;
}

static struct iovec *
pcmk__new_ipc_event(void)
{
    struct iovec *iov = calloc(2, sizeof(struct iovec));

    CRM_ASSERT(iov != NULL);
    return iov;
}

/*!
 * \brief Free an I/O vector created by pcmk__ipc_prepare_iov()
 *
 * \param[in] event  I/O vector to free
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
            crm_trace("Destroying %p/%p (%d remaining)",
                      c, c->ipcs, g_hash_table_size(client_connections) - 1);
            g_hash_table_remove(client_connections, c->ipcs);

        } else {
            crm_trace("Destroying remote connection %p (%d remaining)",
                      c, g_hash_table_size(client_connections) - 1);
            g_hash_table_remove(client_connections, c->id);
        }
    }

    if (c->event_timer) {
        g_source_remove(c->event_timer);
    }

    if (c->event_queue) {
        crm_debug("Destroying %d events", g_queue_get_length(c->event_queue));
        g_queue_free_full(c->event_queue, free_event);
    }

    free(c->id);
    free(c->name);
    free(c->user);
    if (c->remote) {
        if (c->remote->auth_timeout) {
            g_source_remove(c->remote->auth_timeout);
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
 * \param[in]     qmax       New threshold (as non-NULL string)
 *
 * \return true if change was allowed, false otherwise
 */
bool
pcmk__set_client_queue_max(pcmk__client_t *client, const char *qmax)
{
    if (pcmk_is_set(client->flags, pcmk__client_privileged)) {
        long long qmax_ll;

        if ((pcmk__scan_ll(qmax, &qmax_ll, 0LL) == pcmk_rc_ok)
            && (qmax_ll > 0LL) && (qmax_ll <= UINT_MAX)) {
            client->queue_max = (unsigned int) qmax_ll;
            return true;
        }
    }
    return false;
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
 * \param[in]  c       IPC client connection
 * \param[in]  data    Data read from client connection
 * \param[out] id      Where to store message ID from libqb header
 * \param[out] flags   Where to store flags from libqb header
 *
 * \return Message XML on success, NULL otherwise
 */
xmlNode *
pcmk__client_data2xml(pcmk__client_t *c, void *data, uint32_t *id,
                      uint32_t *flags)
{
    xmlNode *xml = NULL;
    char *uncompressed = NULL;
    char *text = ((char *)data) + sizeof(pcmk__ipc_header_t);
    pcmk__ipc_header_t *header = data;

    if (!pcmk__valid_ipc_header(header)) {
        return NULL;
    }

    if (id) {
        *id = ((struct qb_ipc_response_header *)data)->id;
    }
    if (flags) {
        *flags = header->flags;
    }

    if (pcmk_is_set(header->flags, crm_ipc_proxied)) {
        /* Mark this client as being the endpoint of a proxy connection.
         * Proxy connections responses are sent on the event channel, to avoid
         * blocking the controller serving as proxy.
         */
        pcmk__set_client_flags(c, pcmk__client_proxied);
    }

    if (header->size_compressed) {
        int rc = 0;
        unsigned int size_u = 1 + header->size_uncompressed;
        uncompressed = calloc(1, size_u);

        crm_trace("Decompressing message data %u bytes into %u bytes",
                  header->size_compressed, size_u);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &size_u, text, header->size_compressed, 1, 0);
        text = uncompressed;

        if (rc != BZ_OK) {
            crm_err("Decompression failed: %s " CRM_XS " bzerror=%d",
                    bz2_strerror(rc), rc);
            free(uncompressed);
            return NULL;
        }
    }

    CRM_ASSERT(text[header->size_uncompressed - 1] == 0);

    xml = string2xml(text);
    crm_log_xml_trace(xml, "[IPC received]");

    free(uncompressed);
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

    c->event_timer = g_timeout_add(delay, crm_ipcs_flush_events_cb, c);
}

/*!
 * \internal
 * \brief Send client any messages in its queue
 *
 * \param[in]  c  Client to flush
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

    } else if (c->event_timer) {
        /* There is already a timer, wait until it goes off */
        crm_trace("Timer active for %p - %d", c->ipcs, c->event_timer);
        return rc;
    }

    if (c->event_queue) {
        queue_len = g_queue_get_length(c->event_queue);
    }
    while (sent < 100) {
        pcmk__ipc_header_t *header = NULL;
        struct iovec *event = NULL;

        if (c->event_queue) {
            // We don't pop unless send is successful
            event = g_queue_peek_head(c->event_queue);
        }
        if (event == NULL) { // Queue is empty
            break;
        }

        qb_rc = qb_ipcs_event_sendv(c->ipcs, event, 2);
        if (qb_rc < 0) {
            rc = (int) -qb_rc;
            break;
        }
        event = g_queue_pop_head(c->event_queue);

        sent++;
        header = event[0].iov_base;
        if (header->size_compressed) {
            crm_trace("Event %d to %p[%d] (%lld compressed bytes) sent",
                      header->qb.id, c->ipcs, c->pid, (long long) qb_rc);
        } else {
            crm_trace("Event %d to %p[%d] (%lld bytes) sent: %.120s",
                      header->qb.id, c->ipcs, c->pid, (long long) qb_rc,
                      (char *) (event[1].iov_base));
        }
        pcmk_free_ipc_event(event);
    }

    queue_len -= sent;
    if (sent > 0 || queue_len) {
        crm_trace("Sent %d events (%d remaining) for %p[%d]: %s (%lld)",
                  sent, queue_len, c->ipcs, c->pid,
                  pcmk_rc_str(rc), (long long) qb_rc);
    }

    if (queue_len) {

        /* Allow clients to briefly fall behind on processing incoming messages,
         * but drop completely unresponsive clients so the connection doesn't
         * consume resources indefinitely.
         */
        if (queue_len > QB_MAX(c->queue_max, PCMK_IPC_DEFAULT_QUEUE_MAX)) {
            if ((c->queue_backlog <= 1) || (queue_len < c->queue_backlog)) {
                /* Don't evict for a new or shrinking backlog */
                crm_warn("Client with process ID %u has a backlog of %u messages "
                         CRM_XS " %p", c->pid, queue_len, c->ipcs);
            } else {
                crm_err("Evicting client with process ID %u due to backlog of %u messages "
                         CRM_XS " %p", c->pid, queue_len, c->ipcs);
                c->queue_backlog = 0;
                qb_ipcs_disconnect(c->ipcs);
                return rc;
            }
        }

        c->queue_backlog = queue_len;
        delay_next_flush(c, queue_len);

    } else {
        /* Event queue is empty, there is no backlog */
        c->queue_backlog = 0;
    }

    return rc;
}

/*!
 * \internal
 * \brief Create an I/O vector for sending an IPC XML message
 *
 * \param[in]  request        Identifier for libqb response header
 * \param[in]  message        XML message to send
 * \param[in]  max_send_size  If 0, default IPC buffer size is used
 * \param[out] result         Where to store prepared I/O vector
 * \param[out] bytes          Size of prepared data in bytes
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__ipc_prepare_iov(uint32_t request, xmlNode *message,
                      uint32_t max_send_size, struct iovec **result,
                      ssize_t *bytes)
{
    static unsigned int biggest = 0;
    struct iovec *iov;
    unsigned int total = 0;
    char *compressed = NULL;
    char *buffer = NULL;
    pcmk__ipc_header_t *header = NULL;

    if ((message == NULL) || (result == NULL)) {
        return EINVAL;
    }

    header = calloc(1, sizeof(pcmk__ipc_header_t));
    if (header == NULL) {
       return ENOMEM; /* errno mightn't be set by allocator */
    }

    buffer = dump_xml_unformatted(message);

    if (max_send_size == 0) {
        max_send_size = crm_ipc_default_buffer_size();
    }
    CRM_LOG_ASSERT(max_send_size != 0);

    *result = NULL;
    iov = pcmk__new_ipc_event();
    iov[0].iov_len = sizeof(pcmk__ipc_header_t);
    iov[0].iov_base = header;

    header->version = PCMK__IPC_VERSION;
    header->size_uncompressed = 1 + strlen(buffer);
    total = iov[0].iov_len + header->size_uncompressed;

    if (total < max_send_size) {
        iov[1].iov_base = buffer;
        iov[1].iov_len = header->size_uncompressed;

    } else {
        unsigned int new_size = 0;

        if (pcmk__compress(buffer, (unsigned int) header->size_uncompressed,
                           (unsigned int) max_send_size, &compressed,
                           &new_size) == pcmk_rc_ok) {

            pcmk__set_ipc_flags(header->flags, "send data", crm_ipc_compressed);
            header->size_compressed = new_size;

            iov[1].iov_len = header->size_compressed;
            iov[1].iov_base = compressed;

            free(buffer);

            biggest = QB_MAX(header->size_compressed, biggest);

        } else {
            crm_log_xml_trace(message, "EMSGSIZE");
            biggest = QB_MAX(header->size_uncompressed, biggest);

            crm_err("Could not compress %u-byte message into less than IPC "
                    "limit of %u bytes; set PCMK_ipc_buffer to higher value "
                    "(%u bytes suggested)",
                    header->size_uncompressed, max_send_size, 4 * biggest);

            free(compressed);
            free(buffer);
            pcmk_free_ipc_event(iov);
            return EMSGSIZE;
        }
    }

    header->qb.size = iov[0].iov_len + iov[1].iov_len;
    header->qb.id = (int32_t)request;    /* Replying to a specific request */

    *result = iov;
    CRM_ASSERT(header->qb.size > 0);
    if (bytes != NULL) {
        *bytes = header->qb.size;
    }
    return pcmk_rc_ok;
}

int
pcmk__ipc_send_iov(pcmk__client_t *c, struct iovec *iov, uint32_t flags)
{
    int rc = pcmk_rc_ok;
    static uint32_t id = 1;
    pcmk__ipc_header_t *header = iov[0].iov_base;

    if (c->flags & pcmk__client_proxied) {
        /* _ALL_ replies to proxied connections need to be sent as events */
        if (!pcmk_is_set(flags, crm_ipc_server_event)) {
            /* The proxied flag lets us know this was originally meant to be a
             * response, even though we're sending it over the event channel.
             */
            pcmk__set_ipc_flags(flags, "server event",
                                crm_ipc_server_event
                                |crm_ipc_proxied_relay_response);
        }
    }

    pcmk__set_ipc_flags(header->flags, "server event", flags);
    if (flags & crm_ipc_server_event) {
        header->qb.id = id++;   /* We don't really use it, but doesn't hurt to set one */

        if (flags & crm_ipc_server_free) {
            crm_trace("Sending the original to %p[%d]", c->ipcs, c->pid);
            add_event(c, iov);

        } else {
            struct iovec *iov_copy = pcmk__new_ipc_event();

            crm_trace("Sending a copy to %p[%d]", c->ipcs, c->pid);
            iov_copy[0].iov_len = iov[0].iov_len;
            iov_copy[0].iov_base = malloc(iov[0].iov_len);
            memcpy(iov_copy[0].iov_base, iov[0].iov_base, iov[0].iov_len);

            iov_copy[1].iov_len = iov[1].iov_len;
            iov_copy[1].iov_base = malloc(iov[1].iov_len);
            memcpy(iov_copy[1].iov_base, iov[1].iov_base, iov[1].iov_len);

            add_event(c, iov_copy);
        }

    } else {
        ssize_t qb_rc;

        CRM_LOG_ASSERT(header->qb.id != 0);     /* Replying to a specific request */

        qb_rc = qb_ipcs_response_sendv(c->ipcs, iov, 2);
        if (qb_rc < header->qb.size) {
            if (qb_rc < 0) {
                rc = (int) -qb_rc;
            }
            crm_notice("Response %d to pid %d failed: %s "
                       CRM_XS " bytes=%u rc=%lld ipcs=%p",
                       header->qb.id, c->pid, pcmk_rc_str(rc),
                       header->qb.size, (long long) qb_rc, c->ipcs);

        } else {
            crm_trace("Response %d sent, %lld bytes to %p[%d]",
                      header->qb.id, (long long) qb_rc, c->ipcs, c->pid);
        }

        if (flags & crm_ipc_server_free) {
            pcmk_free_ipc_event(iov);
        }
    }

    if (flags & crm_ipc_server_event) {
        rc = crm_ipcs_flush_events(c);
    } else {
        crm_ipcs_flush_events(c);
    }

    if ((rc == EPIPE) || (rc == ENOTCONN)) {
        crm_trace("Client %p disconnected", c->ipcs);
    }
    return rc;
}

int
pcmk__ipc_send_xml(pcmk__client_t *c, uint32_t request, xmlNode *message,
                   uint32_t flags)
{
    struct iovec *iov = NULL;
    int rc = pcmk_rc_ok;

    if (c == NULL) {
        return EINVAL;
    }
    rc = pcmk__ipc_prepare_iov(request, message, crm_ipc_default_buffer_size(),
                               &iov, NULL);
    if (rc == pcmk_rc_ok) {
        pcmk__set_ipc_flags(flags, "send data", crm_ipc_server_free);
        rc = pcmk__ipc_send_iov(c, iov, flags);
    } else {
        pcmk_free_ipc_event(iov);
        crm_notice("IPC message to pid %d failed: %s " CRM_XS " rc=%d",
                   c->pid, pcmk_rc_str(rc), rc);
    }
    return rc;
}

/*!
 * \internal
 * \brief Create an acknowledgement with a status code to send to a client
 *
 * \param[in] function  Calling function
 * \param[in] line      Source file line within calling function
 * \param[in] flags     IPC flags to use when sending
 * \param[in] tag       Element name to use for acknowledgement
 * \param[in] status    Exit status code to add to ack
 *
 * \return Newly created XML for ack
 * \note The caller is responsible for freeing the return value with free_xml().
 */
xmlNode *
pcmk__ipc_create_ack_as(const char *function, int line, uint32_t flags,
                        const char *tag, crm_exit_t status)
{
    xmlNode *ack = NULL;

    if (pcmk_is_set(flags, crm_ipc_client_response)) {
        ack = create_xml_node(NULL, tag);
        crm_xml_add(ack, "function", function);
        crm_xml_add_int(ack, "line", line);
        crm_xml_add_int(ack, "status", (int) status);
    }
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
 * \param[in] tag       Element name to use for acknowledgement
 * \param[in] status    Status code to send with acknowledgement
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__ipc_send_ack_as(const char *function, int line, pcmk__client_t *c,
                      uint32_t request, uint32_t flags, const char *tag,
                      crm_exit_t status)
{
    int rc = pcmk_rc_ok;
    xmlNode *ack = pcmk__ipc_create_ack_as(function, line, flags, tag, status);

    if (ack != NULL) {
        crm_trace("Ack'ing IPC message from client %s as <%s status=%d>",
                  pcmk__client_name(c), tag, status);
        c->request_id = 0;
        rc = pcmk__ipc_send_xml(c, request, ack, flags);
        free_xml(ack);
    }
    return rc;
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the pacemaker-based API
 *
 * \param[out] ipcs_ro   New IPC server for read-only pacemaker-based API
 * \param[out] ipcs_rw   New IPC server for read/write pacemaker-based API
 * \param[out] ipcs_shm  New IPC server for shared-memory pacemaker-based API
 * \param[in]  ro_cb     IPC callbacks for read-only API
 * \param[in]  rw_cb     IPC callbacks for read/write and shared-memory APIs
 *
 * \note This function exits fatally if unable to create the servers.
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
        crm_err("Failed to create the CIB manager: exiting and inhibiting respawn");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled");
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Destroy IPC servers for pacemaker-based API
 *
 * \param[out] ipcs_ro   IPC server for read-only pacemaker-based API
 * \param[out] ipcs_rw   IPC server for read/write pacemaker-based API
 * \param[out] ipcs_shm  IPC server for shared-memory pacemaker-based API
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
 * \brief Add an IPC server to the main loop for the pacemaker-controld API
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
 * \brief Add an IPC server to the main loop for the pacemaker-attrd API
 *
 * \param[in] cb  IPC callbacks
 *
 * \note This function exits fatally if unable to create the servers.
 */
void
pcmk__serve_attrd_ipc(qb_ipcs_service_t **ipcs,
                      struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(T_ATTRD, QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        crm_err("Failed to create pacemaker-attrd server: exiting and inhibiting respawn");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled.");
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the pacemaker-fenced API
 *
 * \param[in] cb  IPC callbacks
 *
 * \note This function exits fatally if unable to create the servers.
 */
void
pcmk__serve_fenced_ipc(qb_ipcs_service_t **ipcs,
                       struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server_with_prio("stonith-ng", QB_IPC_NATIVE, cb,
                                              QB_LOOP_HIGH);

    if (*ipcs == NULL) {
        crm_err("Failed to create fencer: exiting and inhibiting respawn.");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled.");
        crm_exit(CRM_EX_FATAL);
    }
}

/*!
 * \internal
 * \brief Add an IPC server to the main loop for the pacemakerd API
 *
 * \param[in] cb  IPC callbacks
 *
 * \note This function exits with CRM_EX_OSERR if unable to create the servers.
 */
void
pcmk__serve_pacemakerd_ipc(qb_ipcs_service_t **ipcs,
                       struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(CRM_SYSTEM_MCP, QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        crm_err("Couldn't start pacemakerd IPC server");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled.");
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
 * \brief Add an IPC server to the main loop for the pacemaker-schedulerd API
 *
 * \param[in] cb IPC callbacks
 *
 * \note This function exits fatally if unable to create the servers.
 */
qb_ipcs_service_t *
pcmk__serve_schedulerd_ipc(struct qb_ipcs_service_handlers *cb)
{
    return mainloop_add_ipc_server(CRM_SYSTEM_PENGINE, QB_IPC_NATIVE, cb);
}

/*!
 * \brief Check whether string represents a client name used by cluster daemons
 *
 * \param[in] name  String to check
 *
 * \return true if name is standard client name used by daemons, false otherwise
 *
 * \note This is provided by the client, and so cannot be used by itself as a
 *       secure means of authentication.
 */
bool
crm_is_daemon_name(const char *name)
{
    name = pcmk__message_name(name);
    return (!strcmp(name, CRM_SYSTEM_CRMD)
            || !strcmp(name, CRM_SYSTEM_STONITHD)
            || !strcmp(name, "stonith-ng")
            || !strcmp(name, "attrd")
            || !strcmp(name, CRM_SYSTEM_CIB)
            || !strcmp(name, CRM_SYSTEM_MCP)
            || !strcmp(name, CRM_SYSTEM_DC)
            || !strcmp(name, CRM_SYSTEM_TENGINE)
            || !strcmp(name, CRM_SYSTEM_LRMD));
}
