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

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <grp.h>

#include <errno.h>
#include <fcntl.h>
#include <bzlib.h>

#include <crm/crm.h>   /* indirectly: pcmk_err_generic */
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs_internal.h>

#include <crm/common/ipc_internal.h>  /* PCMK__SPECIAL_PID* */

#define PCMK_IPC_VERSION 1

/* Evict clients whose event queue grows this large (by default) */
#define PCMK_IPC_DEFAULT_QUEUE_MAX 500

struct crm_ipc_response_header {
    struct qb_ipc_response_header qb;
    uint32_t size_uncompressed;
    uint32_t size_compressed;
    uint32_t flags;
    uint8_t  version; /* Protect against version changes for anyone that might bother to statically link us */
};

static int hdr_offset = 0;
static unsigned int ipc_buffer_max = 0;
static unsigned int pick_ipc_buffer(unsigned int max);

static inline void
crm_ipc_init(void)
{
    if (hdr_offset == 0) {
        hdr_offset = sizeof(struct crm_ipc_response_header);
    }
    if (ipc_buffer_max == 0) {
        ipc_buffer_max = pick_ipc_buffer(0);
    }
}

unsigned int
crm_ipc_default_buffer_size(void)
{
    return pick_ipc_buffer(0);
}

static char *
generateReference(const char *custom1, const char *custom2)
{
    static uint ref_counter = 0;

    return crm_strdup_printf("%s-%s-%lld-%u",
                             (custom1? custom1 : "_empty_"),
                             (custom2? custom2 : "_empty_"),
                             (long long) time(NULL), ref_counter++);
}

xmlNode *
create_request_adv(const char *task, xmlNode * msg_data,
                   const char *host_to, const char *sys_to,
                   const char *sys_from, const char *uuid_from, const char *origin)
{
    char *true_from = NULL;
    xmlNode *request = NULL;
    char *reference = generateReference(task, sys_from);

    if (uuid_from != NULL) {
        true_from = generate_hash_key(sys_from, uuid_from);
    } else if (sys_from != NULL) {
        true_from = strdup(sys_from);
    } else {
        crm_err("No sys from specified");
    }

    // host_from will get set for us if necessary by the controller when routed
    request = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(request, F_CRM_ORIGIN, origin);
    crm_xml_add(request, F_TYPE, T_CRM);
    crm_xml_add(request, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(request, F_CRM_MSG_TYPE, XML_ATTR_REQUEST);
    crm_xml_add(request, F_CRM_REFERENCE, reference);
    crm_xml_add(request, F_CRM_TASK, task);
    crm_xml_add(request, F_CRM_SYS_TO, sys_to);
    crm_xml_add(request, F_CRM_SYS_FROM, true_from);

    /* HOSTTO will be ignored if it is to the DC anyway. */
    if (host_to != NULL && strlen(host_to) > 0) {
        crm_xml_add(request, F_CRM_HOST_TO, host_to);
    }

    if (msg_data != NULL) {
        add_message_xml(request, F_CRM_DATA, msg_data);
    }
    free(reference);
    free(true_from);

    return request;
}

/*
 * This method adds a copy of xml_response_data
 */
xmlNode *
create_reply_adv(xmlNode * original_request, xmlNode * xml_response_data, const char *origin)
{
    xmlNode *reply = NULL;

    const char *host_from = crm_element_value(original_request, F_CRM_HOST_FROM);
    const char *sys_from = crm_element_value(original_request, F_CRM_SYS_FROM);
    const char *sys_to = crm_element_value(original_request, F_CRM_SYS_TO);
    const char *type = crm_element_value(original_request, F_CRM_MSG_TYPE);
    const char *operation = crm_element_value(original_request, F_CRM_TASK);
    const char *crm_msg_reference = crm_element_value(original_request, F_CRM_REFERENCE);

    if (type == NULL) {
        crm_err("Cannot create new_message, no message type in original message");
        CRM_ASSERT(type != NULL);
        return NULL;
#if 0
    } else if (strcasecmp(XML_ATTR_REQUEST, type) != 0) {
        crm_err("Cannot create new_message, original message was not a request");
        return NULL;
#endif
    }
    reply = create_xml_node(NULL, __FUNCTION__);
    if (reply == NULL) {
        crm_err("Cannot create new_message, malloc failed");
        return NULL;
    }

    crm_xml_add(reply, F_CRM_ORIGIN, origin);
    crm_xml_add(reply, F_TYPE, T_CRM);
    crm_xml_add(reply, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(reply, F_CRM_MSG_TYPE, XML_ATTR_RESPONSE);
    crm_xml_add(reply, F_CRM_REFERENCE, crm_msg_reference);
    crm_xml_add(reply, F_CRM_TASK, operation);

    /* since this is a reply, we reverse the from and to */
    crm_xml_add(reply, F_CRM_SYS_TO, sys_from);
    crm_xml_add(reply, F_CRM_SYS_FROM, sys_to);

    /* HOSTTO will be ignored if it is to the DC anyway. */
    if (host_from != NULL && strlen(host_from) > 0) {
        crm_xml_add(reply, F_CRM_HOST_TO, host_from);
    }

    if (xml_response_data != NULL) {
        add_message_xml(reply, F_CRM_DATA, xml_response_data);
    }

    return reply;
}

/* Libqb based IPC */

/* Server... */

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

/*!
 * \internal
 * \brief Remote IPC clients based on iterative function result
 *
 * \param[in] func       Function to call for each active IPC client
 * \param[in] user_data  Pointer to pass to function
 *
 * \note The parameters are the same as for g_hash_table_foreach_remove().
 */
void
pcmk__foreach_ipc_client_remove(GHRFunc func, gpointer user_data)
{
    if ((func != NULL) && (client_connections != NULL)) {
        g_hash_table_foreach_remove(client_connections, func, user_data);
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

const char *
pcmk__client_name(pcmk__client_t *c)
{
    if (c == NULL) {
        return "null";
    } else if (c->name == NULL && c->id == NULL) {
        return "unknown";
    } else if (c->name == NULL) {
        return c->id;
    } else {
        return c->name;
    }
}

const char *
pcmk__client_type_str(enum pcmk__client_type client_type)
{
    switch (client_type) {
        case PCMK__CLIENT_IPC:
            return "IPC";
        case PCMK__CLIENT_TCP:
            return "TCP";
#ifdef HAVE_GNUTLS_GNUTLS_H
        case PCMK__CLIENT_TLS:
            return "TLS";
#endif
        default:
            return "unknown";
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
#if ENABLE_ACL
        client->user = pcmk__uid2username(uid_client);
        if (client->user == NULL) {
            client->user = strdup("#unprivileged");
            CRM_CHECK(client->user != NULL, free(client); return NULL);
            crm_err("Unable to enforce ACLs for user ID %d, assuming unprivileged",
                    uid_client);
        }
#endif
        client->ipcs = c;
        client->kind = PCMK__CLIENT_IPC;
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
        set_bit(client->flags, pcmk__client_privileged);
    }

    crm_debug("New IPC client %s for PID %u with uid %d and gid %d",
              client->id, client->pid, uid_client, gid_client);
    return client;
}

static struct iovec *
pcmk__new_ipc_event()
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
 * \return TRUE if change was allowed, FALSE otherwise
 */
bool
pcmk__set_client_queue_max(pcmk__client_t *client, const char *qmax)
{
    if (is_set(client->flags, pcmk__client_privileged)) {
        long long qmax_int;

        errno = 0;
        qmax_int = crm_parse_ll(qmax, NULL);
        if ((errno == 0) && (qmax_int > 0)) {
            client->queue_max = (unsigned int) qmax_int;
            return TRUE;
        }
    }
    return FALSE;
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
    char *text = ((char *)data) + sizeof(struct crm_ipc_response_header);
    struct crm_ipc_response_header *header = data;

    if (id) {
        *id = ((struct qb_ipc_response_header *)data)->id;
    }
    if (flags) {
        *flags = header->flags;
    }

    if (is_set(header->flags, crm_ipc_proxied)) {
        /* Mark this client as being the endpoint of a proxy connection.
         * Proxy connections responses are sent on the event channel, to avoid
         * blocking the controller serving as proxy.
         */
        c->flags |= pcmk__client_proxied;
    }

    if(header->version > PCMK_IPC_VERSION) {
        crm_err("Filtering incompatible v%d IPC message, we only support versions <= %d",
                header->version, PCMK_IPC_VERSION);
        return NULL;
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
        struct crm_ipc_response_header *header = NULL;
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
    struct crm_ipc_response_header *header = NULL;

    if ((message == NULL) || (result == NULL)) {
        return EINVAL;
    }

    header = calloc(1, sizeof(struct crm_ipc_response_header));
    if (header == NULL) {
        return errno;
    }

    buffer = dump_xml_unformatted(message);
    crm_ipc_init();

    if (max_send_size == 0) {
        max_send_size = ipc_buffer_max;
    }
    CRM_LOG_ASSERT(max_send_size != 0);

    *result = NULL;
    iov = pcmk__new_ipc_event();
    iov[0].iov_len = hdr_offset;
    iov[0].iov_base = header;

    header->version = PCMK_IPC_VERSION;
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

            header->flags |= crm_ipc_compressed;
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
    struct crm_ipc_response_header *header = iov[0].iov_base;

    if (c->flags & pcmk__client_proxied) {
        /* _ALL_ replies to proxied connections need to be sent as events */
        if (is_not_set(flags, crm_ipc_server_event)) {
            flags |= crm_ipc_server_event;
            /* this flag lets us know this was originally meant to be a response.
             * even though we're sending it over the event channel. */
            flags |= crm_ipc_proxied_relay_response;
        }
    }

    header->flags |= flags;
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
    crm_ipc_init();
    rc = pcmk__ipc_prepare_iov(request, message, ipc_buffer_max, &iov, NULL);
    if (rc == pcmk_rc_ok) {
        rc = pcmk__ipc_send_iov(c, iov, flags | crm_ipc_server_free);
    } else {
        pcmk_free_ipc_event(iov);
        crm_notice("IPC message to pid %d failed: %s " CRM_XS " rc=%d",
                   c->pid, pcmk_rc_str(rc), rc);
    }
    return rc;
}

void
pcmk__ipc_send_ack_as(const char *function, int line, pcmk__client_t *c,
                      uint32_t request, uint32_t flags, const char *tag)
{
    if (flags & crm_ipc_client_response) {
        xmlNode *ack = create_xml_node(NULL, tag);

        crm_trace("Ack'ing IPC message from %s", pcmk__client_name(c));
        c->request_id = 0;
        crm_xml_add(ack, "function", function);
        crm_xml_add_int(ack, "line", line);
        pcmk__ipc_send_xml(c, request, ack, flags);
        free_xml(ack);
    }
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

/* Client... */

#define MIN_MSG_SIZE    12336   /* sizeof(struct qb_ipc_connection_response) */
#define MAX_MSG_SIZE    128*1024 /* 128k default */

struct crm_ipc_s {
    struct pollfd pfd;

    /* the max size we can send/receive over ipc */
    unsigned int max_buf_size;
    /* Size of the allocated 'buffer' */
    unsigned int buf_size;
    int msg_size;
    int need_reply;
    char *buffer;
    char *name;

    qb_ipcc_connection_t *ipc;

};

static unsigned int
pick_ipc_buffer(unsigned int max)
{
    static unsigned int global_max = 0;

    if (global_max == 0) {
        const char *env = getenv("PCMK_ipc_buffer");

        if (env) {
            int env_max = crm_parse_int(env, "0");

            global_max = (env_max > 0)? QB_MAX(MIN_MSG_SIZE, env_max) : MAX_MSG_SIZE;

        } else {
            global_max = MAX_MSG_SIZE;
        }
    }

    return QB_MAX(max, global_max);
}

crm_ipc_t *
crm_ipc_new(const char *name, size_t max_size)
{
    crm_ipc_t *client = NULL;

    client = calloc(1, sizeof(crm_ipc_t));

    client->name = strdup(name);
    client->buf_size = pick_ipc_buffer(max_size);
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
    struct crm_ipc_response_header *header = (struct crm_ipc_response_header *)(void*)client->buffer;

    if (header->size_compressed) {
        int rc = 0;
        unsigned int size_u = 1 + header->size_uncompressed;
        /* never let buf size fall below our max size required for ipc reads. */
        unsigned int new_buf_size = QB_MAX((hdr_offset + size_u), client->max_buf_size);
        char *uncompressed = calloc(1, new_buf_size);

        crm_trace("Decompressing message data %u bytes into %u bytes",
                 header->size_compressed, size_u);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed + hdr_offset, &size_u,
                                        client->buffer + hdr_offset, header->size_compressed, 1, 0);

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
         * CRM_ASSERT((header->size_uncompressed + hdr_offset) >= ipc_buffer_max);
         */
        CRM_ASSERT(size_u == header->size_uncompressed);

        memcpy(uncompressed, client->buffer, hdr_offset);       /* Preserve the header */
        header = (struct crm_ipc_response_header *)(void*)uncompressed;

        free(client->buffer);
        client->buf_size = new_buf_size;
        client->buffer = uncompressed;
    }

    CRM_ASSERT(client->buffer[hdr_offset + header->size_uncompressed - 1] == 0);
    return pcmk_rc_ok;
}

long
crm_ipc_read(crm_ipc_t * client)
{
    struct crm_ipc_response_header *header = NULL;

    CRM_ASSERT(client != NULL);
    CRM_ASSERT(client->ipc != NULL);
    CRM_ASSERT(client->buffer != NULL);

    crm_ipc_init();

    client->buffer[0] = 0;
    client->msg_size = qb_ipcc_event_recv(client->ipc, client->buffer,
                                          client->buf_size, 0);
    if (client->msg_size >= 0) {
        int rc = crm_ipc_decompress(client);

        if (rc != pcmk_rc_ok) {
            return pcmk_rc2legacy(rc);
        }

        header = (struct crm_ipc_response_header *)(void*)client->buffer;
        if(header->version > PCMK_IPC_VERSION) {
            crm_err("Filtering incompatible v%d IPC message, we only support versions <= %d",
                    header->version, PCMK_IPC_VERSION);
            return -EBADMSG;
        }

        crm_trace("Received %s event %d, size=%u, rc=%d, text: %.100s",
                  client->name, header->qb.id, header->qb.size, client->msg_size,
                  client->buffer + hdr_offset);

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
    return client->buffer + sizeof(struct crm_ipc_response_header);
}

uint32_t
crm_ipc_buffer_flags(crm_ipc_t * client)
{
    struct crm_ipc_response_header *header = NULL;

    CRM_ASSERT(client != NULL);
    if (client->buffer == NULL) {
        return 0;
    }

    header = (struct crm_ipc_response_header *)(void*)client->buffer;
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

    crm_ipc_init();

    /* get the reply */
    crm_trace("client %s waiting on reply to msg id %d", client->name, request_id);
    do {

        *bytes = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, 1000);
        if (*bytes > 0) {
            struct crm_ipc_response_header *hdr = NULL;

            rc = crm_ipc_decompress(client);
            if (rc != pcmk_rc_ok) {
                return rc;
            }

            hdr = (struct crm_ipc_response_header *)(void*)client->buffer;
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
    struct crm_ipc_response_header *header;

    crm_ipc_init();

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
        struct crm_ipc_response_header *hdr = (struct crm_ipc_response_header *)(void*)client->buffer;

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


/* Utils */

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
