/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>

struct crm_ipc_request_header 
{
        struct qb_ipc_request_header qb;
        uint32_t flags;
};

static char *
generateReference(const char *custom1, const char *custom2)
{
    static uint ref_counter = 0;
    const char *local_cust1 = custom1;
    const char *local_cust2 = custom2;
    int reference_len = 4;
    char *since_epoch = NULL;

    reference_len += 20;        /* too big */
    reference_len += 40;        /* too big */

    if (local_cust1 == NULL) {
        local_cust1 = "_empty_";
    }
    reference_len += strlen(local_cust1);

    if (local_cust2 == NULL) {
        local_cust2 = "_empty_";
    }
    reference_len += strlen(local_cust2);

    since_epoch = calloc(1, reference_len);

    if (since_epoch != NULL) {
        sprintf(since_epoch, "%s-%s-%ld-%u",
                local_cust1, local_cust2, (unsigned long)time(NULL), ref_counter++);
    }

    return since_epoch;
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

    /* host_from will get set for us if necessary by CRMd when routed */
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
        crm_err("Cannot create new_message," " no message type in original message");
        CRM_ASSERT(type != NULL);
        return NULL;
#if 0
    } else if (strcasecmp(XML_ATTR_REQUEST, type) != 0) {
        crm_err("Cannot create new_message," " original message was not a request");
        return NULL;
#endif
    }
    reply = create_xml_node(NULL, __FUNCTION__);
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

GHashTable *client_connections = NULL;

crm_client_t *
crm_client_get(qb_ipcs_connection_t *c) 
{
    if(client_connections) {
        return g_hash_table_lookup(client_connections, c);
    }

    crm_trace("No client found for %p", c);
    return NULL;
}

crm_client_t *
crm_client_get_by_id(const char *id)
{
    gpointer key;
    crm_client_t *client;
    GHashTableIter iter;

    if(client_connections) {
        g_hash_table_iter_init(&iter, client_connections);
        while (g_hash_table_iter_next(&iter, &key, (gpointer *) & client)) {
            if(strcmp(client->id, id) == 0) {
                return client;
            }
        }
    }

    crm_trace("No client found with id=%s", id);
    return NULL;
}

const char *
crm_client_name(crm_client_t *c) 
{
    if(c == NULL){
        return "null";
    } else if(c->name == NULL && c->id == NULL) {
        return "unknown";
    } else if(c->name == NULL) {
        return c->id;
    } else {
        return c->name;
    }
}

void
crm_client_init(void) 
{
    if(client_connections == NULL) {
        crm_trace("Creating client hash table");
        client_connections = g_hash_table_new(g_direct_hash, g_direct_equal);
    }
}

void
crm_client_cleanup(void) 
{
    if(client_connections == NULL) {
        int active = g_hash_table_size(client_connections);
        if(active) {
            crm_err("Exiting with %d active connections", active);
        }
        g_hash_table_destroy(client_connections);
    }
}

crm_client_t *
crm_client_new(qb_ipcs_connection_t *c, uid_t uid, gid_t gid) 
{
    crm_client_t *client = NULL;

    CRM_LOG_ASSERT(c);
    if(c == NULL) {
        return NULL;
    }

    crm_client_init();

    client = calloc(1, sizeof(crm_client_t));

    client->ipcs = c;
    client->kind = CRM_CLIENT_IPC;
    client->pid = crm_ipcs_client_pid(c);

    client->id = crm_generate_uuid();

    crm_info("Connecting %p for uid=%d gid=%d pid=%u id=%s",
              c, uid, gid, client->pid, client->id);
    
#if ENABLE_ACL
    {
        struct group *crm_grp = NULL;
        crm_grp = getgrnam(CRM_DAEMON_GROUP);
        if (crm_grp) {
            qb_ipcs_connection_auth_set(c, -1, crm_grp->gr_gid, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        }
        client->user = uid2username(uid);
    }
#endif

    g_hash_table_insert(client_connections, c, client);
    return client;
}

void
crm_client_destroy(crm_client_t *c) 
{
    if(c == NULL) {
        return;
    }

    if(client_connections) {
        if(c->ipcs) {
            crm_trace("Destroying %p (%d remaining)",
                      c->ipcs, crm_hash_table_size(client_connections) - 1);
            g_hash_table_remove(client_connections, c->ipcs);
        } else {
            crm_trace("Destroying remote connection %p (%d remaining)",
                      c, crm_hash_table_size(client_connections) - 1);
            g_hash_table_remove(client_connections, c->id);
        }
    }

    crm_info("Destroying %d events", g_list_length(c->event_queue));
    while(c->event_queue) {
        struct iovec *event = c->event_queue->data;
        c->event_queue = g_list_remove(c->event_queue, event);
        free(event[0].iov_base);
        free(event[1].iov_base);
        free(event);
    }
    
    free(c->id);
    free(c->name);
    free(c->user);
    if(c->remote) {
        if (c->remote->auth_timeout) {
            g_source_remove(c->remote->auth_timeout);
        }
        free(c->remote->buffer);
        free(c->remote);
    }
    free(c);
}

int
crm_ipcs_client_pid(qb_ipcs_connection_t *c)
{
     struct qb_ipcs_connection_stats stats;
     stats.client_pid = 0;
     qb_ipcs_connection_stats_get(c, &stats, 0);
     return stats.client_pid;
}

xmlNode *
crm_ipcs_recv(crm_client_t *c, void *data, size_t size, uint32_t *id, uint32_t *flags)
{
    char *text = ((char*)data) + sizeof(struct crm_ipc_request_header);
    crm_trace("Received %.200s", text);
    if(id) {
        *id = ((struct qb_ipc_request_header*)data)->id;
    }
    if(flags) {
        *flags = ((struct crm_ipc_request_header*)data)->flags;
    }
    return string2xml(text);
}

ssize_t crm_ipcs_flush_events(crm_client_t *c);

static gboolean
crm_ipcs_flush_events_cb(gpointer data)
{
    crm_client_t *c = data;
    c->event_timer = 0;
    crm_ipcs_flush_events(c);
    return FALSE;
}

ssize_t
crm_ipcs_flush_events(crm_client_t *c)
{
    int sent = 0;
    ssize_t rc = 0;
    int queue_len = g_list_length(c->event_queue);

    if(c->event_timer) {
        /* There is already a timer, wait until it goes off */
        crm_trace("Timer active for %p - %d", c->ipcs, c->event_timer);
        return FALSE;
    }

    while(c->event_queue && sent < 100) {
        struct qb_ipc_response_header *header = NULL;
        struct iovec *event = c->event_queue->data;
        rc = qb_ipcs_event_sendv(c->ipcs, event, 2);
        if(rc < 0) {
            break;
        }

        sent++;
        header = event[0].iov_base;
        crm_trace("Event %d to %p[%d] (%d bytes) sent: %.120s",
                  header->id, c->ipcs, c->pid, rc, event[1].iov_base);

        c->event_queue = g_list_remove(c->event_queue, event);
        free(event[0].iov_base);
        free(event[1].iov_base);
        free(event);
    }

    queue_len -= sent;
    if(sent > 0 || c->event_queue) {
        crm_trace("Sent %d events (%d remaining) for %p[%d]: %s",
                  sent, queue_len, c->ipcs, c->pid, pcmk_strerror(rc<0?rc:0));
    }

    if(c->event_queue) {
        if(queue_len % 100 == 0 && queue_len > 99) {
            crm_warn("Event queue for %p[%d] has grown to %d", c->ipcs, c->pid, queue_len);

        } else if(queue_len > 500) {
            crm_err("Evicting slow client %p[%d]: event queue reached %d entries",
                    c->ipcs, c->pid, queue_len);
            qb_ipcs_disconnect(c->ipcs);
            return rc;
        }

        c->event_timer = g_timeout_add(1000 + 100 * queue_len, crm_ipcs_flush_events_cb, c);
    }

    return rc;
}

ssize_t
crm_ipcs_send(crm_client_t *c, uint32_t request, xmlNode *message, enum crm_ipc_server_flags flags)
{
    static uint32_t id = 1;

    ssize_t rc = 0;
    ssize_t event_rc;
    struct iovec *iov;
    char *buffer = dump_xml_unformatted(message);
    struct qb_ipc_response_header *header = calloc(1, sizeof(struct qb_ipc_response_header));

    iov = calloc(2, sizeof(struct iovec));

    iov[0].iov_len = sizeof(struct qb_ipc_response_header);
    iov[0].iov_base = header;

    iov[1].iov_len = 1 + strlen(buffer);
    iov[1].iov_base = buffer;

    header->error = 0; /* unused */
    header->size = iov[0].iov_len + iov[1].iov_len;

    if(flags & crm_ipc_server_event) {
        header->id = id++;    /* We don't really use it, but doesn't hurt to set one */
        c->event_queue = g_list_append(c->event_queue, iov);

    } else {
        CRM_LOG_ASSERT (request != 0);
        header->id = request; /* Replying to a specific request */

        rc = qb_ipcs_response_sendv(c->ipcs, iov, 2);
        if(rc < header->size) {
            crm_notice("Response %d to %p[%d] (%d bytes) failed: %s - %.120s",
                       header->id, c->ipcs, c->pid, header->size, pcmk_strerror(rc), buffer);

        } else {
            crm_trace("Response %d sent, %d bytes to %p[%d]: %.120s",
                      header->id, rc, c->ipcs, c->pid, buffer);
        }
        free(iov[0].iov_base);
        free(iov[1].iov_base);
        free(iov);
    }

    event_rc = crm_ipcs_flush_events(c);

    if(rc == -EPIPE || rc == -ENOTCONN) {
        crm_trace("Client %p disconnected", c->ipcs);
    } else if(event_rc == -EPIPE || event_rc == -ENOTCONN) {
        crm_trace("Client %p disconnected", c->ipcs);
        rc = event_rc;
    } else if(flags & crm_ipc_server_event) {
        rc = event_rc;
    }

    return rc;
}

void
crm_ipcs_send_ack(
    crm_client_t *c, uint32_t request, const char *tag, const char *function, int line)
{
    xmlNode *ack = create_xml_node(NULL, tag);
    crm_xml_add(ack, "function", function);
    crm_xml_add_int(ack, "line", line);
    crm_ipcs_send(c, request, ack, 0);
    free_xml(ack);
}

/* Client... */

#define MIN_MSG_SIZE    12336 /* sizeof(struct qb_ipc_connection_response) */
#define MAX_MSG_SIZE    20*1024

struct crm_ipc_s
{
        struct pollfd pfd;
        
        int buf_size;
        int msg_size;
        int need_reply;
        char *buffer;
        char *name;

        qb_ipcc_connection_t *ipc;
        
};

static int
pick_ipc_buffer(int max)
{
    const char *env = getenv("PCMK_ipc_buffer");

    if(env) {
        max = crm_parse_int(env, "0");
    }

    if(max <= 0) {
        max = MAX_MSG_SIZE;
    }

    if(max < MIN_MSG_SIZE) {
        max = MIN_MSG_SIZE;
    }

    crm_trace("Using max message size of %d", max);
    return max;
}

crm_ipc_t *
crm_ipc_new(const char *name, size_t max_size) 
{
    crm_ipc_t *client = NULL;
    client = calloc(1, sizeof(crm_ipc_t));

    client->name = strdup(name);
    client->buf_size = pick_ipc_buffer(max_size);
    client->buffer = malloc(client->buf_size);

    client->pfd.fd = -1;
    client->pfd.events = POLLIN;
    client->pfd.revents = 0;
    
    return client;
}

bool
crm_ipc_connect(crm_ipc_t *client) 
{
    client->need_reply = FALSE;
    client->ipc = qb_ipcc_connect(client->name, client->buf_size);

    if (client->ipc == NULL) {
        crm_perror(LOG_INFO, "Could not establish %s connection", client->name);
        return FALSE;
    }

    client->pfd.fd = crm_ipc_get_fd(client);
    if(client->pfd.fd < 0) {
        crm_perror(LOG_INFO, "Could not obtain file descriptor for %s connection", client->name);
        return FALSE;
    }

    qb_ipcc_context_set(client->ipc, client);

    return TRUE;
}

void
crm_ipc_close(crm_ipc_t *client) 
{
    if(client) {
        crm_trace("Disconnecting %s IPC connection %p (%p.%p)", client->name, client, client->ipc);

        if(client->ipc) {
            qb_ipcc_connection_t *ipc = client->ipc;
            client->ipc = NULL;
            qb_ipcc_disconnect(ipc);
        }
    }
}

void
crm_ipc_destroy(crm_ipc_t *client) 
{
    if(client) {
        if(client->ipc && qb_ipcc_is_connected(client->ipc)) {
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
crm_ipc_get_fd(crm_ipc_t *client)
{
    int fd = 0;
    
    CRM_ASSERT(client != NULL);
    if(client->ipc && qb_ipcc_fd_get(client->ipc, &fd) == 0) {
        return fd;
    }

    crm_perror(LOG_ERR, "Could not obtain file IPC descriptor for %s", client->name);
    return -EINVAL;
}

bool
crm_ipc_connected(crm_ipc_t *client) 
{
    bool rc = FALSE;

    if(client == NULL) {
        crm_trace("No client");
        return FALSE;

    } else if(client->ipc == NULL) {
        crm_trace("No connection");
        return FALSE;

    } else if(client->pfd.fd < 0) {
        crm_trace("Bad descriptor");
        return FALSE;        
    }

    rc = qb_ipcc_is_connected(client->ipc);
    if(rc == FALSE) {
        client->pfd.fd = -EINVAL;
    }
    return rc;
}

int
crm_ipc_ready(crm_ipc_t *client) 
{
    CRM_ASSERT(client != NULL);

    if(crm_ipc_connected(client) == FALSE) {
        return -ENOTCONN;
    }

    client->pfd.revents = 0;
    return poll(&(client->pfd), 1, 0);
}

long
crm_ipc_read(crm_ipc_t *client) 
{
    CRM_ASSERT(client != NULL);
    CRM_ASSERT(client->ipc != NULL);
    CRM_ASSERT(client->buffer != NULL);

    client->buffer[0] = 0;
    client->msg_size = qb_ipcc_event_recv(client->ipc, client->buffer, client->buf_size-1, 0);
    if(client->msg_size >= 0) {
        struct qb_ipc_response_header *header = (struct qb_ipc_response_header *)client->buffer;
        client->buffer[client->msg_size] = 0;

        crm_trace("Recieved %s event %d, size=%d, rc=%d, text: %.100s",
                  client->name, header->id, header->size, client->msg_size,
                  client->buffer+sizeof(struct qb_ipc_response_header));
    } else {
        crm_trace("No message from %s recieved: %s", client->name, pcmk_strerror(client->msg_size));
    }

    if(crm_ipc_connected(client) == FALSE || client->msg_size == -ENOTCONN) {
        crm_err("Connection to %s failed", client->name);
    }
    
    return client->msg_size;
}

const char *
crm_ipc_buffer(crm_ipc_t *client) 
{
    CRM_ASSERT(client != NULL);    
    return client->buffer + sizeof(struct qb_ipc_response_header);
}

const char *crm_ipc_name(crm_ipc_t *client)
{
    CRM_ASSERT(client != NULL);
    return client->name;
}

static int
internal_ipc_send_recv(crm_ipc_t *client, const void *iov)
{
    int rc = 0;
    do {
        rc = qb_ipcc_sendv_recv(client->ipc, iov, 2, client->buffer, client->buf_size, -1);
    } while(rc == -EAGAIN && crm_ipc_connected(client));

    return rc;
}

static int
internal_ipc_send_request(crm_ipc_t *client, const void *iov, int ms_timeout)
{
    int rc = 0;
    time_t timeout = time(NULL) + 1 + (ms_timeout / 1000);

    do {
        rc = qb_ipcc_sendv(client->ipc, iov, 2);
    } while(rc == -EAGAIN && time(NULL) < timeout && crm_ipc_connected(client));

    return rc;
}

static int
internal_ipc_get_reply(crm_ipc_t *client, int request_id, int ms_timeout)
{
    time_t timeout = time(NULL) + 1 + (ms_timeout / 1000);
    int rc = 0;

    /* get the reply */
    crm_trace("client %s waiting on reply to msg id %d", client->name, request_id);
    do {

        rc = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, 1000);
        if(rc > 0) {
            struct qb_ipc_response_header *hdr = (struct qb_ipc_response_header *)client->buffer;

            if(hdr->id == request_id) {
                /* Got it */
                break;
            } else if(hdr->id < request_id){
                xmlNode *bad = string2xml(crm_ipc_buffer(client));
                crm_err("Discarding old reply %d (need %d)", hdr->id, request_id);
                crm_log_xml_notice(bad, "OldIpcReply");

            } else {
                xmlNode *bad = string2xml(crm_ipc_buffer(client));
                crm_err("Discarding newer reply %d (need %d)", hdr->id, request_id);
                crm_log_xml_notice(bad, "ImpossibleReply");
                CRM_ASSERT(hdr->id <= request_id);
            }
        } else if (crm_ipc_connected(client) == FALSE) {
            crm_err("Server disconnected client %s while waiting for msg id %d", client->name, request_id);
            break;
        }

    } while(time(NULL) < timeout);

    return rc;
}

int
crm_ipc_send(crm_ipc_t *client, xmlNode *message, enum crm_ipc_flags flags, int32_t ms_timeout, xmlNode **reply)
{
    long rc = 0;
    struct iovec iov[2];
    static uint32_t id = 0;
    struct crm_ipc_request_header header;
    char *buffer = NULL;

    if(client == NULL) {
        crm_notice("Invalid connection");
        return -ENOTCONN;

    } else if(crm_ipc_connected(client) == FALSE) {
        /* Don't even bother */
        crm_notice("Connection to %s closed", client->name);
        return -ENOTCONN;
    }

    if(client->need_reply) {
        crm_trace("Trying again to obtain pending reply from %s", client->name);
        rc = qb_ipcc_recv(client->ipc, client->buffer, client->buf_size, 300);
        if(rc < 0) {
            crm_warn("Sending to %s (%p) is disabled until pending reply is recieved", client->name, client->ipc);
            free(buffer);
            return -EREMOTEIO;

        } else {
            crm_notice("Lost reply from %s (%p) finally arrived, sending re-enabled", client->name, client->ipc);
            client->need_reply = FALSE;
        }
    }

    buffer = dump_xml_unformatted(message);
    iov[0].iov_len = sizeof(struct crm_ipc_request_header);
    iov[0].iov_base = &header;
    iov[1].iov_len = 1 + strlen(buffer);
    iov[1].iov_base = buffer;

    header.qb.id = ++id;
    header.qb.size = iov[0].iov_len + iov[1].iov_len;
    header.flags = flags;

    if(ms_timeout == 0) {
        ms_timeout = 5000;
    }

    crm_trace("Sending from client: %s request id: %d bytes: %u timeout:%d msg: %.200s...",
        client->name, header.qb.id, header.qb.size, ms_timeout, buffer);

    if(ms_timeout > 0) {

        rc = internal_ipc_send_request(client, iov, ms_timeout);

        if (rc <= 0) {
            crm_trace("Failed to send from client %s request %d with %u bytes: %.200s...",
                client->name, header.qb.id, header.qb.size, buffer);
            goto send_cleanup;
        } else if(is_not_set(flags, crm_ipc_client_response)) {
            crm_trace("Message sent, not waiting for reply to %d from %s to %u bytes: %.200s...",
                      header.qb.id, client->name, header.qb.size, buffer);

            goto send_cleanup;
        }

        rc = internal_ipc_get_reply(client, header.qb.id, ms_timeout);
        if(rc < 0) {
           /* No reply, for now, disable sending
            *
            * The alternative is to close the connection since we don't know
            * how to detect and discard out-of-sequence replies
            *
            * TODO - implement the above
            */
            client->need_reply = TRUE;
        }

    } else {
        rc = internal_ipc_send_recv(client, iov);
    }

    if(rc > 0) {
        struct qb_ipc_response_header *hdr = (struct qb_ipc_response_header *)client->buffer;
        crm_trace("Recieved response %d, size=%d, rc=%ld, text: %.200s", hdr->id, hdr->size, rc, crm_ipc_buffer(client));

        if(reply) {
            *reply = string2xml(crm_ipc_buffer(client));
        }

    } else {
        crm_trace("Response not recieved: rc=%ld, errno=%d", rc, errno);
    }

send_cleanup:
    if(crm_ipc_connected(client) == FALSE) {
        crm_notice("Connection to %s closed: %s (%ld)", client->name, pcmk_strerror(rc), rc);

    } else if(rc == -ETIMEDOUT) {
        crm_warn("Request %d to %s (%p) failed: %s (%ld) after %dms",
                 header.qb.id, client->name, client->ipc, pcmk_strerror(rc), rc, ms_timeout);
        crm_info("Request was %.120s", buffer);
        crm_write_blackbox(0, NULL);

    } else if(rc <= 0) {
        crm_warn("Request %d to %s (%p) failed: %s (%ld)",
                 header.qb.id, client->name, client->ipc, pcmk_strerror(rc), rc);
        crm_info("Request was %.120s", buffer);
    }

    free(buffer);
    return rc;
}

/* Utils */

xmlNode *
create_hello_message(const char *uuid,
                     const char *client_name, const char *major_version, const char *minor_version)
{
    xmlNode *hello_node = NULL;
    xmlNode *hello = NULL;

    if (uuid == NULL || strlen(uuid) == 0
        || client_name == NULL || strlen(client_name) == 0
        || major_version == NULL || strlen(major_version) == 0
        || minor_version == NULL || strlen(minor_version) == 0) {
        crm_err("Missing fields, Hello message will not be valid.");
        return NULL;
    }

    hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
    crm_xml_add(hello_node, "major_version", major_version);
    crm_xml_add(hello_node, "minor_version", minor_version);
    crm_xml_add(hello_node, "client_name", client_name);
    crm_xml_add(hello_node, "client_uuid", uuid);

    crm_trace("creating hello message");
    hello = create_request(CRM_OP_HELLO, hello_node, NULL, NULL, client_name, uuid);
    free_xml(hello_node);

    return hello;
}
