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

int
crm_ipcs_client_pid(qb_ipcs_connection_t *c)
{
    struct qb_ipcs_connection_stats stats;
    stats.client_pid = 0;
    qb_ipcs_connection_stats_get(c, &stats, 0);
    return stats.client_pid;
}

xmlNode *
crm_ipcs_recv(qb_ipcs_connection_t *c, void *data, size_t size, uint32_t *id, uint32_t *flags)
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

ssize_t
crm_ipcs_send(qb_ipcs_connection_t *c, uint32_t request, xmlNode *message, enum crm_ipc_server_flags flags)
{
    int rc;
    int lpc = 0;
    int retries = 40;
    int level = LOG_CRIT;
    struct iovec iov[2];
    static uint32_t id = 1;
    const char *type = "Response";
    struct qb_ipc_response_header header;
    char *buffer = dump_xml_unformatted(message);
    struct timespec delay = { 0, 250000000 }; /* 250ms */

    memset(&iov, 0, 2 * sizeof(struct iovec));
    iov[0].iov_len = sizeof(struct qb_ipc_response_header);
    iov[0].iov_base = &header;
    iov[1].iov_len = 1 + strlen(buffer);
    iov[1].iov_base = buffer;

    if(flags & crm_ipc_server_event) {
        header.id = id++;    /* We don't really use it, but doesn't hurt to set one */
    } else {
        CRM_LOG_ASSERT (request != 0);
        header.id = request; /* Replying to a specific request */
    }

    header.error = 0; /* unused */
    header.size = iov[0].iov_len + iov[1].iov_len;

    if(flags & crm_ipc_server_error) {
        retries = 20;
        level = LOG_ERR;

    } else if(flags & crm_ipc_server_info) {
        retries = 10;
        level = LOG_INFO;
    }

    while(lpc < retries) {
        if(flags & crm_ipc_server_event) {
            type = "Event";
            rc = qb_ipcs_event_sendv(c, iov, 2);
            if(rc == -EPIPE || rc == -ENOTCONN) {
                crm_trace("Client %p disconnected", c);
                level = LOG_INFO;
            }
            
        } else {
            rc = qb_ipcs_response_sendv(c, iov, 2);
        }

        if(rc != -EAGAIN) {
            break;
        }

        lpc++;
        crm_debug("Attempting resend %d of %s %d (%d bytes) to %p[%d]: %.120s",
                  lpc, type, header.id, header.size, c, crm_ipcs_client_pid(c), buffer);
        nanosleep(&delay, NULL);
    }

    if(rc < header.size) {
        struct qb_ipcs_connection_stats_2 *stats = qb_ipcs_connection_stats_get_2(c, 0);
        do_crm_log(level,
                   "%s %d failed, size=%d, to=%p[%d], queue=%d, rc=%d: %.120s",
                   type, header.id, header.size, c, stats->client_pid, stats->event_q_length, rc, buffer);
        free(stats);

    } else {
        crm_trace("%s %d sent, %d bytes to %p[%d]: %.120s", type, header.id, rc,
                  c, crm_ipcs_client_pid(c), buffer);
    }
    free(buffer);
    return rc;
}

void
crm_ipcs_send_ack(
    qb_ipcs_connection_t *c, uint32_t request, const char *tag, const char *function, int line)
{
    xmlNode *ack = create_xml_node(NULL, tag);
    crm_xml_add(ack, "function", function);
    crm_xml_add_int(ack, "line", line);
    crm_ipcs_send(c, request, ack, FALSE);
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
            crm_warn("Sending to %s is disabled until pending reply is recieved", client->name);
            free(buffer);
            return -EREMOTEIO;

        } else {
            crm_notice("Lost reply from %s finally arrived, sending re-enabled", client->name);
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

    } else if(rc <= 0) {
        crm_warn("Request %d to %s failed: %s (%ld)", header.qb.id, client->name, pcmk_strerror(rc), rc);
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
