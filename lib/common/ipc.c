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
#include <crm/common/cluster.h>

xmlNode *
xmlfromIPC(IPC_Channel * ch, int timeout)
{
    xmlNode *xml = NULL;
    HA_Message *msg = NULL;

#if HAVE_MSGFROMIPC_TIMEOUT
    int ipc_rc = IPC_OK;

    msg = msgfromIPC_timeout(ch, MSG_ALLOWINTR, timeout, &ipc_rc);

    if (ipc_rc == IPC_TIMEOUT) {
        crm_warn("No message received in the required interval (%ds)", timeout);
        return NULL;

    } else if (ipc_rc == IPC_BROKEN) {
        crm_debug("Peer disconnected");
        return NULL;

    } else if (ipc_rc != IPC_OK) {
        crm_err("msgfromIPC_timeout failed: rc=%d", ipc_rc);
        return NULL;

    } else if (msg == NULL) {
        crm_err("Empty reply from msgfromIPC_timeout");
        return NULL;
    }
#else
    static gboolean do_show_error = TRUE;

    if (timeout && do_show_error) {
        crm_err("Timeouts are not supported by the current heartbeat libraries");
        do_show_error = FALSE;
    }

    msg = msgfromIPC_noauth(ch);
    if (msg == NULL) {
        crm_debug("Empty reply from msgfromIPC_noauth");
        return NULL;
    }
#endif

    xml = convert_ha_message(NULL, msg, __FUNCTION__);
    CRM_CHECK(xml != NULL, crm_err("Invalid ipc message"));
    crm_msg_del(msg);
    return xml;
}

static int
xml2ipcchan(xmlNode * m, IPC_Channel * ch)
{
    HA_Message *msg = NULL;
    IPC_Message *imsg = NULL;

    if (m == NULL || ch == NULL) {
        crm_err("Invalid msg2ipcchan argument");
        errno = EINVAL;
        return HA_FAIL;
    }

    msg = convert_xml_message(m);
    if ((imsg = hamsg2ipcmsg(msg, ch)) == NULL) {
        crm_err("hamsg2ipcmsg() failure");
        crm_msg_del(msg);
        return HA_FAIL;
    }
    crm_msg_del(msg);

    if (ch->ops->send(ch, imsg) != IPC_OK) {
        if (ch->ch_status == IPC_CONNECT) {
            snprintf(ch->failreason, MAXFAILREASON,
                     "send failed,farside_pid=%d, sendq length=%ld(max is %ld)",
                     ch->farside_pid, (long)ch->send_queue->current_qlen,
                     (long)ch->send_queue->max_qlen);
        }
        imsg->msg_done(imsg);
        return HA_FAIL;
    }
    return HA_OK;
}

/* frees msg */
gboolean
send_ipc_message(IPC_Channel * ipc_client, xmlNode * msg)
{
    gboolean all_is_good = TRUE;
    int fail_level = LOG_WARNING;

    if (ipc_client != NULL && ipc_client->conntype == IPC_CLIENT) {
        fail_level = LOG_ERR;
    }

    if (msg == NULL) {
        crm_err("cant send NULL message");
        all_is_good = FALSE;

    } else if (ipc_client == NULL) {
        crm_err("cant send message without an IPC Channel");
        all_is_good = FALSE;

    } else if (ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
        do_crm_log(fail_level, "IPC Channel to %d is not connected", (int)ipc_client->farside_pid);
        all_is_good = FALSE;
    }

    if (all_is_good && xml2ipcchan(msg, ipc_client) != HA_OK) {
        do_crm_log(fail_level, "Could not send IPC message to %d", (int)ipc_client->farside_pid);
        all_is_good = FALSE;

        if (ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
            do_crm_log(fail_level,
                       "IPC Channel to %d is no longer connected", (int)ipc_client->farside_pid);

        } else if (ipc_client->conntype == IPC_CLIENT) {
            if (ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
                crm_err("Send queue to %d (size=%d) full.",
                        ipc_client->farside_pid, (int)ipc_client->send_queue->max_qlen);
            }
        }
    }
    return all_is_good;
}

void
default_ipc_connection_destroy(gpointer user_data)
{
    return;
}

int
init_server_ipc_comms(char *channel_name,
                      gboolean(*channel_client_connect) (IPC_Channel * newclient,
                                                         gpointer user_data),
                      void (*channel_connection_destroy) (gpointer user_data))
{
    /* the clients wait channel is the other source of events.
     * This source delivers the clients connection events.
     * listen to this source at a relatively lower priority.
     */

    char commpath[SOCKET_LEN];
    IPC_WaitConnection *wait_ch;

    sprintf(commpath, CRM_STATE_DIR "/%s", channel_name);

    wait_ch = wait_channel_init(commpath);

    if (wait_ch == NULL) {
        return 1;
    }

    G_main_add_IPC_WaitConnection(G_PRIORITY_LOW, wait_ch, NULL, FALSE,
                                  channel_client_connect, channel_name, channel_connection_destroy);

    crm_trace("Listening on: %s", commpath);

    return 0;
}

GCHSource *
init_client_ipc_comms(const char *channel_name,
                      gboolean(*dispatch) (IPC_Channel * source_data, gpointer user_data),
                      void *client_data, IPC_Channel ** ch)
{
    IPC_Channel *a_ch = NULL;
    GCHSource *the_source = NULL;
    void *callback_data = client_data;

    a_ch = init_client_ipc_comms_nodispatch(channel_name);
    if (ch != NULL) {
        *ch = a_ch;
        if (callback_data == NULL) {
            callback_data = a_ch;
        }
    }

    if (a_ch == NULL) {
        crm_warn("Setup of client connection failed," " not adding channel to mainloop");

        return NULL;
    }

    if (dispatch == NULL) {
        crm_warn("No dispatch method specified..."
                 "maybe you meant init_client_ipc_comms_nodispatch()?");
    } else {
        crm_trace("Adding dispatch method to channel");

        the_source = G_main_add_IPC_Channel(G_PRIORITY_HIGH, a_ch, FALSE, dispatch, callback_data,
                                            default_ipc_connection_destroy);
    }

    return the_source;
}

IPC_Channel *
init_client_ipc_comms_nodispatch(const char *channel_name)
{
    IPC_Channel *ch;
    GHashTable *attrs;
    static char path[] = IPC_PATH_ATTR;

    char *commpath = NULL;
    int local_socket_len = 2;   /* 2 = '/' + '\0' */

    local_socket_len += strlen(channel_name);
    local_socket_len += strlen(CRM_STATE_DIR);

    crm_malloc0(commpath, local_socket_len);

    sprintf(commpath, CRM_STATE_DIR "/%s", channel_name);
    commpath[local_socket_len - 1] = '\0';
    crm_debug("Attempting to talk on: %s", commpath);

    attrs = g_hash_table_new(crm_str_hash, g_str_equal);
    g_hash_table_insert(attrs, path, commpath);

    ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
    g_hash_table_destroy(attrs);

    if (ch == NULL) {
        crm_err("Could not access channel on: %s", commpath);
        crm_free(commpath);
        return NULL;

    } else if (ch->ops->initiate_connection(ch) != IPC_OK) {
        crm_debug("Could not init comms on: %s", commpath);
        ch->ops->destroy(ch);
        crm_free(commpath);
        return NULL;
    }

    ch->ops->set_recv_qlen(ch, 512);
    ch->ops->set_send_qlen(ch, 512);
    ch->should_send_block = TRUE;

    crm_trace("Processing of %s complete", commpath);

    crm_free(commpath);
    return ch;
}

IPC_WaitConnection *
wait_channel_init(char daemonsocket[])
{
    IPC_WaitConnection *wait_ch;
    mode_t mask;
    char path[] = IPC_PATH_ATTR;
    GHashTable *attrs;

    attrs = g_hash_table_new(crm_str_hash, g_str_equal);
    g_hash_table_insert(attrs, path, daemonsocket);

    mask = umask(0);
    wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
    if (wait_ch == NULL) {
        crm_perror(LOG_ERR, "Can't create wait channel of type %s", IPC_ANYTYPE);
        exit(1);
    }
    mask = umask(mask);

    g_hash_table_destroy(attrs);

    return wait_ch;
}

gboolean
subsystem_msg_dispatch(IPC_Channel * sender, void *user_data)
{
    int lpc = 0;
    xmlNode *msg = NULL;
    xmlNode *data = NULL;
    gboolean all_is_well = TRUE;
    const char *sys_to;
    const char *task;

    gboolean(*process_function)
        (xmlNode * msg, xmlNode * data, IPC_Channel * sender) = NULL;

    while (IPC_ISRCONN(sender)) {
        gboolean process = FALSE;

        if (sender->ops->is_message_pending(sender) == 0) {
            break;
        }

        msg = xmlfromIPC(sender, MAX_IPC_DELAY);
        if (msg == NULL) {
            break;
        }

        lpc++;
        crm_log_xml_trace(msg, __FUNCTION__);

        sys_to = crm_element_value(msg, F_CRM_SYS_TO);
        task = crm_element_value(msg, F_CRM_TASK);

        if (safe_str_eq(task, CRM_OP_HELLO)) {
            process = TRUE;

        } else if (sys_to == NULL) {
            crm_err("Value of %s was NULL!!", F_CRM_SYS_TO);

        } else if (task == NULL) {
            crm_err("Value of %s was NULL!!", F_CRM_TASK);

        } else {
            process = TRUE;
        }

        if (process == FALSE) {
            free_xml(msg);
            msg = NULL;
            continue;
        }

        data = get_message_xml(msg, F_CRM_DATA);
        process_function = user_data;
        if (FALSE == process_function(msg, data, sender)) {
            crm_warn("Received a message destined for %s" " by mistake", sys_to);
        }

        free_xml(msg);
        msg = NULL;

        if (sender->ch_status == IPC_CONNECT) {
            break;
        }
    }

    crm_trace("Processed %d messages", lpc);
    if (sender->ch_status != IPC_CONNECT) {
        crm_err("The server %d has left us: Shutting down...NOW", sender->farside_pid);

        exit(1);                /* shutdown properly later */

        return !all_is_well;
    }
    return all_is_well;
}

gboolean
is_ipc_empty(IPC_Channel * ch)
{
    if (ch == NULL) {
        return TRUE;

    } else if (ch->send_queue->current_qlen == 0 && ch->recv_queue->current_qlen == 0) {
        return TRUE;
    }
    return FALSE;
}

void
send_hello_message(IPC_Channel * ipc_client,
                   const char *uuid,
                   const char *client_name, const char *major_version, const char *minor_version)
{
    xmlNode *hello_node = NULL;
    xmlNode *hello = NULL;

    if (uuid == NULL || strlen(uuid) == 0
        || client_name == NULL || strlen(client_name) == 0
        || major_version == NULL || strlen(major_version) == 0
        || minor_version == NULL || strlen(minor_version) == 0) {
        crm_err("Missing fields, Hello message will not be valid.");
        return;
    }

    hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
    crm_xml_add(hello_node, "major_version", major_version);
    crm_xml_add(hello_node, "minor_version", minor_version);
    crm_xml_add(hello_node, "client_name", client_name);
    crm_xml_add(hello_node, "client_uuid", uuid);

    crm_trace("creating hello message");
    hello = create_request(CRM_OP_HELLO, hello_node, NULL, NULL, client_name, uuid);

    send_ipc_message(ipc_client, hello);
    crm_trace("hello message sent");

    free_xml(hello_node);
    free_xml(hello);
}

gboolean
process_hello_message(xmlNode * hello,
                      char **uuid, char **client_name, char **major_version, char **minor_version)
{
    const char *local_uuid;
    const char *local_client_name;
    const char *local_major_version;
    const char *local_minor_version;

    *uuid = NULL;
    *client_name = NULL;
    *major_version = NULL;
    *minor_version = NULL;

    if (hello == NULL) {
        return FALSE;
    }

    local_uuid = crm_element_value(hello, "client_uuid");
    local_client_name = crm_element_value(hello, "client_name");
    local_major_version = crm_element_value(hello, "major_version");
    local_minor_version = crm_element_value(hello, "minor_version");

    if (local_uuid == NULL || strlen(local_uuid) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "uuid");
        return FALSE;

    } else if (local_client_name == NULL || strlen(local_client_name) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "client name");
        return FALSE;

    } else if (local_major_version == NULL || strlen(local_major_version) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "major version");
        return FALSE;

    } else if (local_minor_version == NULL || strlen(local_minor_version) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "minor version");
        return FALSE;
    }

    *uuid = crm_strdup(local_uuid);
    *client_name = crm_strdup(local_client_name);
    *major_version = crm_strdup(local_major_version);
    *minor_version = crm_strdup(local_minor_version);

    crm_trace("Hello message ok");
    return TRUE;
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
        true_from = crm_strdup(sys_from);
    } else {
        crm_err("No sys from specified");
    }

    /* host_from will get set for us if necessary by CRMd when routed */
    request = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(request, F_CRM_ORIGIN, origin);
    crm_xml_add(request, F_TYPE, T_CRM);
    crm_xml_add(request, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(request, F_CRM_MSG_TYPE, XML_ATTR_REQUEST);
    crm_xml_add(request, XML_ATTR_REFERENCE, reference);
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
    crm_free(reference);
    crm_free(true_from);

    return request;
}

ha_msg_input_t *
new_ha_msg_input(xmlNode * orig)
{
    ha_msg_input_t *input_copy = NULL;

    crm_malloc0(input_copy, sizeof(ha_msg_input_t));
    input_copy->msg = orig;
    input_copy->xml = get_message_xml(input_copy->msg, F_CRM_DATA);
    return input_copy;
}

void
delete_ha_msg_input(ha_msg_input_t * orig)
{
    if (orig == NULL) {
        return;
    }
    free_xml(orig->msg);
    crm_free(orig);
}

xmlNode *
validate_crm_message(xmlNode * msg, const char *sys, const char *uuid, const char *msg_type)
{
    const char *to = NULL;
    const char *type = NULL;
    const char *crm_msg_reference = NULL;
    xmlNode *action = NULL;
    const char *true_sys;
    char *local_sys = NULL;

    if (msg == NULL) {
        return NULL;
    }

    to = crm_element_value(msg, F_CRM_SYS_TO);
    type = crm_element_value(msg, F_CRM_MSG_TYPE);

    crm_msg_reference = crm_element_value(msg, XML_ATTR_REFERENCE);
    action = msg;
    true_sys = sys;

    if (uuid != NULL) {
        local_sys = generate_hash_key(sys, uuid);
        true_sys = local_sys;
    }

    if (to == NULL) {
        crm_info("No sub-system defined.");
        action = NULL;
    } else if (true_sys != NULL && strcasecmp(to, true_sys) != 0) {
        crm_trace("The message is not for this sub-system (%s != %s).", to, true_sys);
        action = NULL;
    }

    crm_free(local_sys);

    if (type == NULL) {
        crm_info("No message type defined.");
        return NULL;

    } else if (msg_type != NULL && strcasecmp(msg_type, type) != 0) {
        crm_info("Expecting a (%s) message but received a (%s).", msg_type, type);
        action = NULL;
    }

    if (crm_msg_reference == NULL) {
        crm_info("No message crm_msg_reference defined.");
        action = NULL;
    }
/*
 	if(action != NULL) 
		crm_trace(
		       "XML is valid and node with message type (%s) found.",
		       type);
	crm_trace("Returning node (%s)", crm_element_name(action));
*/

    return action;
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
    const char *crm_msg_reference = crm_element_value(original_request, XML_ATTR_REFERENCE);

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
    crm_xml_add(reply, XML_ATTR_REFERENCE, crm_msg_reference);
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
crm_ipcs_recv(qb_ipcs_connection_t *c, void *data, size_t size)
{
    char *text = ((char*)data) + sizeof(struct qb_ipc_request_header);
    crm_trace("Received %.120s", text);
    return string2xml(text);
}

ssize_t
crm_ipcs_send(qb_ipcs_connection_t *c, xmlNode *message, gboolean event)
{
    int rc;
    struct iovec iov[2];
    static uint32_t id = 0;
    const char *type = "Response";
    struct qb_ipc_response_header header;
    char *buffer = dump_xml_unformatted(message);

    iov[0].iov_len = sizeof(struct qb_ipc_response_header);
    iov[0].iov_base = &header;
    iov[1].iov_len = 1 + strlen(buffer);
    iov[1].iov_base = buffer;

    header.id = id++; /* We don't really use it, but doesn't hurt to set one */
    header.error = 0; /* unused */
    header.size = iov[0].iov_len + iov[1].iov_len;    
    
    if(event) {
        rc = qb_ipcs_event_sendv(c, iov, 2);
        type = "Event";

    } else {
        rc = qb_ipcs_response_sendv(c, iov, 2);
    }

    if(rc < header.size) {
        do_crm_log((flags & ipcs_send_error)?LOG_ERR:LOG_INFO,
                   "%s %d failed, size=%d, to=%p[%d], rc=%d: %.120s",
                   type, header.id, header.size, crm_ipcs_client_pid(c), rc, buffer);
    } else {
        crm_trace("%s %d sent, %d bytes to %p: %.120s", type, header.id, rc, c, buffer);
    }
    crm_free(buffer);
    return rc;
}

void
crm_ipcs_send_ack(
    qb_ipcs_connection_t *c, const char *tag, const char *function, int line)
{
    xmlNode *ack = create_xml_node(NULL, tag);
    crm_xml_add(ack, "function", function);
    crm_xml_add_int(ack, "line", line);
    crm_ipcs_send(c, ack, FALSE);
    free_xml(ack);
}

/* Client... */

#define MIN_MSG_SIZE    12336 /* sizeof(struct qb_ipc_connection_response) */
#define MAX_MSG_SIZE    20*1024

typedef struct crm_ipc_s
{
        struct pollfd pfd;
        
        int buf_size;
        int msg_size;
        char *buffer;
        char *name;

        qb_ipcc_connection_t *ipc;
        
} crm_ipc_t;

static int
_infer_ipc_buffer(int max)
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
    crm_malloc0(client, sizeof(crm_ipc_t));

    client->name = crm_strdup(name);
    client->buf_size = _infer_ipc_buffer(max_size);
    client->buffer = malloc(client->buf_size);

    client->pfd.fd = -1;
    client->pfd.events = POLLIN;
    client->pfd.revents = 0;
    
    crm_trace("Using max message size of %d for %s", client->buf_size, client->name);
    
    return client;
}

bool
crm_ipc_connect(crm_ipc_t *client) 
{
    client->ipc = qb_ipcc_connect(client->name, client->buf_size);

    if (client->ipc == NULL) {
        crm_perror(LOG_INFO, "Could not establish %s connection", client->name);
        return FALSE;
    }

    client->closed = FALSE;
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
    crm_trace("Disconnecting %s IPC connection %p", client->name, client);
    if(client->ipc) {
        qb_ipcc_disconnect(client->ipc);
    }
}

void
crm_ipc_destroy(crm_ipc_t *client) 
{
    crm_trace("Destroying %s IPC connection %p", client->name, client);
    free(client->buffer);
    free(client->name);
    free(client);    
}

int
crm_ipc_get_fd(crm_ipc_t *client)
{
    int fd = 0;
    
    CRM_ASSERT(client != NULL);
    if(qb_ipcc_fd_get(client->ipc, &fd) < 0) {
        crm_perror(LOG_ERR, "Could not obtain file IPC descriptor for %s", client->name);
    }
    return fd;
}

bool
crm_ipc_connected(crm_ipc_t *client) 
{
    bool rc = FALSE;

    if(client == NULL) {
        crm_trace("No client");
        return FALSE;

    } else if(client->pfd.fd < 0) {
        crm_trace("Bad descriptor");
        return FALSE;        
    }

    rc = qb_ipcc_is_connected(client->ipc);
    if(rc == FALSE) {
        client->pfd.fd = -1;
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
    CRM_ASSERT(client->buffer != NULL);
    
    crm_trace("Message recieved on %s IPC connection", client->name);

    client->buffer[0] = 0;
    client->msg_size = qb_ipcc_event_recv(client->ipc, client->buffer, client->buf_size-1, -1);
    if(client->msg_size >= 0) {
        struct qb_ipc_response_header *header = (struct qb_ipc_response_header *)client->buffer;
        crm_trace("Recieved response %d, size=%d, rc=%d", header->id, header->size, client->msg_size);
        client->buffer[client->msg_size] = 0;
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

int
crm_ipc_send(crm_ipc_t *client, xmlNode *message, xmlNode **reply, int32_t ms_timeout)
{
    long rc = 0;
    struct iovec iov[2];
    static uint32_t id = 0;
    struct qb_ipc_request_header header;
    char *buffer = dump_xml_unformatted(message);

    iov[0].iov_len = sizeof(struct qb_ipc_request_header);
    iov[0].iov_base = &header;
    iov[1].iov_len = 1 + strlen(buffer);
    iov[1].iov_base = buffer;

    header.id = id++; /* We don't really use it, but doesn't hurt to set one */
    header.size = iov[0].iov_len + iov[1].iov_len;

    if(ms_timeout == 0) {
        ms_timeout = 5000;
    }
    
    crm_trace("Waiting for reply to %ld bytes: %.120s...", iov[1].iov_base, buffer);
    rc = qb_ipcc_sendv_recv(client->ipc, iov, 2, client->buffer, client->buf_size, ms_timeout);
    crm_trace("rc=%d, errno=%d", rc, errno);

    if(rc > 0 && reply) {
        *reply = string2xml(crm_ipc_buffer(client));
    }

    if(crm_ipc_connected(client) == FALSE) {
        crm_notice("Connection to %s closed: %d", client->name, rc);

    } else if(rc <= 0) {
        crm_perror(LOG_ERR, "Request to %s failed: %ld", client->name, rc);
        crm_info("Request was %.120s", buffer);
    }

    crm_free(buffer);
    return rc;
}
