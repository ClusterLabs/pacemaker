/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipcs.h>
#include <crm/msg_xml.h>

#include <crm/stonith-ng.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

CRM_TRACE_INIT_DATA(lrmd);

static stonith_t *stonith_api = NULL;

static int lrmd_api_disconnect(lrmd_t * lrmd);
static int lrmd_api_is_connected(lrmd_t * lrmd);

/* IPC proxy functions */
int lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg);
static void lrmd_internal_proxy_dispatch(lrmd_t *lrmd, xmlNode *msg);
void lrmd_internal_set_proxy_callback(lrmd_t * lrmd, void *userdata, void (*callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg));

#ifdef HAVE_GNUTLS_GNUTLS_H
#  define LRMD_CLIENT_HANDSHAKE_TIMEOUT 5000    /* 5 seconds */
gnutls_psk_client_credentials_t psk_cred_s;
int lrmd_tls_set_key(gnutls_datum_t * key, const char *location);
static void lrmd_tls_disconnect(lrmd_t * lrmd);
static int global_remote_msg_id = 0;
int lrmd_tls_send_msg(crm_remote_t * session, xmlNode * msg, uint32_t id, const char *msg_type);
static void lrmd_tls_connection_destroy(gpointer userdata);
#endif

typedef struct lrmd_private_s {
    enum client_type type;
    char *token;
    mainloop_io_t *source;

    /* IPC parameters */
    crm_ipc_t *ipc;

    crm_remote_t *remote;

    /* Extra TLS parameters */
    char *remote_nodename;
#ifdef HAVE_GNUTLS_GNUTLS_H
    char *server;
    int port;
    gnutls_psk_client_credentials_t psk_cred_c;

    int sock;
    GList *pending_notify;
    crm_trigger_t *process_notify;
#endif

    lrmd_event_callback callback;

    /* Internal IPC proxy msg passing for remote guests */
    void (*proxy_callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg);
    void *proxy_callback_userdata;
} lrmd_private_t;

static lrmd_list_t *
lrmd_list_add(lrmd_list_t * head, const char *value)
{
    lrmd_list_t *p, *end;

    p = calloc(1, sizeof(lrmd_list_t));
    p->val = strdup(value);

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

void
lrmd_list_freeall(lrmd_list_t * head)
{
    lrmd_list_t *p;

    while (head) {
        char *val = (char *)head->val;

        p = head->next;
        free(val);
        free(head);
        head = p;
    }
}

lrmd_key_value_t *
lrmd_key_value_add(lrmd_key_value_t * head, const char *key, const char *value)
{
    lrmd_key_value_t *p, *end;

    p = calloc(1, sizeof(lrmd_key_value_t));
    p->key = strdup(key);
    p->value = strdup(value);

    end = head;
    while (end && end->next) {
        end = end->next;
    }

    if (end) {
        end->next = p;
    } else {
        head = p;
    }

    return head;
}

void
lrmd_key_value_freeall(lrmd_key_value_t * head)
{
    lrmd_key_value_t *p;

    while (head) {
        p = head->next;
        free(head->key);
        free(head->value);
        free(head);
        head = p;
    }
}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    g_hash_table_replace(user_data, strdup(key), strdup(value));
}

lrmd_event_data_t *
lrmd_copy_event(lrmd_event_data_t * event)
{
    lrmd_event_data_t *copy = NULL;

    copy = calloc(1, sizeof(lrmd_event_data_t));

    /* This will get all the int values.
     * we just have to be careful not to leave any
     * dangling pointers to strings. */
    memcpy(copy, event, sizeof(lrmd_event_data_t));

    copy->rsc_id = event->rsc_id ? strdup(event->rsc_id) : NULL;
    copy->op_type = event->op_type ? strdup(event->op_type) : NULL;
    copy->user_data = event->user_data ? strdup(event->user_data) : NULL;
    copy->output = event->output ? strdup(event->output) : NULL;
    copy->remote_nodename = event->remote_nodename ? strdup(event->remote_nodename) : NULL;

    if (event->params) {
        copy->params = g_hash_table_new_full(crm_str_hash,
                                             g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

        if (copy->params != NULL) {
            g_hash_table_foreach(event->params, dup_attr, copy->params);
        }
    }

    return copy;
}

void
lrmd_free_event(lrmd_event_data_t * event)
{
    if (!event) {
        return;
    }

    /* free gives me grief if i try to cast */
    free((char *)event->rsc_id);
    free((char *)event->op_type);
    free((char *)event->user_data);
    free((char *)event->output);
    free((char *)event->remote_nodename);
    if (event->params) {
        g_hash_table_destroy(event->params);
    }
    free(event);
}

static int
lrmd_dispatch_internal(lrmd_t * lrmd, xmlNode * msg)
{
    const char *type;
    const char *proxy_session = crm_element_value(msg, F_LRMD_IPC_SESSION);
    lrmd_private_t *native = lrmd->private;
    lrmd_event_data_t event = { 0, };

    if (proxy_session != NULL) {
        /* this is proxy business */
        lrmd_internal_proxy_dispatch(lrmd, msg);
        return 1;
    }

    if (!native->callback) {
        /* no callback set */
        crm_trace("notify event received but client has not set callback");
        return 1;
    }

    event.remote_nodename = native->remote_nodename;
    type = crm_element_value(msg, F_LRMD_OPERATION);
    crm_element_value_int(msg, F_LRMD_CALLID, &event.call_id);
    event.rsc_id = crm_element_value(msg, F_LRMD_RSC_ID);

    if (crm_str_eq(type, LRMD_OP_RSC_REG, TRUE)) {
        event.type = lrmd_event_register;
    } else if (crm_str_eq(type, LRMD_OP_RSC_UNREG, TRUE)) {
        event.type = lrmd_event_unregister;
    } else if (crm_str_eq(type, LRMD_OP_RSC_EXEC, TRUE)) {
        crm_element_value_int(msg, F_LRMD_TIMEOUT, &event.timeout);
        crm_element_value_int(msg, F_LRMD_RSC_INTERVAL, &event.interval);
        crm_element_value_int(msg, F_LRMD_RSC_START_DELAY, &event.start_delay);
        crm_element_value_int(msg, F_LRMD_EXEC_RC, (int *)&event.rc);
        crm_element_value_int(msg, F_LRMD_OP_STATUS, &event.op_status);
        crm_element_value_int(msg, F_LRMD_RSC_DELETED, &event.rsc_deleted);

        crm_element_value_int(msg, F_LRMD_RSC_RUN_TIME, (int *)&event.t_run);
        crm_element_value_int(msg, F_LRMD_RSC_RCCHANGE_TIME, (int *)&event.t_rcchange);
        crm_element_value_int(msg, F_LRMD_RSC_EXEC_TIME, (int *)&event.exec_time);
        crm_element_value_int(msg, F_LRMD_RSC_QUEUE_TIME, (int *)&event.queue_time);

        event.op_type = crm_element_value(msg, F_LRMD_RSC_ACTION);
        event.user_data = crm_element_value(msg, F_LRMD_RSC_USERDATA_STR);
        event.output = crm_element_value(msg, F_LRMD_RSC_OUTPUT);
        event.type = lrmd_event_exec_complete;

        event.params = xml2list(msg);
    } else if (crm_str_eq(type, LRMD_OP_POKE, TRUE)) {
        event.type = lrmd_event_poke;
    } else {
        return 1;
    }

    crm_trace("op %s notify event received", type);
    native->callback(&event);

    if (event.params) {
        g_hash_table_destroy(event.params);
    }
    return 1;
}

static int
lrmd_ipc_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;
    xmlNode *msg;
    int rc;

    if (!native->callback) {
        /* no callback set */
        return 1;
    }

    msg = string2xml(buffer);
    rc = lrmd_dispatch_internal(lrmd, msg);
    free_xml(msg);
    return rc;
}

#ifdef HAVE_GNUTLS_GNUTLS_H
static void
lrmd_free_xml(gpointer userdata)
{
    free_xml((xmlNode *) userdata);
}

static int
lrmd_tls_connected(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->private;

    if (native->remote->tls_session) {
        return TRUE;
    }

    return FALSE;
}

static int
lrmd_tls_dispatch(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;
    xmlNode *xml = NULL;
    int rc = 0;
    int disconnected = 0;

    if (lrmd_tls_connected(lrmd) == FALSE) {
        crm_trace("tls dispatch triggered after disconnect");
        return 0;
    }

    crm_trace("tls_dispatch triggered");

    /* First check if there are any pending notifies to process that came
     * while we were waiting for replies earlier. */
    if (native->pending_notify) {
        GList *iter = NULL;

        crm_trace("Processing pending notifies");
        for (iter = native->pending_notify; iter; iter = iter->next) {
            lrmd_dispatch_internal(lrmd, iter->data);
        }
        g_list_free_full(native->pending_notify, lrmd_free_xml);
        native->pending_notify = NULL;
    }

    /* Next read the current buffer and see if there are any messages to handle. */
    rc = crm_remote_ready(native->remote, 0);
    if (rc == 0) {
        /* nothing to read, see if any full messages are already in buffer. */
        xml = crm_remote_parse_buffer(native->remote);
    } else if (rc < 0) {
        disconnected = 1;
    } else {
        crm_remote_recv(native->remote, -1, &disconnected);
        xml = crm_remote_parse_buffer(native->remote);
    }
    while (xml) {
        lrmd_dispatch_internal(lrmd, xml);
        free_xml(xml);
        xml = crm_remote_parse_buffer(native->remote);
    }

    if (disconnected) {
        crm_info("Server disconnected while reading remote server msg.");
        lrmd_tls_disconnect(lrmd);
        return 0;
    }
    return 1;
}
#endif

/* Not used with mainloop */
int
lrmd_poll(lrmd_t * lrmd, int timeout)
{
    lrmd_private_t *native = lrmd->private;

    switch (native->type) {
        case CRM_CLIENT_IPC:
            return crm_ipc_ready(native->ipc);

#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            if (native->pending_notify) {
                return 1;
            } else if (native->remote->buffer
                       && strstr(native->remote->buffer, REMOTE_MSG_TERMINATOR)) {
                return 1;
            }

            return crm_remote_ready(native->remote, 0);
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    return 0;
}

/* Not used with mainloop */
bool
lrmd_dispatch(lrmd_t * lrmd)
{
    lrmd_private_t *private = NULL;

    CRM_ASSERT(lrmd != NULL);

    private = lrmd->private;
    switch (private->type) {
        case CRM_CLIENT_IPC:
            while (crm_ipc_ready(private->ipc)) {
                if (crm_ipc_read(private->ipc) > 0) {
                    const char *msg = crm_ipc_buffer(private->ipc);

                    lrmd_ipc_dispatch(msg, strlen(msg), lrmd);
                }
            }
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            lrmd_tls_dispatch(lrmd);
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", private->type);
    }

    if (lrmd_api_is_connected(lrmd) == FALSE) {
        crm_err("Connection closed");
        return FALSE;
    }

    return TRUE;
}

static xmlNode *
lrmd_create_op(const char *token, const char *op, xmlNode * data, enum lrmd_call_options options)
{
    xmlNode *op_msg = create_xml_node(NULL, "lrmd_command");

    CRM_CHECK(op_msg != NULL, return NULL);
    CRM_CHECK(token != NULL, return NULL);

    crm_xml_add(op_msg, F_XML_TAGNAME, "lrmd_command");

    crm_xml_add(op_msg, F_TYPE, T_LRMD);
    crm_xml_add(op_msg, F_LRMD_CALLBACK_TOKEN, token);
    crm_xml_add(op_msg, F_LRMD_OPERATION, op);
    crm_trace("Sending call options: %.8lx, %d", (long)options, options);
    crm_xml_add_int(op_msg, F_LRMD_CALLOPTS, options);

    if (data != NULL) {
        add_message_xml(op_msg, F_LRMD_CALLDATA, data);
    }

    return op_msg;
}

static void
lrmd_ipc_connection_destroy(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;

    crm_info("IPC connection destroyed");

    /* Prevent these from being cleaned up in lrmd_api_disconnect() */
    native->ipc = NULL;
    native->source = NULL;

    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.type = lrmd_event_disconnect;
        event.remote_nodename = native->remote_nodename;
        native->callback(&event);
    }
}

#ifdef HAVE_GNUTLS_GNUTLS_H
static void
lrmd_tls_connection_destroy(gpointer userdata)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;

    crm_info("TLS connection destroyed");

    if (native->remote->tls_session) {
        gnutls_bye(*native->remote->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(*native->remote->tls_session);
        gnutls_free(native->remote->tls_session);
    }
    if (native->psk_cred_c) {
        gnutls_psk_free_client_credentials(native->psk_cred_c);
    }
    if (native->sock) {
        close(native->sock);
    }
    if (native->process_notify) {
        mainloop_destroy_trigger(native->process_notify);
        native->process_notify = NULL;
    }
    if (native->pending_notify) {
        g_list_free_full(native->pending_notify, lrmd_free_xml);
        native->pending_notify = NULL;
    }

    free(native->remote->buffer);
    native->remote->buffer = NULL;
    native->source = 0;
    native->sock = 0;
    native->psk_cred_c = NULL;
    native->remote->tls_session = NULL;
    native->sock = 0;

    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.remote_nodename = native->remote_nodename;
        event.type = lrmd_event_disconnect;
        native->callback(&event);
    }
    return;
}

int
lrmd_tls_send_msg(crm_remote_t * session, xmlNode * msg, uint32_t id, const char *msg_type)
{
    int rc = -1;

    crm_xml_add_int(msg, F_LRMD_REMOTE_MSG_ID, id);
    crm_xml_add(msg, F_LRMD_REMOTE_MSG_TYPE, msg_type);

    rc = crm_remote_send(session, msg);

    if (rc < 0) {
        crm_err("Failed to send remote lrmd tls msg, rc = %d", rc);
        return rc;
    }

    return rc;
}

static xmlNode *
lrmd_tls_recv_reply(lrmd_t * lrmd, int total_timeout, int expected_reply_id, int *disconnected)
{
    lrmd_private_t *native = lrmd->private;
    xmlNode *xml = NULL;
    time_t start = time(NULL);
    const char *msg_type = NULL;
    int reply_id = 0;
    int remaining_timeout = 0;

    /* A timeout of 0 here makes no sense.  We have to wait a period of time
     * for the response to come back.  If -1 or 0, default to 10 seconds. */
    if (total_timeout <= 0) {
        total_timeout = 10000;
    }

    while (!xml) {

        xml = crm_remote_parse_buffer(native->remote);
        if (!xml) {
            /* read some more off the tls buffer if we still have time left. */
            if (remaining_timeout) {
                remaining_timeout = remaining_timeout - ((time(NULL) - start) * 1000);
            } else {
                remaining_timeout = total_timeout;
            }
            if (remaining_timeout <= 0) {
                return NULL;
            }

            crm_remote_recv(native->remote, remaining_timeout, disconnected);
            xml = crm_remote_parse_buffer(native->remote);
            if (!xml || *disconnected) {
                return NULL;
            }
        }

        CRM_ASSERT(xml != NULL);

        crm_element_value_int(xml, F_LRMD_REMOTE_MSG_ID, &reply_id);
        msg_type = crm_element_value(xml, F_LRMD_REMOTE_MSG_TYPE);

        if (!msg_type) {
            crm_err("Empty msg type received while waiting for reply");
            free_xml(xml);
            xml = NULL;
        } else if (safe_str_eq(msg_type, "notify")) {
            /* got a notify while waiting for reply, trigger the notify to be processed later */
            crm_info("queueing notify");
            native->pending_notify = g_list_append(native->pending_notify, xml);
            if (native->process_notify) {
                crm_info("notify trigger set.");
                mainloop_set_trigger(native->process_notify);
            }
            xml = NULL;
        } else if (safe_str_neq(msg_type, "reply")) {
            /* msg isn't a reply, make some noise */
            crm_err("Expected a reply, got %s", msg_type);
            free_xml(xml);
            xml = NULL;
        } else if (reply_id != expected_reply_id) {
            crm_err("Got outdated reply, expected id %d got id %d", expected_reply_id, reply_id);
            free_xml(xml);
            xml = NULL;
        }
    }

    if (native->remote->buffer && native->process_notify) {
        mainloop_set_trigger(native->process_notify);
    }

    return xml;
}

static int
lrmd_tls_send(lrmd_t * lrmd, xmlNode * msg)
{
    int rc = 0;
    lrmd_private_t *native = lrmd->private;

    global_remote_msg_id++;
    if (global_remote_msg_id <= 0) {
        global_remote_msg_id = 1;
    }

    rc = lrmd_tls_send_msg(native->remote, msg, global_remote_msg_id, "request");
    if (rc <= 0) {
        crm_err("Remote lrmd send failed, disconnecting");
        lrmd_tls_disconnect(lrmd);
        return -ENOTCONN;
    }
    return pcmk_ok;
}

static int
lrmd_tls_send_recv(lrmd_t * lrmd, xmlNode * msg, int timeout, xmlNode ** reply)
{
    int rc = 0;
    int disconnected = 0;
    xmlNode *xml = NULL;

    if (lrmd_tls_connected(lrmd) == FALSE) {
        return -1;
    }

    rc = lrmd_tls_send(lrmd, msg);
    if (rc < 0) {
        return rc;
    }

    xml = lrmd_tls_recv_reply(lrmd, timeout, global_remote_msg_id, &disconnected);

    if (disconnected) {
        crm_err("Remote lrmd server disconnected while waiting for reply with id %d. ",
                global_remote_msg_id);
        lrmd_tls_disconnect(lrmd);
        rc = -ENOTCONN;
    } else if (!xml) {
        crm_err("Remote lrmd never received reply for request id %d. timeout: %dms ",
                global_remote_msg_id, timeout);
        rc = -ECOMM;
    }

    if (reply) {
        *reply = xml;
    } else {
        free_xml(xml);
    }

    return rc;
}
#endif

static int
lrmd_send_xml(lrmd_t * lrmd, xmlNode * msg, int timeout, xmlNode ** reply)
{
    int rc = -1;
    lrmd_private_t *native = lrmd->private;

    switch (native->type) {
        case CRM_CLIENT_IPC:
            rc = crm_ipc_send(native->ipc, msg, crm_ipc_client_response, timeout, reply);
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            rc = lrmd_tls_send_recv(lrmd, msg, timeout, reply);
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    return rc;
}

static int
lrmd_send_xml_no_reply(lrmd_t * lrmd, xmlNode * msg)
{
    int rc = -1;
    lrmd_private_t *native = lrmd->private;

    switch (native->type) {
        case CRM_CLIENT_IPC:
            rc = crm_ipc_send(native->ipc, msg, crm_ipc_client_none, 0, NULL);
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            rc = lrmd_tls_send(lrmd, msg);
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    return rc;
}

static int
lrmd_api_is_connected(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->private;

    switch (native->type) {
        case CRM_CLIENT_IPC:
            return crm_ipc_connected(native->ipc);
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            return lrmd_tls_connected(lrmd);
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    return 0;
}

static int
lrmd_send_command(lrmd_t * lrmd, const char *op, xmlNode * data, xmlNode ** output_data, int timeout,   /* ms. defaults to 1000 if set to 0 */
                  enum lrmd_call_options options, gboolean expect_reply)
{                               /* TODO we need to reduce usage of this boolean */
    int rc = pcmk_ok;
    int reply_id = -1;
    lrmd_private_t *native = lrmd->private;
    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    if (!lrmd_api_is_connected(lrmd)) {
        return -ENOTCONN;
    }

    if (op == NULL) {
        crm_err("No operation specified");
        return -EINVAL;
    }

    CRM_CHECK(native->token != NULL,;
        );
    crm_trace("sending %s op to lrmd", op);

    op_msg = lrmd_create_op(native->token, op, data, options);

    if (op_msg == NULL) {
        return -EINVAL;
    }

    crm_xml_add_int(op_msg, F_LRMD_TIMEOUT, timeout);

    if (expect_reply) {
        rc = lrmd_send_xml(lrmd, op_msg, timeout, &op_reply);
    } else {
        rc = lrmd_send_xml_no_reply(lrmd, op_msg);
        goto done;
    }

    if (rc < 0) {
        crm_perror(LOG_ERR, "Couldn't perform %s operation (timeout=%d): %d", op, timeout, rc);
        rc = -ECOMM;
        goto done;
    }

    rc = pcmk_ok;
    crm_element_value_int(op_reply, F_LRMD_CALLID, &reply_id);
    crm_trace("%s op reply received", op);
    if (crm_element_value_int(op_reply, F_LRMD_RC, &rc) != 0) {
        rc = -ENOMSG;
        goto done;
    }

    crm_log_xml_trace(op_reply, "Reply");

    if (output_data) {
        *output_data = op_reply;
        op_reply = NULL;        /* Prevent subsequent free */
    }

  done:
    if (lrmd_api_is_connected(lrmd) == FALSE) {
        crm_err("LRMD disconnected");
    }

    free_xml(op_msg);
    free_xml(op_reply);
    return rc;
}

static int
lrmd_api_poke_connection(lrmd_t * lrmd)
{
    int rc;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    rc = lrmd_send_command(lrmd, LRMD_OP_POKE, data, NULL, 0, 0, FALSE);
    free_xml(data);

    return rc;
}

static int
lrmd_handshake(lrmd_t * lrmd, const char *name)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->private;
    xmlNode *reply = NULL;
    xmlNode *hello = create_xml_node(NULL, "lrmd_command");

    crm_xml_add(hello, F_TYPE, T_LRMD);
    crm_xml_add(hello, F_LRMD_OPERATION, CRM_OP_REGISTER);
    crm_xml_add(hello, F_LRMD_CLIENTNAME, name);

    /* advertise that we are a proxy provider */
    if (native->proxy_callback) {
        crm_xml_add(hello, F_LRMD_IS_IPC_PROVIDER, "true");
    }

    rc = lrmd_send_xml(lrmd, hello, -1, &reply);

    if (rc < 0) {
        crm_perror(LOG_DEBUG, "Couldn't complete registration with the lrmd API: %d", rc);
        rc = -ECOMM;
    } else if (reply == NULL) {
        crm_err("Did not receive registration reply");
        rc = -EPROTO;
    } else {
        const char *msg_type = crm_element_value(reply, F_LRMD_OPERATION);
        const char *tmp_ticket = crm_element_value(reply, F_LRMD_CLIENTID);

        if (safe_str_neq(msg_type, CRM_OP_REGISTER)) {
            crm_err("Invalid registration message: %s", msg_type);
            crm_log_xml_err(reply, "Bad reply");
            rc = -EPROTO;
        } else if (tmp_ticket == NULL) {
            crm_err("No registration token provided");
            crm_log_xml_err(reply, "Bad reply");
            rc = -EPROTO;
        } else {
            crm_trace("Obtained registration token: %s", tmp_ticket);
            native->token = strdup(tmp_ticket);
            rc = pcmk_ok;
        }
    }

    free_xml(reply);
    free_xml(hello);

    if (rc != pcmk_ok) {
        lrmd_api_disconnect(lrmd);
    }
    return rc;
}

static int
lrmd_ipc_connect(lrmd_t * lrmd, int *fd)
{
    int rc = pcmk_ok;
    lrmd_private_t *native = lrmd->private;

    static struct ipc_client_callbacks lrmd_callbacks = {
        .dispatch = lrmd_ipc_dispatch,
        .destroy = lrmd_ipc_connection_destroy
    };

    crm_info("Connecting to lrmd");

    if (fd) {
        /* No mainloop */
        native->ipc = crm_ipc_new("lrmd", 0);
        if (native->ipc && crm_ipc_connect(native->ipc)) {
            *fd = crm_ipc_get_fd(native->ipc);
        } else if (native->ipc) {
            rc = -ENOTCONN;
        }
    } else {
        native->source = mainloop_add_ipc_client("lrmd", G_PRIORITY_HIGH, 0, lrmd, &lrmd_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }

    if (native->ipc == NULL) {
        crm_debug("Could not connect to the LRMD API");
        rc = -ENOTCONN;
    }

    return rc;
}

#ifdef HAVE_GNUTLS_GNUTLS_H
int
lrmd_tls_set_key(gnutls_datum_t * key, const char *location)
{
    FILE *stream;
    int read_len = 256;
    int cur_len = 0;
    int buf_len = read_len;
    static char *key_cache = NULL;
    static size_t key_cache_len = 0;
    static time_t key_cache_updated;

    if (key_cache) {
        time_t now = time(NULL);

        if ((now - key_cache_updated) < 60) {
            key->data = gnutls_malloc(key_cache_len + 1);
            key->size = key_cache_len;
            memcpy(key->data, key_cache, key_cache_len);

            crm_debug("using cached LRMD key");
            return 0;
        } else {
            key_cache_len = 0;
            key_cache_updated = 0;
            free(key_cache);
            key_cache = NULL;
            crm_debug("clearing lrmd key cache");
        }
    }

    stream = fopen(location, "r");
    if (!stream) {
        return -1;
    }

    key->data = gnutls_malloc(read_len);
    while (!feof(stream)) {
        char next;

        if (cur_len == buf_len) {
            buf_len = cur_len + read_len;
            key->data = gnutls_realloc(key->data, buf_len);
        }
        next = fgetc(stream);
        if (next == EOF && feof(stream)) {
            break;
        }

        key->data[cur_len] = next;
        cur_len++;
    }
    fclose(stream);

    key->size = cur_len;
    if (!cur_len) {
        gnutls_free(key->data);
        key->data = 0;
        return -1;
    }

    if (!key_cache) {
        key_cache = calloc(1, key->size + 1);
        memcpy(key_cache, key->data, key->size);

        key_cache_len = key->size;
        key_cache_updated = time(NULL);
    }

    return 0;
}

static int
lrmd_tls_key_cb(gnutls_session_t session, char **username, gnutls_datum_t * key)
{
    int rc = 0;

    if (lrmd_tls_set_key(key, DEFAULT_REMOTE_KEY_LOCATION)) {
        rc = lrmd_tls_set_key(key, ALT_REMOTE_KEY_LOCATION);
    }
    if (rc) {
        crm_err("No lrmd remote key found");
        return -1;
    }

    *username = gnutls_malloc(strlen(DEFAULT_REMOTE_USERNAME) + 1);
    strcpy(*username, DEFAULT_REMOTE_USERNAME);

    return rc;
}

static void
lrmd_gnutls_global_init(void)
{
    static int gnutls_init = 0;

    if (!gnutls_init) {
        gnutls_global_init();
    }
    gnutls_init = 1;
}
#endif

static void
report_async_connection_result(lrmd_t * lrmd, int rc)
{
    lrmd_private_t *native = lrmd->private;

    if (native->callback) {
        lrmd_event_data_t event = { 0, };
        event.type = lrmd_event_connect;
        event.remote_nodename = native->remote_nodename;
        event.connection_rc = rc;
        native->callback(&event);
    }
}

#ifdef HAVE_GNUTLS_GNUTLS_H
static void
lrmd_tcp_connect_cb(void *userdata, int sock)
{
    lrmd_t *lrmd = userdata;
    lrmd_private_t *native = lrmd->private;
    char name[256] = { 0, };
    static struct mainloop_fd_callbacks lrmd_tls_callbacks = {
        .dispatch = lrmd_tls_dispatch,
        .destroy = lrmd_tls_connection_destroy,
    };
    int rc = sock;

    if (rc < 0) {
        lrmd_tls_connection_destroy(lrmd);
        crm_info("remote lrmd connect to %s at port %d failed", native->server, native->port);
        report_async_connection_result(lrmd, rc);
        return;
    }

    /* TODO continue with tls stuff now that tcp connect passed. make this async as well soon
     * to avoid all blocking code in the client. */
    native->sock = sock;
    gnutls_psk_allocate_client_credentials(&native->psk_cred_c);
    gnutls_psk_set_client_credentials_function(native->psk_cred_c, lrmd_tls_key_cb);
    native->remote->tls_session = create_psk_tls_session(sock, GNUTLS_CLIENT, native->psk_cred_c);

    if (crm_initiate_client_tls_handshake(native->remote, LRMD_CLIENT_HANDSHAKE_TIMEOUT) != 0) {
        crm_warn("Client tls handshake failed for server %s:%d. Disconnecting", native->server,
                 native->port);
        gnutls_deinit(*native->remote->tls_session);
        gnutls_free(native->remote->tls_session);
        native->remote->tls_session = NULL;
        lrmd_tls_connection_destroy(lrmd);
        report_async_connection_result(lrmd, -1);
        return;
    }

    crm_info("Remote lrmd client TLS connection established with server %s:%d", native->server,
             native->port);

    snprintf(name, 128, "remote-lrmd-%s:%d", native->server, native->port);

    native->process_notify = mainloop_add_trigger(G_PRIORITY_HIGH, lrmd_tls_dispatch, lrmd);
    native->source =
        mainloop_add_fd(name, G_PRIORITY_HIGH, native->sock, lrmd, &lrmd_tls_callbacks);

    rc = lrmd_handshake(lrmd, name);
    report_async_connection_result(lrmd, rc);

    return;
}

static int
lrmd_tls_connect_async(lrmd_t * lrmd, int timeout /*ms */ )
{
    int rc = 0;
    lrmd_private_t *native = lrmd->private;

    lrmd_gnutls_global_init();

    rc = crm_remote_tcp_connect_async(native->server, native->port, timeout, lrmd,
                                      lrmd_tcp_connect_cb);

    return rc;
}

static int
lrmd_tls_connect(lrmd_t * lrmd, int *fd)
{
    static struct mainloop_fd_callbacks lrmd_tls_callbacks = {
        .dispatch = lrmd_tls_dispatch,
        .destroy = lrmd_tls_connection_destroy,
    };

    lrmd_private_t *native = lrmd->private;
    int sock;

    lrmd_gnutls_global_init();

    sock = crm_remote_tcp_connect(native->server, native->port);
    if (sock <= 0) {
        crm_warn("Could not establish remote lrmd connection to %s", native->server);
        lrmd_tls_connection_destroy(lrmd);
        return -ENOTCONN;
    }

    native->sock = sock;
    gnutls_psk_allocate_client_credentials(&native->psk_cred_c);
    gnutls_psk_set_client_credentials_function(native->psk_cred_c, lrmd_tls_key_cb);
    native->remote->tls_session = create_psk_tls_session(sock, GNUTLS_CLIENT, native->psk_cred_c);

    if (crm_initiate_client_tls_handshake(native->remote, LRMD_CLIENT_HANDSHAKE_TIMEOUT) != 0) {
        crm_err("Session creation for %s:%d failed", native->server, native->port);
        gnutls_deinit(*native->remote->tls_session);
        gnutls_free(native->remote->tls_session);
        native->remote->tls_session = NULL;
        lrmd_tls_connection_destroy(lrmd);
        return -1;
    }

    crm_info("Remote lrmd client TLS connection established with server %s:%d", native->server,
             native->port);

    if (fd) {
        *fd = sock;
    } else {
        char name[256] = { 0, };
        snprintf(name, 128, "remote-lrmd-%s:%d", native->server, native->port);

        native->process_notify = mainloop_add_trigger(G_PRIORITY_HIGH, lrmd_tls_dispatch, lrmd);
        native->source =
            mainloop_add_fd(name, G_PRIORITY_HIGH, native->sock, lrmd, &lrmd_tls_callbacks);
    }
    return pcmk_ok;
}
#endif

static int
lrmd_api_connect(lrmd_t * lrmd, const char *name, int *fd)
{
    int rc = -ENOTCONN;
    lrmd_private_t *native = lrmd->private;

    switch (native->type) {
        case CRM_CLIENT_IPC:
            rc = lrmd_ipc_connect(lrmd, fd);
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            rc = lrmd_tls_connect(lrmd, fd);
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    if (rc == pcmk_ok) {
        rc = lrmd_handshake(lrmd, name);
    }

    return rc;
}

static int
lrmd_api_connect_async(lrmd_t * lrmd, const char *name, int timeout)
{
    int rc = 0;
    lrmd_private_t *native = lrmd->private;

    if (!native->callback) {
        crm_err("Async connect not possible, no lrmd client callback set.");
        return -1;
    }

    switch (native->type) {
        case CRM_CLIENT_IPC:
            /* fake async connection with ipc.  it should be fast
             * enough that we gain very little from async */
            rc = lrmd_api_connect(lrmd, name, NULL);
            if (!rc) {
                report_async_connection_result(lrmd, rc);
            }
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            rc = lrmd_tls_connect_async(lrmd, timeout);
            if (rc) {
                /* connection failed, report rc now */
                report_async_connection_result(lrmd, rc);
            }
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    return rc;
}

static void
lrmd_ipc_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->private;

    if (native->source != NULL) {
        /* Attached to mainloop */
        mainloop_del_ipc_client(native->source);
        native->source = NULL;
        native->ipc = NULL;

    } else if (native->ipc) {
        /* Not attached to mainloop */
        crm_ipc_t *ipc = native->ipc;

        native->ipc = NULL;
        crm_ipc_close(ipc);
        crm_ipc_destroy(ipc);
    }
}

#ifdef HAVE_GNUTLS_GNUTLS_H
static void
lrmd_tls_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->private;

    if (native->remote->tls_session) {
        gnutls_bye(*native->remote->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(*native->remote->tls_session);
        gnutls_free(native->remote->tls_session);
        native->remote->tls_session = 0;
    }

    if (native->source != NULL) {
        /* Attached to mainloop */
        mainloop_del_ipc_client(native->source);
        native->source = NULL;

    } else if (native->sock) {
        close(native->sock);
    }

    if (native->pending_notify) {
        g_list_free_full(native->pending_notify, lrmd_free_xml);
        native->pending_notify = NULL;
    }
}
#endif

static int
lrmd_api_disconnect(lrmd_t * lrmd)
{
    lrmd_private_t *native = lrmd->private;

    crm_info("Disconnecting from lrmd service");
    switch (native->type) {
        case CRM_CLIENT_IPC:
            lrmd_ipc_disconnect(lrmd);
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            lrmd_tls_disconnect(lrmd);
            break;
#endif
        default:
            crm_err("Unsupported connection type: %d", native->type);
    }

    free(native->token);
    native->token = NULL;
    return 0;
}

static int
lrmd_api_register_rsc(lrmd_t * lrmd,
                      const char *rsc_id,
                      const char *class,
                      const char *provider, const char *type, enum lrmd_call_options options)
{
    int rc = pcmk_ok;
    xmlNode *data = NULL;

    if (!class || !type || !rsc_id) {
        return -EINVAL;
    }
    if (safe_str_eq(class, "ocf") && !provider) {
        return -EINVAL;
    }

    data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    crm_xml_add(data, F_LRMD_CLASS, class);
    crm_xml_add(data, F_LRMD_PROVIDER, provider);
    crm_xml_add(data, F_LRMD_TYPE, type);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_REG, data, NULL, 0, options, TRUE);
    free_xml(data);

    return rc;
}

static int
lrmd_api_unregister_rsc(lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options)
{
    int rc = pcmk_ok;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_UNREG, data, NULL, 0, options, TRUE);
    free_xml(data);

    return rc;
}

lrmd_rsc_info_t *
lrmd_copy_rsc_info(lrmd_rsc_info_t * rsc_info)
{
    lrmd_rsc_info_t *copy = NULL;

    copy = calloc(1, sizeof(lrmd_rsc_info_t));

    copy->id = strdup(rsc_info->id);
    copy->type = strdup(rsc_info->type);
    copy->class = strdup(rsc_info->class);
    if (rsc_info->provider) {
        copy->provider = strdup(rsc_info->provider);
    }

    return copy;
}

void
lrmd_free_rsc_info(lrmd_rsc_info_t * rsc_info)
{
    if (!rsc_info) {
        return;
    }
    free(rsc_info->id);
    free(rsc_info->type);
    free(rsc_info->class);
    free(rsc_info->provider);
    free(rsc_info);
}

static lrmd_rsc_info_t *
lrmd_api_get_rsc_info(lrmd_t * lrmd, const char *rsc_id, enum lrmd_call_options options)
{
    lrmd_rsc_info_t *rsc_info = NULL;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);
    xmlNode *output = NULL;
    const char *class = NULL;
    const char *provider = NULL;
    const char *type = NULL;

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    lrmd_send_command(lrmd, LRMD_OP_RSC_INFO, data, &output, 0, options, TRUE);
    free_xml(data);

    if (!output) {
        return NULL;
    }

    class = crm_element_value(output, F_LRMD_CLASS);
    provider = crm_element_value(output, F_LRMD_PROVIDER);
    type = crm_element_value(output, F_LRMD_TYPE);

    if (!class || !type) {
        free_xml(output);
        return NULL;
    } else if (safe_str_eq(class, "ocf") && !provider) {
        free_xml(output);
        return NULL;
    }

    rsc_info = calloc(1, sizeof(lrmd_rsc_info_t));
    rsc_info->id = strdup(rsc_id);
    rsc_info->class = strdup(class);
    if (provider) {
        rsc_info->provider = strdup(provider);
    }
    rsc_info->type = strdup(type);

    free_xml(output);
    return rsc_info;
}

static void
lrmd_api_set_callback(lrmd_t * lrmd, lrmd_event_callback callback)
{
    lrmd_private_t *native = lrmd->private;

    native->callback = callback;
}

void
lrmd_internal_set_proxy_callback(lrmd_t * lrmd, void *userdata, void (*callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg))
{
    lrmd_private_t *native = lrmd->private;

    native->proxy_callback = callback;
    native->proxy_callback_userdata = userdata;
}

void
lrmd_internal_proxy_dispatch(lrmd_t *lrmd, xmlNode *msg)
{
    lrmd_private_t *native = lrmd->private;

    if (native->proxy_callback) {
        crm_log_xml_trace(msg, "PROXY_INBOUND");
        native->proxy_callback(lrmd, native->proxy_callback_userdata, msg);
    }
}

int
lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg)
{
    if (lrmd == NULL) {
        return -ENOTCONN;
    }
    crm_xml_add(msg, F_LRMD_OPERATION, CRM_OP_IPC_FWD);

    crm_log_xml_trace(msg, "PROXY_OUTBOUND");
    return lrmd_send_xml_no_reply(lrmd, msg);
}

static int
stonith_get_metadata(const char *provider, const char *type, char **output)
{
    int rc = pcmk_ok;

    stonith_api->cmds->metadata(stonith_api, st_opt_sync_call, type, provider, output, 0);
    if (*output == NULL) {
        rc = -EIO;
    }
    return rc;
}

static int
lsb_get_metadata(const char *type, char **output)
{

#define lsb_metadata_template  \
"<?xml version=\"1.0\"?>\n"\
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"\
"<resource-agent name=\"%s\" version=\"0.1\">\n"\
"  <version>1.0</version>\n"\
"  <longdesc lang=\"en\">\n"\
"    %s"\
"  </longdesc>\n"\
"  <shortdesc lang=\"en\">%s</shortdesc>\n"\
"  <parameters>\n"\
"  </parameters>\n"\
"  <actions>\n"\
"    <action name=\"start\"   timeout=\"15\" />\n"\
"    <action name=\"stop\"    timeout=\"15\" />\n"\
"    <action name=\"status\"  timeout=\"15\" />\n"\
"    <action name=\"restart\"  timeout=\"15\" />\n"\
"    <action name=\"force-reload\"  timeout=\"15\" />\n"\
"    <action name=\"monitor\" timeout=\"15\" interval=\"15\" />\n"\
"    <action name=\"meta-data\"  timeout=\"5\" />\n"\
"  </actions>\n"\
"  <special tag=\"LSB\">\n"\
"    <Provides>%s</Provides>\n"\
"    <Required-Start>%s</Required-Start>\n"\
"    <Required-Stop>%s</Required-Stop>\n"\
"    <Should-Start>%s</Should-Start>\n"\
"    <Should-Stop>%s</Should-Stop>\n"\
"    <Default-Start>%s</Default-Start>\n"\
"    <Default-Stop>%s</Default-Stop>\n"\
"  </special>\n"\
"</resource-agent>\n"

#define LSB_INITSCRIPT_INFOBEGIN_TAG "### BEGIN INIT INFO"
#define LSB_INITSCRIPT_INFOEND_TAG "### END INIT INFO"
#define PROVIDES    "# Provides:"
#define REQ_START   "# Required-Start:"
#define REQ_STOP    "# Required-Stop:"
#define SHLD_START  "# Should-Start:"
#define SHLD_STOP   "# Should-Stop:"
#define DFLT_START  "# Default-Start:"
#define DFLT_STOP   "# Default-Stop:"
#define SHORT_DSCR  "# Short-Description:"
#define DESCRIPTION "# Description:"

#define lsb_meta_helper_free_value(m)   \
    if ((m) != NULL) {                  \
        xmlFree(m);                     \
        (m) = NULL;                     \
    }

#define lsb_meta_helper_get_value(buffer, ptr, keyword)                 \
    if (!ptr && !strncasecmp(buffer, keyword, strlen(keyword))) {       \
        (ptr) = (char *)xmlEncodeEntitiesReentrant(NULL, BAD_CAST buffer+strlen(keyword)); \
        continue;                                                       \
    }

    char ra_pathname[PATH_MAX] = { 0, };
    FILE *fp;
    GString *meta_data = NULL;
    char buffer[1024];
    char *provides = NULL;
    char *req_start = NULL;
    char *req_stop = NULL;
    char *shld_start = NULL;
    char *shld_stop = NULL;
    char *dflt_start = NULL;
    char *dflt_stop = NULL;
    char *s_dscrpt = NULL;
    char *xml_l_dscrpt = NULL;
    GString *l_dscrpt = NULL;

    snprintf(ra_pathname, sizeof(ra_pathname), "%s%s%s",
             type[0] == '/' ? "" : LSB_ROOT_DIR, type[0] == '/' ? "" : "/", type);

    if (!(fp = fopen(ra_pathname, "r"))) {
        return -EIO;
    }

    /* Enter into the lsb-compliant comment block */
    while (fgets(buffer, sizeof(buffer), fp)) {
        /* Now suppose each of the following eight arguments contain only one line */
        lsb_meta_helper_get_value(buffer, provides, PROVIDES)
            lsb_meta_helper_get_value(buffer, req_start, REQ_START)
            lsb_meta_helper_get_value(buffer, req_stop, REQ_STOP)
            lsb_meta_helper_get_value(buffer, shld_start, SHLD_START)
            lsb_meta_helper_get_value(buffer, shld_stop, SHLD_STOP)
            lsb_meta_helper_get_value(buffer, dflt_start, DFLT_START)
            lsb_meta_helper_get_value(buffer, dflt_stop, DFLT_STOP)
            lsb_meta_helper_get_value(buffer, s_dscrpt, SHORT_DSCR)

            /* Long description may cross multiple lines */
            if ((l_dscrpt == NULL) && (0 == strncasecmp(buffer, DESCRIPTION, strlen(DESCRIPTION)))) {
            l_dscrpt = g_string_new(buffer + strlen(DESCRIPTION));
            /* Between # and keyword, more than one space, or a tab character,
             * indicates the continuation line.     Extracted from LSB init script standard */
            while (fgets(buffer, sizeof(buffer), fp)) {
                if (!strncmp(buffer, "#  ", 3) || !strncmp(buffer, "#\t", 2)) {
                    buffer[0] = ' ';
                    l_dscrpt = g_string_append(l_dscrpt, buffer);
                } else {
                    fputs(buffer, fp);
                    break;      /* Long description ends */
                }
            }
            continue;
        }
        if (l_dscrpt) {
            xml_l_dscrpt = (char *)xmlEncodeEntitiesReentrant(NULL, BAD_CAST(l_dscrpt->str));
        }
        if (!strncasecmp(buffer, LSB_INITSCRIPT_INFOEND_TAG, strlen(LSB_INITSCRIPT_INFOEND_TAG))) {
            /* Get to the out border of LSB comment block */
            break;
        }
        if (buffer[0] != '#') {
            break;              /* Out of comment block in the beginning */
        }
    }
    fclose(fp);

    meta_data = g_string_new("");
    g_string_sprintf(meta_data, lsb_metadata_template, type,
                     (xml_l_dscrpt == NULL) ? type : xml_l_dscrpt,
                     (s_dscrpt == NULL) ? type : s_dscrpt, (provides == NULL) ? "" : provides,
                     (req_start == NULL) ? "" : req_start, (req_stop == NULL) ? "" : req_stop,
                     (shld_start == NULL) ? "" : shld_start, (shld_stop == NULL) ? "" : shld_stop,
                     (dflt_start == NULL) ? "" : dflt_start, (dflt_stop == NULL) ? "" : dflt_stop);

    lsb_meta_helper_free_value(xml_l_dscrpt);
    lsb_meta_helper_free_value(s_dscrpt);
    lsb_meta_helper_free_value(provides);
    lsb_meta_helper_free_value(req_start);
    lsb_meta_helper_free_value(req_stop);
    lsb_meta_helper_free_value(shld_start);
    lsb_meta_helper_free_value(shld_stop);
    lsb_meta_helper_free_value(dflt_start);
    lsb_meta_helper_free_value(dflt_stop);

    if (l_dscrpt) {
        g_string_free(l_dscrpt, TRUE);
    }

    *output = strdup(meta_data->str);
    g_string_free(meta_data, TRUE);

    return pcmk_ok;
}

#if SUPPORT_NAGIOS
static int
nagios_get_metadata(const char *type, char **output)
{
    int rc = pcmk_ok;
    FILE *file_strm = NULL;
    int start = 0, length = 0, read_len = 0;
    char *metadata_file = NULL;
    int len = 36;

    len += strlen(NAGIOS_METADATA_DIR);
    len += strlen(type);
    metadata_file = calloc(1, len);
    CRM_CHECK(metadata_file != NULL, return -ENOMEM);

    sprintf(metadata_file, "%s/%s.xml", NAGIOS_METADATA_DIR, type);
    file_strm = fopen(metadata_file, "r");
    if (file_strm == NULL) {
        crm_err("Metadata file %s does not exist", metadata_file);
        free(metadata_file);
        return -EIO;
    }

    /* see how big the file is */
    start = ftell(file_strm);
    fseek(file_strm, 0L, SEEK_END);
    length = ftell(file_strm);
    fseek(file_strm, 0L, start);

    CRM_ASSERT(length >= 0);
    CRM_ASSERT(start == ftell(file_strm));

    if (length <= 0) {
        crm_info("%s was not valid", metadata_file);
        free(*output);
        *output = NULL;
        rc = -EIO;

    } else {
        crm_trace("Reading %d bytes from file", length);
        *output = calloc(1, (length + 1));
        read_len = fread(*output, 1, length, file_strm);
        if (read_len != length) {
            crm_err("Calculated and read bytes differ: %d vs. %d", length, read_len);
            free(*output);
            *output = NULL;
            rc = -EIO;
        }
    }

    fclose(file_strm);
    free(metadata_file);
    return rc;
}
#endif

static int
generic_get_metadata(const char *standard, const char *provider, const char *type, char **output)
{
    svc_action_t *action = resources_action_create(type,
                                                   standard,
                                                   provider,
                                                   type,
                                                   "meta-data",
                                                   0,
                                                   5000,
                                                   NULL);

    if (!(services_action_sync(action))) {
        crm_err("Failed to retrieve meta-data for %s:%s:%s", standard, provider, type);
        services_action_free(action);
        return -EIO;
    }

    if (!action->stdout_data) {
        crm_err("Failed to retrieve meta-data for %s:%s:%s", standard, provider, type);
        services_action_free(action);
        return -EIO;
    }

    *output = strdup(action->stdout_data);
    services_action_free(action);

    return pcmk_ok;
}

static int
lrmd_api_get_metadata(lrmd_t * lrmd,
                      const char *class,
                      const char *provider,
                      const char *type, char **output, enum lrmd_call_options options)
{
    if (!class || !type) {
        return -EINVAL;
    }

    if (safe_str_eq(class, "stonith")) {
        return stonith_get_metadata(provider, type, output);
    } else if (safe_str_eq(class, "lsb")) {
        return lsb_get_metadata(type, output);
#if SUPPORT_NAGIOS
    } else if (safe_str_eq(class, "nagios")) {
        return nagios_get_metadata(type, output);
#endif
    }
    return generic_get_metadata(class, provider, type, output);
}

static int
lrmd_api_exec(lrmd_t * lrmd, const char *rsc_id, const char *action, const char *userdata, int interval,        /* ms */
              int timeout,      /* ms */
              int start_delay,  /* ms */
              enum lrmd_call_options options, lrmd_key_value_t * params)
{
    int rc = pcmk_ok;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);
    xmlNode *args = create_xml_node(data, XML_TAG_ATTRS);
    lrmd_key_value_t *tmp = NULL;

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    crm_xml_add(data, F_LRMD_RSC_ACTION, action);
    crm_xml_add(data, F_LRMD_RSC_USERDATA_STR, userdata);
    crm_xml_add_int(data, F_LRMD_RSC_INTERVAL, interval);
    crm_xml_add_int(data, F_LRMD_TIMEOUT, timeout);
    crm_xml_add_int(data, F_LRMD_RSC_START_DELAY, start_delay);

    for (tmp = params; tmp; tmp = tmp->next) {
        hash2field((gpointer) tmp->key, (gpointer) tmp->value, args);
    }

    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_EXEC, data, NULL, timeout, options, TRUE);
    free_xml(data);

    lrmd_key_value_freeall(params);
    return rc;
}

static int
lrmd_api_cancel(lrmd_t * lrmd, const char *rsc_id, const char *action, int interval)
{
    int rc = pcmk_ok;
    xmlNode *data = create_xml_node(NULL, F_LRMD_RSC);

    crm_xml_add(data, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add(data, F_LRMD_RSC_ACTION, action);
    crm_xml_add(data, F_LRMD_RSC_ID, rsc_id);
    crm_xml_add_int(data, F_LRMD_RSC_INTERVAL, interval);
    rc = lrmd_send_command(lrmd, LRMD_OP_RSC_CANCEL, data, NULL, 0, 0, TRUE);
    free_xml(data);
    return rc;
}

static int
list_stonith_agents(lrmd_list_t ** resources)
{
    int rc = 0;
    stonith_key_value_t *stonith_resources = NULL;
    stonith_key_value_t *dIter = NULL;

    stonith_api->cmds->list_agents(stonith_api, st_opt_sync_call, NULL, &stonith_resources, 0);

    for (dIter = stonith_resources; dIter; dIter = dIter->next) {
        rc++;
        if (resources) {
            *resources = lrmd_list_add(*resources, dIter->value);
        }
    }

    stonith_key_value_freeall(stonith_resources, 1, 0);
    return rc;
}

static int
lrmd_api_list_agents(lrmd_t * lrmd, lrmd_list_t ** resources, const char *class,
                     const char *provider)
{
    int rc = 0;

    if (safe_str_eq(class, "stonith")) {
        rc += list_stonith_agents(resources);

    } else {
        GListPtr gIter = NULL;
        GList *agents = resources_list_agents(class, provider);

        for (gIter = agents; gIter != NULL; gIter = gIter->next) {
            *resources = lrmd_list_add(*resources, (const char *)gIter->data);
            rc++;
        }
        g_list_free_full(agents, free);

        if (!class) {
            rc += list_stonith_agents(resources);
        }
    }

    if (rc == 0) {
        crm_notice("No agents found for class %s", class);
        rc = -EPROTONOSUPPORT;
    }
    return rc;
}

static int
does_provider_have_agent(const char *agent, const char *provider, const char *class)
{
    int found = 0;
    GList *agents = NULL;
    GListPtr gIter2 = NULL;

    agents = resources_list_agents(class, provider);
    for (gIter2 = agents; gIter2 != NULL; gIter2 = gIter2->next) {
        if (safe_str_eq(agent, gIter2->data)) {
            found = 1;
        }
    }
    g_list_free_full(agents, free);

    return found;
}

static int
lrmd_api_list_ocf_providers(lrmd_t * lrmd, const char *agent, lrmd_list_t ** providers)
{
    int rc = pcmk_ok;
    char *provider = NULL;
    GList *ocf_providers = NULL;
    GListPtr gIter = NULL;

    ocf_providers = resources_list_providers("ocf");

    for (gIter = ocf_providers; gIter != NULL; gIter = gIter->next) {
        provider = gIter->data;
        if (!agent || does_provider_have_agent(agent, provider, "ocf")) {
            *providers = lrmd_list_add(*providers, (const char *)gIter->data);
            rc++;
        }
    }

    g_list_free_full(ocf_providers, free);
    return rc;
}

static int
lrmd_api_list_standards(lrmd_t * lrmd, lrmd_list_t ** supported)
{
    int rc = 0;
    GList *standards = NULL;
    GListPtr gIter = NULL;

    standards = resources_list_standards();

    for (gIter = standards; gIter != NULL; gIter = gIter->next) {
        *supported = lrmd_list_add(*supported, (const char *)gIter->data);
        rc++;
    }

    if (list_stonith_agents(NULL) > 0) {
        *supported = lrmd_list_add(*supported, "stonith");
        rc++;
    }

    g_list_free_full(standards, free);
    return rc;
}

lrmd_t *
lrmd_api_new(void)
{
    lrmd_t *new_lrmd = NULL;
    lrmd_private_t *pvt = NULL;

    new_lrmd = calloc(1, sizeof(lrmd_t));
    pvt = calloc(1, sizeof(lrmd_private_t));
    pvt->remote = calloc(1, sizeof(crm_remote_t));
    new_lrmd->cmds = calloc(1, sizeof(lrmd_api_operations_t));

    pvt->type = CRM_CLIENT_IPC;
    new_lrmd->private = pvt;

    new_lrmd->cmds->connect = lrmd_api_connect;
    new_lrmd->cmds->connect_async = lrmd_api_connect_async;
    new_lrmd->cmds->is_connected = lrmd_api_is_connected;
    new_lrmd->cmds->poke_connection = lrmd_api_poke_connection;
    new_lrmd->cmds->disconnect = lrmd_api_disconnect;
    new_lrmd->cmds->register_rsc = lrmd_api_register_rsc;
    new_lrmd->cmds->unregister_rsc = lrmd_api_unregister_rsc;
    new_lrmd->cmds->get_rsc_info = lrmd_api_get_rsc_info;
    new_lrmd->cmds->set_callback = lrmd_api_set_callback;
    new_lrmd->cmds->get_metadata = lrmd_api_get_metadata;
    new_lrmd->cmds->exec = lrmd_api_exec;
    new_lrmd->cmds->cancel = lrmd_api_cancel;
    new_lrmd->cmds->list_agents = lrmd_api_list_agents;
    new_lrmd->cmds->list_ocf_providers = lrmd_api_list_ocf_providers;
    new_lrmd->cmds->list_standards = lrmd_api_list_standards;

    if (!stonith_api) {
        stonith_api = stonith_api_new();
    }

    return new_lrmd;
}

lrmd_t *
lrmd_remote_api_new(const char *nodename, const char *server, int port)
{
#ifdef HAVE_GNUTLS_GNUTLS_H
    lrmd_t *new_lrmd = lrmd_api_new();
    lrmd_private_t *native = new_lrmd->private;

    if (!nodename && !server) {
        return NULL;
    }

    native->type = CRM_CLIENT_TLS;
    native->remote_nodename = nodename ? strdup(nodename) : strdup(server);
    native->server = server ? strdup(server) : strdup(nodename);
    native->port = port ? port : DEFAULT_REMOTE_PORT;
    return new_lrmd;
#else
    crm_err("GNUTLS is not enabled for this build, remote LRMD client can not be created");
    return NULL;
#endif

}

void
lrmd_api_delete(lrmd_t * lrmd)
{
    if (!lrmd) {
        return;
    }
    lrmd->cmds->disconnect(lrmd);       /* no-op if already disconnected */
    free(lrmd->cmds);
    if (lrmd->private) {
        lrmd_private_t *native = lrmd->private;

#ifdef HAVE_GNUTLS_GNUTLS_H
        free(native->server);
#endif
        free(native->remote_nodename);
        free(native->remote);
    }
    free(lrmd->private);
    free(lrmd);
}
