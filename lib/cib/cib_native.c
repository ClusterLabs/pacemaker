/*
 * Copyright (c) 2004 International Business Machines
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

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <cib_private.h>

typedef struct cib_native_opaque_s {
    IPC_Channel *command_channel;
    IPC_Channel *callback_channel;
    GCHSource *callback_source;
    char *token;

} cib_native_opaque_t;

int cib_native_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                          xmlNode * data, xmlNode ** output_data, int call_options);

int cib_native_perform_op_delegate(cib_t * cib, const char *op, const char *host,
                                   const char *section, xmlNode * data, xmlNode ** output_data,
                                   int call_options, const char *user_name);

int cib_native_free(cib_t * cib);
int cib_native_signoff(cib_t * cib);
int cib_native_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_native_signon_raw(cib_t * cib, const char *name, enum cib_conn_type type, int *async_fd,
                          int *sync_fd);

IPC_Channel *cib_native_channel(cib_t * cib);
gboolean cib_native_msgready(cib_t * cib);
gboolean cib_native_dispatch(IPC_Channel * channel, gpointer user_data);

int cib_native_inputfd(cib_t * cib);
int cib_native_rcvmsg(cib_t * cib, int blocking);
int cib_native_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data));

cib_t *
cib_native_new(void)
{
    cib_native_opaque_t *native = NULL;
    cib_t *cib = cib_new_variant();

    crm_malloc0(native, sizeof(cib_native_opaque_t));

    cib->variant = cib_native;
    cib->variant_opaque = native;

    native->command_channel = NULL;
    native->callback_channel = NULL;

    /* assign variant specific ops */
    cib->cmds->variant_op = cib_native_perform_op;
    cib->cmds->delegated_variant_op = cib_native_perform_op_delegate;
    cib->cmds->signon = cib_native_signon;
    cib->cmds->signon_raw = cib_native_signon_raw;
    cib->cmds->signoff = cib_native_signoff;
    cib->cmds->free = cib_native_free;
    cib->cmds->inputfd = cib_native_inputfd;

    cib->cmds->register_notification = cib_native_register_notification;
    cib->cmds->set_connection_dnotify = cib_native_set_connection_dnotify;

    return cib;
}

int
cib_native_signon(cib_t * cib, const char *name, enum cib_conn_type type)
{
    return cib_native_signon_raw(cib, name, type, NULL, NULL);
}

int
cib_native_signon_raw(cib_t * cib, const char *name, enum cib_conn_type type, int *async_fd,
                      int *sync_fd)
{
    int rc = cib_ok;
    xmlNode *hello = NULL;
    char *uuid_ticket = NULL;
    cib_native_opaque_t *native = cib->variant_opaque;

    crm_trace("Connecting command channel");

    if (type == cib_command) {
        cib->state = cib_connected_command;
        native->command_channel = init_client_ipc_comms_nodispatch(cib_channel_rw);

    } else if (type == cib_query) {
        cib->state = cib_connected_query;
        native->command_channel = init_client_ipc_comms_nodispatch(cib_channel_ro);

    } else {
        return cib_not_connected;
    }

    if (native->command_channel == NULL) {
        crm_debug("Connection to command channel failed");
        rc = cib_connection;

    } else if (native->command_channel->ch_status != IPC_CONNECT) {
        crm_err("Connection may have succeeded," " but authentication to command channel failed");
        rc = cib_authentication;
    }

    if (rc == cib_ok) {
        rc = get_channel_token(native->command_channel, &uuid_ticket);
        if (rc == cib_ok) {
            native->token = uuid_ticket;
            uuid_ticket = NULL;
        }
    }

    native->callback_channel = init_client_ipc_comms_nodispatch(cib_channel_callback);
    if (native->callback_channel == NULL) {
        crm_debug("Connection to callback channel failed");
        rc = cib_connection;

    } else if (native->callback_channel->ch_status != IPC_CONNECT) {
        crm_err("Connection may have succeeded," " but authentication to command channel failed");
        rc = cib_authentication;
    }

    if (rc == cib_ok) {
        native->callback_channel->send_queue->max_qlen = 500;
        rc = get_channel_token(native->callback_channel, &uuid_ticket);
        if (rc == cib_ok) {
            crm_free(native->token);
            native->token = uuid_ticket;
        }
    }

    if (rc == cib_ok) {
        CRM_CHECK(native->token != NULL,;);
        hello = cib_create_op(0, native->token, CRM_OP_REGISTER, NULL, NULL, NULL, 0, NULL);
        crm_xml_add(hello, F_CIB_CLIENTNAME, name);

        if (send_ipc_message(native->command_channel, hello) == FALSE) {
            rc = cib_callback_register;
        }

        free_xml(hello);
    }

    if (rc == cib_ok) {
        gboolean do_mainloop = TRUE;

        if (async_fd != NULL) {
            do_mainloop = FALSE;
            *async_fd = native->callback_channel->ops->get_recv_select_fd(native->callback_channel);
        }

        if (sync_fd != NULL) {
            do_mainloop = FALSE;
            *sync_fd = native->callback_channel->ops->get_send_select_fd(native->callback_channel);
        }

        if (do_mainloop) {
            crm_trace("Connecting callback channel");
            native->callback_source =
                G_main_add_IPC_Channel(G_PRIORITY_HIGH, native->callback_channel, FALSE,
                                       cib_native_dispatch, cib, default_ipc_connection_destroy);

            if (native->callback_source == NULL) {
                crm_err("Callback source not recorded");
                rc = cib_connection;
            }
        }
    }

    if (rc == cib_ok) {
#if HAVE_MSGFROMIPC_TIMEOUT
        cib->call_timeout = MAX_IPC_DELAY;
#endif
        crm_debug("Connection to CIB successful");
        return cib_ok;
    }

    crm_debug("Connection to CIB failed: %s", cib_error2string(rc));
    cib_native_signoff(cib);
    return rc;
}

int
cib_native_signoff(cib_t * cib)
{
    cib_native_opaque_t *native = cib->variant_opaque;

    crm_debug("Signing out of the CIB Service");

    /* close channels */
    if (native->command_channel != NULL) {
        native->command_channel->ops->destroy(native->command_channel);
        native->command_channel = NULL;
    }

    if (native->callback_source != NULL) {
        G_main_del_IPC_Channel(native->callback_source);
        native->callback_source = NULL;
    }

    if (native->callback_channel != NULL) {
#ifdef BUG
        native->callback_channel->ops->destroy(native->callback_channel);
#endif
        native->callback_channel = NULL;
    }

    cib->state = cib_disconnected;
    cib->type = cib_none;

    return cib_ok;
}

int
cib_native_free(cib_t * cib)
{
    int rc = cib_ok;

    if (cib->state != cib_disconnected) {
        rc = cib_native_signoff(cib);
    }

    if (cib->state == cib_disconnected) {
        cib_native_opaque_t *native = cib->variant_opaque;

        crm_free(native->token);
        crm_free(cib->variant_opaque);
        crm_free(cib->cmds);
        crm_free(cib);
    }

    return rc;
}

IPC_Channel *
cib_native_channel(cib_t * cib)
{
    cib_native_opaque_t *native = NULL;

    if (cib == NULL) {
        crm_err("Missing cib object");
        return NULL;
    }

    native = cib->variant_opaque;

    if (native != NULL) {
        return native->callback_channel;
    }

    crm_err("couldnt find variant specific data in %p", cib);
    return NULL;
}

int
cib_native_inputfd(cib_t * cib)
{
    IPC_Channel *ch = cib_native_channel(cib);

    return ch->ops->get_recv_select_fd(ch);
}

static gboolean timer_expired = FALSE;

#ifndef HAVE_MSGFROMIPC_TIMEOUT
static struct timer_rec_s sync_timer;
static gboolean
cib_timeout_handler(gpointer data)
{
    struct timer_rec_s *timer = data;

    timer_expired = TRUE;
    crm_err("Call %d timed out after %ds", timer->call_id, timer->timeout);

    /* Always return TRUE, never remove the handler
     * We do that after the while-loop in cib_native_perform_op()
     */
    return TRUE;
}
#endif

int
cib_native_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                      xmlNode * data, xmlNode ** output_data, int call_options)
{
    return cib_native_perform_op_delegate(cib, op, host, section,
                                          data, output_data, call_options, NULL);
}

int
cib_native_perform_op_delegate(cib_t * cib, const char *op, const char *host, const char *section,
                               xmlNode * data, xmlNode ** output_data, int call_options,
                               const char *user_name)
{
    int rc = HA_OK;

    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    cib_native_opaque_t *native = cib->variant_opaque;

    if (cib->state == cib_disconnected) {
        return cib_not_connected;
    }

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if (op == NULL) {
        crm_err("No operation specified");
        return cib_operation;
    }

    cib->call_id++;
    /* prevent call_id from being negative (or zero) and conflicting
     *    with the cib_errors enum
     * use 2 because we use it as (cib->call_id - 1) below
     */
    if (cib->call_id < 1) {
        cib->call_id = 1;
    }

    CRM_CHECK(native->token != NULL,;);
    op_msg =
        cib_create_op(cib->call_id, native->token, op, host, section, data, call_options,
                      user_name);
    if (op_msg == NULL) {
        return cib_create_msg;
    }

    crm_trace("Sending %s message to CIB service", op);
    if (send_ipc_message(native->command_channel, op_msg) == FALSE) {
        crm_err("Sending message to CIB service FAILED");
        free_xml(op_msg);
        return cib_send_failed;

    } else {
        crm_trace("Message sent");
    }

    free_xml(op_msg);

    if ((call_options & cib_discard_reply)) {
        crm_trace("Discarding reply");
        return cib_ok;

    } else if (!(call_options & cib_sync_call)) {
        crm_trace("Async call, returning");
        CRM_CHECK(cib->call_id != 0, return cib_reply_failed);

        return cib->call_id;
    }

    rc = IPC_OK;
    crm_trace("Waiting for a syncronous reply");

#ifndef HAVE_MSGFROMIPC_TIMEOUT
    sync_timer.ref = 0;
    if (cib->call_timeout > 0) {
        timer_expired = FALSE;
        sync_timer.call_id = cib->call_id;
        sync_timer.timeout = cib->call_timeout * 1000;
        sync_timer.ref = g_timeout_add(sync_timer.timeout, cib_timeout_handler, &sync_timer);
    }
#endif
    rc = cib_ok;
    while (timer_expired == FALSE && IPC_ISRCONN(native->command_channel)) {
        int reply_id = -1;
        int msg_id = cib->call_id;

        op_reply = xmlfromIPC(native->command_channel, cib->call_timeout);
        if (op_reply == NULL) {
            rc = cib_remote_timeout;
            break;
        }

        crm_element_value_int(op_reply, F_CIB_CALLID, &reply_id);
        if (reply_id <= 0) {
            rc = cib_reply_failed;
            break;

        } else if (reply_id == msg_id) {
            crm_trace("Syncronous reply received");
            if (crm_element_value_int(op_reply, F_CIB_RC, &rc) != 0) {
                rc = cib_return_code;
            }

            if (output_data != NULL && is_not_set(call_options, cib_discard_reply)) {
                xmlNode *tmp = get_message_xml(op_reply, F_CIB_CALLDATA);

                if (tmp != NULL) {
                    *output_data = copy_xml(tmp);
                }
            }

            break;

        } else if (reply_id < msg_id) {
            crm_debug("Received old reply: %d (wanted %d)", reply_id, msg_id);
            crm_log_xml_trace(op_reply, "Old reply");

        } else if ((reply_id - 10000) > msg_id) {
            /* wrap-around case */
            crm_debug("Received old reply: %d (wanted %d)", reply_id, msg_id);
            crm_log_xml_trace(op_reply, "Old reply");

        } else {
            crm_err("Received a __future__ reply:" " %d (wanted %d)", reply_id, msg_id);
        }
        free_xml(op_reply);
        op_reply = NULL;
    }

    if (IPC_ISRCONN(native->command_channel) == FALSE) {
        crm_err("CIB disconnected: %d", native->command_channel->ch_status);
        cib->state = cib_disconnected;
    }

    if (op_reply == NULL && cib->state == cib_disconnected) {
        rc = cib_not_connected;

    } else if (rc == cib_ok && op_reply == NULL) {
        rc = cib_remote_timeout;
    }

    switch (rc) {
        case cib_ok:
        case cib_not_master:
            break;

            /* This is an internal value that clients do not and should not care about */
        case cib_diff_resync:
            rc = cib_ok;
            break;

            /* These indicate internal problems */
        case cib_return_code:
        case cib_reply_failed:
        case cib_master_timeout:
            crm_err("Call failed: %s", cib_error2string(rc));
            if (op_reply) {
                crm_log_xml_err(op_reply, "Invalid reply");
            }
            break;

        default:
            if (safe_str_neq(op, CIB_OP_QUERY)) {
                crm_warn("Call failed: %s", cib_error2string(rc));
            }
    }

#ifndef HAVE_MSGFROMIPC_TIMEOUT
    if (sync_timer.ref > 0) {
        g_source_remove(sync_timer.ref);
        sync_timer.ref = 0;
    }
#endif

    free_xml(op_reply);
    return rc;
}

gboolean
cib_native_msgready(cib_t * cib)
{
    cib_native_opaque_t *native = NULL;

    if (cib == NULL) {
        crm_err("No CIB!");
        return FALSE;
    }

    native = cib->variant_opaque;

    if (native->command_channel != NULL) {
        /* drain the channel */
        IPC_Channel *cmd_ch = native->command_channel;
        xmlNode *cmd_msg = NULL;

        while (cmd_ch->ch_status != IPC_DISCONNECT && cmd_ch->ops->is_message_pending(cmd_ch)) {
            /* this will happen when the CIB exited from beneath us */
            cmd_msg = xmlfromIPC(cmd_ch, MAX_IPC_DELAY);
            free_xml(cmd_msg);
        }

    } else {
        crm_err("No command channel");
    }

    if (native->callback_channel == NULL) {
        crm_err("No callback channel");
        return FALSE;

    } else if (native->callback_channel->ch_status == IPC_DISCONNECT) {
        crm_info("Lost connection to the CIB service [%d].", native->callback_channel->farside_pid);
        return FALSE;

    } else if (native->callback_channel->ops->is_message_pending(native->callback_channel)) {
        crm_trace("Message pending on command channel [%d]", native->callback_channel->farside_pid);
        return TRUE;
    }

    crm_trace("No message pending");
    return FALSE;
}

int
cib_native_rcvmsg(cib_t * cib, int blocking)
{
    const char *type = NULL;
    xmlNode *msg = NULL;
    cib_native_opaque_t *native = NULL;

    if (cib == NULL) {
        crm_err("No CIB!");
        return FALSE;
    }

    native = cib->variant_opaque;

    /* if it is not blocking mode and no message in the channel, return */
    if (blocking == 0 && cib_native_msgready(cib) == FALSE) {
        crm_trace("No message ready and non-blocking...");
        return 0;

    } else if (cib_native_msgready(cib) == FALSE) {
        crm_debug("Waiting for message from CIB service...");
        if (native->callback_channel == NULL) {
            return -1;

        } else if (native->callback_channel->ch_status != IPC_CONNECT) {
            return -2;

        } else if (native->command_channel && native->command_channel->ch_status != IPC_CONNECT) {
            return -3;
        }
        native->callback_channel->ops->waitin(native->callback_channel);
    }

    /* IPC_INTR is not a factor here */
    msg = xmlfromIPC(native->callback_channel, MAX_IPC_DELAY);
    if (msg == NULL) {
        crm_warn("Received a NULL msg from CIB service.");
        return 0;
    }

    /* do callbacks */
    type = crm_element_value(msg, F_TYPE);
    crm_trace("Activating %s callbacks...", type);

    if (safe_str_eq(type, T_CIB)) {
        cib_native_callback(cib, msg, 0, 0);

    } else if (safe_str_eq(type, T_CIB_NOTIFY)) {
        g_list_foreach(cib->notify_list, cib_native_notify, msg);

    } else {
        crm_err("Unknown message type: %s", type);
    }

    free_xml(msg);

    return 1;
}

gboolean
cib_native_dispatch(IPC_Channel * channel, gpointer user_data)
{
    cib_t *cib = user_data;
    cib_native_opaque_t *native = NULL;
    gboolean stay_connected = TRUE;

    CRM_CHECK(cib != NULL, return FALSE);

    native = cib->variant_opaque;
    CRM_CHECK(native->callback_channel == channel, return FALSE);

    while (cib_native_msgready(cib)) {
        /* invoke the callbacks but dont block */
        int rc = cib_native_rcvmsg(cib, 0);

        if (rc < 0) {
            crm_err("Message acquisition failed: %d", rc);
            break;

        } else if (rc == 0) {
            break;
        }
    }

    if (native->callback_channel && native->callback_channel->ch_status != IPC_CONNECT) {
        crm_crit("Lost connection to the CIB service [%d/callback].", channel->farside_pid);
        native->callback_source = NULL;
        stay_connected = FALSE;
    }

    if (native->command_channel && native->command_channel->ch_status != IPC_CONNECT) {
        crm_crit("Lost connection to the CIB service [%d/command].", channel->farside_pid);
        native->callback_source = NULL;
        stay_connected = FALSE;
    }

    return stay_connected;
}

static void
default_cib_connection_destroy(gpointer user_data)
{
    cib_t *cib = user_data;

    cib->state = cib_disconnected;
}

int
cib_native_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data))
{
    cib_native_opaque_t *native = NULL;

    if (cib == NULL) {
        crm_err("No CIB!");
        return FALSE;
    }

    native = cib->variant_opaque;

    if (dnotify == NULL) {
        crm_warn("Setting dnotify back to default value");
        set_IPC_Channel_dnotify(native->callback_source, default_cib_connection_destroy);

    } else {
        crm_trace("Setting dnotify");
        set_IPC_Channel_dnotify(native->callback_source, dnotify);
    }
    return cib_ok;
}

int
cib_native_register_notification(cib_t * cib, const char *callback, int enabled)
{
    xmlNode *notify_msg = create_xml_node(NULL, "cib-callback");
    cib_native_opaque_t *native = cib->variant_opaque;

    if (cib->state != cib_disconnected) {
        crm_xml_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
        crm_xml_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
        crm_xml_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
        send_ipc_message(native->callback_channel, notify_msg);
    }

    free_xml(notify_msg);
    return cib_ok;
}
