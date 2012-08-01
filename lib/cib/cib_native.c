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
#include <crm/cib/internal.h>

#include <crm/msg_xml.h>
#include <crm/common/mainloop.h>

typedef struct cib_native_opaque_s {
    char *token;
    crm_ipc_t *ipc;
    void (*dnotify_fn) (gpointer user_data);
    mainloop_io_t *source;

} cib_native_opaque_t;

int cib_native_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                          xmlNode * data, xmlNode ** output_data, int call_options);

int cib_native_perform_op_delegate(cib_t * cib, const char *op, const char *host,
                                   const char *section, xmlNode * data, xmlNode ** output_data,
                                   int call_options, const char *user_name);

int cib_native_free(cib_t * cib);
int cib_native_signoff(cib_t * cib);
int cib_native_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_native_signon_raw(cib_t * cib, const char *name, enum cib_conn_type type, int *event_fd);

bool cib_native_dispatch(cib_t * cib);

int cib_native_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data));

cib_t *
cib_native_new(void)
{
    cib_native_opaque_t *native = NULL;
    cib_t *cib = cib_new_variant();

    native = calloc(1, sizeof(cib_native_opaque_t));

    cib->variant = cib_native;
    cib->variant_opaque = native;

    native->ipc = NULL;
    native->source = NULL;
    native->dnotify_fn = NULL;

    /* assign variant specific ops */
    cib->delegate_fn = cib_native_perform_op_delegate;
    cib->cmds->signon = cib_native_signon;
    cib->cmds->signon_raw = cib_native_signon_raw;
    cib->cmds->signoff = cib_native_signoff;
    cib->cmds->free = cib_native_free;

    cib->cmds->register_notification = cib_native_register_notification;
    cib->cmds->set_connection_dnotify = cib_native_set_connection_dnotify;

    return cib;
}

int
cib_native_signon(cib_t * cib, const char *name, enum cib_conn_type type)
{
    return cib_native_signon_raw(cib, name, type, NULL);
}

static int
cib_native_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata)
{
    const char *type = NULL;
    xmlNode *msg = NULL;

    cib_t * cib = userdata;
    cib_native_opaque_t *native;

    crm_trace("dispatching %p", userdata);

    if (cib == NULL) {
        crm_err("No CIB!");
        return 0;
    }

    native = cib->variant_opaque;
    msg = string2xml(buffer);

    if (msg == NULL) {
        crm_warn("Received a NULL msg from CIB service.");
        return 0;
    }

    /* do callbacks */
    type = crm_element_value(msg, F_TYPE);
    crm_trace("Activating %s callbacks...", type);
    crm_log_xml_trace(msg, "cib-reply");

    if (safe_str_eq(type, T_CIB)) {
        cib_native_callback(cib, msg, 0, 0);

    } else if (safe_str_eq(type, T_CIB_NOTIFY)) {
        g_list_foreach(cib->notify_list, cib_native_notify, msg);

    } else {
        crm_err("Unknown message type: %s", type);
    }

    free_xml(msg);
    return 0;
}

bool
cib_native_dispatch(cib_t * cib)
{
    gboolean stay_connected = TRUE;
    cib_native_opaque_t *native;

    if (cib == NULL) {
        crm_err("No CIB!");
        return FALSE;
    }

    crm_trace("dispatching %p", cib);
    native = cib->variant_opaque;
    while(crm_ipc_ready(native->ipc)) {

        if(crm_ipc_read(native->ipc) > 0) {
            const char *msg = crm_ipc_buffer(native->ipc);
            cib_native_dispatch_internal(msg, strlen(msg), cib);
        }

        if(crm_ipc_connected(native->ipc) == FALSE) {
            crm_err("Connection closed");
            stay_connected = FALSE;
        }
    }

    return stay_connected;
}

static void
cib_native_destroy(void *userdata)
{
    cib_t *cib = userdata;
    cib_native_opaque_t *native = cib->variant_opaque;

    crm_trace("destroying %p", userdata);
    cib->state = cib_disconnected;
    native->source = NULL;
    native->ipc = NULL;

    if(native->dnotify_fn) {
        native->dnotify_fn(userdata);
    }
}

int
cib_native_signon_raw(cib_t * cib, const char *name, enum cib_conn_type type, int *async_fd)
{
    int rc = pcmk_ok;
    const char *channel = NULL;
    cib_native_opaque_t *native = cib->variant_opaque;

    static struct ipc_client_callbacks cib_callbacks = 
        {
            .dispatch = cib_native_dispatch_internal,
            .destroy = cib_native_destroy
        };
    
    cib->call_timeout = MAX_IPC_DELAY;

    if (type == cib_command) {
        cib->state = cib_connected_command;
        channel = cib_channel_rw;

    } else if (type == cib_command_nonblocking) {
        cib->state = cib_connected_command;
        channel = cib_channel_shm;

    } else if (type == cib_query) {
        cib->state = cib_connected_query;
        channel = cib_channel_ro;

    } else {
        return -ENOTCONN;
    }

    crm_trace("Connecting %s channel", channel);
    
    if (async_fd != NULL) {
        native->ipc = crm_ipc_new(channel, 0);

        if(native->ipc && crm_ipc_connect(native->ipc)) {
            *async_fd = crm_ipc_get_fd(native->ipc);

        } else if(native->ipc) {
            rc = -ENOTCONN;
        }

    } else {
        native->source = mainloop_add_ipc_client(channel, G_PRIORITY_HIGH, 512*1024 /* 512k */, cib, &cib_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }

    if (rc != pcmk_ok || native->ipc == NULL || crm_ipc_connected(native->ipc) == FALSE) {
        crm_debug("Connection unsuccessful (%d %p)", rc, native->ipc);
        rc = -ENOTCONN;
    }

    if (rc == pcmk_ok) {
        xmlNode *reply = NULL;
        xmlNode *hello = create_xml_node(NULL, "cib_command");

        crm_xml_add(hello, F_TYPE, T_CIB);
        crm_xml_add(hello, F_CIB_OPERATION, CRM_OP_REGISTER);
        crm_xml_add(hello, F_CIB_CLIENTNAME, name);
        crm_xml_add_int(hello, F_CIB_CALLOPTS, cib_sync_call);

        if (crm_ipc_send(native->ipc, hello, crm_ipc_client_response, -1, &reply) > 0) {
            const char *msg_type = crm_element_value(reply, F_CIB_OPERATION);

            rc = pcmk_ok;
            crm_log_xml_trace(reply, "reg-reply");

            if (safe_str_neq(msg_type, CRM_OP_REGISTER)) {
                crm_err("Invalid registration message: %s", msg_type);
                rc = -EPROTO;

            } else {
                native->token = crm_element_value_copy(reply, F_CIB_CLIENTID);
                if (native->token == NULL) {
                    rc = -EPROTO;
                }
            }

        } else {
            rc = -ECOMM;
        }

        free_xml(hello);
    }

    if (rc == pcmk_ok) {
        crm_debug("Connection to CIB successful");
        return pcmk_ok;
    }

    crm_debug("Connection to CIB failed: %s", pcmk_strerror(rc));
    cib_native_signoff(cib);
    return rc;
}

int
cib_native_signoff(cib_t * cib)
{
    cib_native_opaque_t *native = cib->variant_opaque;

    crm_debug("Signing out of the CIB Service");

    if (native->ipc != NULL) {
        /* If attached to mainloop and it is active, _close() will result in:
         *  - the source being removed from mainloop
         *  - the dnotify callback being invoked
         * Otherwise, we are at least correctly disconnecting IPC
         */
        crm_ipc_close(native->ipc);
        crm_ipc_destroy(native->ipc);
        native->source = NULL;
        native->ipc = NULL;
    }

    cib->state = cib_disconnected;
    cib->type = cib_none;

    return pcmk_ok;
}

int
cib_native_free(cib_t * cib)
{
    int rc = pcmk_ok;

    if (cib->state != cib_disconnected) {
        rc = cib_native_signoff(cib);
    }

    if (cib->state == cib_disconnected) {
        cib_native_opaque_t *native = cib->variant_opaque;

        free(native->token);
        free(cib->variant_opaque);
        free(cib->cmds);
        free(cib);
    }

    return rc;
}

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
    int rc = pcmk_ok;
    int reply_id = 0;
    enum crm_ipc_flags ipc_flags = crm_ipc_client_none;

    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    cib_native_opaque_t *native = cib->variant_opaque;

    if (cib->state == cib_disconnected) {
        return -ENOTCONN;
    }

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if (op == NULL) {
        crm_err("No operation specified");
        return -EINVAL;
    }

    if(call_options & cib_sync_call) {
        ipc_flags |= crm_ipc_client_response;
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
        return -EPROTO;
    }

    crm_trace("Sending %s message to CIB service (timeout=%ds)", op, cib->call_timeout);
    rc = crm_ipc_send(native->ipc, op_msg, ipc_flags, cib->call_timeout * 1000, &op_reply);
    free_xml(op_msg);

    if(rc < 0) {
        crm_perror(LOG_ERR, "Couldn't perform %s operation (timeout=%ds): %d", op, cib->call_timeout, rc);
        rc = -ECOMM;
        goto done;
    }

    crm_log_xml_trace(op_reply, "Reply");
    
    if (!(call_options & cib_sync_call)) {
        crm_trace("Async call, returning %d", cib->call_id);
        CRM_CHECK(cib->call_id != 0, return -ENOMSG);
        free_xml(op_reply);
        return cib->call_id;
    }

    rc = pcmk_ok;
    crm_element_value_int(op_reply, F_CIB_CALLID, &reply_id);
    if (reply_id == cib->call_id) {
        xmlNode *tmp = get_message_xml(op_reply, F_CIB_CALLDATA);

        crm_trace("Syncronous reply %d received", reply_id);
        if (crm_element_value_int(op_reply, F_CIB_RC, &rc) != 0) {
            rc = -EPROTO;
        }

        if (output_data == NULL || (call_options & cib_discard_reply)) {
            crm_trace("Discarding reply");

        } else if (tmp != NULL) {
            *output_data = copy_xml(tmp);
        }

    } else if (reply_id <= 0) {
        crm_err("Recieved bad reply: No id set");
        crm_log_xml_err(op_reply, "Bad reply");
        rc = -ENOMSG;
        goto done;
        
    } else {
        crm_err("Recieved bad reply: %d (wanted %d)", reply_id, cib->call_id);
        crm_log_xml_err(op_reply, "Old reply");
        rc = -ENOMSG;
        goto done;
    }
    
    if (op_reply == NULL && cib->state == cib_disconnected) {
        rc = -ENOTCONN;

    } else if (rc == pcmk_ok && op_reply == NULL) {
        rc = -ETIME;
    }

    switch (rc) {
        case pcmk_ok:
        case -EPERM:
            break;

            /* This is an internal value that clients do not and should not care about */
        case -pcmk_err_diff_resync:
            rc = pcmk_ok;
            break;

            /* These indicate internal problems */
        case -EPROTO:
        case -ENOMSG:
            crm_err("Call failed: %s", pcmk_strerror(rc));
            if (op_reply) {
                crm_log_xml_err(op_reply, "Invalid reply");
            }
            break;

        default:
            if (safe_str_neq(op, CIB_OP_QUERY)) {
                crm_warn("Call failed: %s", pcmk_strerror(rc));
            }
    }

  done:
    if (crm_ipc_connected(native->ipc) == FALSE) {
        crm_err("CIB disconnected");
        cib->state = cib_disconnected;
    }

    free_xml(op_reply);
    return rc;
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
    native->dnotify_fn = dnotify;

    return pcmk_ok;
}

int
cib_native_register_notification(cib_t * cib, const char *callback, int enabled)
{
    int rc = pcmk_ok;
    xmlNode *notify_msg = create_xml_node(NULL, "cib-callback");
    cib_native_opaque_t *native = cib->variant_opaque;

    if (cib->state != cib_disconnected) {
        crm_xml_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
        crm_xml_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
        crm_xml_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
        rc = crm_ipc_send(native->ipc, notify_msg, crm_ipc_client_response, 1000 * cib->call_timeout, NULL);
        if(rc <= 0) {
            crm_trace("Notification not registered: %d", rc);
            rc = -ECOMM;
        }
    }

    free_xml(notify_msg);
    return rc;
}
