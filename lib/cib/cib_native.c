/*
 * Copyright 2004 International Business Machines
 * Later changes copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <errno.h>
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

int cib_native_perform_op_delegate(cib_t * cib, const char *op, const char *host,
                                   const char *section, xmlNode * data, xmlNode ** output_data,
                                   int call_options, const char *user_name);

int cib_native_free(cib_t * cib);
int cib_native_signoff(cib_t * cib);
int cib_native_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_native_signon_raw(cib_t * cib, const char *name, enum cib_conn_type type, int *event_fd);

int cib_native_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data));

static int
cib_native_register_notification(cib_t *cib, const char *callback, int enabled)
{
    int rc = pcmk_ok;
    xmlNode *notify_msg = create_xml_node(NULL, "cib-callback");
    cib_native_opaque_t *native = cib->variant_opaque;

    if (cib->state != cib_disconnected) {
        crm_xml_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
        crm_xml_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
        crm_xml_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
        rc = crm_ipc_send(native->ipc, notify_msg, crm_ipc_client_response,
                          1000 * cib->call_timeout, NULL);
        if (rc <= 0) {
            crm_trace("Notification not registered: %d", rc);
            rc = -ECOMM;
        }
    }

    free_xml(notify_msg);
    return rc;
}

cib_t *
cib_native_new(void)
{
    cib_native_opaque_t *native = NULL;
    cib_t *cib = cib_new_variant();

    if (cib == NULL) {
        return NULL;
    }

    native = calloc(1, sizeof(cib_native_opaque_t));

    if (native == NULL) {
        free(cib);
        return NULL;
    }

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

    cib_t *cib = userdata;

    crm_trace("dispatching %p", userdata);

    if (cib == NULL) {
        crm_err("No CIB!");
        return 0;
    }

    msg = string2xml(buffer);

    if (msg == NULL) {
        crm_warn("Received a NULL message from the CIB manager");
        return 0;
    }

    /* do callbacks */
    type = crm_element_value(msg, F_TYPE);
    crm_trace("Activating %s callbacks...", type);
    crm_log_xml_explicit(msg, "cib-reply");

    if (pcmk__str_eq(type, T_CIB, pcmk__str_casei)) {
        cib_native_callback(cib, msg, 0, 0);

    } else if (pcmk__str_eq(type, T_CIB_NOTIFY, pcmk__str_casei)) {
        g_list_foreach(cib->notify_list, cib_native_notify, msg);

    } else {
        crm_err("Unknown message type: %s", type);
    }

    free_xml(msg);
    return 0;
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

    if (native->dnotify_fn) {
        native->dnotify_fn(userdata);
    }
}

int
cib_native_signon_raw(cib_t * cib, const char *name, enum cib_conn_type type, int *async_fd)
{
    int rc = pcmk_ok;
    const char *channel = NULL;
    cib_native_opaque_t *native = cib->variant_opaque;

    struct ipc_client_callbacks cib_callbacks = {
        .dispatch = cib_native_dispatch_internal,
        .destroy = cib_native_destroy
    };

    cib->call_timeout = PCMK__IPC_TIMEOUT;

    if (type == cib_command) {
        cib->state = cib_connected_command;
        channel = PCMK__SERVER_BASED_RW;

    } else if (type == cib_command_nonblocking) {
        cib->state = cib_connected_command;
        channel = PCMK__SERVER_BASED_SHM;

    } else if (type == cib_query) {
        cib->state = cib_connected_query;
        channel = PCMK__SERVER_BASED_RO;

    } else {
        return -ENOTCONN;
    }

    crm_trace("Connecting %s channel", channel);

    if (async_fd != NULL) {
        native->ipc = crm_ipc_new(channel, 0);

        if (native->ipc && crm_ipc_connect(native->ipc)) {
            *async_fd = crm_ipc_get_fd(native->ipc);

        } else if (native->ipc) {
            rc = -ENOTCONN;
        }

    } else {
        native->source =
            mainloop_add_ipc_client(channel, G_PRIORITY_HIGH, 512 * 1024 /* 512k */ , cib,
                                    &cib_callbacks);
        native->ipc = mainloop_get_ipc_client(native->source);
    }

    if (rc != pcmk_ok || native->ipc == NULL || !crm_ipc_connected(native->ipc)) {
        crm_info("Could not connect to CIB manager for %s", name);
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

            if (!pcmk__str_eq(msg_type, CRM_OP_REGISTER, pcmk__str_casei)) {
                crm_info("Reply to CIB registration message has "
                         "unknown type '%s'", msg_type);
                rc = -EPROTO;

            } else {
                native->token = crm_element_value_copy(reply, F_CIB_CLIENTID);
                if (native->token == NULL) {
                    rc = -EPROTO;
                }
            }
            free_xml(reply);

        } else {
            rc = -ECOMM;
        }

        free_xml(hello);
    }

    if (rc == pcmk_ok) {
        crm_info("Successfully connected to CIB manager for %s", name);
        return pcmk_ok;
    }

    crm_info("Connection to CIB manager for %s failed: %s",
             name, pcmk_strerror(rc));
    cib_native_signoff(cib);
    return rc;
}

int
cib_native_signoff(cib_t * cib)
{
    cib_native_opaque_t *native = cib->variant_opaque;

    crm_debug("Disconnecting from the CIB manager");

    cib_free_notify(cib);
    remove_cib_op_callback(0, TRUE);

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

    cib->state = cib_disconnected;
    cib->type = cib_no_connection;

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
cib_native_perform_op_delegate(cib_t * cib, const char *op, const char *host, const char *section,
                               xmlNode * data, xmlNode ** output_data, int call_options,
                               const char *user_name)
{
    int rc = pcmk_ok;
    int reply_id = 0;
    enum crm_ipc_flags ipc_flags = crm_ipc_flags_none;

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

    if (call_options & cib_sync_call) {
        pcmk__set_ipc_flags(ipc_flags, "client", crm_ipc_client_response);
    }

    cib->call_id++;
    if (cib->call_id < 1) {
        cib->call_id = 1;
    }

    op_msg = cib_create_op(cib->call_id, op, host, section, data, call_options,
                           user_name);
    if (op_msg == NULL) {
        return -EPROTO;
    }

    crm_trace("Sending %s message to the CIB manager (timeout=%ds)", op, cib->call_timeout);
    rc = crm_ipc_send(native->ipc, op_msg, ipc_flags, cib->call_timeout * 1000, &op_reply);
    free_xml(op_msg);

    if (rc < 0) {
        crm_err("Couldn't perform %s operation (timeout=%ds): %s (%d)", op,
                cib->call_timeout, pcmk_strerror(rc), rc);
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

        crm_trace("Synchronous reply %d received", reply_id);
        if (crm_element_value_int(op_reply, F_CIB_RC, &rc) != 0) {
            rc = -EPROTO;
        }

        if (output_data == NULL || (call_options & cib_discard_reply)) {
            crm_trace("Discarding reply");

        } else if (tmp != NULL) {
            *output_data = copy_xml(tmp);
        }

    } else if (reply_id <= 0) {
        crm_err("Received bad reply: No id set");
        crm_log_xml_err(op_reply, "Bad reply");
        rc = -ENOMSG;
        goto done;

    } else {
        crm_err("Received bad reply: %d (wanted %d)", reply_id, cib->call_id);
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
            if (!pcmk__str_eq(op, PCMK__CIB_REQUEST_QUERY, pcmk__str_none)) {
                crm_warn("Call failed: %s", pcmk_strerror(rc));
            }
    }

  done:
    if (!crm_ipc_connected(native->ipc)) {
        crm_err("The CIB manager disconnected");
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
