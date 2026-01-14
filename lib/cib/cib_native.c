/*
 * Copyright 2004 International Business Machines
 * Later changes copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // ECOMM, EINVAL, ENOMSG, ENOTCONN, etc.
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdlib.h>                 // calloc, free
#include <sys/types.h>              // ssize_t

#include <glib.h>                   // gpointer, g_*, G_*, FALSE, TRUE
#include <libxml/tree.h>            // xmlNode

#include <crm/cib.h>                // cib_*, remove_cib_op_callback
#include <crm/cib/internal.h>       // cib__*, PCMK__CIB_REQUEST_QUERY
#include <crm/common/internal.h>    // pcmk__err, pcmk__xml_*, etc.
#include <crm/common/ipc.h>         // crm_ipc_*
#include <crm/common/logging.h>     // CRM_CHECK, crm_log_xml_explicit
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/results.h>     // pcmk_rc_ok, pcmk_ok, pcmk_strerror, etc.
#include <crm/crm.h>                // CRM_OP_REGISTER, crm_system_name

typedef struct cib_native_opaque_s {
    char *token;
    crm_ipc_t *ipc;
    void (*dnotify_fn) (gpointer user_data);
    mainloop_io_t *source;
} cib_native_opaque_t;

static int
cib_native_perform_op_delegate(cib_t *cib, const char *op, const char *host,
                               const char *section, xmlNode *data,
                               xmlNode **output_data, int call_options,
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
        pcmk__err("No operation specified");
        return -EINVAL;
    }

    if (call_options & cib_sync_call) {
        pcmk__set_ipc_flags(ipc_flags, "client", crm_ipc_client_response);
    }

    rc = cib__create_op(cib, op, host, section, data, call_options, user_name,
                        NULL, &op_msg);
    rc = pcmk_rc2legacy(rc);
    if (rc != pcmk_ok) {
        return rc;
    }

    if (pcmk__is_set(call_options, cib_transaction)) {
        rc = cib__extend_transaction(cib, op_msg);
        rc = pcmk_rc2legacy(rc);
        goto done;
    }

    pcmk__trace("Sending %s message to the CIB manager (timeout=%ds)", op,
                cib->call_timeout);
    rc = crm_ipc_send(native->ipc, op_msg, ipc_flags, cib->call_timeout * 1000, &op_reply);

    if (rc < 0) {
        pcmk__err("Couldn't perform %s operation (timeout=%ds): %s (%d)", op,
                  cib->call_timeout, pcmk_strerror(rc), rc);
        rc = -ECOMM;
        goto done;
    }

    pcmk__log_xml_trace(op_reply, "Reply");

    if (!(call_options & cib_sync_call)) {
        pcmk__trace("Async call, returning %d", cib->call_id);
        CRM_CHECK(cib->call_id != 0,
                  rc = -ENOMSG; goto done);
        rc = cib->call_id;
        goto done;
    }

    rc = pcmk_ok;
    pcmk__xe_get_int(op_reply, PCMK__XA_CIB_CALLID, &reply_id);
    if (reply_id == cib->call_id) {
        xmlNode *tmp = cib__get_calldata(op_reply);

        pcmk__trace("Synchronous reply %d received", reply_id);
        if (pcmk__xe_get_int(op_reply, PCMK__XA_CIB_RC, &rc) != pcmk_rc_ok) {
            rc = -EPROTO;
        }

        if (output_data == NULL || (call_options & cib_discard_reply)) {
            pcmk__trace("Discarding reply");
        } else {
            *output_data = pcmk__xml_copy(NULL, tmp);
        }

    } else if (reply_id <= 0) {
        pcmk__err("Received bad reply: No id set");
        pcmk__log_xml_err(op_reply, "Bad reply");
        rc = -ENOMSG;
        goto done;

    } else {
        pcmk__err("Received bad reply: %d (wanted %d)", reply_id, cib->call_id);
        pcmk__log_xml_err(op_reply, "Old reply");
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

            /* These indicate internal problems */
        case -EPROTO:
        case -ENOMSG:
            pcmk__err("Call failed: %s", pcmk_strerror(rc));
            if (op_reply) {
                pcmk__log_xml_err(op_reply, "Invalid reply");
            }
            break;

        default:
            if (!pcmk__str_eq(op, PCMK__CIB_REQUEST_QUERY, pcmk__str_none)) {
                pcmk__warn("Call failed: %s", pcmk_strerror(rc));
            }
    }

  done:
    if (!crm_ipc_connected(native->ipc)) {
        pcmk__err("The CIB manager disconnected");
        cib->state = cib_disconnected;
    }

    pcmk__xml_free(op_msg);
    pcmk__xml_free(op_reply);
    return rc;
}

static int
cib_native_dispatch_internal(const char *buffer, ssize_t length,
                             gpointer userdata)
{
    const char *type = NULL;
    xmlNode *msg = NULL;

    cib_t *cib = userdata;

    pcmk__trace("dispatching %p", userdata);

    if (cib == NULL) {
        pcmk__err("No CIB!");
        return 0;
    }

    msg = pcmk__xml_parse(buffer);

    if (msg == NULL) {
        pcmk__warn("Received a NULL message from the CIB manager");
        return 0;
    }

    /* do callbacks */
    type = pcmk__xe_get(msg, PCMK__XA_T);
    pcmk__trace("Activating %s callbacks...", type);
    crm_log_xml_explicit(msg, "cib-reply");

    if (pcmk__str_eq(type, PCMK__VALUE_CIB, pcmk__str_none)) {
        cib_native_callback(cib, msg, 0, 0);

    } else if (pcmk__str_eq(type, PCMK__VALUE_CIB_NOTIFY, pcmk__str_none)) {
        g_list_foreach(cib->notify_list, cib_native_notify, msg);

    } else {
        pcmk__err("Unknown message type: %s", type);
    }

    pcmk__xml_free(msg);
    return 0;
}

static void
cib_native_destroy(void *userdata)
{
    cib_t *cib = userdata;
    cib_native_opaque_t *native = cib->variant_opaque;

    pcmk__trace("destroying %p", userdata);
    cib->state = cib_disconnected;
    native->source = NULL;
    native->ipc = NULL;

    if (native->dnotify_fn) {
        native->dnotify_fn(userdata);
    }
}

static int
cib_native_signoff(cib_t *cib)
{
    cib_native_opaque_t *native = cib->variant_opaque;

    pcmk__debug("Disconnecting from the CIB manager");

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

    cib->cmds->end_transaction(cib, false, cib_none);
    cib->state = cib_disconnected;
    cib->type = cib_no_connection;

    return pcmk_ok;
}

static int
cib_native_signon(cib_t *cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    const char *channel = NULL;
    cib_native_opaque_t *native = cib->variant_opaque;
    xmlNode *hello = NULL;

    struct ipc_client_callbacks cib_callbacks = {
        .dispatch = cib_native_dispatch_internal,
        .destroy = cib_native_destroy
    };

    if (name == NULL) {
        name = pcmk__s(crm_system_name, "client");
    }

    cib->call_timeout = PCMK__IPC_TIMEOUT;

    switch (type) {
        case cib_command:
        case cib_command_nonblocking:
        case cib_query:
            /* @COMPAT cib_command_nonblocking and cib_query are deprecated
             * since 3.0.2
             */
            cib->state = cib_connected_command;
            channel = PCMK__SERVER_BASED_RW;
            break;

        default:
            return -ENOTCONN;
    }

    pcmk__trace("Connecting %s channel", channel);

    native->source = mainloop_add_ipc_client(channel, G_PRIORITY_HIGH, 0, cib,
                                             &cib_callbacks);
    native->ipc = mainloop_get_ipc_client(native->source);

    if (rc != pcmk_ok || native->ipc == NULL || !crm_ipc_connected(native->ipc)) {
        pcmk__info("Could not connect to CIB manager for %s", name);
        rc = -ENOTCONN;
    }

    if (rc == pcmk_ok) {
        rc = cib__create_op(cib, CRM_OP_REGISTER, NULL, NULL, NULL,
                            cib_sync_call, NULL, name, &hello);
        rc = pcmk_rc2legacy(rc);
    }

    if (rc == pcmk_ok) {
        xmlNode *reply = NULL;

        if (crm_ipc_send(native->ipc, hello, crm_ipc_client_response, -1,
                         &reply) > 0) {
            const char *msg_type = pcmk__xe_get(reply, PCMK__XA_CIB_OP);

            pcmk__log_xml_trace(reply, "reg-reply");

            if (!pcmk__str_eq(msg_type, CRM_OP_REGISTER, pcmk__str_casei)) {
                pcmk__info("Reply to CIB registration message has unknown type "
                           "'%s'",
                           msg_type);
                rc = -EPROTO;

            } else {
                native->token = pcmk__xe_get_copy(reply, PCMK__XA_CIB_CLIENTID);
                if (native->token == NULL) {
                    rc = -EPROTO;
                }
            }
            pcmk__xml_free(reply);

        } else {
            rc = -ECOMM;
        }
        pcmk__xml_free(hello);
    }

    if (rc == pcmk_ok) {
        pcmk__info("Successfully connected to CIB manager for %s", name);
        return pcmk_ok;
    }

    pcmk__info("Connection to CIB manager for %s failed: %s", name,
               pcmk_strerror(rc));
    cib_native_signoff(cib);
    return rc;
}

static int
cib_native_free(cib_t *cib)
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
        free(cib->user);
        free(cib);
    }

    return rc;
}

static int
cib_native_register_notification(cib_t *cib, const char *callback, int enabled)
{
    int rc = pcmk_ok;
    xmlNode *notify_msg = pcmk__xe_create(NULL, PCMK__XE_CIB_CALLBACK);
    cib_native_opaque_t *native = cib->variant_opaque;

    if (cib->state != cib_disconnected) {
        pcmk__xe_set(notify_msg, PCMK__XA_CIB_OP, PCMK__VALUE_CIB_NOTIFY);
        pcmk__xe_set(notify_msg, PCMK__XA_CIB_NOTIFY_TYPE, callback);
        pcmk__xe_set_int(notify_msg, PCMK__XA_CIB_NOTIFY_ACTIVATE, enabled);
        rc = crm_ipc_send(native->ipc, notify_msg, crm_ipc_client_response,
                          1000 * cib->call_timeout, NULL);
        if (rc <= 0) {
            pcmk__trace("Notification not registered: %d", rc);
            rc = -ECOMM;
        }
    }

    pcmk__xml_free(notify_msg);
    return rc;
}

static int
cib_native_set_connection_dnotify(cib_t *cib,
                                  void (*dnotify) (gpointer user_data))
{
    cib_native_opaque_t *native = NULL;

    if (cib == NULL) {
        pcmk__err("No CIB!");
        return FALSE;
    }

    native = cib->variant_opaque;
    native->dnotify_fn = dnotify;

    return pcmk_ok;
}

/*!
 * \internal
 * \brief Get the given CIB connection's unique client identifier
 *
 * These can be used to check whether this client requested the action that
 * triggered a CIB notification.
 *
 * \param[in]  cib       CIB connection
 * \param[out] async_id  If not \p NULL, where to store asynchronous client ID
 * \param[out] sync_id   If not \p NULL, where to store synchronous client ID
 *
 * \return Legacy Pacemaker return code (specifically, \p pcmk_ok)
 *
 * \note This is the \p cib_native variant implementation of
 *       \p cib_api_operations_t:client_id().
 * \note For \p cib_native objects, \p async_id and \p sync_id are the same.
 * \note The client ID is assigned during CIB sign-on.
 */
static int
cib_native_client_id(const cib_t *cib, const char **async_id,
                     const char **sync_id)
{
    cib_native_opaque_t *native = cib->variant_opaque;

    if (async_id != NULL) {
        *async_id = native->token;
    }
    if (sync_id != NULL) {
        *sync_id = native->token;
    }
    return pcmk_ok;
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
    cib->cmds->signoff = cib_native_signoff;
    cib->cmds->free = cib_native_free;

    cib->cmds->register_notification = cib_native_register_notification;
    cib->cmds->set_connection_dnotify = cib_native_set_connection_dnotify;

    cib->cmds->client_id = cib_native_client_id;

    return cib;
}
