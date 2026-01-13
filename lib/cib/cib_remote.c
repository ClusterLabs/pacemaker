/*
 * Copyright 2008-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EAGAIN, EINVAL, ENOMSG, ENOTCONN, etc.
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdlib.h>                 // calloc, free
#include <string.h>                 // strdup
#include <sys/socket.h>             // shutdown, SHUT_RDWR
#include <time.h>                   // time, time_t
#include <unistd.h>                 // close

#include <glib.h>                   // gboolean, gpointer, g_*, G_*, etc.
#include <gnutls/gnutls.h>          // gnutls_*, GNUTLS_*
#include <libxml/tree.h>            // xmlNode
#include <qb/qblog.h>               // QB_XS

#include <crm/cib.h>                // cib_*
#include <crm/cib/internal.h>       // cib__*
#include <crm/common/internal.h>    // pcmk__err, pcmk__xml_*, etc.
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/results.h>     // pcmk_rc_*, pcmk_ok, pcmk_strerror, etc.
#include <crm/common/xml.h>         // PCMK_XA_OP, PCMK_XA_USER
#include <crm/crm.h>                // CRM_OP_REGISTER, crm_system_name

// GnuTLS handshake timeout in seconds
#define TLS_HANDSHAKE_TIMEOUT 5

static pcmk__tls_t *tls = NULL;

typedef struct cib_remote_opaque_s {
    int port;
    char *server;
    char *user;
    char *passwd;
    gboolean encrypted;
    pcmk__remote_t command;
    pcmk__remote_t callback;
    pcmk__output_t *out;
    time_t start_time;
    int timeout_sec;
} cib_remote_opaque_t;

static int
cib_remote_perform_op(cib_t *cib, const char *op, const char *host,
                      const char *section, xmlNode *data,
                      xmlNode **output_data, int call_options,
                      const char *user_name)
{
    int rc;
    int remaining_time = 0;
    time_t start_time;

    xmlNode *op_msg = NULL;
    xmlNode *op_reply = NULL;

    cib_remote_opaque_t *private = cib->variant_opaque;

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

    rc = cib__create_op(cib, op, host, section, data, call_options, user_name,
                        NULL, &op_msg);
    rc = pcmk_rc2legacy(rc);
    if (rc != pcmk_ok) {
        return rc;
    }

    if (pcmk__is_set(call_options, cib_transaction)) {
        rc = cib__extend_transaction(cib, op_msg);
        pcmk__xml_free(op_msg);
        return pcmk_rc2legacy(rc);
    }

    pcmk__trace("Sending %s message to the CIB manager", op);
    if (!(call_options & cib_sync_call)) {
        pcmk__remote_send_xml(&private->callback, op_msg);
    } else {
        pcmk__remote_send_xml(&private->command, op_msg);
    }
    pcmk__xml_free(op_msg);

    if (pcmk__is_set(call_options, cib_discard_reply)) {
        pcmk__trace("Discarding reply");
        return pcmk_ok;
    }

    if (!pcmk__is_set(call_options, cib_sync_call)) {
        return cib->call_id;
    }

    pcmk__trace("Waiting for a synchronous reply");

    start_time = time(NULL);
    remaining_time = cib->call_timeout ? cib->call_timeout : 60;

    rc = pcmk_rc_ok;
    while (remaining_time > 0 && (rc != ENOTCONN)) {
        int reply_id = -1;
        int msg_id = cib->call_id;

        rc = pcmk__read_remote_message(&private->command,
                                       remaining_time * 1000);
        op_reply = pcmk__remote_message_xml(&private->command);

        if (!op_reply) {
            break;
        }

        pcmk__xe_get_int(op_reply, PCMK__XA_CIB_CALLID, &reply_id);

        if (reply_id == msg_id) {
            break;

        } else if (reply_id < msg_id) {
            pcmk__debug("Received old reply: %d (wanted %d)", reply_id, msg_id);
            pcmk__log_xml_trace(op_reply, "Old reply");

        } else if ((reply_id - 10000) > msg_id) {
            /* wrap-around case */
            pcmk__debug("Received old reply: %d (wanted %d)", reply_id, msg_id);
            pcmk__log_xml_trace(op_reply, "Old reply");
        } else {
            pcmk__err("Received a __future__ reply: %d (wanted %d)", reply_id,
                      msg_id);
        }

        pcmk__xml_free(op_reply);
        op_reply = NULL;

        /* wasn't the right reply, try and read some more */
        remaining_time = time(NULL) - start_time;
    }

    if (rc == ENOTCONN) {
        pcmk__err("Disconnected while waiting for reply");
        return -ENOTCONN;
    } else if (op_reply == NULL) {
        pcmk__err("No reply message - empty");
        return -ENOMSG;
    }

    pcmk__trace("Synchronous reply received");

    /* Start processing the reply... */
    if (pcmk__xe_get_int(op_reply, PCMK__XA_CIB_RC, &rc) != pcmk_rc_ok) {
        rc = -EPROTO;
    }

    if (rc == pcmk_ok || rc == -EPERM) {
        pcmk__log_xml_debug(op_reply, "passed");

    } else {
        pcmk__err("Call failed: %s", pcmk_strerror(rc));
        pcmk__log_xml_warn(op_reply, "failed");
    }

    if (output_data != NULL) {
        xmlNode *tmp = cib__get_calldata(op_reply);

        if (tmp == NULL) {
            pcmk__trace("No output in reply to \"%s\" command %d", op,
                        (cib->call_id - 1));
        } else {
            *output_data = pcmk__xml_copy(NULL, tmp);
        }
    }

    pcmk__xml_free(op_reply);

    return rc;
}

static int
cib_remote_callback_dispatch(gpointer user_data)
{
    int rc;
    cib_t *cib = user_data;
    cib_remote_opaque_t *private = cib->variant_opaque;

    xmlNode *msg = NULL;
    const char *type = NULL;

    /* If start time is 0, we've previously handled a complete message and this
     * connection is being reused for a new message.  Reset the start_time,
     * giving this new message timeout_sec from now to complete.
     */
    if (private->start_time == 0) {
        private->start_time = time(NULL);
    }

    rc = pcmk__read_available_remote_data(&private->callback);
    switch (rc) {
        case pcmk_rc_ok:
            /* We have the whole message so process it */
            break;

        case EAGAIN:
            /* Have we timed out? */
            if (time(NULL) >= private->start_time + private->timeout_sec) {
                pcmk__info("Error reading from CIB manager connection: %s",
                           pcmk_rc_str(ETIME));
                return -1;
            }

            /* We haven't read the whole message yet */
            return 0;

        default:
            /* Error */
            pcmk__info("Error reading from CIB manager connection: %s",
                       pcmk_rc_str(rc));
            return -1;
    }

    // coverity[tainted_data] This can't easily be changed right now
    msg = pcmk__remote_message_xml(&private->callback);
    if (msg == NULL) {
        private->start_time = 0;
        return 0;
    }

    type = pcmk__xe_get(msg, PCMK__XA_T);

    pcmk__trace("Activating %s callbacks...", type);

    if (pcmk__str_eq(type, PCMK__VALUE_CIB, pcmk__str_none)) {
        cib_native_callback(cib, msg, 0, 0);
    } else if (pcmk__str_eq(type, PCMK__VALUE_CIB_NOTIFY, pcmk__str_none)) {
        g_list_foreach(cib->notify_list, cib_native_notify, msg);
    } else {
        pcmk__err("Unknown message type: %s", type);
    }

    pcmk__xml_free(msg);
    private->start_time = 0;
    return 0;
}

static int
cib_remote_command_dispatch(gpointer user_data)
{
    int rc;
    cib_t *cib = user_data;
    cib_remote_opaque_t *private = cib->variant_opaque;

    /* See cib_remote_callback_dispatch */
    if (private->start_time == 0) {
        private->start_time = time(NULL);
    }

    rc = pcmk__read_available_remote_data(&private->command);
    if (rc == EAGAIN) {
        /* Have we timed out? */
        if (time(NULL) >= private->start_time + private->timeout_sec) {
            pcmk__info("Error reading from CIB manager connection: %s",
                       pcmk_rc_str(ETIME));
            return -1;
        }

        /* We haven't read the whole message yet */
        return 0;
    }

    free(private->command.buffer);
    private->command.buffer = NULL;
    pcmk__err("Received late reply for remote cib connection, discarding");

    if (rc != pcmk_rc_ok) {
        pcmk__info("Error reading from CIB manager connection: %s",
                   pcmk_rc_str(rc));
        return -1;
    }

    private->start_time = 0;
    return 0;
}

static int
cib_tls_close(cib_t *cib)
{
    cib_remote_opaque_t *private = cib->variant_opaque;

    if (private->encrypted) {
        if (private->command.tls_session) {
            gnutls_bye(private->command.tls_session, GNUTLS_SHUT_RDWR);
            gnutls_deinit(private->command.tls_session);
        }

        if (private->callback.tls_session) {
            gnutls_bye(private->callback.tls_session, GNUTLS_SHUT_RDWR);
            gnutls_deinit(private->callback.tls_session);
        }

        private->command.tls_session = NULL;
        private->callback.tls_session = NULL;
        pcmk__free_tls(tls);
        tls = NULL;
    }

    if (private->command.tcp_socket >= 0) {
        shutdown(private->command.tcp_socket, SHUT_RDWR);       /* no more receptions */
        close(private->command.tcp_socket);
    }
    if (private->callback.tcp_socket >= 0) {
        shutdown(private->callback.tcp_socket, SHUT_RDWR);      /* no more receptions */
        close(private->callback.tcp_socket);
    }
    private->command.tcp_socket = -1;
    private->callback.tcp_socket = -1;

    free(private->command.buffer);
    free(private->callback.buffer);
    private->command.buffer = NULL;
    private->callback.buffer = NULL;

    return 0;
}

static void
cib_remote_connection_destroy(gpointer user_data)
{
    pcmk__err("Connection destroyed");
    cib_tls_close(user_data);
}

static int
cib_tls_signon(cib_t *cib, pcmk__remote_t *connection, gboolean event_channel)
{
    cib_remote_opaque_t *private = cib->variant_opaque;
    int rc;

    xmlNode *answer = NULL;
    xmlNode *login = NULL;

    static struct mainloop_fd_callbacks cib_fd_callbacks = { 0, };

    cib_fd_callbacks.dispatch =
        event_channel ? cib_remote_callback_dispatch : cib_remote_command_dispatch;
    cib_fd_callbacks.destroy = cib_remote_connection_destroy;

    connection->tcp_socket = -1;
    connection->tls_session = NULL;
    rc = pcmk__connect_remote(private->server, private->port, 0, NULL,
                              &(connection->tcp_socket), NULL, NULL);
    if (rc != pcmk_rc_ok) {
        pcmk__info("Remote connection to %s:%d failed: %s " QB_XS " rc=%d",
                   private->server, private->port, pcmk_rc_str(rc), rc);
        return -ENOTCONN;
    }

    if (private->encrypted) {
        int tls_rc = GNUTLS_E_SUCCESS;

        // @TODO Implement pre-shared key authentication (see T961)
        rc = pcmk__init_tls(&tls, false, false);
        if (rc != pcmk_rc_ok) {
            return -1;
        }

        /* bind the socket to GnuTls lib */
        connection->tls_session = pcmk__new_tls_session(tls, connection->tcp_socket);
        if (connection->tls_session == NULL) {
            cib_tls_close(cib);
            return -1;
        }

        rc = pcmk__tls_client_handshake(connection, TLS_HANDSHAKE_TIMEOUT,
                                        &tls_rc);
        if (rc != pcmk_rc_ok) {
            const bool proto_err = (rc == EPROTO);

            pcmk__err("Remote CIB session creation for %s:%d failed: %s",
                      private->server, private->port,
                      (proto_err? gnutls_strerror(tls_rc) : pcmk_rc_str(rc)));
            gnutls_deinit(connection->tls_session);
            connection->tls_session = NULL;
            cib_tls_close(cib);
            return -1;
        }
    }

    /* Now that the handshake is done, see if any client TLS certificate is
     * close to its expiration date and log if so.  If a TLS certificate is not
     * in use, this function will just return so we don't need to check for the
     * session type here.
     */
    pcmk__tls_check_cert_expiration(connection->tls_session);

    /* login to server */
    login = pcmk__xe_create(NULL, PCMK__XE_CIB_COMMAND);
    pcmk__xe_set(login, PCMK_XA_OP, "authenticate");
    pcmk__xe_set(login, PCMK_XA_USER, private->user);
    pcmk__xe_set(login, PCMK__XA_PASSWORD, private->passwd);
    pcmk__xe_set(login, PCMK__XA_HIDDEN, PCMK__VALUE_PASSWORD);

    pcmk__remote_send_xml(connection, login);
    pcmk__xml_free(login);

    rc = pcmk_ok;
    if (pcmk__read_remote_message(connection, -1) == ENOTCONN) {
        rc = -ENOTCONN;
    }

    answer = pcmk__remote_message_xml(connection);

    pcmk__log_xml_trace(answer, "Reply");
    if (answer == NULL) {
        rc = -EPROTO;

    } else {
        /* grab the token */
        const char *msg_type = pcmk__xe_get(answer, PCMK__XA_CIB_OP);
        const char *tmp_ticket = pcmk__xe_get(answer, PCMK__XA_CIB_CLIENTID);

        if (!pcmk__str_eq(msg_type, CRM_OP_REGISTER, pcmk__str_casei)) {
            pcmk__err("Invalid registration message: %s", msg_type);
            rc = -EPROTO;

        } else if (tmp_ticket == NULL) {
            rc = -EPROTO;

        } else {
            connection->token = strdup(tmp_ticket);
        }
    }
    pcmk__xml_free(answer);
    answer = NULL;

    if (rc != 0) {
        cib_tls_close(cib);
        return rc;
    }

    pcmk__trace("remote client connection established");
    private->timeout_sec = 60;
    connection->source = mainloop_add_fd("cib-remote", G_PRIORITY_HIGH,
                                         connection->tcp_socket, cib,
                                         &cib_fd_callbacks);
    return rc;
}

static int
cib_remote_signon(cib_t *cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    cib_remote_opaque_t *private = cib->variant_opaque;

    if (name == NULL) {
        name = pcmk__s(crm_system_name, "client");
    }

    if (private->passwd == NULL) {
        if (private->out == NULL) {
            /* If no pcmk__output_t is set, just assume that a text prompt
             * is good enough.
             */
            pcmk__text_prompt("Password", false, &(private->passwd));
        } else {
            private->out->prompt("Password", false, &(private->passwd));
        }
    }

    if (private->server == NULL || private->user == NULL) {
        rc = -EINVAL;
        goto done;
    }

    rc = cib_tls_signon(cib, &(private->command), FALSE);
    if (rc != pcmk_ok) {
        goto done;
    }

    rc = cib_tls_signon(cib, &(private->callback), TRUE);

done:
    if (rc == pcmk_ok) {
        pcmk__info("Opened connection to %s:%d for %s", private->server,
                   private->port, name);
        cib->state = cib_connected_command;
        cib->type = cib_command;

    } else {
        pcmk__info("Connection to %s:%d for %s failed: %s\n", private->server,
                   private->port, name, pcmk_strerror(rc));
    }

    return rc;
}

static int
cib_remote_signoff(cib_t *cib)
{
    int rc = pcmk_ok;

    pcmk__debug("Disconnecting from the CIB manager");
    cib_tls_close(cib);

    cib->cmds->end_transaction(cib, false, cib_none);
    cib->state = cib_disconnected;
    cib->type = cib_no_connection;

    return rc;
}

static int
cib_remote_free(cib_t *cib)
{
    int rc = pcmk_ok;

    pcmk__warn("Freeing CIB");
    if (cib->state != cib_disconnected) {
        rc = cib_remote_signoff(cib);
        if (rc == pcmk_ok) {
            cib_remote_opaque_t *private = cib->variant_opaque;

            free(private->server);
            free(private->user);
            free(private->passwd);
            free(cib->cmds);
            free(cib->user);
            free(private);
            free(cib);
        }
    }

    return rc;
}

static int
cib_remote_register_notification(cib_t * cib, const char *callback, int enabled)
{
    xmlNode *notify_msg = pcmk__xe_create(NULL, PCMK__XE_CIB_COMMAND);
    cib_remote_opaque_t *private = cib->variant_opaque;

    pcmk__xe_set(notify_msg, PCMK__XA_CIB_OP, PCMK__VALUE_CIB_NOTIFY);
    pcmk__xe_set(notify_msg, PCMK__XA_CIB_NOTIFY_TYPE, callback);
    pcmk__xe_set_int(notify_msg, PCMK__XA_CIB_NOTIFY_ACTIVATE, enabled);
    pcmk__remote_send_xml(&private->callback, notify_msg);
    pcmk__xml_free(notify_msg);
    return pcmk_ok;
}

static int
cib_remote_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data))
{
    return -EPROTONOSUPPORT;
}

/*!
 * \internal
 * \brief Get the given CIB connection's unique client identifiers
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
 * \note This is the \p cib_remote variant implementation of
 *       \p cib_api_operations_t:client_id().
 * \note The client IDs are assigned during CIB sign-on.
 */
static int
cib_remote_client_id(const cib_t *cib, const char **async_id,
                     const char **sync_id)
{
    cib_remote_opaque_t *private = cib->variant_opaque;

    if (async_id != NULL) {
        // private->callback is the channel for async requests
        *async_id = private->callback.token;
    }
    if (sync_id != NULL) {
        // private->command is the channel for sync requests
        *sync_id = private->command.token;
    }
    return pcmk_ok;
}

cib_t *
cib_remote_new(const char *server, const char *user, const char *passwd, int port,
               gboolean encrypted)
{
    cib_remote_opaque_t *private = NULL;
    cib_t *cib = cib_new_variant();

    if (cib == NULL) {
        return NULL;
    }

    private = calloc(1, sizeof(cib_remote_opaque_t));

    if (private == NULL) {
        free(cib);
        return NULL;
    }

    cib->variant = cib_remote;
    cib->variant_opaque = private;

    private->server = pcmk__str_copy(server);
    private->user = pcmk__str_copy(user);
    private->passwd = pcmk__str_copy(passwd);
    private->port = port;
    private->encrypted = encrypted;

    /* assign variant specific ops */
    cib->delegate_fn = cib_remote_perform_op;
    cib->cmds->signon = cib_remote_signon;
    cib->cmds->signoff = cib_remote_signoff;
    cib->cmds->free = cib_remote_free;
    cib->cmds->register_notification = cib_remote_register_notification;
    cib->cmds->set_connection_dnotify = cib_remote_set_connection_dnotify;

    cib->cmds->client_id = cib_remote_client_id;

    return cib;
}

void
cib__set_output(cib_t *cib, pcmk__output_t *out)
{
    cib_remote_opaque_t *private;

    if (cib->variant != cib_remote) {
        return;
    }

    private = cib->variant_opaque;
    private->out = out;
}
