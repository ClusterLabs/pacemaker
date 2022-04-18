/*
 * Copyright 2008-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <netdb.h>
#include <termios.h>
#include <sys/socket.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/remote_internal.h>
#include <crm/common/output_internal.h>

#ifdef HAVE_GNUTLS_GNUTLS_H

#  include <gnutls/gnutls.h>

#  define TLS_HANDSHAKE_TIMEOUT_MS 5000

static gnutls_anon_client_credentials_t anon_cred_c;
static gboolean remote_gnutls_credentials_init = FALSE;

#else

typedef void gnutls_session_t;

#endif // HAVE_GNUTLS_GNUTLS_H

#include <arpa/inet.h>

#define DH_BITS 1024

typedef struct cib_remote_opaque_s {
    int flags;
    int socket;
    int port;
    char *server;
    char *user;
    char *passwd;
    gboolean encrypted;
    pcmk__remote_t command;
    pcmk__remote_t callback;
    pcmk__output_t *out;

} cib_remote_opaque_t;

void cib_remote_connection_destroy(gpointer user_data);
int cib_remote_callback_dispatch(gpointer user_data);
int cib_remote_command_dispatch(gpointer user_data);
int cib_remote_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_remote_signoff(cib_t * cib);
int cib_remote_free(cib_t * cib);

int cib_remote_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                          xmlNode * data, xmlNode ** output_data, int call_options,
                          const char *name);

static int
cib_remote_inputfd(cib_t * cib)
{
    cib_remote_opaque_t *private = cib->variant_opaque;

    return private->callback.tcp_socket;
}

static int
cib_remote_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data))
{
    return -EPROTONOSUPPORT;
}

static int
cib_remote_register_notification(cib_t * cib, const char *callback, int enabled)
{
    xmlNode *notify_msg = create_xml_node(NULL, "cib_command");
    cib_remote_opaque_t *private = cib->variant_opaque;

    crm_xml_add(notify_msg, F_CIB_OPERATION, T_CIB_NOTIFY);
    crm_xml_add(notify_msg, F_CIB_NOTIFY_TYPE, callback);
    crm_xml_add_int(notify_msg, F_CIB_NOTIFY_ACTIVATE, enabled);
    pcmk__remote_send_xml(&private->callback, notify_msg);
    free_xml(notify_msg);
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

    pcmk__str_update(&private->server, server);
    pcmk__str_update(&private->user, user);
    pcmk__str_update(&private->passwd, passwd);

    private->port = port;
    private->encrypted = encrypted;

    /* assign variant specific ops */
    cib->delegate_fn = cib_remote_perform_op;
    cib->cmds->signon = cib_remote_signon;
    cib->cmds->signoff = cib_remote_signoff;
    cib->cmds->free = cib_remote_free;
    cib->cmds->inputfd = cib_remote_inputfd;

    cib->cmds->register_notification = cib_remote_register_notification;
    cib->cmds->set_connection_dnotify = cib_remote_set_connection_dnotify;

    return cib;
}

static int
cib_tls_close(cib_t * cib)
{
    cib_remote_opaque_t *private = cib->variant_opaque;

#ifdef HAVE_GNUTLS_GNUTLS_H
    if (private->encrypted) {
        if (private->command.tls_session) {
            gnutls_bye(*(private->command.tls_session), GNUTLS_SHUT_RDWR);
            gnutls_deinit(*(private->command.tls_session));
            gnutls_free(private->command.tls_session);
        }

        if (private->callback.tls_session) {
            gnutls_bye(*(private->callback.tls_session), GNUTLS_SHUT_RDWR);
            gnutls_deinit(*(private->callback.tls_session));
            gnutls_free(private->callback.tls_session);
        }
        private->command.tls_session = NULL;
        private->callback.tls_session = NULL;
        if (remote_gnutls_credentials_init) {
            gnutls_anon_free_client_credentials(anon_cred_c);
            gnutls_global_deinit();
            remote_gnutls_credentials_init = FALSE;
        }
    }
#endif

    if (private->command.tcp_socket) {
        shutdown(private->command.tcp_socket, SHUT_RDWR);       /* no more receptions */
        close(private->command.tcp_socket);
    }
    if (private->callback.tcp_socket) {
        shutdown(private->callback.tcp_socket, SHUT_RDWR);      /* no more receptions */
        close(private->callback.tcp_socket);
    }
    private->command.tcp_socket = 0;
    private->callback.tcp_socket = 0;

    free(private->command.buffer);
    free(private->callback.buffer);
    private->command.buffer = NULL;
    private->callback.buffer = NULL;

    return 0;
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
#ifdef HAVE_GNUTLS_GNUTLS_H
    connection->tls_session = NULL;
#endif
    rc = pcmk__connect_remote(private->server, private->port, 0, NULL,
                              &(connection->tcp_socket), NULL, NULL);
    if (rc != pcmk_rc_ok) {
        crm_info("Remote connection to %s:%d failed: %s " CRM_XS " rc=%d",
                 private->server, private->port, pcmk_rc_str(rc), rc);
        return -ENOTCONN;
    }

    if (private->encrypted) {
        /* initialize GnuTls lib */
#ifdef HAVE_GNUTLS_GNUTLS_H
        if (remote_gnutls_credentials_init == FALSE) {
            crm_gnutls_global_init();
            gnutls_anon_allocate_client_credentials(&anon_cred_c);
            remote_gnutls_credentials_init = TRUE;
        }

        /* bind the socket to GnuTls lib */
        connection->tls_session = pcmk__new_tls_session(connection->tcp_socket,
                                                        GNUTLS_CLIENT,
                                                        GNUTLS_CRD_ANON,
                                                        anon_cred_c);
        if (connection->tls_session == NULL) {
            cib_tls_close(cib);
            return -1;
        }

        if (pcmk__tls_client_handshake(connection, TLS_HANDSHAKE_TIMEOUT_MS)
                != pcmk_rc_ok) {
            crm_err("Session creation for %s:%d failed", private->server, private->port);

            gnutls_deinit(*connection->tls_session);
            gnutls_free(connection->tls_session);
            connection->tls_session = NULL;
            cib_tls_close(cib);
            return -1;
        }
#else
        return -EPROTONOSUPPORT;
#endif
    }

    /* login to server */
    login = create_xml_node(NULL, "cib_command");
    crm_xml_add(login, "op", "authenticate");
    crm_xml_add(login, "user", private->user);
    crm_xml_add(login, "password", private->passwd);
    crm_xml_add(login, "hidden", "password");

    pcmk__remote_send_xml(connection, login);
    free_xml(login);

    rc = pcmk_ok;
    if (pcmk__read_remote_message(connection, -1) == ENOTCONN) {
        rc = -ENOTCONN;
    }

    answer = pcmk__remote_message_xml(connection);

    crm_log_xml_trace(answer, "Reply");
    if (answer == NULL) {
        rc = -EPROTO;

    } else {
        /* grab the token */
        const char *msg_type = crm_element_value(answer, F_CIB_OPERATION);
        const char *tmp_ticket = crm_element_value(answer, F_CIB_CLIENTID);

        if (!pcmk__str_eq(msg_type, CRM_OP_REGISTER, pcmk__str_casei)) {
            crm_err("Invalid registration message: %s", msg_type);
            rc = -EPROTO;

        } else if (tmp_ticket == NULL) {
            rc = -EPROTO;

        } else {
            connection->token = strdup(tmp_ticket);
        }
    }
    free_xml(answer);
    answer = NULL;

    if (rc != 0) {
        cib_tls_close(cib);
        return rc;
    }

    crm_trace("remote client connection established");
    connection->source = mainloop_add_fd("cib-remote", G_PRIORITY_HIGH,
                                         connection->tcp_socket, cib,
                                         &cib_fd_callbacks);
    return rc;
}

void
cib_remote_connection_destroy(gpointer user_data)
{
    crm_err("Connection destroyed");
#ifdef HAVE_GNUTLS_GNUTLS_H
    cib_tls_close(user_data);
#endif
    return;
}

int
cib_remote_command_dispatch(gpointer user_data)
{
    int rc;
    cib_t *cib = user_data;
    cib_remote_opaque_t *private = cib->variant_opaque;

    rc = pcmk__read_remote_message(&private->command, -1);

    free(private->command.buffer);
    private->command.buffer = NULL;
    crm_err("received late reply for remote cib connection, discarding");

    if (rc == ENOTCONN) {
        return -1;
    }
    return 0;
}

int
cib_remote_callback_dispatch(gpointer user_data)
{
    int rc;
    cib_t *cib = user_data;
    cib_remote_opaque_t *private = cib->variant_opaque;

    xmlNode *msg = NULL;

    crm_info("Message on callback channel");

    rc = pcmk__read_remote_message(&private->callback, -1);

    msg = pcmk__remote_message_xml(&private->callback);
    while (msg) {
        const char *type = crm_element_value(msg, F_TYPE);

        crm_trace("Activating %s callbacks...", type);

        if (pcmk__str_eq(type, T_CIB, pcmk__str_casei)) {
            cib_native_callback(cib, msg, 0, 0);

        } else if (pcmk__str_eq(type, T_CIB_NOTIFY, pcmk__str_casei)) {
            g_list_foreach(cib->notify_list, cib_native_notify, msg);

        } else {
            crm_err("Unknown message type: %s", type);
        }

        free_xml(msg);
        msg = pcmk__remote_message_xml(&private->callback);
    }

    if (rc == ENOTCONN) {
        return -1;
    }

    return 0;
}

int
cib_remote_signon(cib_t * cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    cib_remote_opaque_t *private = cib->variant_opaque;

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
    }

    if (rc == pcmk_ok) {
        rc = cib_tls_signon(cib, &(private->command), FALSE);
    }

    if (rc == pcmk_ok) {
        rc = cib_tls_signon(cib, &(private->callback), TRUE);
    }

    if (rc == pcmk_ok) {
        xmlNode *hello =
            cib_create_op(0, private->callback.token, CRM_OP_REGISTER, NULL, NULL, NULL, 0, NULL);
        crm_xml_add(hello, F_CIB_CLIENTNAME, name);
        pcmk__remote_send_xml(&private->command, hello);
        free_xml(hello);
    }

    if (rc == pcmk_ok) {
        crm_info("Opened connection to %s:%d for %s",
                 private->server, private->port, name);
        cib->state = cib_connected_command;
        cib->type = cib_command;

    } else {
        crm_info("Connection to %s:%d for %s failed: %s\n",
                 private->server, private->port, name, pcmk_strerror(rc));
    }

    return rc;
}

int
cib_remote_signoff(cib_t * cib)
{
    int rc = pcmk_ok;

    /* cib_remote_opaque_t *private = cib->variant_opaque; */

    crm_debug("Disconnecting from the CIB manager");
#ifdef HAVE_GNUTLS_GNUTLS_H
    cib_tls_close(cib);
#endif

    cib->state = cib_disconnected;
    cib->type = cib_no_connection;

    return rc;
}

int
cib_remote_free(cib_t * cib)
{
    int rc = pcmk_ok;

    crm_warn("Freeing CIB");
    if (cib->state != cib_disconnected) {
        rc = cib_remote_signoff(cib);
        if (rc == pcmk_ok) {
            cib_remote_opaque_t *private = cib->variant_opaque;

            free(private->server);
            free(private->user);
            free(private->passwd);
            free(cib->cmds);
            free(private);
            free(cib);
        }
    }

    return rc;
}

int
cib_remote_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                      xmlNode * data, xmlNode ** output_data, int call_options, const char *name)
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
        crm_err("No operation specified");
        return -EINVAL;
    }

    cib->call_id++;
    if (cib->call_id < 1) {
        cib->call_id = 1;
    }

    op_msg =
        cib_create_op(cib->call_id, private->callback.token, op, host, section, data, call_options,
                      NULL);
    if (op_msg == NULL) {
        return -EPROTO;
    }

    crm_trace("Sending %s message to the CIB manager", op);
    if (!(call_options & cib_sync_call)) {
        pcmk__remote_send_xml(&private->callback, op_msg);
    } else {
        pcmk__remote_send_xml(&private->command, op_msg);
    }
    free_xml(op_msg);

    if ((call_options & cib_discard_reply)) {
        crm_trace("Discarding reply");
        return pcmk_ok;

    } else if (!(call_options & cib_sync_call)) {
        return cib->call_id;
    }

    crm_trace("Waiting for a synchronous reply");

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

        crm_element_value_int(op_reply, F_CIB_CALLID, &reply_id);

        if (reply_id == msg_id) {
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

        /* wasn't the right reply, try and read some more */
        remaining_time = time(NULL) - start_time;
    }

    /* if(IPC_ISRCONN(native->command_channel) == FALSE) { */
    /*      crm_err("The CIB manager disconnected: %d",  */
    /*              native->command_channel->ch_status); */
    /*      cib->state = cib_disconnected; */
    /* } */

    if (rc == ENOTCONN) {
        crm_err("Disconnected while waiting for reply.");
        return -ENOTCONN;
    } else if (op_reply == NULL) {
        crm_err("No reply message - empty");
        return -ENOMSG;
    }

    crm_trace("Synchronous reply received");

    /* Start processing the reply... */
    if (crm_element_value_int(op_reply, F_CIB_RC, &rc) != 0) {
        rc = -EPROTO;
    }

    if (rc == -pcmk_err_diff_resync) {
        /* This is an internal value that clients do not and should not care about */
        rc = pcmk_ok;
    }

    if (rc == pcmk_ok || rc == -EPERM) {
        crm_log_xml_debug(op_reply, "passed");

    } else {
/* 	} else if(rc == -ETIME) { */
        crm_err("Call failed: %s", pcmk_strerror(rc));
        crm_log_xml_warn(op_reply, "failed");
    }

    if (output_data == NULL) {
        /* do nothing more */

    } else if (!(call_options & cib_discard_reply)) {
        xmlNode *tmp = get_message_xml(op_reply, F_CIB_CALLDATA);

        if (tmp == NULL) {
            crm_trace("No output in reply to \"%s\" command %d", op, cib->call_id - 1);
        } else {
            *output_data = copy_xml(tmp);
        }
    }

    free_xml(op_reply);

    return rc;
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
