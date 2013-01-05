/*
 * Copyright (c) 2008 Andrew Beekhof
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
#include <netdb.h>
#include <termios.h>
#include <sys/socket.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
gnutls_anon_client_credentials anon_cred_c;
#define DEFAULT_CLIENT_HANDSHAKE_TIMEOUT 5000 /* 5 seconds */

const int kx_prio[] = {
    GNUTLS_KX_ANON_DH,
    0
};

static gboolean remote_gnutls_credentials_init = FALSE;
#else
typedef void gnutls_session;
#endif

#include <arpa/inet.h>
#include <sgtty.h>

#define DH_BITS 1024

struct remote_connection_s {
    int socket;
    gboolean encrypted;
    gnutls_session *session;
    mainloop_io_t *source;
    char *token;
    char *recv_buf;
};

typedef struct cib_remote_opaque_s {
    int flags;
    int socket;
    int port;
    char *server;
    char *user;
    char *passwd;
    struct remote_connection_s command;
    struct remote_connection_s callback;

} cib_remote_opaque_t;

void cib_remote_connection_destroy(gpointer user_data);
int cib_remote_callback_dispatch(gpointer user_data);
int cib_remote_command_dispatch(gpointer user_data);
int cib_remote_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_remote_signoff(cib_t * cib);
int cib_remote_free(cib_t * cib);

int cib_remote_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                          xmlNode * data, xmlNode ** output_data, int call_options, const char *name);

static int
cib_remote_inputfd(cib_t * cib)
{
    cib_remote_opaque_t *private = cib->variant_opaque;

    return private->callback.socket;
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
    crm_send_remote_msg(private->callback.session, notify_msg, private->callback.encrypted);
    free_xml(notify_msg);
    return pcmk_ok;
}

cib_t *
cib_remote_new(const char *server, const char *user, const char *passwd, int port,
               gboolean encrypted)
{
    cib_remote_opaque_t *private = NULL;
    cib_t *cib = cib_new_variant();

    private = calloc(1, sizeof(cib_remote_opaque_t));

    cib->variant = cib_remote;
    cib->variant_opaque = private;

    if (server) {
        private->server = strdup(server);
    }

    if (user) {
        private->user = strdup(user);
    }

    if (passwd) {
        private->passwd = strdup(passwd);
    }

    private->port = port;
    private->command.encrypted = encrypted;
    private->callback.encrypted = encrypted;

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
    if (private->command.encrypted) {
        if (private->command.session) {
            gnutls_bye(*(private->command.session), GNUTLS_SHUT_RDWR);
            gnutls_deinit(*(private->command.session));
            gnutls_free(private->command.session);
        }

        if (private->callback.session) {
            gnutls_bye(*(private->callback.session), GNUTLS_SHUT_RDWR);
            gnutls_deinit(*(private->callback.session));
            gnutls_free(private->callback.session);
        }
        private->command.session = NULL;
        private->callback.session = NULL;
        if (remote_gnutls_credentials_init) {
            gnutls_anon_free_client_credentials(anon_cred_c);
            gnutls_global_deinit();
            remote_gnutls_credentials_init = FALSE;
        }
    }
#endif

    if (private->command.socket) {
        shutdown(private->command.socket, SHUT_RDWR);       /* no more receptions */
        close(private->command.socket);
    }
    if (private->callback.socket) {
        shutdown(private->callback.socket, SHUT_RDWR);      /* no more receptions */
        close(private->callback.socket);
    }
    private->command.socket = 0;
    private->callback.socket = 0;

    free(private->command.recv_buf);
    free(private->callback.recv_buf);
    private->command.recv_buf = NULL;
    private->callback.recv_buf = NULL;

    return 0;
}

static int
cib_tls_signon(cib_t * cib, struct remote_connection_s *connection, gboolean event_channel)
{
    int sock;
    cib_remote_opaque_t *private = cib->variant_opaque;
    int rc = 0;

    xmlNode *answer = NULL;
    xmlNode *login = NULL;

    static struct mainloop_fd_callbacks cib_fd_callbacks = { 0, };

    cib_fd_callbacks.dispatch = event_channel ? cib_remote_callback_dispatch : cib_remote_command_dispatch;
    cib_fd_callbacks.destroy = cib_remote_connection_destroy;

    connection->socket = 0;
    connection->session = NULL;

    sock = crm_remote_tcp_connect(private->server, private->port);
    if (sock <= 0) {
        crm_perror(LOG_ERR, "remote tcp connection to %s:%d failed", private->server, private->port);
    }

    connection->socket = sock;
    if (connection->encrypted) {
        /* initialize GnuTls lib */
#ifdef HAVE_GNUTLS_GNUTLS_H
        if (remote_gnutls_credentials_init == FALSE) {
            gnutls_global_init();
            gnutls_anon_allocate_client_credentials(&anon_cred_c);
            remote_gnutls_credentials_init = TRUE;
        }

        /* bind the socket to GnuTls lib */
        connection->session = crm_create_anon_tls_session(sock, GNUTLS_CLIENT, anon_cred_c);

        if (crm_initiate_client_tls_handshake(connection->session, DEFAULT_CLIENT_HANDSHAKE_TIMEOUT) != 0) {
            crm_err("Session creation for %s:%d failed", private->server, private->port);

            gnutls_deinit(*connection->session);
            gnutls_free(connection->session);
            connection->session = NULL;
            cib_tls_close(cib);
            return -1;
        }
#else
        return -EPROTONOSUPPORT;
#endif
    } else {
        connection->session = GUINT_TO_POINTER(sock);
    }

    /* login to server */
    login = create_xml_node(NULL, "cib_command");
    crm_xml_add(login, "op", "authenticate");
    crm_xml_add(login, "user", private->user);
    crm_xml_add(login, "password", private->passwd);
    crm_xml_add(login, "hidden", "password");

    crm_send_remote_msg(connection->session, login, connection->encrypted);
    free_xml(login);

    crm_recv_remote_msg(connection->session, &connection->recv_buf, connection->encrypted, -1, NULL);
    answer = crm_parse_remote_buffer(&connection->recv_buf);

    crm_log_xml_trace(answer, "Reply");
    if (answer == NULL) {
        rc = -EPROTO;

    } else {
        /* grab the token */
        const char *msg_type = crm_element_value(answer, F_CIB_OPERATION);
        const char *tmp_ticket = crm_element_value(answer, F_CIB_CLIENTID);

        if (safe_str_neq(msg_type, CRM_OP_REGISTER)) {
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
    connection->source = mainloop_add_fd("cib-remote", G_PRIORITY_HIGH, connection->socket, cib, &cib_fd_callbacks);
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
    int disconnected = 0;
    cib_t *cib = user_data;
    cib_remote_opaque_t *private = cib->variant_opaque;

    crm_recv_remote_msg(private->command.session, &private->command.recv_buf, private->command.encrypted, -1, &disconnected);

    free(private->command.recv_buf);
    private->command.recv_buf = NULL;
    crm_err("received late reply for remote cib connection, discarding");

    if (disconnected) {
        return -1;
    }
    return 0;
}

int
cib_remote_callback_dispatch(gpointer user_data)
{
    cib_t *cib = user_data;
    cib_remote_opaque_t *private = cib->variant_opaque;

    xmlNode *msg = NULL;
    int disconnected = 0;

    crm_info("Message on callback channel");

    crm_recv_remote_msg(private->callback.session, &private->callback.recv_buf, private->callback.encrypted, -1, &disconnected);

    msg = crm_parse_remote_buffer(&private->callback.recv_buf);
    while (msg) {
        const char *type = crm_element_value(msg, F_TYPE);
        crm_trace("Activating %s callbacks...", type);

        if (safe_str_eq(type, T_CIB)) {
            cib_native_callback(cib, msg, 0, 0);

        } else if (safe_str_eq(type, T_CIB_NOTIFY)) {
            g_list_foreach(cib->notify_list, cib_native_notify, msg);

        } else {
            crm_err("Unknown message type: %s", type);
        }

        free_xml(msg);
        msg = crm_parse_remote_buffer(&private->callback.recv_buf);
    }

    if (disconnected) {
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
        struct termios settings;
        int rc;

        rc = tcgetattr(0, &settings);
        settings.c_lflag &= ~ECHO;
        rc = tcsetattr(0, TCSANOW, &settings);

        fprintf(stderr, "Password: ");
        private->passwd = calloc(1, 1024);
        rc = scanf("%s", private->passwd);
        fprintf(stdout, "\n");
        /* fprintf(stderr, "entered: '%s'\n", buffer); */
        if (rc < 1) {
            private->passwd = NULL;
        }

        settings.c_lflag |= ECHO;
        rc = tcsetattr(0, TCSANOW, &settings);
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
        crm_send_remote_msg(private->command.session, hello, private->command.encrypted);
        free_xml(hello);
    }

    if (rc == pcmk_ok) {
        fprintf(stderr, "%s: Opened connection to %s:%d\n", name, private->server, private->port);
        cib->state = cib_connected_command;
        cib->type = cib_command;

    } else {
        fprintf(stderr, "%s: Connection to %s:%d failed: %s\n",
                name, private->server, private->port, pcmk_strerror(rc));
    }

    return rc;
}

int
cib_remote_signoff(cib_t * cib)
{
    int rc = pcmk_ok;

    /* cib_remote_opaque_t *private = cib->variant_opaque; */

    crm_debug("Signing out of the CIB Service");
#ifdef HAVE_GNUTLS_GNUTLS_H
    cib_tls_close(cib);
#endif

    cib->state = cib_disconnected;
    cib->type = cib_none;

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
    int rc = pcmk_ok;
    int disconnected = 0;
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
    /* prevent call_id from being negative (or zero) and conflicting
     *    with the cib_errors enum
     * use 2 because we use it as (cib->call_id - 1) below
     */
    if (cib->call_id < 1) {
        cib->call_id = 1;
    }

    op_msg =
        cib_create_op(cib->call_id, private->callback.token, op, host, section, data, call_options,
                      NULL);
    if (op_msg == NULL) {
        return -EPROTO;
    }

    crm_trace("Sending %s message to CIB service", op);
    if (!(call_options & cib_sync_call)) {
        crm_send_remote_msg(private->callback.session, op_msg, private->command.encrypted);
    } else {
        crm_send_remote_msg(private->command.session, op_msg, private->command.encrypted);
    }
    free_xml(op_msg);

    if ((call_options & cib_discard_reply)) {
        crm_trace("Discarding reply");
        return pcmk_ok;

    } else if (!(call_options & cib_sync_call)) {
        return cib->call_id;
    }

    crm_trace("Waiting for a syncronous reply");

    start_time = time(NULL);
    remaining_time = cib->call_timeout ? cib->call_timeout : 60;

    while (remaining_time > 0 && !disconnected) {
        int reply_id = -1;
        int msg_id = cib->call_id;

        crm_recv_remote_msg(private->command.session, &private->command.recv_buf, private->command.encrypted, remaining_time * 1000, &disconnected);
        op_reply = crm_parse_remote_buffer(&private->command.recv_buf);

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
    /*      crm_err("CIB disconnected: %d",  */
    /*              native->command_channel->ch_status); */
    /*      cib->state = cib_disconnected; */
    /* } */

    if (disconnected) {
        crm_err("Disconnected while waiting for reply.");
        return -ENOTCONN;
    } else if (op_reply == NULL) {
        crm_err("No reply message - empty");
        return -ENOMSG;
    }

    crm_trace("Syncronous reply received");

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
