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

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/mainloop.h>

#include <lrmd_private.h>

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#ifdef HAVE_GNUTLS_GNUTLS_H
#define LRMD_REMOTE_AUTH_TIMEOUT 3000
gnutls_psk_server_credentials_t psk_cred_s;
gnutls_dh_params_t dh_params;
static int ssock = 0;
extern int lrmd_call_id;

static void
debug_log(int level, const char *str)
{
    fputs(str, stderr);
}

static int
lrmd_remote_client_msg(gpointer data)
{
    int id = 0;
    int rc = 0;
    int disconnected = 0;
    xmlNode *request = NULL;
    crm_client_t *client = data;

    if (client->handshake_complete == FALSE) {
        int rc = 0;

        /* Muliple calls to handshake will be required, this callback
         * will be invoked once the client sends more handshake data. */
        do {
            rc = gnutls_handshake(*client->session);

            if (rc < 0 && rc != GNUTLS_E_AGAIN) {
                crm_err("Remote lrmd tls handshake failed");
                return -1;
            }
        } while (rc == GNUTLS_E_INTERRUPTED);

        if (rc == 0) {
            crm_debug("Remote lrmd tls handshake completed");
            client->handshake_complete = TRUE;
            if (client->remote_auth_timeout) {
                g_source_remove(client->remote_auth_timeout);
            }
            client->remote_auth_timeout = 0;
        }
        return 0;
    }

    rc = crm_recv_remote_ready(client->session, TRUE, 0);
    if (rc == 0) {
        /* no msg to read */
        return 0;
    } else if (rc < 0) {
        crm_info("Client disconnected during remote client read");
        return -1;
    }

    crm_recv_remote_msg(client->session, &client->recv_buf, TRUE, -1, &disconnected);

    request = crm_parse_remote_buffer(&client->recv_buf);
	while (request) {
        crm_element_value_int(request, F_LRMD_REMOTE_MSG_ID, &id);
        crm_trace("processing request from remote client with remote msg id %d", id);
        if (!client->name) {
            const char *value = crm_element_value(request, F_LRMD_CLIENTNAME);
            if (value) {
                client->name = strdup(value);
            }
        }

        lrmd_call_id++;
        if (lrmd_call_id < 1) {
            lrmd_call_id = 1;
        }

        crm_xml_add(request, F_LRMD_CLIENTID, client->id);
        crm_xml_add(request, F_LRMD_CLIENTNAME, client->name);
        crm_xml_add_int(request, F_LRMD_CALLID, lrmd_call_id);

        process_lrmd_message(client, id, request);
        free_xml(request);

        /* process all the messages in the current buffer */
        request = crm_parse_remote_buffer(&client->recv_buf);
    }

    if (disconnected) {
        crm_info("Client disconnect detected in tls msg dispatcher.");
        return -1;
    }

    return 0;
}

static void
lrmd_remote_client_destroy(gpointer user_data)
{
    crm_client_t *client = user_data;

    if (client == NULL) {
        return;
    }

    client_disconnect_cleanup(client->id);

    crm_notice("LRMD client disconnecting remote client - name: %s id: %s",
        client->name ? client->name : "<unknown>",
        client->id);

    if (client->session) {
        void *sock_ptr;
        int csock;
        sock_ptr = gnutls_transport_get_ptr(*client->session);
        csock = GPOINTER_TO_INT(sock_ptr);

        gnutls_bye(*client->session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(*client->session);
        gnutls_free(client->session);
        close(csock);
    }

    crm_client_destroy(client);

    return;
}

static gboolean
lrmd_auth_timeout_cb(gpointer data)
{
    crm_client_t *client = data;

    client->remote_auth_timeout = 0;

    if (client->handshake_complete == TRUE) {
        return FALSE;
    }

    mainloop_del_fd(client->remote);
    client->remote = NULL;
    crm_err("Remote client authentication timed out");

    return FALSE;
}

static int
lrmd_remote_listen(gpointer data)
{
    int csock = 0;
    int flag = 0;
    unsigned laddr;
    struct sockaddr_in addr;
    gnutls_session *session = NULL;
    crm_client_t *new_client = NULL;

    static struct mainloop_fd_callbacks lrmd_remote_fd_cb =
        {
            .dispatch = lrmd_remote_client_msg,
            .destroy = lrmd_remote_client_destroy,
        };

    /* accept the connection */
    laddr = sizeof(addr);
    csock = accept(ssock, (struct sockaddr *)&addr, &laddr);
    crm_debug("New remote connection from %s", inet_ntoa(addr.sin_addr));

    if (csock == -1) {
        crm_err("accept socket failed");
        return TRUE;
    }

    if ((flag = fcntl(csock, F_GETFL)) >= 0) {
        if (fcntl(csock, F_SETFL, flag | O_NONBLOCK) < 0) {
            crm_err( "fcntl() write failed");
            close(csock);
            return TRUE;
        }
    } else {
        crm_err( "fcntl() read failed");
        close(csock);
        return TRUE;
    }

    session = create_psk_tls_session(csock, GNUTLS_SERVER, psk_cred_s);
    if (session == NULL) {
        crm_err("TLS session creation failed");
        close(csock);
        return TRUE;
    }

    new_client = calloc(1, sizeof(crm_client_t));
    new_client->kind = client_type_tls;
    new_client->session = session;
    new_client->id = crm_generate_uuid();
    new_client->remote_auth_timeout = g_timeout_add(LRMD_REMOTE_AUTH_TIMEOUT, lrmd_auth_timeout_cb, new_client);
    crm_notice("LRMD client connection established. %p id: %s", new_client, new_client->id);

    new_client->remote = mainloop_add_fd("lrmd-remote-client", G_PRIORITY_DEFAULT, csock, new_client, &lrmd_remote_fd_cb);
    g_hash_table_insert(client_connections, new_client->id, new_client);

    return TRUE;
}

static void
lrmd_remote_connection_destroy(gpointer user_data)
{
    crm_notice("Remote tls server disconnected");
    return;
}

static int
lrmd_tls_server_key_cb(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
    int rc = 0;

    if (lrmd_tls_set_key(key, DEFAULT_REMOTE_KEY_LOCATION)) {
        rc = lrmd_tls_set_key(key, ALT_REMOTE_KEY_LOCATION);
    }
    if (rc) {
        crm_err("No lrmd remote key found");
        return -1;
    }

    return rc;
}

int
lrmd_init_remote_tls_server(int port)
{
    int rc;
    struct sockaddr_in saddr;
    int optval;
    static struct mainloop_fd_callbacks remote_listen_fd_callbacks =
        {
            .dispatch = lrmd_remote_listen,
            .destroy = lrmd_remote_connection_destroy,
        };

    crm_notice("Starting a tls listener on port %d.", port);
    gnutls_global_init();
    gnutls_global_set_log_function(debug_log);

    gnutls_dh_params_init(&dh_params);
    gnutls_dh_params_generate2(dh_params, 1024);
    gnutls_psk_allocate_server_credentials(&psk_cred_s);
    gnutls_psk_set_server_credentials_function(psk_cred_s, lrmd_tls_server_key_cb);
    gnutls_psk_set_server_dh_params(psk_cred_s, dh_params);

    /* create server socket */
    ssock = socket(AF_INET, SOCK_STREAM, 0);
    if (ssock == -1) {
        crm_err("Can not create server socket.");
        return -1;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if(rc < 0) {
        crm_perror(LOG_INFO, "Couldn't allow the reuse of local addresses by our remote listener");
    }

    rc = -1;

    /* bind server socket */
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    if (bind(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        crm_err("Can not bind server socket.");
        goto init_remote_cleanup;
    }

    if (listen(ssock, 10) == -1) {
        crm_err("Can not start listen.");
        goto init_remote_cleanup;
    }

    mainloop_add_fd("lrmd-remote", G_PRIORITY_DEFAULT, ssock, NULL, &remote_listen_fd_callbacks);

    rc = ssock;
init_remote_cleanup:
    if (rc < 0) {
        close(ssock);
        ssock = 0;
    }
    return rc;

}

void
lrmd_tls_server_destroy(void)
{
    if (psk_cred_s) {
        gnutls_psk_free_server_credentials(psk_cred_s);
        psk_cred_s = 0;
    }

    if (ssock > 0) {
        close(ssock);
        ssock = 0;
    }
}
#endif
