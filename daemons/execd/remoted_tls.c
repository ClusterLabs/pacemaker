/*
 * Copyright 2012-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/remote_internal.h>
#include <crm/lrmd_internal.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "pacemaker-execd.h"

#ifdef HAVE_GNUTLS_GNUTLS_H

#  include <gnutls/gnutls.h>

#  define LRMD_REMOTE_AUTH_TIMEOUT 10000
gnutls_psk_server_credentials_t psk_cred_s;
gnutls_dh_params_t dh_params;
static int ssock = -1;
extern int lrmd_call_id;

static void
debug_log(int level, const char *str)
{
    fputs(str, stderr);
}

/*!
 * \internal
 * \brief Read (more) TLS handshake data from client
 */
static int
remoted__read_handshake_data(pcmk__client_t *client)
{
    int rc = pcmk__read_handshake_data(client);

    if (rc == EAGAIN) {
        /* No more data is available at the moment. Just return for now;
         * we'll get invoked again once the client sends more.
         */
        return 0;
    } else if (rc != pcmk_rc_ok) {
        return -1;
    }

    if (client->remote->auth_timeout) {
        g_source_remove(client->remote->auth_timeout);
    }
    client->remote->auth_timeout = 0;

    client->remote->tls_handshake_complete = TRUE;
    crm_notice("Remote client connection accepted");

    /* Only a client with access to the TLS key can connect, so we can treat
     * it as privileged.
     */
    pcmk__set_client_flags(client, pcmk__client_privileged);

    // Alert other clients of the new connection
    notify_of_new_client(client);
    return 0;
}

static int
lrmd_remote_client_msg(gpointer data)
{
    int id = 0;
    int rc;
    xmlNode *request = NULL;
    pcmk__client_t *client = data;

    if (client->remote->tls_handshake_complete == FALSE) {
        return remoted__read_handshake_data(client);
    }

    switch (pcmk__remote_ready(client->remote, 0)) {
        case pcmk_rc_ok:
            break;
        case ETIME: // No message available to read
            return 0;
        default:    // Error
            crm_info("Remote client disconnected while polling it");
            return -1;
    }

    rc = pcmk__read_remote_message(client->remote, -1);

    request = pcmk__remote_message_xml(client->remote);
    while (request) {
        crm_element_value_int(request, F_LRMD_REMOTE_MSG_ID, &id);
        crm_trace("Processing remote client request %d", id);
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
        request = pcmk__remote_message_xml(client->remote);
    }

    if (rc == ENOTCONN) {
        crm_info("Remote client disconnected while reading from it");
        return -1;
    }

    return 0;
}

static void
lrmd_remote_client_destroy(gpointer user_data)
{
    pcmk__client_t *client = user_data;

    if (client == NULL) {
        return;
    }

    crm_notice("Cleaning up after remote client %s disconnected",
               pcmk__client_name(client));

    ipc_proxy_remove_provider(client);

    /* if this is the last remote connection, stop recurring
     * operations */
    if (pcmk__ipc_client_count() == 1) {
        client_disconnect_cleanup(NULL);
    }

    if (client->remote->tls_session) {
        void *sock_ptr;
        int csock;

        sock_ptr = gnutls_transport_get_ptr(*client->remote->tls_session);
        csock = GPOINTER_TO_INT(sock_ptr);

        gnutls_bye(*client->remote->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(*client->remote->tls_session);
        gnutls_free(client->remote->tls_session);
        close(csock);
    }

    lrmd_client_destroy(client);
    return;
}

static gboolean
lrmd_auth_timeout_cb(gpointer data)
{
    pcmk__client_t *client = data;

    client->remote->auth_timeout = 0;

    if (client->remote->tls_handshake_complete == TRUE) {
        return FALSE;
    }

    mainloop_del_fd(client->remote->source);
    client->remote->source = NULL;
    crm_err("Remote client authentication timed out");

    return FALSE;
}

// Dispatch callback for remote server socket
static int
lrmd_remote_listen(gpointer data)
{
    int csock = -1;
    gnutls_session_t *session = NULL;
    pcmk__client_t *new_client = NULL;

    // For client socket
    static struct mainloop_fd_callbacks lrmd_remote_fd_cb = {
        .dispatch = lrmd_remote_client_msg,
        .destroy = lrmd_remote_client_destroy,
    };

    CRM_CHECK(ssock >= 0, return TRUE);

    if (pcmk__accept_remote_connection(ssock, &csock) != pcmk_rc_ok) {
        return TRUE;
    }

    session = pcmk__new_tls_session(csock, GNUTLS_SERVER, GNUTLS_CRD_PSK,
                                    psk_cred_s);
    if (session == NULL) {
        close(csock);
        return TRUE;
    }

    new_client = pcmk__new_unauth_client(NULL);
    new_client->remote = calloc(1, sizeof(pcmk__remote_t));
    pcmk__set_client_flags(new_client, pcmk__client_tls);
    new_client->remote->tls_session = session;

    // Require the client to authenticate within this time
    new_client->remote->auth_timeout = g_timeout_add(LRMD_REMOTE_AUTH_TIMEOUT,
                                                     lrmd_auth_timeout_cb,
                                                     new_client);
    crm_info("Remote client pending authentication "
             CRM_XS " %p id: %s", new_client, new_client->id);

    new_client->remote->source =
        mainloop_add_fd("pacemaker-remote-client", G_PRIORITY_DEFAULT, csock,
                        new_client, &lrmd_remote_fd_cb);
    return TRUE;
}

static void
tls_server_dropped(gpointer user_data)
{
    crm_notice("TLS server session ended");
    /* If we are in the process of shutting down, then we should actually exit.
     * bz#1804259
     */
    execd_exit_if_shutting_down();
    return;
}

// \return 0 on success, -1 on error (gnutls_psk_server_credentials_function)
static int
lrmd_tls_server_key_cb(gnutls_session_t session, const char *username, gnutls_datum_t * key)
{
    return (lrmd__init_remote_key(key) == pcmk_rc_ok)? 0 : -1;
}

static int
bind_and_listen(struct addrinfo *addr)
{
    int optval;
    int fd;
    int rc;
    char buffer[INET6_ADDRSTRLEN] = { 0, };

    pcmk__sockaddr2str(addr->ai_addr, buffer);
    crm_trace("Attempting to bind to address %s", buffer);

    fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (fd < 0) {
        crm_perror(LOG_ERR, "Listener socket creation failed");
        return -1;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (rc < 0) {
        crm_perror(LOG_ERR, "Local address reuse not allowed on %s", buffer);
        close(fd);
        return -1;
    }

    if (addr->ai_family == AF_INET6) {
        optval = 0;
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));
        if (rc < 0) {
            crm_perror(LOG_INFO, "Couldn't disable IPV6-only on %s", buffer);
            close(fd);
            return -1;
        }
    }

    if (bind(fd, addr->ai_addr, addr->ai_addrlen) != 0) {
        crm_perror(LOG_ERR, "Cannot bind to %s", buffer);
        close(fd);
        return -1;
    }

    if (listen(fd, 10) == -1) {
        crm_perror(LOG_ERR, "Cannot listen on %s", buffer);
        close(fd);
        return -1;
    }
    return fd;
}

static int
get_address_info(const char *bind_name, int port, struct addrinfo **res)
{
    int rc;
    char port_str[6]; // at most "65535"
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC; // IPv6 or IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%d", port);
    rc = getaddrinfo(bind_name, port_str, &hints, res);
    if (rc) {
        crm_err("Unable to get IP address(es) for %s: %s",
                (bind_name? bind_name : "local node"), gai_strerror(rc));
        return -EADDRNOTAVAIL;
    }
    return pcmk_ok;
}

int
lrmd_init_remote_tls_server()
{
    int filter;
    int port = crm_default_remote_port();
    struct addrinfo *res = NULL, *iter;
    gnutls_datum_t psk_key = { NULL, 0 };
    const char *bind_name = getenv("PCMK_remote_address");

    static struct mainloop_fd_callbacks remote_listen_fd_callbacks = {
        .dispatch = lrmd_remote_listen,
        .destroy = tls_server_dropped,
    };

    CRM_CHECK(ssock == -1, return ssock);

    crm_debug("Starting TLS listener on %s port %d",
              (bind_name? bind_name : "all addresses on"), port);
    crm_gnutls_global_init();
    gnutls_global_set_log_function(debug_log);

    if (pcmk__init_tls_dh(&dh_params) != pcmk_rc_ok) {
        return -1;
    }
    gnutls_psk_allocate_server_credentials(&psk_cred_s);
    gnutls_psk_set_server_credentials_function(psk_cred_s, lrmd_tls_server_key_cb);
    gnutls_psk_set_server_dh_params(psk_cred_s, dh_params);

    /* The key callback won't get called until the first client connection
     * attempt. Do it once here, so we can warn the user at start-up if we can't
     * read the key. We don't error out, though, because it's fine if the key is
     * going to be added later.
     */
    if (lrmd__init_remote_key(&psk_key) != pcmk_rc_ok) {
        crm_warn("A cluster connection will not be possible until the key is available");
    }
    gnutls_free(psk_key.data);

    if (get_address_info(bind_name, port, &res) != pcmk_ok) {
        return -1;
    }

    /* Currently we listen on only one address from the resulting list (the
     * first IPv6 address we can bind to if possible, otherwise the first IPv4
     * address we can bind to). When bind_name is NULL, this should be the
     * respective wildcard address.
     *
     * @TODO If there is demand for specifying more than one address, allow
     * bind_name to be a space-separated list, call getaddrinfo() for each,
     * and create a socket for each result (set IPV6_V6ONLY on IPv6 sockets
     * since IPv4 listeners will have their own sockets).
     */
    iter = res;
    filter = AF_INET6;
    while (iter) {
        if (iter->ai_family == filter) {
            ssock = bind_and_listen(iter);
        }
        if (ssock != -1) {
            break;
        }

        iter = iter->ai_next;
        if (iter == NULL && filter == AF_INET6) {
            iter = res;
            filter = AF_INET;
        }
    }

    if (ssock >= 0) {
        mainloop_add_fd("pacemaker-remote-server", G_PRIORITY_DEFAULT, ssock,
                        NULL, &remote_listen_fd_callbacks);
        crm_debug("Started TLS listener on %s port %d",
                  (bind_name? bind_name : "all addresses on"), port);
    }
    freeaddrinfo(res);
    return ssock;
}

void
execd_stop_tls_server(void)
{
    if (psk_cred_s) {
        gnutls_psk_free_server_credentials(psk_cred_s);
        psk_cred_s = 0;
    }

    if (ssock >= 0) {
        close(ssock);
        ssock = -1;
    }
}
#endif
