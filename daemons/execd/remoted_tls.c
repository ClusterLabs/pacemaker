/*
 * Copyright 2012-2025 the Pacemaker project contributors
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
#include <crm/common/mainloop.h>
#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>
#include <crm/common/tls_internal.h>
#include <crm/lrmd_internal.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "pacemaker-execd.h"

#include <gnutls/gnutls.h>

#define LRMD_REMOTE_AUTH_TIMEOUT 10000

static pcmk__tls_t *tls = NULL;
static int ssock = -1;
extern int lrmd_call_id;

/*!
 * \internal
 * \brief Read (more) TLS handshake data from client
 *
 * \param[in,out] client  IPC client doing handshake
 *
 * \return 0 on success or more data needed, -1 on error
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

    pcmk__set_client_flags(client, pcmk__client_tls_handshake_complete);
    crm_notice("Remote client connection accepted");

    /* Now that the handshake is done, see if any client TLS certificate is
     * close to its expiration date and log if so.  If a TLS certificate is not
     * in use, this function will just return so we don't need to check for the
     * session type here.
     */
    pcmk__tls_check_cert_expiration(client->remote->tls_session);

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
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;
    pcmk__client_t *client = data;

    if (!pcmk_is_set(client->flags, pcmk__client_tls_handshake_complete)) {
        return remoted__read_handshake_data(client);
    }

    rc = pcmk__remote_ready(client->remote, 0);
    switch (rc) {
        case pcmk_rc_ok:
            break;

        case ETIME:
            /* No message available to read */
            return 0;

        default:
            /* Error */
            crm_info("Error polling remote client: %s", pcmk_rc_str(rc));
            return -1;
    }

    rc = pcmk__read_available_remote_data(client->remote);
    switch (rc) {
        case pcmk_rc_ok:
            break;

        case EAGAIN:
            /* We haven't read the whole message yet */
            return 0;

        default:
            /* Error */
            crm_info("Error reading from remote client: %s", pcmk_rc_str(rc));
            return -1;
    }

    request = pcmk__remote_message_xml(client->remote);
    if (request == NULL) {
        return 0;
    }

    pcmk__xe_get_int(request, PCMK__XA_LRMD_REMOTE_MSG_ID, &id);
    crm_trace("Processing remote client request %d", id);
    if (!client->name) {
        client->name = pcmk__xe_get_copy(request, PCMK__XA_LRMD_CLIENTNAME);
    }

    lrmd_call_id++;
    if (lrmd_call_id < 1) {
        lrmd_call_id = 1;
    }

    crm_xml_add(request, PCMK__XA_LRMD_CLIENTID, client->id);
    crm_xml_add(request, PCMK__XA_LRMD_CLIENTNAME, client->name);
    crm_xml_add_int(request, PCMK__XA_LRMD_CALLID, lrmd_call_id);

    process_lrmd_message(client, id, request);
    pcmk__xml_free(request);

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
        int csock = pcmk__tls_get_client_sock(client->remote);

        gnutls_bye(client->remote->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(client->remote->tls_session);
        client->remote->tls_session = NULL;
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

    if (pcmk_is_set(client->flags,
                    pcmk__client_tls_handshake_complete)) {
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
    gnutls_session_t session = NULL;
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

    session = pcmk__new_tls_session(tls, csock);
    if (session == NULL) {
        close(csock);
        return TRUE;
    }

    new_client = pcmk__new_unauth_client(NULL);
    new_client->remote = pcmk__assert_alloc(1, sizeof(pcmk__remote_t));
    pcmk__set_client_flags(new_client, pcmk__client_tls);
    new_client->remote->tls_session = session;

    // Require the client to authenticate within this time
    new_client->remote->auth_timeout = pcmk__create_timer(LRMD_REMOTE_AUTH_TIMEOUT,
                                                          lrmd_auth_timeout_cb,
                                                          new_client);
    crm_info("Remote client pending authentication "
             QB_XS " %p id: %s", new_client, new_client->id);

    new_client->remote->source =
        mainloop_add_fd("pacemaker-remote-client", G_PRIORITY_DEFAULT, csock,
                        new_client, &lrmd_remote_fd_cb);
    return TRUE;
}

static void
tls_server_dropped(gpointer user_data)
{
    crm_notice("TLS server session ended");
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
        rc = errno;
        crm_err("Listener socket creation failed: %", pcmk_rc_str(rc));
        return -rc;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (rc < 0) {
        rc = errno;
        crm_err("Local address reuse not allowed on %s: %s", buffer, pcmk_rc_str(rc));
        close(fd);
        return -rc;
    }

    if (addr->ai_family == AF_INET6) {
        optval = 0;
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));
        if (rc < 0) {
            rc = errno;
            crm_err("Couldn't disable IPV6-only on %s: %s", buffer, pcmk_rc_str(rc));
            close(fd);
            return -rc;
        }
    }

    if (bind(fd, addr->ai_addr, addr->ai_addrlen) != 0) {
        rc = errno;
        crm_err("Cannot bind to %s: %s", buffer, pcmk_rc_str(rc));
        close(fd);
        return -rc;
    }

    if (listen(fd, 10) == -1) {
        rc = errno;
        crm_err("Cannot listen on %s: %s", buffer, pcmk_rc_str(rc));
        close(fd);
        return -rc;
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
    rc = pcmk__gaierror2rc(rc);

    if (rc != pcmk_rc_ok) {
        crm_err("Unable to get IP address(es) for %s: %s",
                (bind_name? bind_name : "local node"), pcmk_rc_str(rc));
        return rc;
    }

    return pcmk_rc_ok;
}

int
lrmd_init_remote_tls_server(void)
{
    int rc = pcmk_rc_ok;
    int filter;
    int port = crm_default_remote_port();
    struct addrinfo *res = NULL, *iter;
    const char *bind_name = pcmk__env_option(PCMK__ENV_REMOTE_ADDRESS);
    bool use_cert = pcmk__x509_enabled();

    static struct mainloop_fd_callbacks remote_listen_fd_callbacks = {
        .dispatch = lrmd_remote_listen,
        .destroy = tls_server_dropped,
    };

    CRM_CHECK(ssock == -1, return ssock);

    crm_debug("Starting TLS listener on %s port %d",
              (bind_name? bind_name : "all addresses on"), port);

    rc = pcmk__init_tls(&tls, true, use_cert ? GNUTLS_CRD_CERTIFICATE : GNUTLS_CRD_PSK);
    if (rc != pcmk_rc_ok) {
        return -1;
    }

    if (!use_cert) {
        gnutls_datum_t psk_key = { NULL, 0 };

        pcmk__tls_add_psk_callback(tls, lrmd_tls_server_key_cb);

        /* The key callback won't get called until the first client connection
         * attempt. Do it once here, so we can warn the user at start-up if we can't
         * read the key. We don't error out, though, because it's fine if the key is
         * going to be added later.
         */
        if (lrmd__init_remote_key(&psk_key) != pcmk_rc_ok) {
            crm_warn("A cluster connection will not be possible until the key is available");
        }

        gnutls_free(psk_key.data);
    }

    if (get_address_info(bind_name, port, &res) != pcmk_rc_ok) {
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
        if (ssock >= 0) {
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
    if (tls != NULL) {
        pcmk__free_tls(tls);
        tls = NULL;
    }

    if (ssock >= 0) {
        close(ssock);
        ssock = -1;
    }
}
