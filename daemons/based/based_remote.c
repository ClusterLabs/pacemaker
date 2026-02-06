/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <arpa/inet.h>              // htons
#include <errno.h>                  // errno, EAGAIN
#include <grp.h>                    // getgrgid, getgrnam, group
#include <inttypes.h>               // PRIx64
#include <netinet/in.h>             // sockaddr_in, INADDR_ANY
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdlib.h>                 // calloc, free, getenv
#include <string.h>                 // memset
#include <sys/socket.h>             // sockaddr{,_storage}, AF_INET, etc.
#include <unistd.h>                 // close

#include <glib.h>                   // gboolean, gpointer, g_source_remove, etc.
#include <gnutls/gnutls.h>          // gnutls_bye, gnutls_deinit
#include <libxml/tree.h>            // xmlNode
#include <qb/qblog.h>               // QB_XS

#include <crm_config.h>             // CRM_DAEMON_GROUP
#include <crm/cib/internal.h>       // cib__init_remote_key
#include <crm/common/internal.h>    // pcmk__client_t, etc.
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/results.h>     // pcmk_rc_*
#include <crm/common/xml.h>         // PCMK_XA_*
#include <crm/crm.h>                // CRM_OP_REGISTER

#include "pacemaker-based.h"

#if HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>      // pam_*, PAM_*
#define HAVE_PAM 1
#elif HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>           // pam_*, PAM_*
#define HAVE_PAM 1
#endif

static pcmk__tls_t *tls = NULL;

int remote_fd = 0;
int remote_tls_fd = 0;

// @TODO This is rather short for someone to type their password
#define REMOTE_AUTH_TIMEOUT 10000

/*!
 * \internal
 * \brief Destroy a client if not authenticated after the timeout has expired
 *
 * This is used as a callback that runs \c REMOTE_AUTH_TIMEOUT milliseconds
 * after a new remote CIB client connects.
 *
 * If the client is not authenticated, drop it by removing its source from the
 * mainloop. It will be freed by \c based_remote_client_destroy() via
 * \c remote_client_fd_callbacks.
 *
 * \param[in,out] data  Remote CIB client (\c pcmk__client_t)
 *
 * \return \c G_SOURCE_REMOVE (to destroy the timeout)
 */
static gboolean
remote_auth_timeout_cb(gpointer data)
{
    pcmk__client_t *client = data;

    client->remote->auth_timeout = 0;

    if (pcmk__is_set(client->flags, pcmk__client_authenticated)) {
        return G_SOURCE_REMOVE;
    }

    mainloop_del_fd(client->remote->source);
    pcmk__err("Remote client authentication timed out");
    return G_SOURCE_REMOVE;
}

/*!
 * \internal
 * \brief Check whether a given user is a member of \c CRM_DAEMON_GROUP
 *
 * \param[in] user  User name
 *
 * \return \c true if \p user is a member of \c CRM_DAEMON_GROUP, or \c false
 *         otherwise
 */
static bool
is_daemon_group_member(const char *user)
{
    const struct group *group = getgrnam(CRM_DAEMON_GROUP);

    if (group == NULL) {
        pcmk__err("Rejecting remote client: " CRM_DAEMON_GROUP " is not a "
                  "valid group");
        return false;
    }

    for (const char *const *member = (const char *const *) group->gr_mem;
         *member != NULL; member++) {

        if (pcmk__str_eq(user, *member, pcmk__str_none)) {
            return true;
        }
    }

    pcmk__notice("Rejecting remote client: User %s is not a member of group %s",
                 user, CRM_DAEMON_GROUP);
    return false;
}

#ifdef HAVE_PAM
/*!
 * \internal
 * \brief Pass remote user's password to PAM
 *
 * \param[in]  num_msg   Number of entries in \p msg
 * \param[in]  msg       Array of PAM messages
 * \param[out] response  Where to set response to PAM
 * \param[in]  data      User data (the password string)
 *
 * \return PAM return code (PAM_BUF_ERR for memory errors, PAM_CONV_ERR for all
 *         other errors, or PAM_SUCCESS on success)
 * \note See pam_conv(3) for more explanation
 */
static int
construct_pam_passwd(int num_msg, const struct pam_message **msg,
                     struct pam_response **response, void *data)
{
    /* In theory, multiple messages are allowed, but due to OS compatibility
     * issues, PAM implementations are recommended to only send one message at a
     * time. We can require that here for simplicity.
     */
    CRM_CHECK((num_msg == 1) && (msg != NULL) && (response != NULL)
              && (data != NULL), return PAM_CONV_ERR);

    switch (msg[0]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
            // Password requested
            break;
        case PAM_TEXT_INFO:
            pcmk__info("PAM: %s", msg[0]->msg);
            data = NULL;
            break;
        case PAM_ERROR_MSG:
            /* In theory we should show msg[0]->msg, but that might
             * contain the password, which we don't want in the logs
             */
            pcmk__err("PAM reported an error");
            data = NULL;
            break;
        default:
            pcmk__warn("Ignoring PAM message of unrecognized type %d",
                       msg[0]->msg_style);
            return PAM_CONV_ERR;
    }

    *response = calloc(1, sizeof(struct pam_response));
    if (*response == NULL) {
        return PAM_BUF_ERR;
    }
    (*response)->resp_retcode = 0;
    (*response)->resp = pcmk__str_copy((const char *) data); // Caller will free
    return PAM_SUCCESS;
}
#endif

/*!
 * \internal
 * \brief Verify the username and password passed for a remote CIB connection
 *
 * \param[in] user    Username passed for remote CIB connection
 * \param[in] passwd  Password passed for remote CIB connection
 *
 * \return \c true if the username and password are accepted, otherwise \c false
 * \note This function rejects all credentials when built without PAM support.
 */
static bool
authenticate_user(const char *user, const char *passwd)
{
#ifdef HAVE_PAM
    int rc = 0;
    bool pass = false;
    const void *p_user = NULL;
    struct pam_conv p_conv;
    struct pam_handle *pam_h = NULL;

    static const char *pam_name = NULL;

    if (pam_name == NULL) {
        pam_name = getenv("CIB_pam_service");
        if (pam_name == NULL) {
            pam_name = "login";
        }
    }

    p_conv.conv = construct_pam_passwd;
    p_conv.appdata_ptr = (void *) passwd;

    rc = pam_start(pam_name, user, &p_conv, &pam_h);
    if (rc != PAM_SUCCESS) {
        pcmk__warn("Rejecting remote client for user %s because PAM "
                   "initialization failed: %s",
                   user, pam_strerror(pam_h, rc));
        goto bail;
    }

    // Check user credentials
    rc = pam_authenticate(pam_h, PAM_SILENT);
    if (rc != PAM_SUCCESS) {
        pcmk__notice("Access for remote user %s denied: %s", user,
                     pam_strerror(pam_h, rc));
        goto bail;
    }

    /* Get the authenticated user name (PAM modules can map the original name to
     * something else). Since the CIB manager runs as the daemon user (not
     * root), that is the only user that can be successfully authenticated.
     */
    rc = pam_get_item(pam_h, PAM_USER, &p_user);
    if (rc != PAM_SUCCESS) {
        pcmk__warn("Rejecting remote client for user %s because PAM failed to "
                   "return final user name: %s",
                   user, pam_strerror(pam_h, rc));
        goto bail;
    }
    if (p_user == NULL) {
        pcmk__warn("Rejecting remote client for user %s because PAM returned "
                   "no final user name",
                   user);
        goto bail;
    }

    // @TODO Why do we require these to match?
    if (!pcmk__str_eq(p_user, user, pcmk__str_none)) {
        pcmk__warn("Rejecting remote client for user %s because PAM returned "
                   "different final user name %s",
                   user, p_user);
        goto bail;
    }

    // Check user account restrictions (expiration, etc.)
    rc = pam_acct_mgmt(pam_h, PAM_SILENT);
    if (rc != PAM_SUCCESS) {
        pcmk__notice("Access for remote user %s denied: %s", user,
                     pam_strerror(pam_h, rc));
        goto bail;
    }
    pass = true;

bail:
    pam_end(pam_h, rc);
    return pass;
#else
    // @TODO Implement for non-PAM environments
    pcmk__warn("Rejecting remote user %s because this build does not have PAM "
               "support",
               user);
    return false;
#endif
}

static bool
cib_remote_auth(xmlNode * login)
{
    const char *user = NULL;
    const char *pass = NULL;
    const char *tmp = NULL;

    if (login == NULL) {
        return false;
    }

    if (!pcmk__xe_is(login, PCMK__XE_CIB_COMMAND)) {
        pcmk__warn("Rejecting remote client: Unrecognizable message (element "
                   "'%s' not '" PCMK__XE_CIB_COMMAND "')",
                   login->name);
        pcmk__log_xml_debug(login, "bad");
        return false;
    }

    tmp = pcmk__xe_get(login, PCMK_XA_OP);
    if (!pcmk__str_eq(tmp, "authenticate", pcmk__str_casei)) {
        pcmk__warn("Rejecting remote client: Unrecognizable message (operation "
                   "'%s' not 'authenticate')",
                   tmp);
        pcmk__log_xml_debug(login, "bad");
        return false;
    }

    user = pcmk__xe_get(login, PCMK_XA_USER);
    pass = pcmk__xe_get(login, PCMK__XA_PASSWORD);
    if (!user || !pass) {
        pcmk__warn("Rejecting remote client: No %s given",
                   ((user == NULL)? "username" : "password"));
        pcmk__log_xml_debug(login, "bad");
        return false;
    }

    pcmk__log_xml_debug(login, "auth");

    return is_daemon_group_member(user) && authenticate_user(user, pass);
}

static void
cib_handle_remote_msg(pcmk__client_t *client, xmlNode *command)
{
    int rc = pcmk_rc_ok;
    uint32_t call_options = cib_none;
    const char *op = pcmk__xe_get(command, PCMK__XA_CIB_OP);

    if (!pcmk__xe_is(command, PCMK__XE_CIB_COMMAND)) {
        pcmk__log_xml_trace(command, "bad");
        return;
    }

    if (client->name == NULL) {
        client->name = pcmk__str_copy(client->id);
    }

    /* unset dangerous options */
    pcmk__xe_remove_attr(command, PCMK__XA_SRC);
    pcmk__xe_remove_attr(command, PCMK__XA_CIB_HOST);
    pcmk__xe_remove_attr(command, PCMK__XA_CIB_UPDATE);

    pcmk__xe_set(command, PCMK__XA_T, PCMK__VALUE_CIB);
    pcmk__xe_set(command, PCMK__XA_CIB_CLIENTID, client->id);
    pcmk__xe_set(command, PCMK__XA_CIB_CLIENTNAME, client->name);
    pcmk__xe_set(command, PCMK__XA_CIB_USER, client->user);

    if (pcmk__xe_get(command, PCMK__XA_CIB_CALLID) == NULL) {
        char *call_uuid = pcmk__generate_uuid();

        /* fix the command */
        pcmk__xe_set(command, PCMK__XA_CIB_CALLID, call_uuid);
        free(call_uuid);
    }

    rc = pcmk__xe_get_flags(command, PCMK__XA_CIB_CALLOPT, &call_options,
                            cib_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request from remote client %s: "
                   "%s", client->name, pcmk_rc_str(rc));
        pcmk__log_xml_info(command, "bad-call-opts");
    }

    /* Requests with cib_transaction set should not be sent to based directly
     * (that is, outside of a commit-transaction request)
     */
    if (pcmk__is_set(call_options, cib_transaction)) {
        pcmk__warn("Ignoring CIB request from remote client %s with "
                   "cib_transaction flag set outside of any transaction",
                   client->name);
        pcmk__log_xml_info(command, "no-transaction");
        return;
    }

    pcmk__log_xml_trace(command, "remote-request");

    if (pcmk__str_eq(op, PCMK__VALUE_CIB_NOTIFY, pcmk__str_none)) {
        based_update_notify_flags(command, client);
    }

    based_process_request(command, true, client);
}

static int
cib_remote_msg(gpointer data)
{
    xmlNode *command = NULL;
    pcmk__client_t *client = data;
    int rc;
    const char *client_name = pcmk__client_name(client);

    pcmk__trace("Remote %s message received for client %s",
                pcmk__client_type_str(PCMK__CLIENT_TYPE(client)), client_name);

    if ((PCMK__CLIENT_TYPE(client) == pcmk__client_tls)
        && !pcmk__is_set(client->flags, pcmk__client_tls_handshake_complete)) {

        int rc = pcmk__read_handshake_data(client);

        if (rc == EAGAIN) {
            /* No more data is available at the moment. Just return for now;
             * we'll get invoked again once the client sends more.
             */
            return 0;
        } else if (rc != pcmk_rc_ok) {
            return -1;
        }

        pcmk__debug("Completed TLS handshake with remote client %s",
                    client_name);
        pcmk__set_client_flags(client, pcmk__client_tls_handshake_complete);
        if (client->remote->auth_timeout) {
            g_source_remove(client->remote->auth_timeout);
        }

        /* Now that the handshake is done, see if any client TLS certificate is
         * close to its expiration date and log if so.  If a TLS certificate is not
         * in use, this function will just return so we don't need to check for the
         * session type here.
         */
        pcmk__tls_check_cert_expiration(client->remote->tls_session);

        // Require the client to authenticate within this time
        client->remote->auth_timeout = pcmk__create_timer(REMOTE_AUTH_TIMEOUT,
                                                          remote_auth_timeout_cb,
                                                          client);
        return 0;
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
            pcmk__trace("Error reading from remote client: %s",
                        pcmk_rc_str(rc));
            return -1;
    }

    /* must pass auth before we will process anything else */
    if (!pcmk__is_set(client->flags, pcmk__client_authenticated)) {
        xmlNode *reg;
        const char *user = NULL;

        command = pcmk__remote_message_xml(client->remote);
        if (!cib_remote_auth(command)) {
            pcmk__xml_free(command);
            return -1;
        }

        pcmk__set_client_flags(client, pcmk__client_authenticated);
        g_source_remove(client->remote->auth_timeout);
        client->remote->auth_timeout = 0;
        client->name = pcmk__xe_get_copy(command, PCMK_XA_NAME);

        user = pcmk__xe_get(command, PCMK_XA_USER);
        if (user) {
            client->user = pcmk__str_copy(user);
        }

        pcmk__notice("Remote connection accepted for authenticated user %s "
                     QB_XS " client %s",
                     pcmk__s(user, ""), client_name);

        /* send ACK */
        reg = pcmk__xe_create(NULL, PCMK__XE_CIB_RESULT);
        pcmk__xe_set(reg, PCMK__XA_CIB_OP, CRM_OP_REGISTER);
        pcmk__xe_set(reg, PCMK__XA_CIB_CLIENTID, client->id);
        pcmk__remote_send_xml(client->remote, reg);
        pcmk__xml_free(reg);
        pcmk__xml_free(command);
    }

    command = pcmk__remote_message_xml(client->remote);
    if (command != NULL) {
        pcmk__trace("Remote message received from client %s", client_name);
        cib_handle_remote_msg(client, command);
        pcmk__xml_free(command);
    }

    return 0;
}

static void
based_remote_client_destroy(gpointer user_data)
{
    pcmk__client_t *client = user_data;
    int csock = -1;

    if (client == NULL) {
        return;
    }

    pcmk__trace("Cleaning up after client %s disconnect",
                pcmk__client_name(client));

    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_tcp:
            csock = client->remote->tcp_socket;
            break;
        case pcmk__client_tls:
            if (client->remote->tls_session) {
                csock = pcmk__tls_get_client_sock(client->remote);

                if (pcmk__is_set(client->flags,
                                 pcmk__client_tls_handshake_complete)) {
                    gnutls_bye(client->remote->tls_session, GNUTLS_SHUT_WR);
                }
                gnutls_deinit(client->remote->tls_session);
                client->remote->tls_session = NULL;
            }
            break;
        default:
            pcmk__warn("Unknown transport for client %s "
                       QB_XS " flags=%#016" PRIx64,
                       pcmk__client_name(client), client->flags);
    }

    if (csock >= 0) {
        close(csock);
    }

    pcmk__free_client(client);

    pcmk__trace("Freed the cib client");

    if (cib_shutdown_flag) {
        based_shutdown(0);
    }
}

static int
cib_remote_listen(gpointer data)
{
    int csock = -1;
    unsigned laddr;
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];
    int ssock = *(int *)data;
    int rc;

    pcmk__client_t *new_client = NULL;

    static struct mainloop_fd_callbacks remote_client_fd_callbacks = {
        .dispatch = cib_remote_msg,
        .destroy = based_remote_client_destroy,
    };

    /* accept the connection */
    laddr = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    csock = accept(ssock, (struct sockaddr *)&addr, &laddr);
    if (csock == -1) {
        pcmk__warn("Could not accept remote connection: %s",
                   pcmk_rc_str(errno));
        return 0;
    }

    pcmk__sockaddr2str(&addr, ipstr);

    rc = pcmk__set_nonblocking(csock);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Dropping remote connection from %s because it could not be "
                   "set to non-blocking: %s",
                   ipstr, pcmk_rc_str(rc));
        close(csock);
        return 0;
    }

    new_client = pcmk__new_unauth_client(NULL);
    new_client->remote = pcmk__assert_alloc(1, sizeof(pcmk__remote_t));

    if (ssock == remote_tls_fd) {
        pcmk__set_client_flags(new_client, pcmk__client_tls);

        /* create gnutls session for the server socket */
        new_client->remote->tls_session = pcmk__new_tls_session(tls, csock);
        if (new_client->remote->tls_session == NULL) {
            close(csock);
            return 0;
        }
    } else {
        pcmk__set_client_flags(new_client, pcmk__client_tcp);
        new_client->remote->tcp_socket = csock;
    }

    // Require the client to authenticate within this time
    new_client->remote->auth_timeout = pcmk__create_timer(REMOTE_AUTH_TIMEOUT,
                                                          remote_auth_timeout_cb,
                                                          new_client);
    pcmk__info("%s connection from %s pending authentication for client %s",
               ((ssock == remote_tls_fd)? "Encrypted" : "Clear-text"), ipstr,
               new_client->id);

    new_client->remote->source =
        mainloop_add_fd("cib-remote-client", G_PRIORITY_DEFAULT, csock, new_client,
                        &remote_client_fd_callbacks);

    return 0;
}

static void
based_remote_listener_destroy(gpointer user_data)
{
    pcmk__info("No longer listening for remote connections");
}

static int
init_remote_listener(int port)
{
    int rc;
    int *ssock = NULL;
    struct sockaddr_in saddr;
    int optval;

    static struct mainloop_fd_callbacks remote_listen_fd_callbacks = {
        .dispatch = cib_remote_listen,
        .destroy = based_remote_listener_destroy,
    };

#ifndef HAVE_PAM
    pcmk__warn("This build does not support remote administrators because PAM "
               "support is not available");
#endif

    /* create server socket */
    ssock = pcmk__assert_alloc(1, sizeof(int));
    *ssock = socket(AF_INET, SOCK_STREAM, 0);
    if (*ssock == -1) {
        pcmk__err("Listener socket creation failed: %s", pcmk_rc_str(errno));
        free(ssock);
        return -1;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(*ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (rc < 0) {
        pcmk__err("Local address reuse not allowed on listener socket: %s",
                  pcmk_rc_str(errno));
    }

    /* bind server socket */
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    if (bind(*ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        pcmk__err("Cannot bind to listener socket: %s", pcmk_rc_str(errno));
        close(*ssock);
        free(ssock);
        return -2;
    }
    if (listen(*ssock, 10) == -1) {
        pcmk__err("Cannot listen on socket: %s", pcmk_rc_str(errno));
        close(*ssock);
        free(ssock);
        return -3;
    }

    mainloop_add_fd("cib-remote", G_PRIORITY_DEFAULT, *ssock, ssock, &remote_listen_fd_callbacks);
    pcmk__debug("Started listener on port %d", port);

    return *ssock;
}

// \return 0 on success, -1 on error (gnutls_psk_server_credentials_function)
static int
based_tls_server_key_cb(gnutls_session_t session, const char *username,
                        gnutls_datum_t *key)
{
    /* First, check that the client's username is valid.  For remote CIB
     * connections, all clients will have the same username so we don't need
     * to look it up anywhere.
     */
    if (!pcmk__str_eq(CRM_DAEMON_USER, username, pcmk__str_none)) {
        pcmk__err("Expected remote username %s, but got %s",
                  CRM_DAEMON_USER, username);
        return -1;
    }

    /* All remote CIB connections use the same key, too, so we don't need to
     * do any lookups here either.  Just attempt to load the key from disk
     * (or cache) and put it in the key variable.
     */
    return (cib__init_remote_key(key) == pcmk_rc_ok)? 0 : -1;
}

/*!
 * \internal
 * \brief Initialize remote listeners using ports configured in the CIB
 */
void
based_remote_init(void)
{
    const char *port_s = NULL;
    int port = 0;

    port_s = pcmk__xe_get(the_cib, PCMK_XA_REMOTE_TLS_PORT);

    if ((pcmk__scan_port(port_s, &port) == pcmk_rc_ok) && (port > 0)) {
        int rc = pcmk_rc_ok;
        bool have_psk = false;
        gnutls_datum_t psk_key = { NULL, 0 };

        /* This is a little convoluted because for backwards compatibility
         * purposes, we need to be able to fall back to anonymous authentication
         * if PSK is not enabled on this node.  When that support is removed,
         * this code can be greatly simplified.
         *
         * Note one difference between this code and similar looking code in
         * remoted_tls.c.  In that code, if the key isn't available at init
         * time, it's okay because the key will be loaded when a client makes
         * a connection.  We only check there to log a warning.  Here, if the
         * key isn't available at init time, we will fall back to anonymous
         * authentication instead and it doesn't matter if the key shows up
         * later.
         */

        /* Attempt to load the key up front in order to determine whether
         * or not PSK is enabled on this node.  The comments in
         * lrmd_init_remote_tls_server on key loading apply here as well.
         */
        if (cib__init_remote_key(&psk_key) == pcmk_rc_ok) {
            have_psk = true;
        } else {
            pcmk__warn("Falling back to anonymous authentication for remote "
                       "CIB connections");
        }

        gnutls_free(psk_key.data);

        /* Now that we know whether to fall back to anonymous authentication
         * or not, we can actually initialize TLS support.
         */
        rc = pcmk__init_tls(&tls, true, have_psk);
        if (rc != pcmk_rc_ok) {
            pcmk__err("Failed to initialize TLS: %s. Not starting TLS listener ",
                      "on port %d", pcmk_rc_str(rc), port);

            remote_tls_fd = -1;
            goto try_clear_port;
        }

        if (have_psk && !pcmk__x509_enabled()) {
            /* Register the callback function that will be used to load the key
             * when a client connects.
             */
            pcmk__tls_server_add_psk_callback(tls, based_tls_server_key_cb);
        }

        pcmk__notice("Starting TLS listener on port %d", port);
        remote_tls_fd = init_remote_listener(port);
    }

try_clear_port:
    /* Regardless of whether or not we successfully enabled remote-tls port,
     * we also want to try to enable remote-clear-port as well.
     */
    port_s = pcmk__xe_get(the_cib, PCMK_XA_REMOTE_CLEAR_PORT);

    if ((pcmk__scan_port(port_s, &port) == pcmk_rc_ok) && (port > 0)) {
        pcmk__warn("Starting clear-text listener on port %d. This is insecure; "
                   PCMK_XA_REMOTE_TLS_PORT " is recommended instead.", port);
        remote_fd = init_remote_listener(port);
    }
}
