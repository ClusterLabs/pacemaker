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

static mainloop_io_t *tcp_listener = NULL;
static mainloop_io_t *tls_listener = NULL;

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
 * \brief Read (more) TLS handshake data from a client
 *
 * \param[in,out] client  IPC client
 *
 * \retval  0  on success or more data needed
 * \retval -1  on error
 */
static int
based_read_handshake_data(pcmk__client_t *client)
{
    int rc = pcmk__read_handshake_data(client);

    if (rc == EAGAIN) {
        /* No more data is available at the moment. Just return for now; we'll
         * get invoked again once the client sends more.
         */
        return 0;
    }

    if (rc != pcmk_rc_ok) {
        return -1;
    }

    if (client->remote->auth_timeout != 0) {
        g_source_remove(client->remote->auth_timeout);
        client->remote->auth_timeout = 0;
    }

    pcmk__set_client_flags(client, pcmk__client_tls_handshake_complete);
    pcmk__debug("Completed TLS handshake with remote client %s",
                pcmk__client_name(client));

    /* Now that the handshake is done, see if any client TLS certificate is
     * close to its expiration date and log if so. If a TLS certificate is not
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

/*!
 * \internal
 * \brief Parse a remote client auth message
 *
 * This first validates that the message is a well-formed remote client
 * authentication request and then extracts the username and password
 * attributes.
 *
 * \param[in]  msg          Message from remote client
 * \param[out] user         Where to store username
 * \param[out] password     Where to store password
 * \param[in]  client_name  Remote client name (for logging only)
 *
 * \return \c true if \p msg is a well-formed authentication request, or
 *         \c false otherwise.
 *
 * \note \p *user and \p *password are set to \c NULL on error.
 */
static bool
parse_auth_message(const xmlNode *msg, const char **user, const char **password,
                   const char *client_name)
{
    const char *op = NULL;

    if (msg == NULL) {
        pcmk__warn("Rejecting remote client %s: Unrecognizable message",
                   client_name);
        return false;
    }

    if (!pcmk__xe_is(msg, PCMK__XE_CIB_COMMAND)) {
        pcmk__warn("Rejecting remote client %s: Expected "
                   "element '" PCMK__XE_CIB_COMMAND "', got '%s'", client_name,
                   (const char *) msg->name);
        return false;
    }

    op = pcmk__xe_get(msg, PCMK_XA_OP);
    if (!pcmk__str_eq(op, "authenticate", pcmk__str_none)) {
        pcmk__warn("Rejecting remote client %s: Expected "
                   PCMK_XA_OP "='authenticate', got " PCMK_XA_OP "='%s'", op);
        return false;
    }

    *user = pcmk__xe_get(msg, PCMK_XA_USER);
    *password = pcmk__xe_get(msg, PCMK__XA_PASSWORD);

    if ((*user == NULL) || (*password == NULL)) {
        pcmk__warn("Rejecting remote client %s: No %s given", client_name,
                   ((*user == NULL)? "username" : "password"));
        *user = NULL;
        *password = NULL;
        return false;
    }

    return true;
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
 * \param[in] user         Username passed for remote CIB connection
 * \param[in] passwd       Password passed for remote CIB connection
 * \param[in] client_name  Remote client name (for logging only)
 *
 * \return \c true if the username and password are accepted, otherwise \c false
 * \note This function rejects all credentials when built without PAM support.
 */
static bool
authenticate_user(const char *user, const char *passwd, const char *client_name)
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
        pcmk__warn("Rejecting remote client %s because PAM initialization "
                   "failed for user %s: %s", client_name, user,
                   pam_strerror(pam_h, rc));
        goto bail;
    }

    // Check user credentials
    rc = pam_authenticate(pam_h, PAM_SILENT);
    if (rc != PAM_SUCCESS) {
        pcmk__notice("Rejecting remote client %s because PAM authentication "
                     "failed for user %s: %s", client_name, user,
                     pam_strerror(pam_h, rc));
        goto bail;
    }

    /* Get the authenticated user name (PAM modules can map the original name to
     * something else). Since the CIB manager runs as the daemon user (not
     * root), that is the only user that can be successfully authenticated.
     */
    rc = pam_get_item(pam_h, PAM_USER, &p_user);
    if (rc != PAM_SUCCESS) {
        pcmk__warn("Rejecting remote client %s because PAM failed to return "
                   "the authenticated user name for user %s: %s", client_name,
                   user, pam_strerror(pam_h, rc));
        goto bail;
    }

    if (p_user == NULL) {
        pcmk__warn("Rejecting remote client %s because PAM returned no "
                   "authenticated user name for user %s", client_name, user);
        goto bail;
    }

    // @TODO Why do we require these to match?
    if (!pcmk__str_eq(p_user, user, pcmk__str_none)) {
        pcmk__warn("Rejecting remote client %s because PAM returned "
                   "non-matching authenticated user name %s for user %s",
                   client_name, user, p_user);
        goto bail;
    }

    // Check user account restrictions (expiration, etc.)
    rc = pam_acct_mgmt(pam_h, PAM_SILENT);
    if (rc != PAM_SUCCESS) {
        pcmk__warn("Rejecting remote client %s because PAM denied access to "
                   "user %s", client_name, user, pam_strerror(pam_h, rc));
        goto bail;
    }

    pass = true;

bail:
    pam_end(pam_h, rc);
    return pass;
#else
    // @TODO Implement for non-PAM environments
    pcmk__warn("Rejecting remote client %s (user %s) because this build does "
               "not have PAM support", client_name, user);
    return false;
#endif
}

/*!
 * \internal
 * \brief Try to authenticate a remote client based on the message in its buffer
 *
 * Read the first message from the client's buffer. Validate that it's a well-
 * formed remote client authentication request. Parse the username and password.
 * Ensure that the user is a member of \c CRM_DAEMON_GROUP and use the
 * credentials to authenticate the user via PAM (if available). Finally, on
 * success, set the \c pcmk__client_authenticated flag, and send a reply
 * informing the client of its success and its client ID.
 *
 * \param[in,out] client  Remote CIB manager client
 *
 * \return \c true if \p client authenticated successfully, or \c false
 *         otherwise
 */
static bool
based_remote_client_auth(pcmk__client_t *client)
{
    // @TODO If we want to debug/trace-log an auth message, strip password first
    const char *user = NULL;
    const char *password = NULL;
    const char *client_name = pcmk__client_name(client);
    xmlNode *msg = NULL;
    xmlNode *cib_result = NULL;

    msg = pcmk__remote_message_xml(client->remote);
    if (!parse_auth_message(msg, &user, &password, client_name)) {
        // Error already logged
        goto done;
    }

    if (!pcmk__is_user_in_group(user, CRM_DAEMON_GROUP)) {
        pcmk__notice("Rejecting remote client %s: User %s is not a member of "
                     "group %s", client_name, user, CRM_DAEMON_GROUP);
        goto done;
    }

    if (!authenticate_user(user, password, client_name)) {
        // Error already logged
        goto done;
    }

    // @FIXME Should this be done regardless of whether auth succeeds?
    if (client->remote->auth_timeout != 0) {
        g_source_remove(client->remote->auth_timeout);
        client->remote->auth_timeout = 0;
    }

    pcmk__set_client_flags(client, pcmk__client_authenticated);

    // @TODO What sets PCMK_XA_NAME? Added by commit 22832641.
    client->name = pcmk__xe_get_copy(msg, PCMK_XA_NAME);
    if (client->name == NULL) {
        client->name = pcmk__str_copy(client->id);
    }

    client->user = pcmk__str_copy(user);

    // Setting client->name may have changed the return value
    client_name = pcmk__client_name(client);

    pcmk__notice("Remote connection accepted for authenticated user %s "
                 QB_XS " client %s", client->user, client_name);

    // Notify client of success and of its ID
    cib_result = pcmk__xe_create(NULL, PCMK__XE_CIB_RESULT);
    pcmk__xe_set(cib_result, PCMK__XA_CIB_OP, CRM_OP_REGISTER);
    pcmk__xe_set(cib_result, PCMK__XA_CIB_CLIENTID, client->id);

    pcmk__remote_send_xml(client->remote, cib_result);

done:
    pcmk__xml_free(msg);
    pcmk__xml_free(cib_result);
    return pcmk__is_set(client->flags, pcmk__client_authenticated);
}

static void
based_remote_client_message(pcmk__client_t *client, xmlNode *msg)
{
    int rc = pcmk_rc_ok;
    uint32_t call_options = cib_none;
    const char *op = pcmk__xe_get(msg, PCMK__XA_CIB_OP);

    if (!pcmk__xe_is(msg, PCMK__XE_CIB_COMMAND)) {
        pcmk__debug("Unrecognizable remote data from client %s",
                    pcmk__client_name(client));
        return;
    }

    rc = pcmk__xe_get_flags(msg, PCMK__XA_CIB_CALLOPT, &call_options, cib_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    /* Requests with cib_transaction set should not be sent to based directly
     * (that is, outside of a commit-transaction request)
     */
    if (pcmk__is_set(call_options, cib_transaction)) {
        pcmk__warn("Ignoring CIB request from remote client %s with "
                   "cib_transaction flag set outside of any transaction",
                   pcmk__client_name(client));
        return;
    }

    /* Unset dangerous options.
     *
     * @TODO These were commented as "dangerous" with no explanation when this
     * code was added by commit 8e08a242 (2007). We usually process whatever
     * message we receive, taking a "submit a malformed request at your own
     * risk" view. Our client API and CLI tools should not be able to submit a
     * malformed request. A malicious user would have to send it directly,
     * without our tools. If they have that level of access and are able to
     * authenticate their request, then they can cause havoc regardless of
     * whether we remove these "dangerous" attributes that shouldn't be present
     * in a remote client's request.
     *
     * This seems overly paranoid, and seems like an arbitrary place to be
     * paranoid.
     *
     * Best guesses about how they might be dangerous (or not):
     * * PCMK_XA_SRC: This is mostly used for logging. Perhaps the CIB could get
     *   synced to the wrong host, or local client notifications could get sent
     *   on the wrong host?
     * * PCMK__XA_CIB_HOST: It seems as if this should be allowed. Our client
     *   code actually sets this, apparently as a destination node.
     *   cib_remote_perform_op() takes a host argument and passes it to
     *   cib__create_op(), which sets it as PCMK__XA_CIB_HOST.
     * * PCMK__XA_CIB_UPDATE: This can prevent CIB versions from being updated,
     *   because the update is treated as a sync.
     */
    pcmk__xe_remove_attr(msg, PCMK__XA_SRC);
    pcmk__xe_remove_attr(msg, PCMK__XA_CIB_HOST);
    pcmk__xe_remove_attr(msg, PCMK__XA_CIB_UPDATE);

    // Similarly impossible via our API/tools. cib__create_op() sets this.
    if (pcmk__xe_get(msg, PCMK__XA_CIB_CALLID) == NULL) {
        char *call_uuid = pcmk__generate_uuid();

        pcmk__xe_set(msg, PCMK__XA_CIB_CALLID, call_uuid);
        free(call_uuid);
    }

    pcmk__xe_set(msg, PCMK__XA_T, PCMK__VALUE_CIB);
    pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTID, client->id);
    pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTNAME, client->name);
    pcmk__xe_set(msg, PCMK__XA_CIB_USER, client->user);

    pcmk__log_xml_trace(msg, "remote-request");

    if (pcmk__str_eq(op, PCMK__VALUE_CIB_NOTIFY, pcmk__str_none)) {
        based_update_notify_flags(msg, client);

    } else {
        /* @TODO Should ipc_id be set to a nonzero value? client->request_id
         * needs to match it if so, since pcmk__request_sync is set.
         */
        pcmk__request_t request = {
            .ipc_client     = client,
            .ipc_id         = 0,
            .ipc_flags      = crm_ipc_flags_none,
            .peer           = NULL,
            .xml            = msg,
            .call_options   = call_options,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = pcmk__xe_get_copy(request.xml, PCMK__XA_CIB_OP);
        CRM_CHECK(request.op != NULL, return);

        if (pcmk__is_set(request.call_options, cib_sync_call)) {
            pcmk__set_request_flags(&request, pcmk__request_sync);
        }

        based_handle_request(&request);
    }
}

static int
based_remote_client_dispatch(gpointer data)
{
    int rc = pcmk_rc_ok;
    xmlNode *msg = NULL;
    pcmk__client_t *client = data;
    const char *client_name = pcmk__client_name(client);

    pcmk__trace("Remote %s message received for client %s",
                pcmk__client_type_str(PCMK__CLIENT_TYPE(client)), client_name);

    if ((PCMK__CLIENT_TYPE(client) == pcmk__client_tls)
        && !pcmk__is_set(client->flags, pcmk__client_tls_handshake_complete)) {

        return based_read_handshake_data(client);
    }

    rc = pcmk__remote_ready(client->remote, 0);
    switch (rc) {
        case pcmk_rc_ok:
            break;

        case ETIME:
            // No message available to read
            return 0;

        default:
            pcmk__trace("Error polling remote client: %s", pcmk_rc_str(rc));
            return -1;
    }

    rc = pcmk__read_available_remote_data(client->remote);
    switch (rc) {
        case pcmk_rc_ok:
            break;

        case EAGAIN:
            // We haven't read the whole message yet
            return 0;

        default:
            pcmk__trace("Error reading from remote client: %s",
                        pcmk_rc_str(rc));
            return -1;
    }

    // Client must authenticate before we will process anything else
    if (!pcmk__is_set(client->flags, pcmk__client_authenticated)
        && !based_remote_client_auth(client)) {

        return -1;
    }

    msg = pcmk__remote_message_xml(client->remote);
    based_remote_client_message(client, msg);

    pcmk__xml_free(msg);
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
}

static int
cib_remote_listen(gpointer user_data)
{
    int ssock = GPOINTER_TO_INT(user_data);
    const bool is_tls = (tls_listener != NULL) && (ssock == tls_listener->fd);

    int csock = -1;
    unsigned laddr;
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];
    int rc;

    pcmk__client_t *new_client = NULL;

    static struct mainloop_fd_callbacks remote_client_fd_callbacks = {
        .dispatch = based_remote_client_dispatch,
        .destroy = based_remote_client_destroy,
    };

    if (based_shutting_down()) {
        pcmk__info("Ignoring new remote connection during shutdown");
        return 0;
    }

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

    if (is_tls) {
        pcmk__set_client_flags(new_client, pcmk__client_tls);

        /* create gnutls session for the server socket */
        new_client->remote->tls_session = pcmk__new_tls_session(tls, csock);
        if (new_client->remote->tls_session == NULL) {
            pcmk__err("Dropping remote connection from %s because we failed to "
                      "create a TLS session for it", ipstr);
            pcmk__free_client(new_client);
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
               (is_tls? "Encrypted" : "Clear-text"), ipstr, new_client->id);

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

static mainloop_io_t *
init_remote_listener(int port)
{
    int rc;
    int ssock = -1;
    struct sockaddr_in saddr;
    int optval;
    mainloop_io_t *listener = NULL;

    static struct mainloop_fd_callbacks remote_listen_fd_callbacks = {
        .dispatch = cib_remote_listen,
        .destroy = based_remote_listener_destroy,
    };

#ifndef HAVE_PAM
    pcmk__warn("This build does not support remote administrators because PAM "
               "support is not available");
#endif

    /* create server socket */
    ssock = socket(AF_INET, SOCK_STREAM, 0);
    if (ssock == -1) {
        pcmk__err("Listener socket creation failed: %s", strerror(errno));
        return NULL;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (rc < 0) {
        pcmk__err("Local address reuse not allowed on listener socket: %s",
                  strerror(errno));
    }

    /* bind server socket */
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    if (bind(ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        pcmk__err("Cannot bind to listener socket: %s", strerror(errno));
        close(ssock);
        return NULL;
    }
    if (listen(ssock, 10) == -1) {
        pcmk__err("Cannot listen on socket: %s", strerror(errno));
        close(ssock);
        return NULL;
    }

    listener = mainloop_add_fd("based-remote-listener", G_PRIORITY_DEFAULT,
                               ssock, GINT_TO_POINTER(ssock),
                               &remote_listen_fd_callbacks);
    if (listener == NULL) {
        pcmk__err("Cannot add pacemaker-based remote listener (port %d) to "
                  "mainloop: %s", port, strerror(errno));
        return NULL;
    }

    pcmk__debug("Started pacemaker-based remote listener on port %d", port);
    return listener;
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

    port_s = pcmk__xe_get(based_cib, PCMK_XA_REMOTE_TLS_PORT);

    if ((pcmk__scan_port(port_s, &port) == pcmk_rc_ok) && (port > 0)) {
        // @TODO Implement pre-shared key authentication (see T961)
        int rc = pcmk__init_tls(&tls, true, false);

        if (rc != pcmk_rc_ok) {
            pcmk__err("Failed to initialize TLS: %s. Not starting TLS listener ",
                      "on port %d", pcmk_rc_str(rc), port);

        } else {
            pcmk__notice("Starting TLS listener on port %d", port);
            tls_listener = init_remote_listener(port);
        }
    }

    port_s = pcmk__xe_get(based_cib, PCMK_XA_REMOTE_CLEAR_PORT);

    if ((pcmk__scan_port(port_s, &port) == pcmk_rc_ok) && (port > 0)) {
        pcmk__warn("Starting clear-text listener on port %d. This is insecure; "
                   PCMK_XA_REMOTE_TLS_PORT " is recommended instead.", port);
        tcp_listener = init_remote_listener(port);
    }
}

/*!
 * \internal
 * \brief Stop remote listeners
 *
 * \note Remote clients are dropped in \c based_ipc_cleanup() rather than here,
 *       because they're part of the IPC client table and must be dropped before
 *       we call \c pcmk__client_cleanup().
 */
void
based_remote_cleanup(void)
{
    g_clear_pointer(&tcp_listener, mainloop_del_fd);
    g_clear_pointer(&tls_listener, mainloop_del_fd);
}

/*!
 * \internal
 * \brief Disconnect and free a CIB manager client if it is a remote client
 *
 * If \p value is a remote client, drop it by removing its source from the
 * mainloop. It will be freed by \c based_remote_client_destroy() via
 * \c remote_client_fd_callbacks.
 *
 * \param[in]     key        Ignored
 * \param[in,out] value      CIB manager client (<tt>pcmk__client_t *</tt>)
 * \param[in]     user_data  Ignored
 */
static void
drop_client_if_remote(gpointer key, gpointer value, gpointer user_data)
{
    pcmk__client_t *client = value;

    if (client->remote != NULL) {
        return;
    }

    pcmk__notice("Disconnecting remote client %s", pcmk__client_name(client));
    mainloop_del_fd(client->remote->source);
}

/*!
 * \internal
 * \brief Disconnect and free all remote CIB manager clients
 */
void
based_drop_remote_clients(void)
{
    pcmk__foreach_ipc_client(drop_client_if_remote, NULL);
}
