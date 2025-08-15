/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>           // PRIx64
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ip.h>

#include <stdlib.h>
#include <errno.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>
#include <crm/common/tls_internal.h>
#include <crm/cib/internal.h>

#include "pacemaker-based.h"

#include <gnutls/gnutls.h>

#include <pwd.h>
#include <grp.h>
#if HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#  define HAVE_PAM 1
#elif HAVE_PAM_PAM_APPL_H
#  include <pam/pam_appl.h>
#  define HAVE_PAM 1
#endif

static pcmk__tls_t *tls = NULL;

extern int remote_tls_fd;
extern gboolean cib_shutdown_flag;

int init_remote_listener(int port, gboolean encrypted);
void cib_remote_connection_destroy(gpointer user_data);

// @TODO This is rather short for someone to type their password
#define REMOTE_AUTH_TIMEOUT 10000

int num_clients;
static bool authenticate_user(const char *user, const char *passwd);
static int cib_remote_listen(gpointer data);
static int cib_remote_msg(gpointer data);

static void
remote_connection_destroy(gpointer user_data)
{
    crm_info("No longer listening for remote connections");
    return;
}

int
init_remote_listener(int port, gboolean encrypted)
{
    int rc;
    int *ssock = NULL;
    struct sockaddr_in saddr;
    int optval;

    static struct mainloop_fd_callbacks remote_listen_fd_callbacks = {
        .dispatch = cib_remote_listen,
        .destroy = remote_connection_destroy,
    };

    if (port <= 0) {
        /* don't start it */
        return 0;
    }

    if (encrypted) {
        bool use_cert = pcmk__x509_enabled();

        crm_notice("Starting TLS listener on port %d", port);

        rc = pcmk__init_tls(&tls, true, use_cert ? GNUTLS_CRD_CERTIFICATE : GNUTLS_CRD_ANON);
        if (rc != pcmk_rc_ok) {
            return -1;
        }
    } else {
        crm_warn("Starting plain-text listener on port %d", port);
    }
#ifndef HAVE_PAM
    crm_warn("This build does not support remote administrators "
             "because PAM support is not available");
#endif

    /* create server socket */
    ssock = pcmk__assert_alloc(1, sizeof(int));
    *ssock = socket(AF_INET, SOCK_STREAM, 0);
    if (*ssock == -1) {
        crm_err("Listener socket creation failed: %s", pcmk_rc_str(errno));
        free(ssock);
        return -1;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(*ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (rc < 0) {
        crm_err("Local address reuse not allowed on listener socket: %s",
                pcmk_rc_str(errno));
    }

    /* bind server socket */
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    if (bind(*ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        crm_err("Cannot bind to listener socket: %s", pcmk_rc_str(errno));
        close(*ssock);
        free(ssock);
        return -2;
    }
    if (listen(*ssock, 10) == -1) {
        crm_err("Cannot listen on socket: %s", pcmk_rc_str(errno));
        close(*ssock);
        free(ssock);
        return -3;
    }

    mainloop_add_fd("cib-remote", G_PRIORITY_DEFAULT, *ssock, ssock, &remote_listen_fd_callbacks);
    crm_debug("Started listener on port %d", port);

    return *ssock;
}

static int
check_group_membership(const char *usr, const char *grp)
{
    int index = 0;
    struct passwd *pwd = NULL;
    struct group *group = NULL;

    pwd = getpwnam(usr);
    if (pwd == NULL) {
        crm_notice("Rejecting remote client: '%s' is not a valid user", usr);
        return FALSE;
    }

    group = getgrgid(pwd->pw_gid);
    if (group != NULL && pcmk__str_eq(grp, group->gr_name, pcmk__str_none)) {
        return TRUE;
    }

    group = getgrnam(grp);
    if (group == NULL) {
        crm_err("Rejecting remote client: '%s' is not a valid group", grp);
        return FALSE;
    }

    while (TRUE) {
        char *member = group->gr_mem[index++];

        if (member == NULL) {
            break;

        } else if (pcmk__str_eq(usr, member, pcmk__str_none)) {
            return TRUE;
        }
    }

    crm_notice("Rejecting remote client: User '%s' is not a member of "
               "group '%s'", usr, grp);
    return FALSE;
}

static gboolean
cib_remote_auth(xmlNode * login)
{
    const char *user = NULL;
    const char *pass = NULL;
    const char *tmp = NULL;

    if (login == NULL) {
        return FALSE;
    }

    if (!pcmk__xe_is(login, PCMK__XE_CIB_COMMAND)) {
        crm_warn("Rejecting remote client: Unrecognizable message "
                 "(element '%s' not '" PCMK__XE_CIB_COMMAND "')", login->name);
        crm_log_xml_debug(login, "bad");
        return FALSE;
    }

    tmp = pcmk__xe_get(login, PCMK_XA_OP);
    if (!pcmk__str_eq(tmp, "authenticate", pcmk__str_casei)) {
        crm_warn("Rejecting remote client: Unrecognizable message "
                 "(operation '%s' not 'authenticate')", tmp);
        crm_log_xml_debug(login, "bad");
        return FALSE;
    }

    user = pcmk__xe_get(login, PCMK_XA_USER);
    pass = pcmk__xe_get(login, PCMK__XA_PASSWORD);
    if (!user || !pass) {
        crm_warn("Rejecting remote client: No %s given",
                 ((user == NULL)? "username" : "password"));
        crm_log_xml_debug(login, "bad");
        return FALSE;
    }

    crm_log_xml_debug(login, "auth");

    return check_group_membership(user, CRM_DAEMON_GROUP)
           && authenticate_user(user, pass);
}

static gboolean
remote_auth_timeout_cb(gpointer data)
{
    pcmk__client_t *client = data;

    client->remote->auth_timeout = 0;

    if (pcmk_is_set(client->flags, pcmk__client_authenticated)) {
        return FALSE;
    }

    mainloop_del_fd(client->remote->source);
    crm_err("Remote client authentication timed out");

    return FALSE;
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
        .destroy = cib_remote_connection_destroy,
    };

    /* accept the connection */
    laddr = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    csock = accept(ssock, (struct sockaddr *)&addr, &laddr);
    if (csock == -1) {
        crm_warn("Could not accept remote connection: %s", pcmk_rc_str(errno));
        return TRUE;
    }

    pcmk__sockaddr2str(&addr, ipstr);

    rc = pcmk__set_nonblocking(csock);
    if (rc != pcmk_rc_ok) {
        crm_warn("Dropping remote connection from %s because "
                 "it could not be set to non-blocking: %s",
                 ipstr, pcmk_rc_str(rc));
        close(csock);
        return TRUE;
    }

    num_clients++;

    new_client = pcmk__new_unauth_client(NULL);
    new_client->remote = pcmk__assert_alloc(1, sizeof(pcmk__remote_t));

    if (ssock == remote_tls_fd) {
        pcmk__set_client_flags(new_client, pcmk__client_tls);

        /* create gnutls session for the server socket */
        new_client->remote->tls_session = pcmk__new_tls_session(tls, csock);
        if (new_client->remote->tls_session == NULL) {
            close(csock);
            return TRUE;
        }
    } else {
        pcmk__set_client_flags(new_client, pcmk__client_tcp);
        new_client->remote->tcp_socket = csock;
    }

    // Require the client to authenticate within this time
    new_client->remote->auth_timeout = pcmk__create_timer(REMOTE_AUTH_TIMEOUT,
                                                          remote_auth_timeout_cb,
                                                          new_client);
    crm_info("%s connection from %s pending authentication for client %s",
             ((ssock == remote_tls_fd)? "Encrypted" : "Clear-text"),
             ipstr, new_client->id);

    new_client->remote->source =
        mainloop_add_fd("cib-remote-client", G_PRIORITY_DEFAULT, csock, new_client,
                        &remote_client_fd_callbacks);

    return TRUE;
}

void
cib_remote_connection_destroy(gpointer user_data)
{
    pcmk__client_t *client = user_data;
    int csock = -1;

    if (client == NULL) {
        return;
    }

    crm_trace("Cleaning up after client %s disconnect",
              pcmk__client_name(client));

    num_clients--;
    crm_trace("Num unfree'd clients: %d", num_clients);

    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_tcp:
            csock = client->remote->tcp_socket;
            break;
        case pcmk__client_tls:
            if (client->remote->tls_session) {
                csock = pcmk__tls_get_client_sock(client->remote);

                if (pcmk_is_set(client->flags,
                                pcmk__client_tls_handshake_complete)) {
                    gnutls_bye(client->remote->tls_session, GNUTLS_SHUT_WR);
                }
                gnutls_deinit(client->remote->tls_session);
                client->remote->tls_session = NULL;
            }
            break;
        default:
            crm_warn("Unknown transport for client %s "
                     QB_XS " flags=%#016" PRIx64,
                     pcmk__client_name(client), client->flags);
    }

    if (csock >= 0) {
        close(csock);
    }

    pcmk__free_client(client);

    crm_trace("Freed the cib client");

    if (cib_shutdown_flag) {
        cib_shutdown(0);
    }
    return;
}

static void
cib_handle_remote_msg(pcmk__client_t *client, xmlNode *command)
{
    if (!pcmk__xe_is(command, PCMK__XE_CIB_COMMAND)) {
        crm_log_xml_trace(command, "bad");
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
        char *call_uuid = crm_generate_uuid();

        /* fix the command */
        pcmk__xe_set(command, PCMK__XA_CIB_CALLID, call_uuid);
        free(call_uuid);
    }

    if (pcmk__xe_get(command, PCMK__XA_CIB_CALLOPT) == NULL) {
        pcmk__xe_set_int(command, PCMK__XA_CIB_CALLOPT, 0);
    }

    crm_log_xml_trace(command, "Remote command: ");
    cib_common_callback_worker(0, 0, command, client, TRUE);
}

static int
cib_remote_msg(gpointer data)
{
    xmlNode *command = NULL;
    pcmk__client_t *client = data;
    int rc;
    const char *client_name = pcmk__client_name(client);

    crm_trace("Remote %s message received for client %s",
              pcmk__client_type_str(PCMK__CLIENT_TYPE(client)), client_name);

    if ((PCMK__CLIENT_TYPE(client) == pcmk__client_tls)
        && !pcmk_is_set(client->flags, pcmk__client_tls_handshake_complete)) {

        int rc = pcmk__read_handshake_data(client);

        if (rc == EAGAIN) {
            /* No more data is available at the moment. Just return for now;
             * we'll get invoked again once the client sends more.
             */
            return 0;
        } else if (rc != pcmk_rc_ok) {
            return -1;
        }

        crm_debug("Completed TLS handshake with remote client %s", client_name);
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
            crm_trace("Error reading from remote client: %s", pcmk_rc_str(rc));
            return -1;
    }

    /* must pass auth before we will process anything else */
    if (!pcmk_is_set(client->flags, pcmk__client_authenticated)) {
        xmlNode *reg;
        const char *user = NULL;

        command = pcmk__remote_message_xml(client->remote);
        if (cib_remote_auth(command) == FALSE) {
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

        crm_notice("Remote connection accepted for authenticated user %s "
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
        crm_trace("Remote message received from client %s", client_name);
        cib_handle_remote_msg(client, command);
        pcmk__xml_free(command);
    }

    return 0;
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
            crm_info("PAM: %s", msg[0]->msg);
            data = NULL;
            break;
        case PAM_ERROR_MSG:
            /* In theory we should show msg[0]->msg, but that might
             * contain the password, which we don't want in the logs
             */
            crm_err("PAM reported an error");
            data = NULL;
            break;
        default:
            crm_warn("Ignoring PAM message of unrecognized type %d",
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
        crm_warn("Rejecting remote client for user %s "
                 "because PAM initialization failed: %s",
                 user, pam_strerror(pam_h, rc));
        goto bail;
    }

    // Check user credentials
    rc = pam_authenticate(pam_h, PAM_SILENT);
    if (rc != PAM_SUCCESS) {
        crm_notice("Access for remote user %s denied: %s",
                   user, pam_strerror(pam_h, rc));
        goto bail;
    }

    /* Get the authenticated user name (PAM modules can map the original name to
     * something else). Since the CIB manager runs as the daemon user (not
     * root), that is the only user that can be successfully authenticated.
     */
    rc = pam_get_item(pam_h, PAM_USER, &p_user);
    if (rc != PAM_SUCCESS) {
        crm_warn("Rejecting remote client for user %s "
                 "because PAM failed to return final user name: %s",
                 user, pam_strerror(pam_h, rc));
        goto bail;
    }
    if (p_user == NULL) {
        crm_warn("Rejecting remote client for user %s "
                 "because PAM returned no final user name", user);
        goto bail;
    }

    // @TODO Why do we require these to match?
    if (!pcmk__str_eq(p_user, user, pcmk__str_none)) {
        crm_warn("Rejecting remote client for user %s "
                 "because PAM returned different final user name %s",
                 user, p_user);
        goto bail;
    }

    // Check user account restrictions (expiration, etc.)
    rc = pam_acct_mgmt(pam_h, PAM_SILENT);
    if (rc != PAM_SUCCESS) {
        crm_notice("Access for remote user %s denied: %s",
                   user, pam_strerror(pam_h, rc));
        goto bail;
    }
    pass = true;

bail:
    pam_end(pam_h, rc);
    return pass;
#else
    // @TODO Implement for non-PAM environments
    crm_warn("Rejecting remote user %s because this build does not have "
             "PAM support", user);
    return false;
#endif
}
