/*
 * Copyright 2004-2021 the Pacemaker project contributors
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

#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>
#include <crm/cib/internal.h>

#include "pacemaker-based.h"

/* #undef HAVE_PAM_PAM_APPL_H */
/* #undef HAVE_GNUTLS_GNUTLS_H */

#ifdef HAVE_GNUTLS_GNUTLS_H
#  include <gnutls/gnutls.h>
#endif

#include <pwd.h>
#include <grp.h>
#if HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#  define HAVE_PAM 1
#else
#  if HAVE_PAM_PAM_APPL_H
#    include <pam/pam_appl.h>
#    define HAVE_PAM 1
#  endif
#endif

extern int remote_tls_fd;
extern gboolean cib_shutdown_flag;

int init_remote_listener(int port, gboolean encrypted);
void cib_remote_connection_destroy(gpointer user_data);

#ifdef HAVE_GNUTLS_GNUTLS_H
gnutls_dh_params_t dh_params;
gnutls_anon_server_credentials_t anon_cred_s;
static void
debug_log(int level, const char *str)
{
    fputs(str, stderr);
}
#endif

#define REMOTE_AUTH_TIMEOUT 10000

int num_clients;
int authenticate_user(const char *user, const char *passwd);
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
#ifndef HAVE_GNUTLS_GNUTLS_H
        crm_warn("TLS support is not available");
        return 0;
#else
        crm_notice("Starting TLS listener on port %d", port);
        crm_gnutls_global_init();
        /* gnutls_global_set_log_level (10); */
        gnutls_global_set_log_function(debug_log);
        if (pcmk__init_tls_dh(&dh_params) != pcmk_rc_ok) {
            return -1;
        }
        gnutls_anon_allocate_server_credentials(&anon_cred_s);
        gnutls_anon_set_server_dh_params(anon_cred_s, dh_params);
#endif
    } else {
        crm_warn("Starting plain-text listener on port %d", port);
    }
#ifndef HAVE_PAM
    crm_warn("PAM is _not_ enabled!");
#endif

    /* create server socket */
    ssock = malloc(sizeof(int));
    if(ssock == NULL) {
        crm_perror(LOG_ERR, "Listener socket allocation failed");
        return -1;
    }

    *ssock = socket(AF_INET, SOCK_STREAM, 0);
    if (*ssock == -1) {
        crm_perror(LOG_ERR, "Listener socket creation failed");
        free(ssock);
        return -1;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(*ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (rc < 0) {
        crm_perror(LOG_WARNING,
                   "Local address reuse not allowed on listener socket");
    }

    /* bind server socket */
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    if (bind(*ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        crm_perror(LOG_ERR, "Cannot bind to listener socket");
        close(*ssock);
        free(ssock);
        return -2;
    }
    if (listen(*ssock, 10) == -1) {
        crm_perror(LOG_ERR, "Cannot listen on socket");
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

    CRM_CHECK(usr != NULL, return FALSE);
    CRM_CHECK(grp != NULL, return FALSE);

    pwd = getpwnam(usr);
    if (pwd == NULL) {
        crm_err("No user named '%s' exists!", usr);
        return FALSE;
    }

    group = getgrgid(pwd->pw_gid);
    if (group != NULL && pcmk__str_eq(grp, group->gr_name, pcmk__str_none)) {
        return TRUE;
    }

    group = getgrnam(grp);
    if (group == NULL) {
        crm_err("No group named '%s' exists!", grp);
        return FALSE;
    }

    while (TRUE) {
        char *member = group->gr_mem[index++];

        if (member == NULL) {
            break;

        } else if (pcmk__str_eq(usr, member, pcmk__str_none)) {
            return TRUE;
        }
    };

    return FALSE;
}

static gboolean
cib_remote_auth(xmlNode * login)
{
    const char *user = NULL;
    const char *pass = NULL;
    const char *tmp = NULL;

    crm_log_xml_info(login, "Login: ");
    if (login == NULL) {
        return FALSE;
    }

    tmp = crm_element_name(login);
    if (!pcmk__str_eq(tmp, "cib_command", pcmk__str_casei)) {
        crm_err("Wrong tag: %s", tmp);
        return FALSE;
    }

    tmp = crm_element_value(login, "op");
    if (!pcmk__str_eq(tmp, "authenticate", pcmk__str_casei)) {
        crm_err("Wrong operation: %s", tmp);
        return FALSE;
    }

    user = crm_element_value(login, "user");
    pass = crm_element_value(login, "password");

    if (!user || !pass) {
        crm_err("missing auth credentials");
        return FALSE;
    }

    /* Non-root daemons can only validate the password of the
     * user they're running as
     */
    if (check_group_membership(user, CRM_DAEMON_GROUP) == FALSE) {
        crm_err("User is not a member of the required group");
        return FALSE;

    } else if (authenticate_user(user, pass) == FALSE) {
        crm_err("PAM auth failed");
        return FALSE;
    }

    return TRUE;
}

static gboolean
remote_auth_timeout_cb(gpointer data)
{
    pcmk__client_t *client = data;

    client->remote->auth_timeout = 0;

    if (client->remote->authenticated == TRUE) {
        return FALSE;
    }

    mainloop_del_fd(client->remote->source);
    crm_err("Remote client authentication timed out");

    return FALSE;
}

static int
cib_remote_listen(gpointer data)
{
    int csock = 0;
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
        crm_perror(LOG_ERR, "Could not accept socket connection");
        return TRUE;
    }

    pcmk__sockaddr2str(&addr, ipstr);
    crm_debug("New %s connection from %s",
              ((ssock == remote_tls_fd)? "secure" : "clear-text"), ipstr);

    rc = pcmk__set_nonblocking(csock);
    if (rc != pcmk_rc_ok) {
        crm_err("Could not set socket non-blocking: %s " CRM_XS " rc=%d",
                pcmk_rc_str(rc), rc);
        close(csock);
        return TRUE;
    }

    num_clients++;

    new_client = pcmk__new_unauth_client(NULL);
    new_client->remote = calloc(1, sizeof(pcmk__remote_t));

    if (ssock == remote_tls_fd) {
#ifdef HAVE_GNUTLS_GNUTLS_H
        pcmk__set_client_flags(new_client, pcmk__client_tls);

        /* create gnutls session for the server socket */
        new_client->remote->tls_session = pcmk__new_tls_session(csock,
                                                                GNUTLS_SERVER,
                                                                GNUTLS_CRD_ANON,
                                                                anon_cred_s);
        if (new_client->remote->tls_session == NULL) {
            close(csock);
            return TRUE;
        }
#endif
    } else {
        pcmk__set_client_flags(new_client, pcmk__client_tcp);
        new_client->remote->tcp_socket = csock;
    }

    // Require the client to authenticate within this time
    new_client->remote->auth_timeout = g_timeout_add(REMOTE_AUTH_TIMEOUT,
                                                     remote_auth_timeout_cb,
                                                     new_client);
    crm_info("Remote CIB client pending authentication "
             CRM_XS " %p id: %s", new_client, new_client->id);

    new_client->remote->source =
        mainloop_add_fd("cib-remote-client", G_PRIORITY_DEFAULT, csock, new_client,
                        &remote_client_fd_callbacks);

    return TRUE;
}

void
cib_remote_connection_destroy(gpointer user_data)
{
    pcmk__client_t *client = user_data;
    int csock = 0;

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
#ifdef HAVE_GNUTLS_GNUTLS_H
        case pcmk__client_tls:
            if (client->remote->tls_session) {
                void *sock_ptr = gnutls_transport_get_ptr(*client->remote->tls_session);

                csock = GPOINTER_TO_INT(sock_ptr);
                if (client->remote->tls_handshake_complete) {
                    gnutls_bye(*client->remote->tls_session, GNUTLS_SHUT_WR);
                }
                gnutls_deinit(*client->remote->tls_session);
                gnutls_free(client->remote->tls_session);
                client->remote->tls_session = NULL;
            }
            break;
#endif
        default:
            crm_warn("Unknown transport for client %s "
                     CRM_XS " flags=0x%016" PRIx64,
                     pcmk__client_name(client), client->flags);
    }

    if (csock > 0) {
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
    const char *value = NULL;

    value = crm_element_name(command);
    if (!pcmk__str_eq(value, "cib_command", pcmk__str_casei)) {
        crm_log_xml_trace(command, "Bad command: ");
        return;
    }

    if (client->name == NULL) {
        value = crm_element_value(command, F_CLIENTNAME);
        if (value == NULL) {
            client->name = strdup(client->id);
        } else {
            client->name = strdup(value);
        }
    }

    if (client->userdata == NULL) {
        value = crm_element_value(command, F_CIB_CALLBACK_TOKEN);
        if (value != NULL) {
            client->userdata = strdup(value);
            crm_trace("Callback channel for %s is %s", client->id, (char*)client->userdata);

        } else {
            client->userdata = strdup(client->id);
        }
    }

    /* unset dangerous options */
    xml_remove_prop(command, F_ORIG);
    xml_remove_prop(command, F_CIB_HOST);
    xml_remove_prop(command, F_CIB_GLOBAL_UPDATE);

    crm_xml_add(command, F_TYPE, T_CIB);
    crm_xml_add(command, F_CIB_CLIENTID, client->id);
    crm_xml_add(command, F_CIB_CLIENTNAME, client->name);
    crm_xml_add(command, F_CIB_USER, client->user);

    if (crm_element_value(command, F_CIB_CALLID) == NULL) {
        char *call_uuid = crm_generate_uuid();

        /* fix the command */
        crm_xml_add(command, F_CIB_CALLID, call_uuid);
        free(call_uuid);
    }

    if (crm_element_value(command, F_CIB_CALLOPTS) == NULL) {
        crm_xml_add_int(command, F_CIB_CALLOPTS, 0);
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
    int timeout = client->remote->authenticated ? -1 : 1000;

    crm_trace("Remote %s message received for client %s",
              pcmk__client_type_str(PCMK__CLIENT_TYPE(client)),
              pcmk__client_name(client));

#ifdef HAVE_GNUTLS_GNUTLS_H
    if ((PCMK__CLIENT_TYPE(client) == pcmk__client_tls)
        && !(client->remote->tls_handshake_complete)) {

        int rc = pcmk__read_handshake_data(client);

        if (rc == EAGAIN) {
            /* No more data is available at the moment. Just return for now;
             * we'll get invoked again once the client sends more.
             */
            return 0;
        } else if (rc != pcmk_rc_ok) {
            return -1;
        }

        crm_debug("TLS handshake with remote CIB client completed");
        client->remote->tls_handshake_complete = TRUE;
        if (client->remote->auth_timeout) {
            g_source_remove(client->remote->auth_timeout);
        }

        // Require the client to authenticate within this time
        client->remote->auth_timeout = g_timeout_add(REMOTE_AUTH_TIMEOUT,
                                                     remote_auth_timeout_cb,
                                                     client);
        return 0;
    }
#endif

    rc = pcmk__read_remote_message(client->remote, timeout);

    /* must pass auth before we will process anything else */
    if (client->remote->authenticated == FALSE) {
        xmlNode *reg;
        const char *user = NULL;

        command = pcmk__remote_message_xml(client->remote);
        if (cib_remote_auth(command) == FALSE) {
            free_xml(command);
            return -1;
        }

        crm_notice("Remote CIB client connection accepted");
        client->remote->authenticated = TRUE;
        g_source_remove(client->remote->auth_timeout);
        client->remote->auth_timeout = 0;
        client->name = crm_element_value_copy(command, "name");

        user = crm_element_value(command, "user");
        if (user) {
            client->user = strdup(user);
        }

        /* send ACK */
        reg = create_xml_node(NULL, "cib_result");
        crm_xml_add(reg, F_CIB_OPERATION, CRM_OP_REGISTER);
        crm_xml_add(reg, F_CIB_CLIENTID, client->id);
        pcmk__remote_send_xml(client->remote, reg);
        free_xml(reg);
        free_xml(command);
    }

    command = pcmk__remote_message_xml(client->remote);
    while (command) {
        crm_trace("Remote client message received");
        cib_handle_remote_msg(client, command);
        free_xml(command);
        command = pcmk__remote_message_xml(client->remote);
    }

    if (rc == ENOTCONN) {
        crm_trace("Remote CIB client disconnected while reading from it");
        return -1;
    }

    return 0;
}

#ifdef HAVE_PAM
static int
construct_pam_passwd(int num_msg, const struct pam_message **msg,
                     struct pam_response **response, void *data)
{
    int count = 0;
    struct pam_response *reply;
    char *string = (char *)data;

    CRM_CHECK(data, return PAM_CONV_ERR);
    CRM_CHECK(num_msg == 1, return PAM_CONV_ERR);       /* We only want to handle one message */

    reply = calloc(1, sizeof(struct pam_response));
    CRM_ASSERT(reply != NULL);

    for (count = 0; count < num_msg; ++count) {
        switch (msg[count]->msg_style) {
            case PAM_TEXT_INFO:
                crm_info("PAM: %s", msg[count]->msg);
                break;
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                reply[count].resp_retcode = 0;
                reply[count].resp = string;     /* We already made a copy */
            case PAM_ERROR_MSG:
                /* In theory we'd want to print this, but then
                 * we see the password prompt in the logs
                 */
                /* crm_err("PAM error: %s", msg[count]->msg); */
                break;
            default:
                crm_err("Unhandled conversation type: %d", msg[count]->msg_style);
                goto bail;
        }
    }

    *response = reply;
    reply = NULL;

    return PAM_SUCCESS;

  bail:
    for (count = 0; count < num_msg; ++count) {
        if (reply[count].resp != NULL) {
            switch (msg[count]->msg_style) {
                case PAM_PROMPT_ECHO_ON:
                case PAM_PROMPT_ECHO_OFF:
                    /* Erase the data - it contained a password */
                    while (*(reply[count].resp)) {
                        *(reply[count].resp)++ = '\0';
                    }
                    free(reply[count].resp);
                    break;
            }
            reply[count].resp = NULL;
        }
    }
    free(reply);
    reply = NULL;

    return PAM_CONV_ERR;
}
#endif

int
authenticate_user(const char *user, const char *passwd)
{
#ifndef HAVE_PAM
    gboolean pass = TRUE;
#else
    int rc = 0;
    gboolean pass = FALSE;
    const void *p_user = NULL;

    struct pam_conv p_conv;
    struct pam_handle *pam_h = NULL;
    static const char *pam_name = NULL;

    if (pam_name == NULL) {
        pam_name = getenv("CIB_pam_service");
    }
    if (pam_name == NULL) {
        pam_name = "login";
    }

    p_conv.conv = construct_pam_passwd;
    p_conv.appdata_ptr = strdup(passwd);

    rc = pam_start(pam_name, user, &p_conv, &pam_h);
    if (rc != PAM_SUCCESS) {
        crm_err("Could not initialize PAM: %s (%d)", pam_strerror(pam_h, rc), rc);
        goto bail;
    }

    rc = pam_authenticate(pam_h, 0);
    if (rc != PAM_SUCCESS) {
        crm_err("Authentication failed for %s: %s (%d)", user, pam_strerror(pam_h, rc), rc);
        goto bail;
    }

    /* Make sure we authenticated the user we wanted to authenticate.
     * Since we also run as non-root, it might be worth pre-checking
     * the user has the same EID as us, since that the only user we
     * can authenticate.
     */
    rc = pam_get_item(pam_h, PAM_USER, &p_user);
    if (rc != PAM_SUCCESS) {
        crm_err("Internal PAM error: %s (%d)", pam_strerror(pam_h, rc), rc);
        goto bail;

    } else if (p_user == NULL) {
        crm_err("Unknown user authenticated.");
        goto bail;

    } else if (!pcmk__str_eq(p_user, user, pcmk__str_casei)) {
        crm_err("User mismatch: %s vs. %s.", (const char *)p_user, (const char *)user);
        goto bail;
    }

    rc = pam_acct_mgmt(pam_h, 0);
    if (rc != PAM_SUCCESS) {
        crm_err("Access denied: %s (%d)", pam_strerror(pam_h, rc), rc);
        goto bail;
    }
    pass = TRUE;

  bail:
    pam_end(pam_h, rc);
#endif
    return pass;
}
