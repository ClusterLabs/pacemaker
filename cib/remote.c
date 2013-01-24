/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <crm/crm.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ip.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>

#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/common/xml.h>
#include <crm/cib/internal.h>

#include "callbacks.h"
/* #undef HAVE_PAM_PAM_APPL_H */
/* #undef HAVE_GNUTLS_GNUTLS_H */

#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
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
#  define DH_BITS 1024
gnutls_dh_params dh_params;
gnutls_anon_server_credentials anon_cred_s;
static void
debug_log(int level, const char *str)
{
    fputs(str, stderr);
}
#endif

#define REMOTE_AUTH_TIMEOUT 10000

int num_clients;
int authenticate_user(const char *user, const char *passwd);
int cib_remote_listen(gpointer data);
int cib_remote_msg(gpointer data);

static void
remote_connection_destroy(gpointer user_data)
{
    return;
}

#define ERROR_SUFFIX "  Shutting down remote listener"
int
init_remote_listener(int port, gboolean encrypted)
{
    int rc;
    int *ssock = NULL;
    struct sockaddr_in saddr;
    int optval;
    static struct mainloop_fd_callbacks remote_listen_fd_callbacks = 
        {
            .dispatch = cib_remote_listen,
            .destroy = remote_connection_destroy,
        };

    if (port <= 0) {
        /* dont start it */
        return 0;
    }

    if (encrypted) {
#ifndef HAVE_GNUTLS_GNUTLS_H
        crm_warn("TLS support is not available");
        return 0;
#else
        crm_notice("Starting a tls listener on port %d.", port);
        gnutls_global_init();
        /* gnutls_global_set_log_level (10); */
        gnutls_global_set_log_function(debug_log);
        gnutls_dh_params_init(&dh_params);
        gnutls_dh_params_generate2(dh_params, DH_BITS);
        gnutls_anon_allocate_server_credentials(&anon_cred_s);
        gnutls_anon_set_server_dh_params(anon_cred_s, dh_params);
#endif
    } else {
        crm_warn("Starting a plain_text listener on port %d.", port);
    }
#ifndef HAVE_PAM
    crm_warn("PAM is _not_ enabled!");
#endif

    /* create server socket */
    ssock = malloc(sizeof(int));
    *ssock = socket(AF_INET, SOCK_STREAM, 0);
    if (*ssock == -1) {
        crm_perror(LOG_ERR, "Can not create server socket." ERROR_SUFFIX);
        free(ssock);
        return -1;
    }

    /* reuse address */
    optval = 1;
    rc = setsockopt(*ssock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if(rc < 0) {
        crm_perror(LOG_INFO, "Couldn't allow the reuse of local addresses by our remote listener");
    }

    /* bind server socket */
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);
    if (bind(*ssock, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        crm_perror(LOG_ERR, "Can not bind server socket." ERROR_SUFFIX);
        close(*ssock);
        free(ssock);
        return -2;
    }
    if (listen(*ssock, 10) == -1) {
        crm_perror(LOG_ERR, "Can not start listen." ERROR_SUFFIX);
        close(*ssock);
        free(ssock);
        return -3;
    }

    mainloop_add_fd("cib-remote", G_PRIORITY_DEFAULT, *ssock, ssock, &remote_listen_fd_callbacks);

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
    if (group != NULL && crm_str_eq(grp, group->gr_name, TRUE)) {
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

        } else if (crm_str_eq(usr, member, TRUE)) {
            return TRUE;
        }
    };

    return FALSE;
}

static gboolean
cib_remote_auth(xmlNode *login)
{
    const char *user = NULL;
    const char *pass = NULL;
    const char *tmp = NULL;

    crm_log_xml_info(login, "Login: ");
    if (login == NULL) {
        return FALSE;
    }

    tmp = crm_element_name(login);
    if (safe_str_neq(tmp, "cib_command")) {
        crm_err("Wrong tag: %s", tmp);
        return FALSE;
    }

    tmp = crm_element_value(login, "op");
    if (safe_str_neq(tmp, "authenticate")) {
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
    crm_client_t *client = data;

    client->remote->auth_timeout = 0;

    if (client->remote->authenticated == TRUE) {
        return FALSE;
    }

    mainloop_del_fd(client->remote->source);
    crm_err("Remote client authentication timed out");

    return FALSE;
}
int
cib_remote_listen(gpointer data)
{
    int csock = 0;
    unsigned laddr;
    struct sockaddr_in addr;
    int ssock = *(int *)data;
    int flag;

    crm_client_t *new_client = NULL;

    static struct mainloop_fd_callbacks remote_client_fd_callbacks = 
        {
            .dispatch = cib_remote_msg,
            .destroy = cib_remote_connection_destroy,
        };

    /* accept the connection */
    laddr = sizeof(addr);
    csock = accept(ssock, (struct sockaddr *)&addr, &laddr);
    crm_debug("New %s connection from %s",
              ssock == remote_tls_fd ? "secure" : "clear-text", inet_ntoa(addr.sin_addr));

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

    if (ssock == remote_tls_fd) {
#ifdef HAVE_GNUTLS_GNUTLS_H
        /* create gnutls session for the server socket */
        new_client->remote->tls_session = crm_create_anon_tls_session(
            csock, GNUTLS_SERVER, anon_cred_s);

        if (new_client->remote->tls_session == NULL) {
            crm_err("TLS session creation failed");
            close(csock);
            return TRUE;
        }
#endif
    }

    num_clients++;

    crm_client_init();
    new_client = calloc(1, sizeof(crm_client_t));
    new_client->remote = calloc(1, sizeof(crm_remote_t));
    
    new_client->id = crm_generate_uuid();

    g_hash_table_insert(client_connections, new_client->id/* Should work */, new_client);
    
#if ENABLE_ACL
    new_client->user = strdup(user);
#endif

    /* clients have a few seconds to perform handshake. */
    new_client->remote->auth_timeout = g_timeout_add(
        REMOTE_AUTH_TIMEOUT, remote_auth_timeout_cb, new_client);

    if (ssock == remote_tls_fd) {
#ifdef HAVE_GNUTLS_GNUTLS_H
        new_client->kind = CRM_CLIENT_TLS;
#endif
    } else {
        new_client->kind = CRM_CLIENT_TCP;
        new_client->remote->tcp_socket = csock;
    }

    new_client->remote->source = mainloop_add_fd(
        "cib-remote-client", G_PRIORITY_DEFAULT, csock, new_client, &remote_client_fd_callbacks);

    return TRUE;
}

void
cib_remote_connection_destroy(gpointer user_data)
{
    crm_client_t *client = user_data;
    int csock = 0;

    if (client == NULL) {
        return;
    }

    crm_trace("Cleaning up after client disconnect: %s/%s",
              crm_str(client->name), client->id);

    num_clients--;
    crm_trace("Num unfree'd clients: %d", num_clients);

    if (client->kind == CRM_CLIENT_TLS) {
#ifdef HAVE_GNUTLS_GNUTLS_H
        if (client->remote->tls_session) {
            void *sock_ptr = gnutls_transport_get_ptr(*client->remote->tls_session);
            csock = GPOINTER_TO_INT(sock_ptr);
            if (client->remote->tls_handshake_complete) {
                gnutls_bye(*client->remote->tls_session, GNUTLS_SHUT_WR);
            }
            gnutls_deinit(*client->remote->tls_session);
            gnutls_free(client->remote->tls_session);
        }
#endif
    } else {
        csock = GPOINTER_TO_INT(client->remote->tls_session);
    }
    client->remote->tls_session = NULL;

    if (csock > 0) {
        close(csock);
    }

    crm_client_destroy(client);

    crm_trace("Freed the cib client");

    if (cib_shutdown_flag) {
        cib_shutdown(0);
    }
    return;
}

static void
cib_handle_remote_msg(crm_client_t *client, xmlNode *command)
{
    const char *value = NULL;

    value = crm_element_name(command);
    if (safe_str_neq(value, "cib_command")) {
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
            crm_trace("Callback channel for %s is %s", client->id, client->userdata);

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
#if ENABLE_ACL
    crm_xml_add(command, F_CIB_USER, client->user);
#endif

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

int
cib_remote_msg(gpointer data)
{
    xmlNode *command = NULL;
    crm_client_t *client = data;
    int disconnected = 0;
    int timeout = client->remote->authenticated ? -1 : 1000;

    crm_trace("%s callback", client->kind == CRM_CLIENT_TLS ? "secure" : "clear-text");

#ifdef HAVE_GNUTLS_GNUTLS_H
    if (client->kind == CRM_CLIENT_TLS && (client->remote->tls_handshake_complete == FALSE)) {
        int rc = 0;

        /* Muliple calls to handshake will be required, this callback
         * will be invoked once the client sends more handshake data. */
        do {
            rc = gnutls_handshake(*client->remote->tls_session);

            if (rc < 0 && rc != GNUTLS_E_AGAIN) {
                crm_err("Remote cib tls handshake failed");
                return -1;
            }
        } while (rc == GNUTLS_E_INTERRUPTED);

        if (rc == 0) {
            crm_debug("Remote cib tls handshake completed");
            client->remote->tls_handshake_complete = TRUE;
            if (client->remote->auth_timeout) {
                g_source_remove(client->remote->auth_timeout);
            }
            /* after handshake, clients must send auth in a few seconds */
            client->remote->auth_timeout = g_timeout_add(REMOTE_AUTH_TIMEOUT, remote_auth_timeout_cb, client);
        }
        return 0;
    }
#endif

    crm_remote_recv(client->remote, timeout, &disconnected);

    /* must pass auth before we will process anything else */
    if (client->remote->authenticated == FALSE) {
        xmlNode *reg;
#if ENABLE_ACL
        const char *user = NULL;
#endif
        command = crm_remote_parse_buffer(client->remote);
        if (cib_remote_auth(command) == FALSE) {
            free_xml(command);
            return -1;
        }

        crm_debug("remote connection authenticated successfully");
        client->remote->authenticated = TRUE;
        g_source_remove(client->remote->auth_timeout);
        client->remote->auth_timeout = 0;
        client->name = crm_element_value_copy(command, "name");

#if ENABLE_ACL
        user = crm_element_value(command, "user");
        if (user) {
           new_client->user = strdup(user);
        }
#endif

        /* send ACK */
        reg = create_xml_node(NULL, "cib_result");
        crm_xml_add(reg, F_CIB_OPERATION, CRM_OP_REGISTER);
        crm_xml_add(reg, F_CIB_CLIENTID, client->id);
        crm_remote_send(client->remote, reg);
        free_xml(reg);
        free_xml(command);
    }

    command = crm_remote_parse_buffer(client->remote);
    while (command) {
        crm_trace("command received");
        cib_handle_remote_msg(client, command);
        free_xml(command);
        command = crm_remote_parse_buffer(client->remote);
    }

    if (disconnected) {
        crm_trace("disconnected while receiving remote cib msg.");
        return -1;
    }

    return 0;
}

#ifdef HAVE_PAM
/* 
 * Useful Examples:
 *    http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html
 *    http://developer.apple.com/samplecode/CryptNoMore/index.html
 */
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
                crm_info("PAM: %s\n", msg[count]->msg);
                break;
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                reply[count].resp_retcode = 0;
                reply[count].resp = string;     /* We already made a copy */
            case PAM_ERROR_MSG:
                /* In theory we'd want to print this, but then
                 * we see the password prompt in the logs
                 */
                /* crm_err("PAM error: %s\n", msg[count]->msg); */
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

    } else if (safe_str_neq(p_user, user)) {
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
    rc = pam_end(pam_h, rc);
#endif
    return pass;
}
