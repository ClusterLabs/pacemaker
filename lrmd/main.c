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
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>

#include <lrmd_private.h>

GMainLoop *mainloop = NULL;
qb_ipcs_service_t *ipcs = NULL;
stonith_t *stonith_api = NULL;
static gboolean enable_remote = FALSE;
static int remote_port = 0;
int lrmd_call_id = 0;

static void
stonith_connection_destroy_cb(stonith_t * st, stonith_event_t *e)
{
    stonith_api->state = stonith_disconnected;
    crm_err("LRMD lost STONITH connection");
    stonith_connection_failed();
}

stonith_t *
get_stonith_connection(void)
{
    if (stonith_api && stonith_api->state == stonith_disconnected) {
        stonith_api_delete(stonith_api);
        stonith_api = NULL;
    }

    if (!stonith_api) {
        int rc = 0;
        int tries = 10;

        stonith_api = stonith_api_new();
        do {
            rc = stonith_api->cmds->connect(stonith_api, "lrmd", NULL);
            if (rc == pcmk_ok) {
                stonith_api->cmds->register_notification(stonith_api,
                    T_STONITH_NOTIFY_DISCONNECT,
                    stonith_connection_destroy_cb);
                break;
            }
            sleep(1);
            tries--;
        } while (tries);

        if (rc) {
            crm_err("Unable to connect to stonith daemon to execute command. error: %s",
                    pcmk_strerror(rc));
            stonith_api_delete(stonith_api);
            stonith_api = NULL;
        }
    }
    return stonith_api;
}

static int32_t
lrmd_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if(crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
lrmd_ipc_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

static int32_t
lrmd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crm_client_t *client = crm_client_get(c);
    xmlNode *request = crm_ipcs_recv(client, data, size, &id, &flags);

    CRM_CHECK(client != NULL, crm_err("Invalid client");
              return FALSE);
    CRM_CHECK(client->id != NULL, crm_err("Invalid client: %p", client);
              return FALSE);

    CRM_CHECK(flags & crm_ipc_client_response, crm_err("Invalid client request: %p", client);
              return FALSE);

    if (!request) {
        return 0;
    }

    if (!client->name) {
        const char *value = crm_element_value(request, F_LRMD_CLIENTNAME);

        if (value == NULL) {
            client->name = crm_itoa(crm_ipcs_client_pid(c));
        } else {
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
    return 0;
}

static int32_t
lrmd_ipc_closed(qb_ipcs_connection_t * c)
{
    crm_client_t *client = crm_client_get(c);
    crm_trace("Connection %p", c);
    client_disconnect_cleanup(client->id);
    crm_client_destroy(client);
    return 0;
}

static void
lrmd_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

static struct qb_ipcs_service_handlers lrmd_ipc_callbacks = {
    .connection_accept = lrmd_ipc_accept,
    .connection_created = lrmd_ipc_created,
    .msg_process = lrmd_ipc_dispatch,
    .connection_closed = lrmd_ipc_closed,
    .connection_destroyed = lrmd_ipc_destroy
};

int lrmd_server_send_reply(crm_client_t *client, uint32_t id, xmlNode *reply)
{

    crm_trace("sending reply to client (%s) with msg id %d", client->id, id);
    switch (client->kind) {
        case CRM_CLIENT_IPC:
            return crm_ipcs_send(client, id, reply, FALSE);
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            return lrmd_tls_send_msg(client->remote, reply, id, "reply");
#endif
        default:
            crm_err("Unknown lrmd client type %d" , client->kind);
    }
    return -1;
}

int lrmd_server_send_notify(crm_client_t *client, xmlNode *msg)
{
    crm_trace("sending notify to client (%s)", client->id);
    switch (client->kind) {
        case CRM_CLIENT_IPC:
            if (client->ipcs == NULL) {
                crm_trace("Asked to send event to disconnected local client");
                return -1;
            }
            return crm_ipcs_send(client, 0, msg, TRUE);
#ifdef HAVE_GNUTLS_GNUTLS_H
        case CRM_CLIENT_TLS:
            if (client->remote == NULL) {
                crm_trace("Asked to send event to disconnected remote client");
                return -1;
            }
            return lrmd_tls_send_msg(client->remote, msg, 0, "notify");
#endif
        default:
            crm_err("Unknown lrmd client type %d" , client->kind);
    }
    return -1;
}

void
lrmd_shutdown(int nsig)
{
    crm_info("Terminating with  %d clients", crm_hash_table_size(client_connections));
    if (ipcs) {
        mainloop_del_ipc_server(ipcs);
    }
    crm_exit(0);
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0,    '?', "\tThis text"},
    {"version", 0, 0,    '$', "\tVersion information"  },
    {"verbose", 0, 0,    'V', "\tIncrease debug output"},
    {"tls_enable", 0, 0, 't', "\tEnable TLS connection."},
    {"tls_port", 1, 0,   'p', "\tTLS port to listen to, defaults to 1984"},

    {"logfile", 1, 0,    'l', "\tSend logs to the additional named logfile"},
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int rc = 0;
    int flag = 0;
    int index = 0;

    crm_log_init("lrmd", LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "[options]", long_options, "Daemon for controlling services confirming to different standards");

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1) {
            break;
        }

        switch (flag) {
            case 'l':
                crm_add_logfile(optarg);
                break;
            case 't':
                enable_remote = TRUE;
                break;
            case 'p':
                remote_port = atoi(optarg);
            case 'V':
                set_crm_log_level(crm_log_level+1);
                break;
            case '?':
            case '$':
                crm_help(flag, EX_OK);
                break;
            default:
                crm_help('?', EX_USAGE);
                break;
        }
    }

    if (enable_remote && !remote_port) {
        remote_port = DEFAULT_REMOTE_PORT;
    }

    rsc_list = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, free_rsc);
    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_LRMD, QB_IPC_SHM, &lrmd_ipc_callbacks);
    if (ipcs == NULL) {
        crm_err("Failed to create IPC server: shutting down and inhibiting respawn");
        crm_exit(100);
    }

    if (enable_remote) {
#ifdef HAVE_GNUTLS_GNUTLS_H
        if (lrmd_init_remote_tls_server(remote_port) < 0) {
            crm_err("Failed to create TLS server: shutting down and inhibiting respawn");
            crm_exit(100);
        }
#else
        crm_err("GNUTLS not enabled in this build, can not establish remote server");
        crm_exit(100);
#endif
    }

    mainloop_add_signal(SIGTERM, lrmd_shutdown);
    mainloop = g_main_new(FALSE);
    crm_info("Starting");
    g_main_run(mainloop);

    mainloop_del_ipc_server(ipcs);
    crm_client_cleanup();
    if (enable_remote) {
#ifdef HAVE_GNUTLS_GNUTLS_H
        lrmd_tls_server_destroy();
#endif
    }

    g_hash_table_destroy(rsc_list);

    if (stonith_api) {
        stonith_api->cmds->disconnect(stonith_api);
        stonith_api_delete(stonith_api);
    }

    return rc;
}
