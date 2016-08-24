/*
 * Copyright (c) 2015 David Vossel <davidvossel@gmail.com>
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

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>

extern GHashTable *proxy_table;
void lrmd_internal_set_proxy_callback(lrmd_t * lrmd, void *userdata, void (*callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg));

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"help",             0, 0, '?'},
    {"verbose",          0, 0, 'V', "\t\tPrint out logs and events to screen"},
    {"quiet",            0, 0, 'Q', "\t\tSuppress all output to screen"},
    {"tls",              1, 0, 'S', "\t\tSet tls host to contact"},
    {"tls-port",         1, 0, 'p', "\t\tUse custom tls port"},
    {"node",             1, 0, 'n', "\tNode name to use for ipc proxy"},
    {"api-call",         1, 0, 'c', "\tDirectly relates to lrmd api functions"},
    {"-spacer-",         1, 0, '-', "\nParameters for api-call option"},
    {"action",           1, 0, 'a'},
    {"rsc-id",           1, 0, 'r'},
    {"provider",         1, 0, 'P'},
    {"class",            1, 0, 'C'},
    {"type",             1, 0, 'T'},
    {"timeout",          1, 0, 't'},
    {"param-key",        1, 0, 'k'},
    {"param-val",        1, 0, 'v'},
    
    {"-spacer-",         1, 0, '-'},
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static int wait_poke = 0;
static int exec_call_id = 0;
static gboolean client_start(gpointer user_data);
static void try_connect(void);

static struct {
    int verbose;
    int quiet;
    int print;
    int interval;
    int timeout;
    int port;
    const char *node_name;
    const char *api_call;
    const char *rsc_id;
    const char *provider;
    const char *class;
    const char *type;
    const char *action;
    const char *listen;
    const char *tls_host;
    lrmd_key_value_t *params;
} options;

GMainLoop *mainloop = NULL;
lrmd_t *lrmd_conn = NULL;

static void
client_exit(int rc)
{
    lrmd_api_delete(lrmd_conn);
    if (proxy_table) {
        g_hash_table_destroy(proxy_table); proxy_table = NULL;
    }
    exit(rc);
}

static void
client_shutdown(int nsig)
{
    lrmd_api_delete(lrmd_conn);
    lrmd_conn = NULL;
}

static void
read_events(lrmd_event_data_t * event)
{
    if (wait_poke && event->type == lrmd_event_poke) {
        client_exit(PCMK_OCF_OK);
    }
    if ((event->call_id == exec_call_id) && (event->type == lrmd_event_exec_complete)) {
        if (event->output) {
            crm_info("%s", event->output);
        }
        if (event->exit_reason) {
            fprintf(stderr, "%s%s\n", PCMK_OCF_REASON_PREFIX, event->exit_reason);
        }
        client_exit(event->rc);
    }
}

static gboolean
timeout_err(gpointer data)
{
    crm_err("timed out in remote_client");
    client_exit(PCMK_OCF_TIMEOUT);

    return FALSE;
}

static void
connection_events(lrmd_event_data_t * event)
{
    int rc = event->connection_rc;

    if (event->type != lrmd_event_connect) {
        /* ignore */
        return;
    }

    if (!rc) {
        client_start(NULL);
        return;
    } else {
        sleep(1);
        try_connect();
    }
}

static void
try_connect(void)
{
    int tries = 10;
    static int num_tries = 0;
    int rc = 0;

    lrmd_conn->cmds->set_callback(lrmd_conn, connection_events);
    for (; num_tries < tries; num_tries++) {
        rc = lrmd_conn->cmds->connect_async(lrmd_conn, "lrmd", 10000);

        if (!rc) {
            num_tries++;
            return;             /* we'll hear back in async callback */
        }
        sleep(1);
    }

    crm_err("Failed to connect to pacemaker remote.");
    client_exit(PCMK_OCF_UNKNOWN_ERROR);
}

static gboolean
client_start(gpointer user_data)
{
    int rc = 0;

    if (!lrmd_conn->cmds->is_connected(lrmd_conn)) {
        try_connect();
        /* async connect -- this function will get called back into */
        return 0;
    }

    lrmd_conn->cmds->set_callback(lrmd_conn, read_events);


    if (safe_str_eq(options.api_call, "ipc_debug")) {
        /* Do nothing, leave connection up just for debugging ipc proxy */
        return 0;
    }
    if (options.timeout) {
        g_timeout_add(options.timeout, timeout_err, NULL);
    }

    if (safe_str_eq(options.api_call, "metadata")) {
        char *output = NULL;

        rc = lrmd_conn->cmds->get_metadata(lrmd_conn,
                                           options.class,
                                           options.provider, options.type, &output, 0);
        if (rc == pcmk_ok) {
            printf("%s", output);
            free(output);
            client_exit(PCMK_OCF_OK);
        }
        client_exit(PCMK_OCF_UNKNOWN_ERROR);

    } else if (safe_str_eq(options.api_call, "poke")) {
        rc = lrmd_conn->cmds->poke_connection(lrmd_conn);
        if (rc != pcmk_ok) {
            client_exit(PCMK_OCF_UNKNOWN_ERROR);
        }
        wait_poke = 1;
    } else {
        lrmd_rsc_info_t *rsc_info = NULL;

        rsc_info = lrmd_conn->cmds->get_rsc_info(lrmd_conn, options.rsc_id, 0);
        if (rsc_info == NULL) {
            rc = lrmd_conn->cmds->register_rsc(lrmd_conn, options.rsc_id,
                                               options.class, options.provider, options.type, 0);

            if (rc != 0){
                crm_err("failed to register resource %s with pacemaker_remote. rc: %d", options.rsc_id, rc);
                client_exit(1);
            }
        }
        lrmd_free_rsc_info(rsc_info);

        rc = lrmd_conn->cmds->exec(lrmd_conn,
                                   options.rsc_id,
                                   options.action,
                                   NULL,
                                   options.interval,
                                   options.timeout,
                                   0, 0, options.params);

        if (rc > 0) {
            exec_call_id = rc;
        } else {
            crm_err("execution of rsc %s failed. rc = %d", options.rsc_id, rc);
            client_exit(PCMK_OCF_UNKNOWN_ERROR);
        }
    }

    return 0;
}

static int
remote_proxy_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata)
{
    /* Async responses from cib and friends back to clients via pacemaker_remoted */
    xmlNode *xml = NULL;
    remote_proxy_t *proxy = userdata;
    uint32_t flags;

    xml = string2xml(buffer);
    if (xml == NULL) {
        crm_warn("Received a NULL msg from IPC service.");
        return 1;
    }

    flags = crm_ipc_buffer_flags(proxy->ipc);
    if (flags & crm_ipc_proxied_relay_response) {
        crm_trace("Passing response back to %.8s on %s: %.200s - request id: %d", proxy->session_id, proxy->node_name, buffer, proxy->last_request_id);
        remote_proxy_relay_response(lrmd_conn, proxy->session_id, xml, proxy->last_request_id);
        proxy->last_request_id = 0;

    } else {
        crm_trace("Passing event back to %.8s on %s: %.200s", proxy->session_id, proxy->node_name, buffer);
        remote_proxy_relay_event(lrmd_conn, proxy->session_id, xml);
    }
    free_xml(xml);
    return 1;
}

static void
remote_proxy_disconnected(void *userdata)
{
    remote_proxy_t *proxy = userdata;

    crm_trace("destroying %p", userdata);

    proxy->source = NULL;
    proxy->ipc = NULL;

    remote_proxy_notify_destroy(lrmd_conn, proxy->session_id);
    g_hash_table_remove(proxy_table, proxy->session_id);
}

static remote_proxy_t *
remote_proxy_new(const char *node_name, const char *session_id, const char *channel)
{
    static struct ipc_client_callbacks proxy_callbacks = {
        .dispatch = remote_proxy_dispatch_internal,
        .destroy = remote_proxy_disconnected
    };
    remote_proxy_t *proxy = calloc(1, sizeof(remote_proxy_t));

    proxy->node_name = strdup(node_name);
    proxy->session_id = strdup(session_id);

    if (safe_str_eq(channel, CRM_SYSTEM_CRMD)) {
        proxy->is_local = TRUE;
    } else {
        proxy->source = mainloop_add_ipc_client(channel, G_PRIORITY_LOW, 0, proxy, &proxy_callbacks);
        proxy->ipc = mainloop_get_ipc_client(proxy->source);

        if (proxy->source == NULL) {
            remote_proxy_free(proxy);
            return NULL;
        }
    }

    crm_trace("created proxy session ID %s", proxy->session_id);
    g_hash_table_insert(proxy_table, proxy->session_id, proxy);

    return proxy;
}

static void
remote_proxy_cb(lrmd_t *lrmd, void *userdata, xmlNode *msg)
{
    const char *op = crm_element_value(msg, F_LRMD_IPC_OP);
    const char *session = crm_element_value(msg, F_LRMD_IPC_SESSION);
    int msg_id = 0;

    /* sessions are raw ipc connections to IPC,
     * all we do is proxy requests/responses exactly
     * like they are given to us at the ipc level. */

    CRM_CHECK(op != NULL, return);
    CRM_CHECK(session != NULL, return);

    crm_element_value_int(msg, F_LRMD_IPC_MSG_ID, &msg_id);

    /* This is msg from remote ipc client going to real ipc server */
    if (safe_str_eq(op, LRMD_IPC_OP_NEW)) {
        const char *channel = crm_element_value(msg, F_LRMD_IPC_IPC_SERVER);

        CRM_CHECK(channel != NULL, return);

        if (remote_proxy_new(options.node_name, session, channel) == NULL) {
            remote_proxy_notify_destroy(lrmd, session);
        }
        crm_info("new remote proxy client established to %s, session id %s", channel, session);
    } else if (safe_str_eq(op, LRMD_IPC_OP_DESTROY)) {
        remote_proxy_end_session(session);

    } else if (safe_str_eq(op, LRMD_IPC_OP_REQUEST)) {
        int flags = 0;
        xmlNode *request = get_message_xml(msg, F_LRMD_IPC_MSG);
        const char *name = crm_element_value(msg, F_LRMD_IPC_CLIENT);
        remote_proxy_t *proxy = g_hash_table_lookup(proxy_table, session);

        CRM_CHECK(request != NULL, return);

        if (proxy == NULL) {
            /* proxy connection no longer exists */
            remote_proxy_notify_destroy(lrmd, session);
            return;
        } else if ((proxy->is_local == FALSE) && (crm_ipc_connected(proxy->ipc) == FALSE)) {
            remote_proxy_end_session(session);
            return;
        }
        proxy->last_request_id = 0;
        crm_element_value_int(msg, F_LRMD_IPC_MSG_FLAGS, &flags);
        crm_xml_add(request, XML_ACL_TAG_ROLE, "pacemaker-remote");

#if ENABLE_ACL
        CRM_ASSERT(options.node_name);
        crm_acl_get_set_user(request, F_LRMD_IPC_USER, options.node_name);
#endif

        if (is_set(flags, crm_ipc_proxied)) {
            int rc = crm_ipc_send(proxy->ipc, request, flags, 5000, NULL);

            if(rc < 0) {
                xmlNode *op_reply = create_xml_node(NULL, "nack");

                crm_err("Could not relay %s request %d from %s to %s for %s: %s (%d)",
                         op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name, pcmk_strerror(rc), rc);

                /* Send a n'ack so the caller doesn't block */
                crm_xml_add(op_reply, "function", __FUNCTION__);
                crm_xml_add_int(op_reply, "line", __LINE__);
                crm_xml_add_int(op_reply, "rc", rc);
                remote_proxy_relay_response(lrmd, session, op_reply, msg_id);
                free_xml(op_reply);

            } else {
                crm_trace("Relayed %s request %d from %s to %s for %s",
                          op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name);
                proxy->last_request_id = msg_id;
            }
        }
    } else {
        crm_err("Unknown proxy operation: %s", op);
    }
}

int
main(int argc, char **argv)
{
    int option_index = 0;
    int argerr = 0;
    int flag;
    char *key = NULL;
    char *val = NULL;
    gboolean use_tls = FALSE;
    crm_trigger_t *trig;

    crm_set_options(NULL, "mode [options]", long_options,
                    "Inject commands into the lrmd and watch for events\n");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'V':
                options.verbose = 1;
                break;
            case 'Q':
                options.quiet = 1;
                options.verbose = 0;
                break;
            case 'n':
                options.node_name = optarg;
                break;
            case 'c':
                options.api_call = optarg;
                break;
            case 'a':
                options.action = optarg;
                break;
            case 'r':
                options.rsc_id = optarg;
                break;
            case 'P':
                options.provider = optarg;
                break;
            case 'C':
                options.class = optarg;
                break;
            case 'T':
                options.type = optarg;
                break;
            case 't':
                if(optarg) {
                    options.timeout = atoi(optarg);
                }
                break;
            case 'k':
                key = optarg;
                if (key && val) {
                    options.params = lrmd_key_value_add(options.params, key, val);
                    key = val = NULL;
                }
                break;
            case 'v':
                val = optarg;
                if (key && val) {
                    options.params = lrmd_key_value_add(options.params, key, val);
                    key = val = NULL;
                }
                break;
            case 'S':
                options.tls_host = optarg;
                use_tls = TRUE;
                break;
            case 'p':
                if(optarg) {
                    options.port = atoi(optarg);
                }
                use_tls = TRUE;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }
    if (optind > argc) {
        ++argerr;
    }
    crm_log_init("remote_client", LOG_INFO, FALSE, options.verbose ? TRUE : FALSE, argc, argv, FALSE);

    /* if we can't perform an api_call or listen for events, 
     * there is nothing to do */
    if (!options.api_call ) {
        crm_err("Nothing to be done.  Please specify 'api-call'");
        return PCMK_OCF_UNKNOWN_ERROR;
    }

    if (!options.timeout ) {
        options.timeout = 20000;
    }

    if (use_tls) {
        if (options.node_name == NULL) {
            crm_err("\"node\" option required when tls is in use.");
            return PCMK_OCF_UNKNOWN_ERROR;
        }
        proxy_table =
            g_hash_table_new_full(crm_strcase_hash, crm_strcase_equal, NULL, remote_proxy_free);
        lrmd_conn = lrmd_remote_api_new(NULL, options.tls_host ? options.tls_host : "localhost", options.port);
        lrmd_internal_set_proxy_callback(lrmd_conn, NULL,  remote_proxy_cb);
    } else {
        lrmd_conn = lrmd_api_new();
    }
    trig = mainloop_add_trigger(G_PRIORITY_HIGH, client_start, NULL);
    mainloop_set_trigger(trig);
    mainloop_add_signal(SIGTERM, client_shutdown);

    mainloop = g_main_new(FALSE);
    g_main_run(mainloop);

    client_exit(0);
    return 0;
}
