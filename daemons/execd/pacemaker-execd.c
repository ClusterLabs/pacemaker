/*
 * Copyright 2012-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <signal.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/output_internal.h>
#include <crm/common/remote_internal.h>
#include <crm/lrmd_internal.h>

#include "pacemaker-execd.h"

#ifdef PCMK__COMPILE_REMOTE
#  define EXECD_TYPE "remote"
#  define EXECD_NAME "pacemaker-remoted"
#  define SUMMARY "resource agent executor daemon for Pacemaker Remote nodes"
#else
#  define EXECD_TYPE "local"
#  define EXECD_NAME "pacemaker-execd"
#  define SUMMARY "resource agent executor daemon for Pacemaker cluster nodes"
#endif

static GMainLoop *mainloop = NULL;
static qb_ipcs_service_t *ipcs = NULL;
static stonith_t *stonith_api = NULL;
int lrmd_call_id = 0;

static struct {
    gchar **log_files;
#ifdef PCMK__COMPILE_REMOTE
    gchar *port;
#endif  // PCMK__COMPILE_REMOTE
} options;

#ifdef PCMK__COMPILE_REMOTE
/* whether shutdown request has been sent */
static gboolean shutting_down = FALSE;

/* timer for waiting for acknowledgment of shutdown request */
static guint shutdown_ack_timer = 0;

static gboolean lrmd_exit(gpointer data);
#endif

static void
stonith_connection_destroy_cb(stonith_t * st, stonith_event_t * e)
{
    stonith_api->state = stonith_disconnected;
    stonith_connection_failed();
}

stonith_t *
get_stonith_connection(void)
{
    if (stonith_api && stonith_api->state == stonith_disconnected) {
        stonith_api_delete(stonith_api);
        stonith_api = NULL;
    }

    if (stonith_api == NULL) {
        int rc = pcmk_ok;

        stonith_api = stonith_api_new();
        if (stonith_api == NULL) {
            crm_err("Could not connect to fencer: API memory allocation failed");
            return NULL;
        }
        rc = stonith_api_connect_retry(stonith_api, crm_system_name, 10);
        if (rc != pcmk_ok) {
            crm_err("Could not connect to fencer in 10 attempts: %s "
                    CRM_XS " rc=%d", pcmk_strerror(rc), rc);
            stonith_api_delete(stonith_api);
            stonith_api = NULL;
        } else {
            stonith_api->cmds->register_notification(stonith_api,
                                                     T_STONITH_NOTIFY_DISCONNECT,
                                                     stonith_connection_destroy_cb);
        }
    }
    return stonith_api;
}

static int32_t
lrmd_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
lrmd_ipc_created(qb_ipcs_connection_t * c)
{
    pcmk__client_t *new_client = pcmk__find_client(c);

    crm_trace("Connection %p", c);
    CRM_ASSERT(new_client != NULL);
    /* Now that the connection is offically established, alert
     * the other clients a new connection exists. */

    notify_of_new_client(new_client);
}

static int32_t
lrmd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *request = pcmk__client_data2xml(client, data, &id, &flags);

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
            client->name = pcmk__itoa(pcmk__client_pid(c));
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

/*!
 * \internal
 * \brief Free a client connection, and exit if appropriate
 *
 * \param[in,out] client  Client connection to free
 */
void
lrmd_client_destroy(pcmk__client_t *client)
{
    pcmk__free_client(client);

#ifdef PCMK__COMPILE_REMOTE
    /* If we were waiting to shut down, we can now safely do so
     * if there are no more proxied IPC providers
     */
    if (shutting_down && (ipc_proxy_get_provider() == NULL)) {
        lrmd_exit(NULL);
    }
#endif
}

static int32_t
lrmd_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }

    crm_trace("Connection %p", c);
    client_disconnect_cleanup(client->id);
#ifdef PCMK__COMPILE_REMOTE
    ipc_proxy_remove_provider(client);
#endif
    lrmd_client_destroy(client);
    return 0;
}

static void
lrmd_ipc_destroy(qb_ipcs_connection_t * c)
{
    lrmd_ipc_closed(c);
    crm_trace("Connection %p", c);
}

static struct qb_ipcs_service_handlers lrmd_ipc_callbacks = {
    .connection_accept = lrmd_ipc_accept,
    .connection_created = lrmd_ipc_created,
    .msg_process = lrmd_ipc_dispatch,
    .connection_closed = lrmd_ipc_closed,
    .connection_destroyed = lrmd_ipc_destroy
};

// \return Standard Pacemaker return code
int
lrmd_server_send_reply(pcmk__client_t *client, uint32_t id, xmlNode *reply)
{
    crm_trace("Sending reply (%d) to client (%s)", id, client->id);
    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_ipc:
            return pcmk__ipc_send_xml(client, id, reply, FALSE);
#ifdef PCMK__COMPILE_REMOTE
        case pcmk__client_tls:
            return lrmd__remote_send_xml(client->remote, reply, id, "reply");
#endif
        default:
            crm_err("Could not send reply: unknown type for client %s "
                    CRM_XS " flags=%#llx",
                    pcmk__client_name(client), client->flags);
    }
    return ENOTCONN;
}

// \return Standard Pacemaker return code
int
lrmd_server_send_notify(pcmk__client_t *client, xmlNode *msg)
{
    crm_trace("Sending notification to client (%s)", client->id);
    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_ipc:
            if (client->ipcs == NULL) {
                crm_trace("Could not notify local client: disconnected");
                return ENOTCONN;
            }
            return pcmk__ipc_send_xml(client, 0, msg, crm_ipc_server_event);
#ifdef PCMK__COMPILE_REMOTE
        case pcmk__client_tls:
            if (client->remote == NULL) {
                crm_trace("Could not notify remote client: disconnected");
                return ENOTCONN;
            } else {
                return lrmd__remote_send_xml(client->remote, msg, 0, "notify");
            }
#endif
        default:
            crm_err("Could not notify client %s with unknown transport "
                    CRM_XS " flags=%#llx",
                    pcmk__client_name(client), client->flags);
    }
    return ENOTCONN;
}

/*!
 * \internal
 * \brief Clean up and exit immediately
 *
 * \param[in] data  Ignored
 *
 * \return Doesn't return
 * \note   This can be used as a timer callback.
 */
static gboolean
lrmd_exit(gpointer data)
{
    crm_info("Terminating with %d clients", pcmk__ipc_client_count());
    if (stonith_api) {
        stonith_api->cmds->remove_notification(stonith_api, T_STONITH_NOTIFY_DISCONNECT);
        stonith_api->cmds->disconnect(stonith_api);
        stonith_api_delete(stonith_api);
    }
    if (ipcs) {
        mainloop_del_ipc_server(ipcs);
    }

#ifdef PCMK__COMPILE_REMOTE
    execd_stop_tls_server();
    ipc_proxy_cleanup();
#endif

    pcmk__client_cleanup();
    g_hash_table_destroy(rsc_list);

    if (mainloop) {
        lrmd_drain_alerts(mainloop);
    }

    crm_exit(CRM_EX_OK);
    return FALSE;
}

/*!
 * \internal
 * \brief Request cluster shutdown if appropriate, otherwise exit immediately
 *
 * \param[in] nsig  Signal that caused invocation (ignored)
 */
static void
lrmd_shutdown(int nsig)
{
#ifdef PCMK__COMPILE_REMOTE
    pcmk__client_t *ipc_proxy = ipc_proxy_get_provider();

    /* If there are active proxied IPC providers, then we may be running
     * resources, so notify the cluster that we wish to shut down.
     */
    if (ipc_proxy) {
        if (shutting_down) {
            crm_notice("Waiting for cluster to stop resources before exiting");
            return;
        }

        crm_info("Sending shutdown request to cluster");
        if (ipc_proxy_shutdown_req(ipc_proxy) < 0) {
            crm_crit("Shutdown request failed, exiting immediately");

        } else {
            /* We requested a shutdown. Now, we need to wait for an
             * acknowledgement from the proxy host (which ensures the proxy host
             * supports shutdown requests), then wait for all proxy hosts to
             * disconnect (which ensures that all resources have been stopped).
             */
            shutting_down = TRUE;

            /* Stop accepting new proxy connections */
            execd_stop_tls_server();

            /* Older controller versions will never acknowledge our request, so
             * set a fairly short timeout to exit quickly in that case. If we
             * get the ack, we'll defuse this timer.
             */
            shutdown_ack_timer = g_timeout_add_seconds(20, lrmd_exit, NULL);

            /* Currently, we let the OS kill us if the clients don't disconnect
             * in a reasonable time. We could instead set a long timer here
             * (shorter than what the OS is likely to use) and exit immediately
             * if it pops.
             */
            return;
        }
    }
#endif
    lrmd_exit(NULL);
}

/*!
 * \internal
 * \brief Defuse short exit timer if shutting down
 */
void
handle_shutdown_ack(void)
{
#ifdef PCMK__COMPILE_REMOTE
    if (shutting_down) {
        crm_info("Received shutdown ack");
        if (shutdown_ack_timer > 0) {
            g_source_remove(shutdown_ack_timer);
            shutdown_ack_timer = 0;
        }
        return;
    }
#endif
    crm_debug("Ignoring unexpected shutdown ack");
}

/*!
 * \internal
 * \brief Make short exit timer fire immediately
 */
void
handle_shutdown_nack(void)
{
#ifdef PCMK__COMPILE_REMOTE
    if (shutting_down) {
        crm_info("Received shutdown nack");
        if (shutdown_ack_timer > 0) {
            g_source_remove(shutdown_ack_timer);
            shutdown_ack_timer = g_timeout_add(0, lrmd_exit, NULL);
        }
        return;
    }
#endif
    crm_debug("Ignoring unexpected shutdown nack");
}

static GOptionEntry entries[] = {
    { "logfile", 'l', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME_ARRAY,
      &options.log_files, "Send logs to the additional named logfile", NULL },

#ifdef PCMK__COMPILE_REMOTE

    { "port", 'p', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.port,
      "Port to listen on (defaults to " G_STRINGIFY(DEFAULT_REMOTE_PORT) ")", NULL },
#endif  // PCMK__COMPILE_REMOTE

    { NULL }
};

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv, char **envp)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    const char *option = NULL;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
#ifdef PCMK__COMPILE_REMOTE
    gchar **processed_args = pcmk__cmdline_preproc(argv, "lp");
#else
    gchar **processed_args = pcmk__cmdline_preproc(argv, "l");
#endif  // PCMK__COMPILE_REMOTE
    GOptionContext *context = build_arg_context(args, &output_group);

#ifdef PCMK__COMPILE_REMOTE
    // If necessary, create PID 1 now before any file descriptors are opened
    remoted_spawn_pidone(argc, argv, envp);
#endif

    crm_log_preinit(EXECD_NAME, argc, argv);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    // Open additional log files
    if (options.log_files != NULL) {
        for (gchar **fname = options.log_files; *fname != NULL; fname++) {
            rc = pcmk__add_logfile(*fname);

            if (rc != pcmk_rc_ok) {
                out->err(out, "Logging to %s is disabled: %s",
                         *fname, pcmk_rc_str(rc));
            }
        }
    }

    pcmk__cli_init_logging(EXECD_NAME, args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    option = pcmk__env_option(PCMK__ENV_LOGFACILITY);
    if (!pcmk__str_eq(option, PCMK__VALUE_NONE,
                      pcmk__str_casei|pcmk__str_null_matches)
        && !pcmk__str_eq(option, "/dev/null", pcmk__str_none)) {
        setenv("HA_LOGFACILITY", option, 1);  /* Used by the ocf_log/ha_log OCF macro */
    }

    option = pcmk__env_option(PCMK__ENV_LOGFILE);
    if (!pcmk__str_eq(option, PCMK__VALUE_NONE,
                      pcmk__str_casei|pcmk__str_null_matches)) {
        setenv("HA_LOGFILE", option, 1);      /* Used by the ocf_log/ha_log OCF macro */

        if (pcmk__env_option_enabled(crm_system_name, PCMK__ENV_DEBUG)) {
            setenv("HA_DEBUGLOG", option, 1); /* Used by the ocf_log/ha_debug OCF macro */
        }
    }

#ifdef PCMK__COMPILE_REMOTE
    if (options.port != NULL) {
        setenv("PCMK_remote_port", options.port, 1);
    }
#endif  // PCMK__COMPILE_REMOTE

    crm_notice("Starting Pacemaker " EXECD_TYPE " executor");

    /* The presence of this variable allegedly controls whether child
     * processes like httpd will try and use Systemd's sd_notify
     * API
     */
    unsetenv("NOTIFY_SOCKET");

    {
        // Temporary directory for resource agent use (leave owned by root)
        int rc = pcmk__build_path(CRM_RSCTMP_DIR, 0755);

        if (rc != pcmk_rc_ok) {
            crm_warn("Could not create resource agent temporary directory "
                     CRM_RSCTMP_DIR ": %s", pcmk_rc_str(rc));
        }
    }

    rsc_list = pcmk__strkey_table(NULL, free_rsc);
    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_LRMD, QB_IPC_SHM, &lrmd_ipc_callbacks);
    if (ipcs == NULL) {
        crm_err("Failed to create IPC server: shutting down and inhibiting respawn");
        exit_code = CRM_EX_FATAL;
        goto done;
    }

#ifdef PCMK__COMPILE_REMOTE
    if (lrmd_init_remote_tls_server() < 0) {
        crm_err("Failed to create TLS listener: shutting down and staying down");
        exit_code = CRM_EX_FATAL;
        goto done;
    }
    ipc_proxy_init();
#endif

    mainloop_add_signal(SIGTERM, lrmd_shutdown);
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker " EXECD_TYPE " executor successfully started and accepting connections");
    crm_notice("OCF resource agent search path is %s", OCF_RA_PATH);
    g_main_loop_run(mainloop);

    /* should never get here */
    lrmd_exit(NULL);

done:
    g_strfreev(options.log_files);
#ifdef PCMK__COMPILE_REMOTE
    g_free(options.port);
#endif  // PCMK__COMPILE_REMOTE

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(exit_code);
}
