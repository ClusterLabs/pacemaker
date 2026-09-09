/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // ENOTCONN
#include <signal.h>                 // SIGTERM
#include <stdbool.h>                // true
#include <stdlib.h>                 // unsetenv
#include <syslog.h>                 // LOG_INFO

#include <glib.h>                   // G_OPTION_*
#include <qb/qblog.h>               // QB_XS
#include <qb/qbloop.h>              // QB_LOOP_MED

#include <crm/common/ipc.h>         // crm_ipc_flags
#include <crm/common/logging.h>     // crm_log_init, crm_log_preinit
#include <crm/common/mainloop.h>    // mainloop_add_signal
#include <crm/common/options.h>     // PCMK_VALUE_NONE
#include <crm/common/results.h>     // pcmk_rc_str, pcmk_rc_*, crm_exit
#include <crm/crm.h>                // crm_system_name
#include <crm/fencing/internal.h>   // stonith__api_free, stonith__api_connect_retry
#include <crm/lrmd_internal.h>      // lrmd__remote_send_xml
#include <crm/stonith-ng.h>         // stonith_s, stonith_t, stonith_state

#include "pacemaker-execd.h"

#ifdef PCMK__COMPILE_REMOTE
#  define EXECD_TYPE "remote"
#  define EXECD_NAME PCMK__SERVER_REMOTED
#  define SUMMARY "resource agent executor daemon for Pacemaker Remote nodes"
#else
#  define EXECD_TYPE "local"
#  define EXECD_NAME PCMK__SERVER_EXECD
#  define SUMMARY "resource agent executor daemon for Pacemaker cluster nodes"
#endif

static bool execd_quit(pcmk__daemon_t *d);

static pcmk__daemon_fns_t fns = {
    .quit = execd_quit,
};

static pcmk__daemon_ipc_fns_t ipc_fns = {
    .cleanup = pcmk__daemon_ipc_cleanup,
    .closed = execd_ipc_closed,
    .created = execd_ipc_created,
    .dispatch = execd_ipc_dispatch,
    .init = pcmk__daemon_ipc_init,
    .invalid_msg = execd_invalid_msg,
};

pcmk__daemon_t execd = {
    .type = pcmk_ipc_execd,
    .ec = CRM_EX_OK,
    .priority = QB_LOOP_MED,
    .op = PCMK__XA_LRMD_OP,
    .fns = &fns,
    .ipc_fns = &ipc_fns,
};

static stonith_t *fencer_api = NULL;

static gchar **processed_args = NULL;
static GOptionContext *context = NULL;

static struct {
    gchar **log_files;
#ifdef PCMK__COMPILE_REMOTE
    gchar *port;
#endif  // PCMK__COMPILE_REMOTE
} options;

static void
fencer_connection_destroy_cb(stonith_t *st, stonith_event_t *e)
{
    fencer_api->state = stonith_disconnected;
    execd_fencer_connection_failed();
}

stonith_t *
execd_get_fencer_connection(void)
{
    if ((fencer_api != NULL) && (fencer_api->state == stonith_disconnected)) {
        g_clear_pointer(&fencer_api, stonith__api_free);
    }

    if (fencer_api == NULL) {
        int rc = pcmk_ok;

        fencer_api = stonith__api_new();

        rc = stonith__api_connect_retry(fencer_api, crm_system_name, 10);
        if (rc != pcmk_rc_ok) {
            pcmk__err("Could not connect to fencer in 10 attempts: %s "
                      QB_XS " rc=%d",
                      pcmk_rc_str(rc), rc);
            g_clear_pointer(&fencer_api, stonith__api_free);

        } else {
            stonith_api_operations_t *cmds = fencer_api->cmds;

            cmds->register_notification(fencer_api,
                                        PCMK__VALUE_ST_NOTIFY_DISCONNECT,
                                        fencer_connection_destroy_cb);
        }
    }
    return fencer_api;
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
    /* If we were waiting to shut down, we can now safely do so if there are
     * no more proxied IPC providers
     *
     * This kills the main loop and cleans everything up.  Control flow will
     * eventually make it back up to lrmd_remote_client_destroy or
     * execd_ipc_closed, which were both called directly from the main loop.
     * After that, we'll return to the done label in main() and finish
     * shutting down.
     */
    if (execd.shutting_down && (ipc_proxy_get_provider() == NULL)) {
        // Unset shutting_down so pcmk__daemon_quit does something
        execd.shutting_down = false;
        pcmk__daemon_quit(&execd, CRM_EX_OK);
    }
#endif
}

// \return Standard Pacemaker return code
int
lrmd_server_send_reply(pcmk__client_t *client, uint32_t id, xmlNode *reply)
{
    pcmk__trace("Sending reply (%d) to client (%s)", id, client->id);
    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_ipc:
            return pcmk__ipc_send_xml(client, id, reply, crm_ipc_flags_none);
#ifdef PCMK__COMPILE_REMOTE
        case pcmk__client_tls:
            return lrmd__remote_send_xml(client->remote, reply, id, "reply");
#endif
        default:
            pcmk__err("Could not send reply: unknown type for client %s "
                      QB_XS " flags=%#llx",
                      pcmk__client_name(client), client->flags);
    }
    return ENOTCONN;
}

// \return Standard Pacemaker return code
int
lrmd_server_send_notify(pcmk__client_t *client, xmlNode *msg)
{
    pcmk__trace("Sending notification to client (%s)", client->id);
    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_ipc:
            if (client->ipcs == NULL) {
                pcmk__trace("Could not notify local client: disconnected");
                return ENOTCONN;
            }
            return pcmk__ipc_send_xml(client, 0, msg, crm_ipc_server_event);
#ifdef PCMK__COMPILE_REMOTE
        case pcmk__client_tls:
            if (client->remote == NULL) {
                pcmk__trace("Could not notify remote client: disconnected");
                return ENOTCONN;
            } else {
                return lrmd__remote_send_xml(client->remote, msg, 0, "notify");
            }
#endif
        default:
            pcmk__err("Could not notify client %s with unknown transport "
                      QB_XS " flags=%#llx",
                      pcmk__client_name(client), client->flags);
    }
    return ENOTCONN;
}

static void
execd_cleanup(void)
{
    const unsigned int nclients = pcmk__ipc_client_count();

    pcmk__info("Terminating with %d client%s", nclients,
               pcmk__plural_s(nclients));
    stonith__api_free(fencer_api);
    execd.ipc_fns->cleanup(&execd);

#ifdef PCMK__COMPILE_REMOTE
    execd_stop_tls_server();
    ipc_proxy_cleanup();
#endif

    g_clear_pointer(&rsc_list, g_hash_table_destroy);
}

/*!
 * \internal
 * \brief Log a shutdown acknowledgment
 */
void
handle_shutdown_ack(void)
{
#ifdef PCMK__COMPILE_REMOTE
    if (execd.shutting_down) {
        pcmk__info("IPC proxy provider acknowledged shutdown request");
        return;
    }
#endif
    pcmk__debug("Ignoring unexpected shutdown acknowledgment from IPC proxy "
                "provider");
}

#ifdef PCMK__COMPILE_REMOTE
static bool
execd_quit_on_nack(pcmk__daemon_t *d)
{
    lrmd_drain_alerts(execd.mainloop);
    return true;
}
#endif

/*!
 * \internal
 * \brief Handle rejection of shutdown request
 *
 * \return Standard Pacemaker return code
 */
int
handle_shutdown_nack(void)
{
#ifdef PCMK__COMPILE_REMOTE
    if (execd.shutting_down) {
        pcmk__info("Exiting immediately after IPC proxy provider indicated no "
                   "resources will be stopped");

        /* Avoid calling the original quit function because that can potentially
         * just lead us right back to this point.  However, we still want to do
         * everything in pcmk__daemon_quit (most importantly, kill the main loop)
         * as well as drain alerts.
         */
        execd.shutting_down = false;
        execd.fns->quit = execd_quit_on_nack;
        pcmk__daemon_quit(&execd, CRM_EX_OK);

        return ESHUTDOWN;
    }
#endif

    pcmk__debug("Ignoring unexpected shutdown rejection from IPC proxy "
                "provider");
    return pcmk_rc_ok;
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

static void
execd_cleanup_cmdline(void)
{
    g_clear_pointer(&processed_args, g_strfreev);
    g_clear_pointer(&context, g_option_context_free);
    g_clear_pointer(&options.log_files, g_strfreev);
#ifdef PCMK__COMPILE_REMOTE
    g_clear_pointer(&options.port, g_free);
#endif
}

static bool
execd_quit(pcmk__daemon_t *d)
{
#ifdef PCMK__COMPILE_REMOTE
    pcmk__client_t *ipc_proxy = ipc_proxy_get_provider();

    if (ipc_proxy == NULL) {
        goto done;
    }

    /* If there are active proxied IPC providers, then we may be running
     * resources, so notify the cluster that we wish to shut down.
     */
    if (execd.shutting_down) {
        pcmk__notice("Waiting for cluster to stop resources before exiting");
        return false;
    }

    pcmk__info("Sending shutdown request to cluster");
    if (ipc_proxy_shutdown_req(ipc_proxy) < 0) {
        pcmk__crit("Shutdown request failed, exiting immediately");
        goto done;
    }

    /* We requested a shutdown. Now, we need to wait for an acknowledgement
     * from the proxy host, then wait for all proxy hosts to disconnect (which
     * ensures that all resources have been stopped).
     */
    execd.shutting_down = true;

    /* Stop accepting new proxy connections */
    execd_stop_tls_server();

    /* Currently, we let the OS kill us if the clients don't disconnect in a
     * reasonable time. We could instead set a long timer here (shorter than
     * what the OS is likely to use) and exit immediately if it pops.
     */
    return false;

done:
#endif

    lrmd_drain_alerts(execd.mainloop);
    return true;
}

/*!
 * \internal
 * \brief  Quit the main loop and set the exit code to \c CRM_EX_OK
 *
 * \param[in] nsig  Ignored
 *
 * \note This is a main loop signal handler function.
 */
static void
execd_shutdown(int nsig)
{
    pcmk__daemon_quit(&execd, CRM_EX_OK);
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;

    const char *option = NULL;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = NULL;

    atexit(execd_cleanup_cmdline);

#ifdef PCMK__COMPILE_REMOTE
    // If necessary, create PID 1 now before any file descriptors are opened
    remoted_spawn_pidone(argc, argv);
#endif

    args = pcmk__new_common_args(SUMMARY);
#ifdef PCMK__COMPILE_REMOTE
    processed_args = pcmk__cmdline_preproc(argv, "lp");
#else
    processed_args = pcmk__cmdline_preproc(argv, "l");
#endif  // PCMK__COMPILE_REMOTE
    context = build_arg_context(args, &output_group);

    crm_log_preinit(EXECD_NAME, argc, argv);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        execd.ec = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        execd.ec = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, execd.ec,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    // Open additional log files
    pcmk__add_logfiles(options.log_files, out);

    pcmk__cli_init_logging(EXECD_NAME, args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    // ocf_log() (in resource-agents) uses the capitalized env options below
    option = pcmk__env_option(PCMK__ENV_LOGFACILITY);
    if (!pcmk__str_eq(option, PCMK_VALUE_NONE,
                      pcmk__str_casei|pcmk__str_null_matches)
        && !pcmk__str_eq(option, "/dev/null", pcmk__str_none)) {

        pcmk__set_env_option("LOGFACILITY", option, true);
    }

    option = pcmk__env_option(PCMK__ENV_LOGFILE);
    if (!pcmk__str_eq(option, PCMK_VALUE_NONE,
                      pcmk__str_casei|pcmk__str_null_matches)) {
        pcmk__set_env_option("LOGFILE", option, true);

        if (pcmk__env_option_enabled(crm_system_name, PCMK__ENV_DEBUG)) {
            pcmk__set_env_option("DEBUGLOG", option, true);
        }
    }

#ifdef PCMK__COMPILE_REMOTE
    if (options.port != NULL) {
        pcmk__set_env_option(PCMK__ENV_REMOTE_PORT, options.port, false);
    }
#endif  // PCMK__COMPILE_REMOTE

    pcmk__notice("Starting Pacemaker " EXECD_TYPE " executor");

    /* The presence of this variable allegedly controls whether child
     * processes like httpd will try and use Systemd's sd_notify
     * API
     */
    unsetenv("NOTIFY_SOCKET");

    {
        // Temporary directory for resource agent use (leave owned by root)
        int rc = pcmk__build_path(PCMK__OCF_TMP_DIR, 0755);

        if (rc != pcmk_rc_ok) {
            pcmk__warn("Could not create resource agent temporary directory "
                       PCMK__OCF_TMP_DIR ": %s",
                       pcmk_rc_str(rc));
        }
    }

    rsc_list = pcmk__strkey_table(NULL, execd_free_rsc);

#ifdef PCMK__COMPILE_REMOTE
    if (lrmd_init_remote_tls_server() < 0) {
        pcmk__err("Failed to create TLS listener: shutting down and staying "
                  "down");
        execd.ec = CRM_EX_FATAL;
        goto done;
    }

    if (!ipc_proxy_init()) {
        goto done;
    }
#endif

    rc = pcmk__daemon_init(&execd, execd_handlers);
    if (rc != pcmk_rc_ok) {
        execd.ec = (rc == EIO) ? CRM_EX_FATAL : CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, execd.ec,
                    "Error initializing daemon object: %s",
                    pcmk_rc_str(rc));
        goto done;
    }

    mainloop_add_signal(SIGTERM, execd_shutdown);

    pcmk__daemon_run(&execd);

done:
    execd_cleanup();

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, execd.ec, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(execd.ec);
}
