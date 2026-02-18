/*
 * Copyright 2010-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // errno, ECONNREFUSED, EEXIST
#include <signal.h>                     // SIGHUP, SIGINT, SIGQUIT
#include <stdarg.h>                     // va_list
#include <stdbool.h>                    // true, false, bool
#include <stdlib.h>                     // setenv
#include <string.h>                     // strerror, strsignal
#include <sys/resource.h>               // rlimit, RLIMIT_*
#include <sys/stat.h>                   // mkdir
#include <sys/types.h>                  // gid_t, uid_t
#include <syslog.h>                     // LOG_INFO
#include <unistd.h>                     // chown, geteuid, sleep

#include <qb/qblog.h>                   // QB_XS

#include <crm_config.h>                 // SUPPORT_COROSYNC, BUILD_VERSION
#include <crm/common/ipc.h>             // pcmk_ipc_is_connected
#include <crm/common/ipc_pacemakerd.h>  // pcmk_pacemakerd_api_shutdown
#include <crm/common/mainloop.h>        // mainloop_*
#include <crm/common/options.h>         // PCMK_VALUE_*
#include <crm/common/results.h>         // crm_exit_t, CRM_EX_*, pcmk_rc_*
#include <crm/common/xml.h>             // PCMK_XA_*, PCMK_XE_*
#include <crm/crm.h>                    // CRM_FEATURE_SET, crm_system_name

#include "pacemakerd.h"
#if SUPPORT_COROSYNC
#include "pcmkd_corosync.h"                 // cluster_{dis,}connect_cfg
#endif

#define SUMMARY "pacemakerd - primary Pacemaker daemon that launches and monitors all subsidiary Pacemaker daemons"

struct {
    gboolean features;
    gboolean foreground;
    gboolean shutdown;
    gboolean standby;
} options;

static pcmk__output_t *out = NULL;

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

PCMK__OUTPUT_ARGS("features")
static int
pacemakerd_features(pcmk__output_t *out, va_list args) {
    out->info(out, "Pacemaker %s (Build: %s)\n Supporting v%s: %s", PACEMAKER_VERSION,
              BUILD_VERSION, CRM_FEATURE_SET, CRM_FEATURES);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("features")
static int
pacemakerd_features_xml(pcmk__output_t *out, va_list args) {
    gchar **feature_list = g_strsplit(CRM_FEATURES, " ", 0);

    pcmk__output_xml_create_parent(out, PCMK_XE_PACEMAKERD,
                                   PCMK_XA_VERSION, PACEMAKER_VERSION,
                                   PCMK_XA_BUILD, BUILD_VERSION,
                                   PCMK_XA_FEATURE_SET, CRM_FEATURE_SET,
                                   NULL);
    out->begin_list(out, NULL, NULL, PCMK_XE_FEATURES);

    for (char **s = feature_list; *s != NULL; s++) {
        pcmk__output_create_xml_text_node(out, PCMK_XE_FEATURE, *s);
    }

    out->end_list(out);

    pcmk__output_xml_pop_parent(out);

    g_strfreev(feature_list);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "features", "default", pacemakerd_features },
    { "features", "xml", pacemakerd_features_xml },

    { NULL, NULL, NULL }
};

static gboolean
pid_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    return TRUE;
}

static gboolean
standby_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    options.standby = TRUE;
    pcmk__set_env_option(PCMK__ENV_NODE_START_STATE, PCMK_VALUE_STANDBY, false);
    return TRUE;
}

static GOptionEntry entries[] = {
    { "features", 'F', 0, G_OPTION_ARG_NONE, &options.features,
      "Display full version and list of features Pacemaker was built with",
      NULL },
    { "foreground", 'f', 0, G_OPTION_ARG_NONE, &options.foreground,
      "(Ignored) Pacemaker always runs in the foreground",
      NULL },
    { "pid-file", 'p', 0, G_OPTION_ARG_CALLBACK, pid_cb,
      "(Ignored) Daemon pid file location",
      "FILE" },
    { "shutdown", 'S', 0, G_OPTION_ARG_NONE, &options.shutdown,
      "Instruct Pacemaker to shutdown on this machine",
      NULL },
    { "standby", 's', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, standby_cb,
      "Start node in standby state",
      NULL },

    { NULL }
};

static void
pcmk_ignore(int nsig)
{
    pcmk__info("Ignoring signal %s (%d)", strsignal(nsig), nsig);
}

static void
pcmk_sigquit(int nsig)
{
    pcmk__panic("Received SIGQUIT");
}

static void
pacemakerd_chown(const char *path, uid_t uid, gid_t gid)
{
    int rc = chown(path, uid, gid);

    if (rc < 0) {
        pcmk__warn("Cannot change the ownership of %s to user " CRM_DAEMON_USER
                   " and gid %d: %s",
                   path, gid, pcmk_rc_str(errno));
    }
}

static void
create_pcmk_dirs(void)
{
    uid_t pcmk_uid = 0;
    gid_t pcmk_gid = 0;

    const char *dirs[] = {
        PCMK__PERSISTENT_DATA_DIR,  // core/blackbox/scheduler/CIB files
        CRM_CORE_DIR,               // core files
        CRM_BLACKBOX_DIR,           // blackbox dumps
        PCMK_SCHEDULER_INPUT_DIR,   // scheduler inputs
        CRM_CONFIG_DIR,             // the Cluster Information Base (CIB)
        // Don't build PCMK__OCF_TMP_DIR the executor will do it
        NULL
    };

    if (pcmk__daemon_user(&pcmk_uid, &pcmk_gid) != pcmk_rc_ok) {
        pcmk__err("Cluster user " CRM_DAEMON_USER " does not exist, aborting "
                  "Pacemaker startup");
        crm_exit(CRM_EX_NOUSER);
    }

    // Used by some resource agents
    if ((mkdir(CRM_STATE_DIR, 0750) < 0) && (errno != EEXIST)) {
        pcmk__warn("Could not create directory " CRM_STATE_DIR ": %s",
                   pcmk_rc_str(errno));
    } else {
        pacemakerd_chown(CRM_STATE_DIR, pcmk_uid, pcmk_gid);
    }

    for (int i = 0; dirs[i] != NULL; ++i) {
        int rc = pcmk__build_path(dirs[i], 0750);

        if (rc != pcmk_rc_ok) {
            pcmk__warn("Could not create directory %s: %s", dirs[i],
                       pcmk_rc_str(rc));
        } else {
            pacemakerd_chown(dirs[i], pcmk_uid, pcmk_gid);
        }
    }
}

static void
remove_core_file_limit(void)
{
    struct rlimit cores;

    // Get current limits
    if (getrlimit(RLIMIT_CORE, &cores) < 0) {
        pcmk__notice("Unable to check system core file limits (consider "
                     "ensuring the size is unlimited): %s",
                     strerror(errno));
        return;
    }

    // Check whether core dumps are disabled
    if (cores.rlim_max == 0) {
        if (geteuid() != 0) { // Yes, and there's nothing we can do about it
            pcmk__notice("Core dumps are disabled (consider enabling them)");
            return;
        }
        cores.rlim_max = RLIM_INFINITY; // Yes, but we're root, so enable them
    }

    // Raise soft limit to hard limit (if not already done)
    if (cores.rlim_cur != cores.rlim_max) {
        cores.rlim_cur = cores.rlim_max;
        if (setrlimit(RLIMIT_CORE, &cores) < 0) {
            pcmk__notice("Unable to raise system limit on core file size "
                         "(consider doing so manually): %s",
                         strerror(errno));
            return;
        }
    }

    if (cores.rlim_cur == RLIM_INFINITY) {
        pcmk__trace("Core file size is unlimited");
    } else {
        pcmk__trace("Core file size is limited to %llu bytes",
                    (unsigned long long) cores.rlim_cur);
    }
}

static void
pacemakerd_event_cb(pcmk_ipc_api_t *pacemakerd_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    pcmk_pacemakerd_api_reply_t *reply = event_data;

    switch (event_type) {
        case pcmk_ipc_event_reply:
            break;

        default:
            return;
    }

    if (status != CRM_EX_OK) {
        out->err(out, "Bad reply from pacemakerd: %s", crm_exit_str(status));
        return;
    }

    if (reply->reply_type != pcmk_pacemakerd_reply_shutdown) {
        out->err(out, "Unknown reply type %d from pacemakerd",
                 reply->reply_type);
    }
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, entries);
    return context;
}

static int
handle_old_instance(gboolean shutdown)
{
    pcmk_ipc_api_t *old_instance = NULL;
    bool old_instance_connected = false;

    int rc = pcmk_rc_ok;

    pcmk__debug("Checking for existing Pacemaker instance");

    rc = pcmk_new_ipc_api(&old_instance, pcmk_ipc_pacemakerd);
    if (old_instance == NULL) {
        out->err(out, "Could not check for existing pacemakerd: %s", pcmk_rc_str(rc));
        return rc;
    }

    pcmk_register_ipc_callback(old_instance, pacemakerd_event_cb, NULL);
    rc = pcmk__connect_ipc(old_instance, pcmk_ipc_dispatch_sync, 2);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("No existing %s instance found: %s",
                    pcmk_ipc_name(old_instance, true), pcmk_rc_str(rc));
        rc = pcmk_rc_ok;
    }

    old_instance_connected = pcmk_ipc_is_connected(old_instance);

    if (shutdown) {
        if (old_instance_connected) {
            rc = pcmk_pacemakerd_api_shutdown(old_instance, crm_system_name);
            pcmk_dispatch_ipc(old_instance);

            if (rc != pcmk_rc_ok) {
                goto done;
            }

            /* We get the ACK immediately, and the response right after that,
             * but it might take a while for pacemakerd to get around to
             * shutting down.  Wait for that to happen (with 30-minute timeout).
             */
            for (int i = 0; i < 900; i++) {
                if (!pcmk_ipc_is_connected(old_instance)) {
                    rc = pcmk_rc_ok;
                    goto done;
                }

                sleep(2);
            }

            rc = ETIMEDOUT;
            goto done;

        } else {
            out->err(out, "Could not request shutdown "
                     "of existing Pacemaker instance: %s", pcmk_rc_str(rc));
            rc = ECONNREFUSED;
            goto done;
        }

    } else if (old_instance_connected) {
        pcmk__err("Aborting start-up because active Pacemaker instance found");
        rc = pcmk_rc_already;
    }

done:
    pcmk_free_ipc_api(old_instance);
    return rc;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "p");
    GOptionContext *context = build_arg_context(args, &output_group);

    subdaemon_check_progress = time(NULL);

    setenv("LC_ALL", "C", 1); // Ensure logs are in a common language

    crm_log_preinit(NULL, argc, argv);
    mainloop_add_signal(SIGHUP, pcmk_ignore);
    mainloop_add_signal(SIGQUIT, pcmk_sigquit);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pcmk__register_messages(out, fmt_functions);

    if (options.features) {
        out->message(out, "features");
        exit_code = CRM_EX_OK;
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    if (options.shutdown) {
        pcmk__cli_init_logging(PCMK__SERVER_PACEMAKERD, args->verbosity);
    } else {
        crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    }

    rc = handle_old_instance(options.shutdown);
    if ((rc == pcmk_rc_ok) && options.shutdown) {
        goto done;
    } else if (rc == pcmk_rc_already) {
        exit_code = CRM_EX_FATAL;
        goto done;
    } else if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        goto done;
    }

    /* Don't allow any accidental output after this point. */
    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        g_clear_pointer(&out, pcmk__output_free);
    }

#if SUPPORT_COROSYNC
    if (pacemakerd_read_config() == FALSE) {
        crm_exit(CRM_EX_UNAVAILABLE);
    }
#endif

    // OCF shell functions and cluster-glue need facility under different name
    {
        const char *facility = pcmk__env_option(PCMK__ENV_LOGFACILITY);

        if (!pcmk__str_eq(facility, PCMK_VALUE_NONE,
                          pcmk__str_casei|pcmk__str_null_matches)) {
            pcmk__set_env_option("LOGFACILITY", facility, true);
        }
    }

    pcmk__notice("Starting Pacemaker " PACEMAKER_VERSION " "
                 QB_XS " build=" BUILD_VERSION " features:" CRM_FEATURES);
    mainloop = g_main_loop_new(NULL, FALSE);

    remove_core_file_limit();
    create_pcmk_dirs();
    pacemakerd_ipc_init();

#if SUPPORT_COROSYNC
    /* Allows us to block shutdown */
    if (!cluster_connect_cfg()) {
        exit_code = CRM_EX_PROTOCOL;
        goto done;
    }
#endif

    if (pcmk__locate_sbd() > 0) {
        running_with_sbd = true;
    }

    switch (find_and_track_existing_processes()) {
        case pcmk_rc_ok:
            break;
        case pcmk_rc_ipc_unauthorized:
            exit_code = CRM_EX_CANTCREAT;
            goto done;
        default:
            exit_code = CRM_EX_FATAL;
            goto done;
    };

    mainloop_add_signal(SIGTERM, pcmk_shutdown);
    mainloop_add_signal(SIGINT, pcmk_shutdown);

    if ((running_with_sbd) && pcmk__get_sbd_sync_resource_startup()) {
        pcmk__notice("Waiting for startup-trigger from SBD");
        pacemakerd_state = PCMK__VALUE_WAIT_FOR_PING;
        startup_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, init_children_processes, NULL);
    } else {
        if (running_with_sbd) {
            pcmk__warn("Enabling SBD_SYNC_RESOURCE_STARTUP would (if supported "
                       "by your SBD version) improve reliability of "
                       "interworking between SBD & pacemaker.");
        }
        pacemakerd_state = PCMK__VALUE_STARTING_DAEMONS;
        init_children_processes(NULL);
    }

    pcmk__notice("Pacemaker daemon successfully started and accepting "
                 "connections");
    g_main_loop_run(mainloop);
    pacemakerd_ipc_cleanup();
    pacemakerd_unregister_handlers();

    g_main_loop_unref(mainloop);
#if SUPPORT_COROSYNC
    cluster_disconnect_cfg();
#endif

done:
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
