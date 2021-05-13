/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "pacemakerd.h"

#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <crm/crm.h>  /* indirectly: CRM_EX_* */
#include <crm/msg_xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipc_pacemakerd.h>
#include <crm/cluster/internal.h>
#include <crm/cluster.h>

static void
pcmk_ignore(int nsig)
{
    crm_info("Ignoring signal %s (%d)", strsignal(nsig), nsig);
}

static void
pcmk_sigquit(int nsig)
{
    pcmk__panic(__func__);
}

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "shutdown", no_argument, NULL, 'S',
        "\tInstruct Pacemaker to shutdown on this machine", pcmk__option_default
    },
    {
        "features", no_argument, NULL, 'F',
        "\tDisplay full version and list of features Pacemaker was built with",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdditional Options:", pcmk__option_default
    },
    {
        "foreground", no_argument, NULL, 'f',
        "\t(Ignored) Pacemaker always runs in the foreground",
        pcmk__option_default
    },
    {
        "pid-file", required_argument, NULL, 'p',
        "\t(Ignored) Daemon pid file location", pcmk__option_default
    },
    {
        "standby", no_argument, NULL, 's',
        "\tStart node in standby state", pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

static void
mcp_chown(const char *path, uid_t uid, gid_t gid)
{
    int rc = chown(path, uid, gid);

    if (rc < 0) {
        crm_warn("Cannot change the ownership of %s to user %s and gid %d: %s",
                 path, CRM_DAEMON_USER, gid, pcmk_strerror(errno));
    }
}

static void
create_pcmk_dirs(void)
{
    uid_t pcmk_uid = 0;
    gid_t pcmk_gid = 0;

    const char *dirs[] = {
        CRM_PACEMAKER_DIR, // core/blackbox/scheduler/CIB files
        CRM_CORE_DIR,      // core files
        CRM_BLACKBOX_DIR,  // blackbox dumps
        PE_STATE_DIR,      // scheduler inputs
        CRM_CONFIG_DIR,    // the Cluster Information Base (CIB)
        // Don't build CRM_RSCTMP_DIR, pacemaker-execd will do it
        NULL
    };

    if (pcmk_daemon_user(&pcmk_uid, &pcmk_gid) < 0) {
        crm_err("Cluster user %s does not exist, aborting Pacemaker startup",
                CRM_DAEMON_USER);
        crm_exit(CRM_EX_NOUSER);
    }

    // Used by some resource agents
    if ((mkdir(CRM_STATE_DIR, 0750) < 0) && (errno != EEXIST)) {
        crm_warn("Could not create directory " CRM_STATE_DIR ": %s",
                 pcmk_rc_str(errno));
    } else {
        mcp_chown(CRM_STATE_DIR, pcmk_uid, pcmk_gid);
    }

    for (int i = 0; dirs[i] != NULL; ++i) {
        int rc = pcmk__build_path(dirs[i], 0750);

        if (rc != pcmk_rc_ok) {
            crm_warn("Could not create directory %s: %s",
                     dirs[i], pcmk_rc_str(rc));
        } else {
            mcp_chown(dirs[i], pcmk_uid, pcmk_gid);
        }
    }
}

static void
remove_core_file_limit(void)
{
    struct rlimit cores;
    int rc = getrlimit(RLIMIT_CORE, &cores);

    if (rc < 0) {
        crm_warn("Cannot determine current maximum core file size: %s",
                 strerror(errno));
        return;
    }

    if ((cores.rlim_max == 0) && (geteuid() == 0)) {
        cores.rlim_max = RLIM_INFINITY;
    } else {
        crm_info("Maximum core file size is %llu bytes",
                 (unsigned long long) cores.rlim_max);
    }
    cores.rlim_cur = cores.rlim_max;

    rc = setrlimit(RLIMIT_CORE, &cores);
    if (rc < 0) {
        crm_warn("Cannot raise system limit on core file size "
                 "(consider doing so manually)");
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
        fprintf(stderr, "Bad reply from pacemakerd: %s", crm_exit_str(status));
        return;
    }

    if (reply->reply_type != pcmk_pacemakerd_reply_shutdown) {
        fprintf(stderr, "Unknown reply type %d from pacemakerd",
                reply->reply_type);
    }
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    int flag;
    int argerr = 0;

    int option_index = 0;
    bool old_instance_connected = false;
    gboolean shutdown = FALSE;

    pcmk_ipc_api_t *old_instance = NULL;
    qb_ipcs_service_t *ipcs = NULL;

    crm_log_preinit(NULL, argc, argv);
    pcmk__set_cli_options(NULL, "[options]", long_options,
                          "primary Pacemaker daemon that launches and "
                          "monitors all subsidiary Pacemaker daemons");
    mainloop_add_signal(SIGHUP, pcmk_ignore);
    mainloop_add_signal(SIGQUIT, pcmk_sigquit);

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'f':
                /* Legacy */
                break;
            case 'p':
                break;
            case 's':
                pcmk__set_env_option("node_start_state", "standby");
                break;
            case '$':
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'S':
                shutdown = TRUE;
                break;
            case 'F':
                printf("Pacemaker %s (Build: %s)\n Supporting v%s: %s\n", PACEMAKER_VERSION, BUILD_VERSION,
                       CRM_FEATURE_SET, CRM_FEATURES);
                crm_exit(CRM_EX_OK);
            default:
                printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }
    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }


    setenv("LC_ALL", "C", 1);

    pcmk__set_env_option("mcp", "true");

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    crm_debug("Checking for existing Pacemaker instance");

    rc = pcmk_new_ipc_api(&old_instance, pcmk_ipc_pacemakerd);
    if (old_instance == NULL) {
        fprintf(stderr, "Could not connect to pacemakerd: %s",
                pcmk_rc_str(rc));
        crm_exit(pcmk_rc2exitc(rc));
    }

    pcmk_register_ipc_callback(old_instance, pacemakerd_event_cb, NULL);
    rc = pcmk_connect_ipc(old_instance, pcmk_ipc_dispatch_sync);
    old_instance_connected = pcmk_ipc_is_connected(old_instance);

    if (shutdown) {
        if (old_instance_connected) {
            rc = pcmk_pacemakerd_api_shutdown(old_instance, crm_system_name);
            pcmk_dispatch_ipc(old_instance);
            pcmk_free_ipc_api(old_instance);
            crm_exit(pcmk_rc2exitc(rc));
        } else {
            crm_err("Could not request shutdown of existing "
                    "Pacemaker instance: %s", strerror(errno));
            pcmk_free_ipc_api(old_instance);
            crm_exit(CRM_EX_DISCONNECT);
        }

    } else if (old_instance_connected) {
        pcmk_free_ipc_api(old_instance);
        crm_err("Aborting start-up because active Pacemaker instance found");
        crm_exit(CRM_EX_FATAL);
    }

    pcmk_free_ipc_api(old_instance);

#ifdef SUPPORT_COROSYNC
    if (mcp_read_config() == FALSE) {
        crm_exit(CRM_EX_UNAVAILABLE);
    }
#endif

    // OCF shell functions and cluster-glue need facility under different name
    {
        const char *facility = pcmk__env_option("logfacility");

        if (facility && !pcmk__str_eq(facility, "none", pcmk__str_casei)) {
            setenv("HA_LOGFACILITY", facility, 1);
        }
    }

    crm_notice("Starting Pacemaker %s "CRM_XS" build=%s features:%s",
               PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    mainloop = g_main_loop_new(NULL, FALSE);

    remove_core_file_limit();
    create_pcmk_dirs();
    pcmk__serve_pacemakerd_ipc(&ipcs, &mcp_ipc_callbacks);

#ifdef SUPPORT_COROSYNC
    /* Allows us to block shutdown */
    if (!cluster_connect_cfg()) {
        crm_exit(CRM_EX_PROTOCOL);
    }
#endif

    if (pcmk__locate_sbd() > 0) {
        setenv("PCMK_watchdog", "true", 1);
        running_with_sbd = TRUE;
    } else {
        setenv("PCMK_watchdog", "false", 1);
    }

    switch (find_and_track_existing_processes()) {
        case pcmk_rc_ok:
            break;
        case pcmk_rc_ipc_unauthorized:
            crm_exit(CRM_EX_CANTCREAT);
        default:
            crm_exit(CRM_EX_FATAL);
    };

    mainloop_add_signal(SIGTERM, pcmk_shutdown);
    mainloop_add_signal(SIGINT, pcmk_shutdown);

    if ((running_with_sbd) && pcmk__get_sbd_sync_resource_startup()) {
        crm_notice("Waiting for startup-trigger from SBD.");
        pacemakerd_state = XML_PING_ATTR_PACEMAKERDSTATE_WAITPING;
        startup_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, init_children_processes, NULL);
    } else {
        if (running_with_sbd) {
            crm_warn("Enabling SBD_SYNC_RESOURCE_STARTUP would (if supported "
                     "by your SBD version) improve reliability of "
                     "interworking between SBD & pacemaker.");
        }
        pacemakerd_state = XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS;
        init_children_processes(NULL);
    }

    crm_notice("Pacemaker daemon successfully started and accepting connections");
    g_main_loop_run(mainloop);

    if (ipcs) {
        crm_trace("Closing IPC server");
        mainloop_del_ipc_server(ipcs);
        ipcs = NULL;
    }

    g_main_loop_unref(mainloop);
#ifdef SUPPORT_COROSYNC
    cluster_disconnect_cfg();
#endif
    crm_exit(CRM_EX_OK);
}
