/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <bzlib.h>
#include <sys/types.h>

#include <libxml/parser.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster/internal.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>

#include <pacemaker-based.h>

extern int init_remote_listener(int port, gboolean encrypted);
gboolean cib_shutdown_flag = FALSE;
int cib_status = pcmk_ok;

crm_cluster_t crm_cluster;

GMainLoop *mainloop = NULL;
const char *cib_root = NULL;
char *cib_our_uname = NULL;
static gboolean preserve_status = FALSE;

gboolean cib_writes_enabled = TRUE;

int remote_fd = 0;
int remote_tls_fd = 0;

GHashTable *config_hash = NULL;
GHashTable *local_notify_queue = NULL;

static void cib_init(void);
void cib_shutdown(int nsig);
static bool startCib(const char *filename);
extern int write_cib_contents(gpointer p);
void cib_cleanup(void);

static void
cib_enable_writes(int nsig)
{
    crm_info("(Re)enabling disk writes");
    cib_writes_enabled = TRUE;
}

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, 0, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "stand-alone", no_argument, NULL, 's',
        "\tAdvanced use only", pcmk__option_default
    },
    {
        "disk-writes", no_argument, NULL, 'w',
        "\tAdvanced use only", pcmk__option_default
    },
    {
        "cib-root", required_argument, NULL, 'r',
        "\tAdvanced use only", pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

int
main(int argc, char **argv)
{
    int flag;
    int rc = 0;
    int index = 0;
    int argerr = 0;
    struct passwd *pwentry = NULL;
    crm_ipc_t *old_instance = NULL;

    if( is_zh_language() ){
         setlocale(LC_MESSAGES, "zh_CN.UTF-8");
    }else{
         setlocale(LC_MESSAGES, "en_US.UTF-8");
    }
    bindtextdomain(PACKAGE_NAME, PACKAGE_LOCALEDIR);
    textdomain(PACKAGE_NAME);
    bind_textdomain_codeset(PACKAGE_NAME, "UTF-8");

    crm_log_preinit(NULL, argc, argv);
    pcmk__set_cli_options(NULL, "[options]", long_options,
                          "daemon for managing the configuration "
                          "of a Pacemaker cluster");

    mainloop_add_signal(SIGTERM, cib_shutdown);
    mainloop_add_signal(SIGPIPE, cib_enable_writes);

    cib_writer = mainloop_add_trigger(G_PRIORITY_LOW, write_cib_contents, NULL);

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 's':
                stand_alone = TRUE;
                preserve_status = TRUE;
                cib_writes_enabled = FALSE;

                pwentry = getpwnam(CRM_DAEMON_USER);
                CRM_CHECK(pwentry != NULL,
                          crm_perror(LOG_ERR, "Invalid uid (%s) specified", CRM_DAEMON_USER);
                          return CRM_EX_FATAL);

                rc = setgid(pwentry->pw_gid);
                if (rc < 0) {
                    crm_perror(LOG_ERR, "Could not set group to %d", pwentry->pw_gid);
                    return CRM_EX_FATAL;
                }

                rc = initgroups(CRM_DAEMON_USER, pwentry->pw_gid);
                if (rc < 0) {
                    crm_perror(LOG_ERR, "Could not setup groups for user %d", pwentry->pw_uid);
                    return CRM_EX_FATAL;
                }

                rc = setuid(pwentry->pw_uid);
                if (rc < 0) {
                    crm_perror(LOG_ERR, "Could not set user to %d", pwentry->pw_uid);
                    return CRM_EX_FATAL;
                }
                break;
            case '?':          /* Help message */
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'w':
                cib_writes_enabled = TRUE;
                break;
            case 'r':
                cib_root = optarg;
                break;
            case 'm':
                cib_metadata();
                return CRM_EX_OK;
            default:
                ++argerr;
                break;
        }
    }
    if (argc - optind == 1 && pcmk__str_eq("metadata", argv[optind], pcmk__str_casei)) {
        cib_metadata();
        return CRM_EX_OK;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    crm_notice("Starting Pacemaker CIB manager");

    old_instance = crm_ipc_new(PCMK__SERVER_BASED_RO, 0);
    if (crm_ipc_connect(old_instance)) {
        /* IPC end-point already up */
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("pacemaker-based is already active, aborting startup");
        crm_exit(CRM_EX_OK);
    } else {
        /* not up or not authentic, we'll proceed either way */
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    if (cib_root == NULL) {
        cib_root = CRM_CONFIG_DIR;
    } else {
        crm_notice("Using custom config location: %s", cib_root);
    }

    if (pcmk__daemon_can_write(cib_root, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on %s", cib_root);
        fprintf(stderr, "ERROR: Bad permissions on %s (see logs for details)\n",
                cib_root);
        fflush(stderr);
        return CRM_EX_FATAL;
    }

    crm_peer_init();

    // Read initial CIB, connect to cluster, and start IPC servers
    cib_init();

    // Run the main loop
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker CIB manager successfully started and accepting connections");
    g_main_loop_run(mainloop);

    /* If main loop returned, clean up and exit. We disconnect in case
     * terminate_cib() was called with fast=-1.
     */
    crm_cluster_disconnect(&crm_cluster);
    pcmk__stop_based_ipc(ipcs_ro, ipcs_rw, ipcs_shm);
    crm_exit(CRM_EX_OK);
}

void
cib_cleanup(void)
{
    crm_peer_destroy();
    if (local_notify_queue) {
        g_hash_table_destroy(local_notify_queue);
    }
    pcmk__client_cleanup();
    g_hash_table_destroy(config_hash);
    free(cib_our_uname);
}

#if SUPPORT_COROSYNC
static void
cib_cs_dispatch(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }
    if (kind == crm_class_cluster) {
        xml = string2xml(data);
        if (xml == NULL) {
            crm_err("Invalid XML: '%.120s'", data);
            free(data);
            return;
        }
        crm_xml_add(xml, F_ORIG, from);
        /* crm_xml_add_int(xml, F_SEQ, wrapper->id); */
        cib_peer_callback(xml, NULL);
    }

    free_xml(xml);
    free(data);
}

static void
cib_cs_destroy(gpointer user_data)
{
    if (cib_shutdown_flag) {
        crm_info("Corosync disconnection complete");
    } else {
        crm_crit("Lost connection to cluster layer, shutting down");
        terminate_cib(__func__, CRM_EX_DISCONNECT);
    }
}
#endif

static void
cib_peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    switch (type) {
        case crm_status_processes:
            if (cib_legacy_mode()
                && !pcmk_is_set(node->processes, crm_get_cluster_proc())) {

                uint32_t old = data? *(const uint32_t *)data : 0;

                if ((node->processes ^ old) & crm_proc_cpg) {
                    crm_info("Attempting to disable legacy mode after %s left the cluster",
                             node->uname);
                    legacy_mode = FALSE;
                }
            }
            break;

        case crm_status_uname:
        case crm_status_nstate:
            if (cib_shutdown_flag && (crm_active_peers() < 2)
                && (pcmk__ipc_client_count() == 0)) {

                crm_info("No more peers");
                terminate_cib(__func__, -1);
            }
            break;
    }
}

static void
cib_init(void)
{
    if (is_corosync_cluster()) {
#if SUPPORT_COROSYNC
        crm_cluster.destroy = cib_cs_destroy;
        crm_cluster.cpg.cpg_deliver_fn = cib_cs_dispatch;
        crm_cluster.cpg.cpg_confchg_fn = pcmk_cpg_membership;
#endif
    }

    config_hash = pcmk__strkey_table(free, free);

    if (startCib("cib.xml") == FALSE) {
        crm_crit("Cannot start CIB... terminating");
        crm_exit(CRM_EX_NOINPUT);
    }

    if (stand_alone == FALSE) {
        if (is_corosync_cluster()) {
            crm_set_status_callback(&cib_peer_update_callback);
        }

        if (crm_cluster_connect(&crm_cluster) == FALSE) {
            crm_crit("Cannot sign in to the cluster... terminating");
            crm_exit(CRM_EX_FATAL);
        }
        cib_our_uname = crm_cluster.uname;

    } else {
        cib_our_uname = strdup("localhost");
    }

    pcmk__serve_based_ipc(&ipcs_ro, &ipcs_rw, &ipcs_shm, &ipc_ro_callbacks,
                          &ipc_rw_callbacks);

    if (stand_alone) {
        cib_is_master = TRUE;
    }
}

static bool
startCib(const char *filename)
{
    gboolean active = FALSE;
    xmlNode *cib = readCibXmlFile(cib_root, filename, !preserve_status);

    if (activateCibXml(cib, TRUE, "start") == 0) {
        int port = 0;

        active = TRUE;

        cib_read_config(config_hash, cib);

        pcmk__scan_port(crm_element_value(cib, "remote-tls-port"), &port);
        if (port >= 0) {
            remote_tls_fd = init_remote_listener(port, TRUE);
        }

        pcmk__scan_port(crm_element_value(cib, "remote-clear-port"), &port);
        if (port >= 0) {
            remote_fd = init_remote_listener(port, FALSE);
        }
    }
    return active;
}
