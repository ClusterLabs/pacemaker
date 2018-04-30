/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include <libxml/parser.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster/internal.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>

#include <pacemaker-based.h>

#if HAVE_BZLIB_H
#  include <bzlib.h>
#endif

extern int init_remote_listener(int port, gboolean encrypted);
gboolean cib_shutdown_flag = FALSE;
int cib_status = pcmk_ok;

crm_cluster_t crm_cluster;

GMainLoop *mainloop = NULL;
const char *cib_root = NULL;
char *cib_our_uname = NULL;
gboolean preserve_status = FALSE;

/* volatile because it may be changed in a signal handler */
volatile gboolean cib_writes_enabled = TRUE;

int remote_fd = 0;
int remote_tls_fd = 0;

GHashTable *config_hash = NULL;
GHashTable *local_notify_queue = NULL;

int cib_init(void);
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

static void
log_cib_client(gpointer key, gpointer value, gpointer user_data)
{
    crm_info("Client %s", crm_client_name(value));
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {"per-action-cib", 0, 0, 'a', "\tAdvanced use only"},
    {"stand-alone",    0, 0, 's', "\tAdvanced use only"},
    {"disk-writes",    0, 0, 'w', "\tAdvanced use only"},
    {"cib-root",       1, 0, 'r', "\tAdvanced use only"},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int flag;
    int rc = 0;
    int index = 0;
    int argerr = 0;
    struct passwd *pwentry = NULL;

    crm_log_preinit(NULL, argc, argv);
    crm_set_options(NULL, "[options]",
                    long_options, "Daemon for storing and replicating the cluster configuration");

    crm_peer_init();

    mainloop_add_signal(SIGTERM, cib_shutdown);
    mainloop_add_signal(SIGPIPE, cib_enable_writes);

    cib_writer = mainloop_add_trigger(G_PRIORITY_LOW, write_cib_contents, NULL);

    while (1) {
        flag = crm_get_option(argc, argv, &index);
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
                crm_help(flag, CRM_EX_OK);
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
    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        cib_metadata();
        return CRM_EX_OK;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

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

    /* read local config file */
    cib_init();

    // This should not be reachable
    CRM_CHECK(crm_hash_table_size(client_connections) == 0,
              crm_warn("Not all clients gone at exit"));
    g_hash_table_foreach(client_connections, log_cib_client, NULL);
    cib_cleanup();

    crm_info("Done");
    return CRM_EX_OK;
}

void
cib_cleanup(void)
{
    crm_peer_destroy();
    if (local_notify_queue) {
        g_hash_table_destroy(local_notify_queue);
    }
    crm_client_cleanup();
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
        terminate_cib(__FUNCTION__, CRM_EX_DISCONNECT);
    }
}
#endif

static void
cib_peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    switch (type) {
        case crm_status_processes:
            if (cib_legacy_mode()
                && is_not_set(node->processes, crm_get_cluster_proc())) {

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
                && crm_hash_table_size(client_connections) == 0) {

                crm_info("No more peers");
                terminate_cib(__FUNCTION__, -1);
            }
            break;
    }
}

int
cib_init(void)
{
    if (is_corosync_cluster()) {
#if SUPPORT_COROSYNC
        crm_cluster.destroy = cib_cs_destroy;
        crm_cluster.cpg.cpg_deliver_fn = cib_cs_dispatch;
        crm_cluster.cpg.cpg_confchg_fn = pcmk_cpg_membership;
#endif
    }

    config_hash = crm_str_table_new();

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

    cib_ipc_servers_init(&ipcs_ro,
                         &ipcs_rw,
                         &ipcs_shm,
                         &ipc_ro_callbacks,
                         &ipc_rw_callbacks);

    if (stand_alone) {
        cib_is_master = TRUE;
    }

    /* Create the mainloop and run it... */
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_info("Starting %s mainloop", crm_system_name);
    g_main_loop_run(mainloop);

    /* If main loop returned, clean up and exit. We disconnect in case
     * terminate_cib() was called with fast=-1.
     */
    crm_cluster_disconnect(&crm_cluster);
    cib_ipc_servers_destroy(ipcs_ro, ipcs_rw, ipcs_shm);

    return crm_exit(CRM_EX_OK);
}

static bool
startCib(const char *filename)
{
    gboolean active = FALSE;
    xmlNode *cib = readCibXmlFile(cib_root, filename, !preserve_status);

    if (activateCibXml(cib, TRUE, "start") == 0) {
        int port = 0;
        const char *port_s = NULL;

        active = TRUE;

        cib_read_config(config_hash, cib);

        port_s = crm_element_value(cib, "remote-tls-port");
        if (port_s) {
            port = crm_parse_int(port_s, "0");
            remote_tls_fd = init_remote_listener(port, TRUE);
        }

        port_s = crm_element_value(cib, "remote-clear-port");
        if (port_s) {
            port = crm_parse_int(port_s, "0");
            remote_fd = init_remote_listener(port, FALSE);
        }

        crm_info("CIB Initialization completed successfully");
    }

    return active;
}
