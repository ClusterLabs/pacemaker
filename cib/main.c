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

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>

#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/common/mainloop.h>

#include <cibio.h>
#include <callbacks.h>
#include <pwd.h>

#if HAVE_LIBXML2
#  include <libxml/parser.h>
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#if HAVE_BZLIB_H
#  include <bzlib.h>
#endif

extern int init_remote_listener(int port, gboolean encrypted);
extern gboolean stand_alone;

gboolean cib_shutdown_flag = FALSE;
enum cib_errors cib_status = cib_ok;

#if SUPPORT_HEARTBEAT
oc_ev_t *cib_ev_token;
ll_cluster_t *hb_conn = NULL;
extern void oc_ev_special(const oc_ev_t *, oc_ev_class_t, int);
gboolean cib_register_ha(ll_cluster_t * hb_cluster, const char *client_name);
#endif

extern void terminate_cib(const char *caller, gboolean fast);

GMainLoop *mainloop = NULL;
const char *cib_root = CRM_CONFIG_DIR;
char *cib_our_uname = NULL;
gboolean preserve_status = FALSE;
gboolean cib_writes_enabled = TRUE;
int remote_fd = 0;
int remote_tls_fd = 0;

void usage(const char *cmd, int exit_status);
int cib_init(void);
void cib_shutdown(int nsig);
gboolean startCib(const char *filename);
extern int write_cib_contents(gpointer p);

GTRIGSource *cib_writer = NULL;
GHashTable *client_list = NULL;
GHashTable *config_hash = NULL;

char *channel1 = NULL;
char *channel2 = NULL;
char *channel3 = NULL;
char *channel4 = NULL;
char *channel5 = NULL;

#define OPTARGS	"maswr:V?"
void cib_cleanup(void);

static void
cib_enable_writes(int nsig)
{
    crm_info("(Re)enabling disk writes");
    cib_writes_enabled = TRUE;
}

static void
cib_diskwrite_complete(gpointer userdata, int status, int signo, int exitcode)
{
    if (exitcode != LSB_EXIT_OK || signo != 0 || status != 0) {
        crm_err("Disk write failed: status=%d, signo=%d, exitcode=%d", status, signo, exitcode);

        if (cib_writes_enabled) {
            crm_err("Disabling disk writes after write failure");
            cib_writes_enabled = FALSE;
        }

    } else {
        crm_trace("Disk write passed");
    }
}

static void
log_cib_client(gpointer key, gpointer value, gpointer user_data)
{
    cib_client_t *a_client = value;

    crm_info("Client %s", crm_str(a_client->name));
}

int
main(int argc, char **argv)
{
    int flag;
    int rc = 0;
    int argerr = 0;

#ifdef HAVE_GETOPT_H
    int option_index = 0;
/* *INDENT-OFF* */
	static struct option long_options[] = {
		{"per-action-cib", 0, 0, 'a'},
		{"stand-alone",    0, 0, 's'},
		{"disk-writes",    0, 0, 'w'},

		{"cib-root",    1, 0, 'r'},

		{"verbose",     0, 0, 'V'},
		{"help",        0, 0, '?'},
		{"metadata",    0, 0, 'm'},

		{0, 0, 0, 0}
	};
/* *INDENT-ON* */
#endif

    struct passwd *pwentry = NULL;

    crm_log_init("cib", LOG_INFO, TRUE, FALSE, 0, NULL);
    mainloop_add_signal(SIGTERM, cib_shutdown);
    mainloop_add_signal(SIGPIPE, cib_enable_writes);

    cib_writer =
        G_main_add_tempproc_trigger(G_PRIORITY_LOW, write_cib_contents, "write_cib_contents", NULL,
                                    NULL, NULL, cib_diskwrite_complete);

    /* EnableProcLogging(); */
    set_sigchld_proctrack(G_PRIORITY_HIGH, DEFAULT_MAXDISPATCHTIME);

    crm_peer_init();
    client_list = g_hash_table_new(crm_str_hash, g_str_equal);

    while (1) {
#ifdef HAVE_GETOPT_H
        flag = getopt_long(argc, argv, OPTARGS, long_options, &option_index);
#else
        flag = getopt(argc, argv, OPTARGS);
#endif
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level();
                break;
            case 's':
                stand_alone = TRUE;
                preserve_status = TRUE;
                cib_writes_enabled = FALSE;

                pwentry = getpwnam(CRM_DAEMON_USER);
                CRM_CHECK(pwentry != NULL,
                          crm_perror(LOG_ERR, "Invalid uid (%s) specified", CRM_DAEMON_USER);
                          return 100);

                rc = setgid(pwentry->pw_gid);
                if (rc < 0) {
                    crm_perror(LOG_ERR, "Could not set group to %d", pwentry->pw_gid);
                    return 100;
                }

                rc = setuid(pwentry->pw_uid);
                if (rc < 0) {
                    crm_perror(LOG_ERR, "Could not set user to %d", pwentry->pw_uid);
                    return 100;
                }
                break;
            case '?':          /* Help message */
                usage(crm_system_name, LSB_EXIT_OK);
                break;
            case 'w':
                cib_writes_enabled = TRUE;
                break;
            case 'r':
                cib_root = optarg;
                break;
            case 'm':
                cib_metadata();
                return 0;
            default:
                ++argerr;
                break;
        }
    }
    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        cib_metadata();
        return 0;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        usage(crm_system_name, LSB_EXIT_GENERIC);
    }

    if (crm_is_writable(cib_root, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) == FALSE) {
        crm_err("Bad permissions on %s. Terminating", cib_root);
        fprintf(stderr, "ERROR: Bad permissions on %s. See logs for details\n", cib_root);
        fflush(stderr);
        return 100;
    }

    /* read local config file */
    rc = cib_init();

    CRM_CHECK(g_hash_table_size(client_list) == 0, crm_warn("Not all clients gone at exit"));
    g_hash_table_foreach(client_list, log_cib_client, NULL);
    cib_cleanup();

#if SUPPORT_HEARTBEAT
    if (hb_conn) {
        hb_conn->llc_ops->delete(hb_conn);
    }
#endif

    crm_info("Done");
    return rc;
}

void
cib_cleanup(void)
{
    crm_peer_destroy();
    g_hash_table_destroy(config_hash);
    g_hash_table_destroy(client_list);
    crm_free(cib_our_uname);
#if HAVE_LIBXML2
    crm_xml_cleanup();
#endif
    crm_free(channel1);
    crm_free(channel2);
    crm_free(channel3);
    crm_free(channel4);
    crm_free(channel5);
}

unsigned long cib_num_ops = 0;
const char *cib_stat_interval = "10min";
unsigned long cib_num_local = 0, cib_num_updates = 0, cib_num_fail = 0;
unsigned long cib_bad_connects = 0, cib_num_timeouts = 0;
longclock_t cib_call_time = 0;

gboolean cib_stats(gpointer data);

gboolean
cib_stats(gpointer data)
{
    int local_log_level = LOG_DEBUG;
    static unsigned long last_stat = 0;
    unsigned int cib_calls_ms = 0;
    static unsigned long cib_stat_interval_ms = 0;

    if (cib_stat_interval_ms == 0) {
        cib_stat_interval_ms = crm_get_msec(cib_stat_interval);
    }

    cib_calls_ms = longclockto_ms(cib_call_time);

    if ((cib_num_ops - last_stat) > 0) {
        unsigned long calls_diff = cib_num_ops - last_stat;
        double stat_1 = (1000 * cib_calls_ms) / calls_diff;

        local_log_level = LOG_INFO;
        do_crm_log(local_log_level,
                   "Processed %lu operations"
                   " (%.2fus average, %lu%% utilization) in the last %s",
                   calls_diff, stat_1,
                   (100 * cib_calls_ms) / cib_stat_interval_ms, cib_stat_interval);
    }

    crm_trace(
                        "\tDetail: %lu operations (%ums total)"
                        " (%lu local, %lu updates, %lu failures,"
                        " %lu timeouts, %lu bad connects)",
                        cib_num_ops, cib_calls_ms, cib_num_local, cib_num_updates,
                        cib_num_fail, cib_bad_connects, cib_num_timeouts);

    last_stat = cib_num_ops;
    cib_call_time = 0;
    return TRUE;
}

#if SUPPORT_HEARTBEAT
gboolean ccm_connect(void);

static void
ccm_connection_destroy(gpointer user_data)
{
    crm_err("CCM connection failed... blocking while we reconnect");
    CRM_ASSERT(ccm_connect());
    return;
}

static void *ccm_library = NULL;

gboolean
ccm_connect(void)
{
    gboolean did_fail = TRUE;
    int num_ccm_fails = 0;
    int max_ccm_fails = 30;
    int ret;
    int cib_ev_fd;

    int (*ccm_api_register) (oc_ev_t ** token) =
        find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_register");

    int (*ccm_api_set_callback) (const oc_ev_t * token,
                                 oc_ev_class_t class,
                                 oc_ev_callback_t * fn,
                                 oc_ev_callback_t ** prev_fn) =
        find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_set_callback");

    void (*ccm_api_special) (const oc_ev_t *, oc_ev_class_t, int) =
        find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_special");
    int (*ccm_api_activate) (const oc_ev_t * token, int *fd) =
        find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_activate");
    int (*ccm_api_unregister) (oc_ev_t * token) =
        find_library_function(&ccm_library, CCM_LIBRARY, "oc_ev_unregister");

    static struct mainloop_fd_callbacks ccm_fd_callbacks = 
        {
            .dispatch = cib_ccm_dispatch,
            .destroy = ccm_connection_destroy,
        };
    
    while (did_fail) {
        did_fail = FALSE;
        crm_info("Registering with CCM...");
        ret = (*ccm_api_register) (&cib_ev_token);
        if (ret != 0) {
            did_fail = TRUE;
        }

        if (did_fail == FALSE) {
            crm_trace("Setting up CCM callbacks");
            ret = (*ccm_api_set_callback) (cib_ev_token, OC_EV_MEMB_CLASS,
                                           cib_ccm_msg_callback, NULL);
            if (ret != 0) {
                crm_warn("CCM callback not set");
                did_fail = TRUE;
            }
        }
        if (did_fail == FALSE) {
            (*ccm_api_special) (cib_ev_token, OC_EV_MEMB_CLASS, 0);

            crm_trace("Activating CCM token");
            ret = (*ccm_api_activate) (cib_ev_token, &cib_ev_fd);
            if (ret != 0) {
                crm_warn("CCM Activation failed");
                did_fail = TRUE;
            }
        }

        if (did_fail) {
            num_ccm_fails++;
            (*ccm_api_unregister) (cib_ev_token);

            if (num_ccm_fails < max_ccm_fails) {
                crm_warn("CCM Connection failed %d times (%d max)", num_ccm_fails, max_ccm_fails);
                sleep(3);

            } else {
                crm_err("CCM Activation failed %d (max) times", num_ccm_fails);
                return FALSE;
            }
        }
    }

    crm_debug("CCM Activation passed... all set to go!");
    mainloop_add_fd("heartbeat-ccm", cib_ev_fd, cib_ev_token, &ccm_fd_callbacks);

    return TRUE;
}
#endif

#if SUPPORT_COROSYNC
static gboolean
cib_ais_dispatch(AIS_Message * wrapper, char *data, int sender)
{
    xmlNode *xml = NULL;

    if (wrapper->header.id == crm_class_cluster) {
        xml = string2xml(data);
        if (xml == NULL) {
            goto bail;
        }
        crm_xml_add(xml, F_ORIG, wrapper->sender.uname);
        crm_xml_add_int(xml, F_SEQ, wrapper->id);
        cib_peer_callback(xml, NULL);
    }

    free_xml(xml);
    return TRUE;

  bail:
    crm_err("Invalid XML: '%.120s'", data);
    return TRUE;

}

static void
cib_ais_destroy(gpointer user_data)
{
    if (cib_shutdown_flag) {
        crm_info("Corosync disconnection complete");
    } else {
        crm_err("Corosync connection lost!  Exiting.");
        terminate_cib(__FUNCTION__, TRUE);
    }
}
#endif

static void
cib_peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
#if 0
    /* crm_active_peers(crm_proc_cib) appears to give the wrong answer
     * sometimes, this might help figure out why
     */
    if(type == crm_status_nstate) {
        crm_info("status: %s is now %s (was %s)", node->uname, node->state, (const char *)data);
        if (safe_str_eq(CRMD_STATE_ACTIVE, node->state)) {
            return;
        }

    } else if(type == crm_status_processes) {
        uint32_t old = 0;
        if (data) {
            old = *(const uint32_t *)data;
        }
        
        if ((node->processes ^ old) & crm_proc_cib) {
            crm_info("status: cib process on %s is now %sactive",
                     node->uname, is_set(node->processes, crm_proc_cib)?"":"in");
        } else {
            return;
        }

    } else {
        return;
    }
#endif
    if(cib_shutdown_flag && crm_active_peers() < 2 && g_hash_table_size(client_list) == 0) {
        crm_info("No more peers");
        terminate_cib(__FUNCTION__, FALSE);
    }
}

#if SUPPORT_HEARTBEAT
static void
cib_ha_connection_destroy(gpointer user_data)
{
    if (cib_shutdown_flag) {
        crm_info("Heartbeat disconnection complete... exiting");
        terminate_cib(__FUNCTION__, FALSE);
    } else {
        crm_err("Heartbeat connection lost!  Exiting.");
        terminate_cib(__FUNCTION__, TRUE);
    }
}
#endif

int
cib_init(void)
{
    gboolean was_error = FALSE;

    config_hash =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    if (startCib("cib.xml") == FALSE) {
        crm_crit("Cannot start CIB... terminating");
        exit(1);
    }

    if (stand_alone == FALSE) {
        void *dispatch = NULL;
        void *destroy = NULL;

        if (is_openais_cluster()) {
#if SUPPORT_COROSYNC
            destroy = cib_ais_destroy;
            dispatch = cib_ais_dispatch;
#endif
        } else if(is_heartbeat_cluster()) {
#if SUPPORT_HEARTBEAT
            dispatch = cib_ha_peer_callback;
            destroy = cib_ha_connection_destroy;
#endif
        }

        if (crm_cluster_connect(&cib_our_uname, NULL, dispatch, destroy,
#if SUPPORT_HEARTBEAT
                                &hb_conn
#else
                                NULL
#endif
            ) == FALSE) {
            crm_crit("Cannot sign in to the cluster... terminating");
            exit(100);
        }
        if (is_openais_cluster()) {
            crm_set_status_callback(&cib_peer_update_callback);
        }
#if SUPPORT_HEARTBEAT
        if (is_heartbeat_cluster()) {

            if (was_error == FALSE) {
                if (HA_OK !=
                    hb_conn->llc_ops->set_cstatus_callback(hb_conn, cib_client_status_callback,
                                                           hb_conn)) {

                    crm_err("Cannot set cstatus callback: %s", hb_conn->llc_ops->errmsg(hb_conn));
                    was_error = TRUE;
                }
            }

            if (was_error == FALSE) {
                was_error = (ccm_connect() == FALSE);
            }

            if (was_error == FALSE) {
                /* Async get client status information in the cluster */
                crm_info("Requesting the list of configured nodes");
                hb_conn->llc_ops->client_status(hb_conn, NULL, CRM_SYSTEM_CIB, -1);
            }
        }
#endif

    } else {
        cib_our_uname = crm_strdup("localhost");
    }

    ipcs_ro = mainloop_add_ipc_server(cib_channel_ro, QB_IPC_NATIVE, &ipc_ro_callbacks);
    ipcs_rw = mainloop_add_ipc_server(cib_channel_rw, QB_IPC_NATIVE, &ipc_rw_callbacks);

    if (stand_alone) {
        if (was_error) {
            crm_err("Couldnt start");
            return 1;
        }
        cib_is_master = TRUE;

        /* Create the mainloop and run it... */
        mainloop = g_main_new(FALSE);
        crm_info("Starting %s mainloop", crm_system_name);

        g_main_run(mainloop);
        return 0;
    }

    if (was_error == FALSE) {
        /* Create the mainloop and run it... */
        mainloop = g_main_new(FALSE);
        crm_info("Starting %s mainloop", crm_system_name);

        g_timeout_add(crm_get_msec(cib_stat_interval), cib_stats, NULL);

        g_main_run(mainloop);

    } else {
        crm_err("Couldnt start all communication channels, exiting.");
    }

    return 0;
}

void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s [-%s]\n", cmd, OPTARGS);
    fprintf(stream, "\t--%s (-%c)\t\tTurn on debug info."
            "  Additional instances increase verbosity\n", "verbose", 'V');
    fprintf(stream, "\t--%s (-%c)\t\tThis help message\n", "help", '?');
    fprintf(stream, "\t--%s (-%c)\t\tShow configurable cib options\n", "metadata", 'm');
    fprintf(stream, "\t--%s (-%c)\tAdvanced use only\n", "per-action-cib", 'a');
    fprintf(stream, "\t--%s (-%c)\tAdvanced use only\n", "stand-alone", 's');
    fprintf(stream, "\t--%s (-%c)\tAdvanced use only\n", "disk-writes", 'w');
    fprintf(stream, "\t--%s (-%c)\t\tAdvanced use only\n", "cib-root", 'r');
    fflush(stream);

    exit(exit_status);
}

gboolean
startCib(const char *filename)
{
    gboolean active = FALSE;
    xmlNode *cib = readCibXmlFile(cib_root, filename, !preserve_status);

    CRM_ASSERT(cib != NULL);

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
