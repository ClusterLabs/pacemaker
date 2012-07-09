/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USAA
 */

#include <crm_internal.h>
#include <crm/cluster/internal.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <corosync/totem/totempg.h>
#include <corosync/engine/objdb.h>
#include <corosync/engine/config.h>

#include <config.h>
#include "plugin.h"
#include "utils.h"

#include <glib.h>

#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>
#include <bzlib.h>
#include <pwd.h>

struct corosync_api_v1 *pcmk_api = NULL;

uint32_t plugin_has_votes = 0;
uint32_t plugin_expected_votes = 2;

int use_mgmtd = 0;
int plugin_log_level = LOG_DEBUG;
char *local_uname = NULL;
int local_uname_len = 0;
char *local_cname = NULL;
int local_cname_len = 0;
uint32_t local_nodeid = 0;
char *ipc_channel_name = NULL;
static uint64_t local_born_on = 0;

uint64_t membership_seq = 0;
pthread_t pcmk_wait_thread;

gboolean use_mcp = FALSE;
gboolean wait_active = TRUE;
gboolean have_reliable_membership_id = FALSE;
GHashTable *ipc_client_list = NULL;
GHashTable *membership_list = NULL;
GHashTable *membership_notify_list = NULL;

#define MAX_RESPAWN		100
#define LOOPBACK_ID		16777343
#define crm_flag_none		0x00000000
#define crm_flag_members	0x00000001

struct crm_identify_msg_s {
    cs_ipc_header_request_t header __attribute__ ((aligned(8)));
    uint32_t id;
    uint32_t pid;
    int32_t votes;
    uint32_t processes;
    char uname[256];
    char version[256];
    uint64_t born_on;
} __attribute__ ((packed));

/* *INDENT-OFF* */
static crm_child_t pcmk_children[] = {
    { 0, crm_proc_none,     crm_flag_none,    0, 0, FALSE, "none",     NULL,		NULL,			   NULL, NULL },
    { 0, crm_proc_plugin,      crm_flag_none,    0, 0, FALSE, "ais",      NULL,		NULL,			   NULL, NULL },
    { 0, crm_proc_lrmd,     crm_flag_none,    3, 0, TRUE,  "lrmd",     NULL,		CRM_DAEMON_DIR"/lrmd",     NULL, NULL },
    { 0, crm_proc_cib,      crm_flag_members, 1, 0, TRUE,  "cib",      CRM_DAEMON_USER, CRM_DAEMON_DIR"/cib",      NULL, NULL },
    { 0, crm_proc_crmd,     crm_flag_members, 6, 0, TRUE,  "crmd",     CRM_DAEMON_USER, CRM_DAEMON_DIR"/crmd",     NULL, NULL },
    { 0, crm_proc_attrd,    crm_flag_none,    4, 0, TRUE,  "attrd",    CRM_DAEMON_USER, CRM_DAEMON_DIR"/attrd",    NULL, NULL },
    { 0, crm_proc_stonithd, crm_flag_none,    0, 0, TRUE,  "stonithd", NULL,		"/bin/false",		   NULL, NULL },
    { 0, crm_proc_pe,       crm_flag_none,    5, 0, TRUE,  "pengine",  CRM_DAEMON_USER, CRM_DAEMON_DIR"/pengine",  NULL, NULL },
    { 0, crm_proc_mgmtd,    crm_flag_none,    7, 0, TRUE,  "mgmtd",    NULL,		HB_DAEMON_DIR"/mgmtd",     NULL, NULL },
    { 0, crm_proc_stonith_ng, crm_flag_none,  2, 0, TRUE,  "stonith-ng", NULL,		CRM_DAEMON_DIR"/stonithd", NULL, NULL },
};
/* *INDENT-ON* */

void send_cluster_id(void);
int send_cluster_msg_raw(const AIS_Message * ais_msg);
char *pcmk_generate_membership_data(void);
gboolean check_message_sanity(const AIS_Message * msg, const char *data);

typedef const void ais_void_ptr;
int pcmk_shutdown(void);
void pcmk_peer_update(enum totem_configuration_type configuration_type,
                      const unsigned int *member_list, size_t member_list_entries,
                      const unsigned int *left_list, size_t left_list_entries,
                      const unsigned int *joined_list, size_t joined_list_entries,
                      const struct memb_ring_id *ring_id);

int pcmk_startup(struct corosync_api_v1 *corosync_api);
int pcmk_config_init(struct corosync_api_v1 *corosync_api);

int pcmk_ipc_exit(void *conn);
int pcmk_ipc_connect(void *conn);
void pcmk_ipc(void *conn, ais_void_ptr * msg);

void pcmk_exec_dump(void);
void pcmk_cluster_swab(void *msg);
void pcmk_cluster_callback(ais_void_ptr * message, unsigned int nodeid);

void pcmk_nodeid(void *conn, ais_void_ptr * msg);
void pcmk_nodes(void *conn, ais_void_ptr * msg);
void pcmk_notify(void *conn, ais_void_ptr * msg);
void pcmk_remove_member(void *conn, ais_void_ptr * msg);
void pcmk_quorum(void *conn, ais_void_ptr * msg);

void pcmk_cluster_id_swab(void *msg);
void pcmk_cluster_id_callback(ais_void_ptr * message, unsigned int nodeid);
void ais_remove_peer(char *node_id);

static uint32_t
get_process_list(void)
{
    int lpc = 0;
    uint32_t procs = crm_proc_plugin;

    if (use_mcp) {
        return 0;
    }

    for (lpc = 0; lpc < SIZEOF(pcmk_children); lpc++) {
        if (pcmk_children[lpc].pid != 0) {
            procs |= pcmk_children[lpc].flag;
        }
    }
    return procs;
}

static struct corosync_lib_handler pcmk_lib_service[] = {
    {                           /* 0 */
     .lib_handler_fn = pcmk_ipc,
     .flow_control = COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
     },
    {                           /* 1 */
     .lib_handler_fn = pcmk_nodes,
     .flow_control = COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
     },
    {                           /* 2 */
     .lib_handler_fn = pcmk_notify,
     .flow_control = COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
     },
    {                           /* 3 */
     .lib_handler_fn = pcmk_nodeid,
     .flow_control = COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
     },
    {                           /* 4 */
     .lib_handler_fn = pcmk_remove_member,
     .flow_control = COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
     },
    {                           /* 5 */
     .lib_handler_fn = pcmk_quorum,
     .flow_control = COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED,
     },
};

static struct corosync_exec_handler pcmk_exec_service[] = {
    {                           /* 0 */
     .exec_handler_fn = pcmk_cluster_callback,
     .exec_endian_convert_fn = pcmk_cluster_swab},
    {                           /* 1 */
     .exec_handler_fn = pcmk_cluster_id_callback,
     .exec_endian_convert_fn = pcmk_cluster_id_swab}
};

/*
 * Exports the interface for the service
 */
/* *INDENT-OFF* */
struct corosync_service_engine pcmk_service_handler = {
    .name			= (char *)"Pacemaker Cluster Manager "PACKAGE_VERSION,
    .id				= PCMK_SERVICE_ID,
    .private_data_size		= 0,
    .flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED, 
    .allow_inquorate		= CS_LIB_ALLOW_INQUORATE,
    .lib_init_fn		= pcmk_ipc_connect,
    .lib_exit_fn		= pcmk_ipc_exit,
    .exec_init_fn		= pcmk_startup,
    .exec_exit_fn		= pcmk_shutdown,
    .config_init_fn		= pcmk_config_init,
    .priority			= 50,    
    .lib_engine			= pcmk_lib_service,
    .lib_engine_count		= sizeof (pcmk_lib_service) / sizeof (struct corosync_lib_handler),
    .exec_engine		= pcmk_exec_service,
    .exec_engine_count		= sizeof (pcmk_exec_service) / sizeof (struct corosync_exec_handler),
    .confchg_fn			= pcmk_peer_update,
    .exec_dump_fn		= pcmk_exec_dump,
/* 	void (*sync_init) (void); */
/* 	int (*sync_process) (void); */
/* 	void (*sync_activate) (void); */
/* 	void (*sync_abort) (void); */
};


/*
 * Dynamic Loader definition
 */
struct corosync_service_engine *pcmk_get_handler_ver0 (void);

struct corosync_service_engine_iface_ver0 pcmk_service_handler_iface = {
    .corosync_get_service_engine_ver0 = pcmk_get_handler_ver0
};

static struct lcr_iface openais_pcmk_ver0[2] = {
    {
	.name				= "pacemaker",
	.version			= 0,
	.versions_replace		= 0,
	.versions_replace_count		= 0,
	.dependencies			= 0,
	.dependency_count		= 0,
	.constructor			= NULL,
	.destructor			= NULL,
	.interfaces			= NULL
    },
    {
	.name				= "pacemaker",
	.version			= 1,
	.versions_replace		= 0,
	.versions_replace_count		= 0,
	.dependencies			= 0,
	.dependency_count		= 0,
	.constructor			= NULL,
	.destructor			= NULL,
	.interfaces			= NULL
    }
};

static struct lcr_comp pcmk_comp_ver0 = {
    .iface_count			= 2,
    .ifaces				= openais_pcmk_ver0
};
/* *INDENT-ON* */

struct corosync_service_engine *
pcmk_get_handler_ver0(void)
{
    return (&pcmk_service_handler);
}

__attribute__ ((constructor))
static void
register_this_component(void)
{
    lcr_interfaces_set(&openais_pcmk_ver0[0], &pcmk_service_handler_iface);
    lcr_interfaces_set(&openais_pcmk_ver0[1], &pcmk_service_handler_iface);

    lcr_component_register(&pcmk_comp_ver0);
}

static int
plugin_has_quorum(void)
{
    if ((plugin_expected_votes >> 1) < plugin_has_votes) {
        return 1;
    }
    return 0;
}

static void
update_expected_votes(int value)
{
    if (value < plugin_has_votes) {
        /* Never drop below the number of connected nodes */
        ais_info("Cannot update expected quorum votes %d -> %d:"
                 " value cannot be less that the current number of votes",
                 plugin_expected_votes, value);

    } else if (plugin_expected_votes != value) {
        ais_info("Expected quorum votes %d -> %d", plugin_expected_votes, value);
        plugin_expected_votes = value;
    }
}

/* Create our own local copy of the config so we can navigate it */
static void
process_ais_conf(void)
{
    char *value = NULL;
    gboolean any_log = FALSE;
    hdb_handle_t top_handle = 0;
    hdb_handle_t local_handle = 0;

    ais_info("Reading configure");
    top_handle = config_find_init(pcmk_api, "logging");
    local_handle = config_find_next(pcmk_api, "logging", top_handle);

    get_config_opt(pcmk_api, local_handle, "debug", &value, "on");
    if (ais_get_boolean(value)) {
        plugin_log_level = LOG_DEBUG;
        pcmk_env.debug = "1";

    } else {
        plugin_log_level = LOG_INFO;
        pcmk_env.debug = "0";
    }

    get_config_opt(pcmk_api, local_handle, "to_logfile", &value, "off");
    if (ais_get_boolean(value)) {
        get_config_opt(pcmk_api, local_handle, "logfile", &value, NULL);

        if (value == NULL) {
            ais_err("Logging to a file requested but no log file specified");

        } else {
            uid_t pcmk_uid = geteuid();
            uid_t pcmk_gid = getegid();

            FILE *logfile = fopen(value, "a");

            if (logfile) {
                int ignore = 0;
                int logfd = fileno(logfile);

                pcmk_env.logfile = value;

                /* Ensure the file has the correct permissions */
                ignore = fchown(logfd, pcmk_uid, pcmk_gid);
                ignore = fchmod(logfd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

                fprintf(logfile, "Set r/w permissions for uid=%d, gid=%d on %s\n",
                        pcmk_uid, pcmk_gid, value);
                fflush(logfile);
                fsync(logfd);
                fclose(logfile);
                any_log = TRUE;

            } else {
                ais_err("Couldn't create logfile: %s", value);
            }
        }
    }

    get_config_opt(pcmk_api, local_handle, "to_syslog", &value, "on");
    if (any_log && ais_get_boolean(value) == FALSE) {
        ais_info("User configured file based logging and explicitly disabled syslog.");
        value = "none";

    } else {
        if (ais_get_boolean(value) == FALSE) {
            ais_err
                ("Please enable some sort of logging, either 'to_file: on' or  'to_syslog: on'.");
            ais_err("If you use file logging, be sure to also define a value for 'logfile'");
        }
        get_config_opt(pcmk_api, local_handle, "syslog_facility", &value, "daemon");
    }
    pcmk_env.syslog = value;

    config_find_done(pcmk_api, local_handle);

    top_handle = config_find_init(pcmk_api, "quorum");
    local_handle = config_find_next(pcmk_api, "quorum", top_handle);
    get_config_opt(pcmk_api, local_handle, "provider", &value, NULL);
    if (value && ais_str_eq("quorum_cman", value)) {
        pcmk_env.quorum = "cman";
    } else {
        pcmk_env.quorum = "pcmk";
    }

    top_handle = config_find_init(pcmk_api, "service");
    local_handle = config_find_next(pcmk_api, "service", top_handle);
    while (local_handle) {
        value = NULL;
        pcmk_api->object_key_get(local_handle, "name", strlen("name"), (void **)&value, NULL);
        if (ais_str_eq("pacemaker", value)) {
            break;
        }
        local_handle = config_find_next(pcmk_api, "service", top_handle);
    }

    get_config_opt(pcmk_api, local_handle, "ver", &value, "0");
    if (ais_str_eq(value, "1")) {
        ais_info("Enabling MCP mode: Use the Pacemaker init script to complete Pacemaker startup");
        use_mcp = TRUE;
    }

    get_config_opt(pcmk_api, local_handle, "clustername", &local_cname, "pcmk");
    local_cname_len = strlen(local_cname);

    get_config_opt(pcmk_api, local_handle, "use_logd", &value, "no");
    pcmk_env.use_logd = value;

    get_config_opt(pcmk_api, local_handle, "use_mgmtd", &value, "no");
    if (ais_get_boolean(value) == FALSE) {
        int lpc = 0;

        for (; lpc < SIZEOF(pcmk_children); lpc++) {
            if (crm_proc_mgmtd & pcmk_children[lpc].flag) {
                /* Disable mgmtd startup */
                pcmk_children[lpc].start_seq = 0;
                break;
            }
        }
    }

    config_find_done(pcmk_api, local_handle);
}

int
pcmk_config_init(struct corosync_api_v1 *unused)
{
    return 0;
}

static void *
pcmk_wait_dispatch(void *arg)
{
    struct timespec waitsleep = {
        .tv_sec = 1,
        .tv_nsec = 0
    };

    while (wait_active) {
        int lpc = 0;

        for (; lpc < SIZEOF(pcmk_children); lpc++) {
            if (pcmk_children[lpc].pid > 0) {
                int status;
                pid_t pid = wait4(pcmk_children[lpc].pid, &status, WNOHANG, NULL);

                if (pid == 0) {
                    continue;

                } else if (pid < 0) {
                    ais_perror("Call to wait4(%s) failed", pcmk_children[lpc].name);
                    continue;
                }

                /* cleanup */
                pcmk_children[lpc].pid = 0;
                pcmk_children[lpc].conn = NULL;
                pcmk_children[lpc].async_conn = NULL;

                if (WIFSIGNALED(status)) {
                    int sig = WTERMSIG(status);

                    ais_err("Child process %s terminated with signal %d"
                            " (pid=%d, core=%s)",
                            pcmk_children[lpc].name, sig, pid,
                            WCOREDUMP(status) ? "true" : "false");

                } else if (WIFEXITED(status)) {
                    int rc = WEXITSTATUS(status);

                    do_ais_log(rc == 0 ? LOG_NOTICE : LOG_ERR,
                               "Child process %s exited (pid=%d, rc=%d)", pcmk_children[lpc].name,
                               pid, rc);

                    if (rc == 100) {
                        ais_notice("Child process %s no longer wishes"
                                   " to be respawned", pcmk_children[lpc].name);
                        pcmk_children[lpc].respawn = FALSE;
                    }
                }

                /* Broadcast the fact that one of our processes died
                 * 
                 * Try to get some logging of the cause out first though
                 * because we're probably about to get fenced
                 *
                 * Potentially do this only if respawn_count > N
                 * to allow for local recovery
                 */
                send_cluster_id();

                pcmk_children[lpc].respawn_count += 1;
                if (pcmk_children[lpc].respawn_count > MAX_RESPAWN) {
                    ais_err("Child respawn count exceeded by %s", pcmk_children[lpc].name);
                    pcmk_children[lpc].respawn = FALSE;
                }
                if (pcmk_children[lpc].respawn) {
                    ais_notice("Respawning failed child process: %s", pcmk_children[lpc].name);
                    spawn_child(&(pcmk_children[lpc]));
                }
                send_cluster_id();
            }
        }
        sched_yield();
        nanosleep(&waitsleep, 0);
    }
    return 0;
}

static uint32_t
pcmk_update_nodeid(void)
{
    int last = local_nodeid;

    local_nodeid = pcmk_api->totem_nodeid_get();

    if (last != local_nodeid) {
        if (last == 0) {
            ais_info("Local node id: %u", local_nodeid);

        } else {
            char *last_s = NULL;

            ais_malloc0(last_s, 32);
            ais_warn("Detected local node id change: %u -> %u", last, local_nodeid);
            snprintf(last_s, 31, "%u", last);
            ais_remove_peer(last_s);
            ais_free(last_s);
        }
        update_member(local_nodeid, 0, 0, 1, 0, local_uname, CRM_NODE_MEMBER, NULL);
    }

    return local_nodeid;
}

static void
build_path(const char *path_c, mode_t mode)
{
    int offset = 1, len = 0;
    char *path = ais_strdup(path_c);

    AIS_CHECK(path != NULL, return);
    for (len = strlen(path); offset < len; offset++) {
        if (path[offset] == '/') {
            path[offset] = 0;
            if (mkdir(path, mode) < 0 && errno != EEXIST) {
                ais_perror("Could not create directory '%s'", path);
                break;
            }
            path[offset] = '/';
        }
    }
    if (mkdir(path, mode) < 0 && errno != EEXIST) {
        ais_perror("Could not create directory '%s'", path);
    }
    ais_free(path);
}

int
pcmk_startup(struct corosync_api_v1 *init_with)
{
    int rc = 0;
    int lpc = 0;
    int start_seq = 1;
    struct utsname us;
    struct rlimit cores;
    static int max = SIZEOF(pcmk_children);

    uid_t pcmk_uid = 0;
    gid_t pcmk_gid = 0;

    uid_t root_uid = -1;
    uid_t cs_uid = geteuid();

    pcmk_user_lookup("root", &root_uid, NULL);

    pcmk_api = init_with;

    pcmk_env.debug = "0";
    pcmk_env.logfile = NULL;
    pcmk_env.use_logd = "false";
    pcmk_env.syslog = "daemon";

    if (cs_uid != root_uid) {
        ais_err("Corosync must be configured to start as 'root',"
                " otherwise Pacemaker cannot manage services."
                "  Expected %d got %d", root_uid, cs_uid);
        return -1;
    }

    process_ais_conf();

    membership_list = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, destroy_ais_node);
    membership_notify_list = g_hash_table_new(g_direct_hash, g_direct_equal);
    ipc_client_list = g_hash_table_new(g_direct_hash, g_direct_equal);

    ais_info("CRM: Initialized");
    log_printf(LOG_INFO, "Logging: Initialized %s\n", __PRETTY_FUNCTION__);

    rc = getrlimit(RLIMIT_CORE, &cores);
    if (rc < 0) {
        ais_perror("Cannot determine current maximum core size.");
    } else {
        if (cores.rlim_max == 0 && geteuid() == 0) {
            cores.rlim_max = RLIM_INFINITY;
        } else {
            ais_info("Maximum core file size is: %lu", cores.rlim_max);
        }
        cores.rlim_cur = cores.rlim_max;

        rc = setrlimit(RLIMIT_CORE, &cores);
        if (rc < 0) {
            ais_perror("Core file generation will remain disabled."
                       " Core files are an important diagnositic tool,"
                       " please consider enabling them by default.");
        }
#if 0
        /* system() is not thread-safe, can't call from here
         * Actually, its a pretty hacky way to try and achieve this anyway
         */
        if (system("echo 1 > /proc/sys/kernel/core_uses_pid") != 0) {
            ais_perror("Could not enable /proc/sys/kernel/core_uses_pid");
        }
#endif
    }

    if (pcmk_user_lookup(CRM_DAEMON_USER, &pcmk_uid, &pcmk_gid) < 0) {
        ais_err("Cluster user %s does not exist, aborting Pacemaker startup", CRM_DAEMON_USER);
        return TRUE;
    }

    rc = mkdir(CRM_STATE_DIR, 0750);
    rc = chown(CRM_STATE_DIR, pcmk_uid, pcmk_gid);

    /* Used by stonithd */
    build_path(HA_STATE_DIR "/heartbeat", 0755);

    /* Used by RAs - Leave owned by root */
    build_path(CRM_RSCTMP_DIR, 0755);

    rc = uname(&us);
    AIS_ASSERT(rc == 0);
    local_uname = ais_strdup(us.nodename);
    local_uname_len = strlen(local_uname);

    ais_info("Service: %d", PCMK_SERVICE_ID);
    ais_info("Local hostname: %s", local_uname);
    pcmk_update_nodeid();

    if (use_mcp == FALSE) {
        pthread_create(&pcmk_wait_thread, NULL, pcmk_wait_dispatch, NULL);
        for (start_seq = 1; start_seq < max; start_seq++) {
            /* dont start anything with start_seq < 1 */
            for (lpc = 0; lpc < max; lpc++) {
                if (start_seq == pcmk_children[lpc].start_seq) {
                    spawn_child(&(pcmk_children[lpc]));
                }
            }
        }
    }
    return 0;
}

/*
  static void ais_print_node(const char *prefix, struct totem_ip_address *host) 
  {
  int len = 0;
  char *buffer = NULL;

  ais_malloc0(buffer, INET6_ADDRSTRLEN+1);
	
  inet_ntop(host->family, host->addr, buffer, INET6_ADDRSTRLEN);

  len = strlen(buffer);
  ais_info("%s: %.*s", prefix, len, buffer);
  ais_free(buffer);
  }
*/

#if 0
/* copied here for reference from exec/totempg.c */
char *
totempg_ifaces_print(unsigned int nodeid)
{
    static char iface_string[256 * INTERFACE_MAX];
    char one_iface[64];
    struct totem_ip_address interfaces[INTERFACE_MAX];
    char **status;
    unsigned int iface_count;
    unsigned int i;
    int res;

    iface_string[0] = '\0';

    res = totempg_ifaces_get(nodeid, interfaces, &status, &iface_count);
    if (res == -1) {
        return ("no interface found for nodeid");
    }

    for (i = 0; i < iface_count; i++) {
        sprintf(one_iface, "r(%d) ip(%s), ", i, totemip_print(&interfaces[i]));
        strcat(iface_string, one_iface);
    }
    return (iface_string);
}
#endif

static void
ais_mark_unseen_peer_dead(gpointer key, gpointer value, gpointer user_data)
{
    int *changed = user_data;
    crm_node_t *node = value;

    if (node->last_seen != membership_seq && ais_str_eq(CRM_NODE_LOST, node->state) == FALSE) {
        ais_info("Node %s was not seen in the previous transition", node->uname);
        *changed += update_member(node->id, 0, membership_seq, node->votes,
                                  node->processes, node->uname, CRM_NODE_LOST, NULL);
    }
}

void
pcmk_peer_update(enum totem_configuration_type configuration_type,
                 const unsigned int *member_list, size_t member_list_entries,
                 const unsigned int *left_list, size_t left_list_entries,
                 const unsigned int *joined_list, size_t joined_list_entries,
                 const struct memb_ring_id *ring_id)
{
    int lpc = 0;
    int changed = 0;
    int do_update = 0;

    AIS_ASSERT(ring_id != NULL);
    switch (configuration_type) {
        case TOTEM_CONFIGURATION_REGULAR:
            do_update = 1;
            break;
        case TOTEM_CONFIGURATION_TRANSITIONAL:
            break;
    }

    membership_seq = ring_id->seq;
    ais_notice("%s membership event on ring %lld: memb=%ld, new=%ld, lost=%ld",
               do_update ? "Stable" : "Transitional", ring_id->seq,
               (long)member_list_entries, (long)joined_list_entries, (long)left_list_entries);

    if (do_update == 0) {
        for (lpc = 0; lpc < joined_list_entries; lpc++) {
            const char *prefix = "new: ";
            uint32_t nodeid = joined_list[lpc];

            ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
        }
        for (lpc = 0; lpc < member_list_entries; lpc++) {
            const char *prefix = "memb:";
            uint32_t nodeid = member_list[lpc];

            ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
        }
        for (lpc = 0; lpc < left_list_entries; lpc++) {
            const char *prefix = "lost:";
            uint32_t nodeid = left_list[lpc];

            ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
        }
        return;
    }

    for (lpc = 0; lpc < joined_list_entries; lpc++) {
        const char *prefix = "NEW: ";
        uint32_t nodeid = joined_list[lpc];
        crm_node_t *node = NULL;

        changed += update_member(nodeid, 0, membership_seq, -1, 0, NULL, CRM_NODE_MEMBER, NULL);

        ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);

        node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(nodeid));
        if (node->addr == NULL) {
            const char *addr = totempg_ifaces_print(nodeid);

            node->addr = ais_strdup(addr);
            ais_debug("Node %u has address %s", nodeid, node->addr);
        }
    }

    for (lpc = 0; lpc < member_list_entries; lpc++) {
        const char *prefix = "MEMB:";
        uint32_t nodeid = member_list[lpc];

        changed += update_member(nodeid, 0, membership_seq, -1, 0, NULL, CRM_NODE_MEMBER, NULL);

        ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
    }

    for (lpc = 0; lpc < left_list_entries; lpc++) {
        const char *prefix = "LOST:";
        uint32_t nodeid = left_list[lpc];

        changed += update_member(nodeid, 0, membership_seq, -1, 0, NULL, CRM_NODE_LOST, NULL);
        ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
    }

    if (changed && joined_list_entries == 0 && left_list_entries == 0) {
        ais_err("Something strange happened: %d", changed);
        changed = 0;
    }

    ais_trace("Reaping unseen nodes...");
    g_hash_table_foreach(membership_list, ais_mark_unseen_peer_dead, &changed);

    if (member_list_entries > 1) {
        /* Used to set born-on in send_cluster_id())
         * We need to wait until we have at least one peer since first
         * membership id is based on the one before we stopped and isn't reliable
         */
        have_reliable_membership_id = TRUE;
    }

    if (changed) {
        ais_debug("%d nodes changed", changed);
        pcmk_update_nodeid();
        send_member_notification();
    }

    send_cluster_id();
}

int
pcmk_ipc_exit(void *conn)
{
    int lpc = 0;
    const char *client = NULL;
    void *async_conn = conn;

    for (; lpc < SIZEOF(pcmk_children); lpc++) {
        if (pcmk_children[lpc].conn == conn) {
            if (wait_active == FALSE) {
                /* Make sure the shutdown loop exits */
                pcmk_children[lpc].pid = 0;
            }
            pcmk_children[lpc].conn = NULL;
            pcmk_children[lpc].async_conn = NULL;
            client = pcmk_children[lpc].name;
            break;
        }
    }

    g_hash_table_remove(membership_notify_list, async_conn);
    g_hash_table_remove(ipc_client_list, async_conn);

    if (client) {
        do_ais_log(LOG_INFO, "Client %s (conn=%p, async-conn=%p) left", client, conn, async_conn);
    } else {
        do_ais_log((LOG_DEBUG + 1), "Client %s (conn=%p, async-conn=%p) left",
                   "unknown-transient", conn, async_conn);
    }

    return (0);
}

int
pcmk_ipc_connect(void *conn)
{
    /* OpenAIS hasn't finished setting up the connection at this point
     * Sending messages now messes up the protocol!
     */
    return (0);
}

/*
 * Executive message handlers
 */
void
pcmk_cluster_swab(void *msg)
{
    AIS_Message *ais_msg = msg;

    ais_trace("Performing endian conversion...");
    ais_msg->id = swab32(ais_msg->id);
    ais_msg->size = swab32(ais_msg->size);
    ais_msg->is_compressed = swab32(ais_msg->is_compressed);
    ais_msg->compressed_size = swab32(ais_msg->compressed_size);

    ais_msg->host.id = swab32(ais_msg->host.id);
    ais_msg->host.pid = swab32(ais_msg->host.pid);
    ais_msg->host.type = swab32(ais_msg->host.type);
    ais_msg->host.size = swab32(ais_msg->host.size);
    ais_msg->host.local = swab32(ais_msg->host.local);

    ais_msg->sender.id = swab32(ais_msg->sender.id);
    ais_msg->sender.pid = swab32(ais_msg->sender.pid);
    ais_msg->sender.type = swab32(ais_msg->sender.type);
    ais_msg->sender.size = swab32(ais_msg->sender.size);
    ais_msg->sender.local = swab32(ais_msg->sender.local);

    ais_msg->header.size = swab32(ais_msg->header.size);
    ais_msg->header.id = swab32(ais_msg->header.id);
    ais_msg->header.error = swab32(ais_msg->header.error);
}

void
pcmk_cluster_callback(ais_void_ptr * message, unsigned int nodeid)
{
    const AIS_Message *ais_msg = message;

    ais_trace("Message from node %u (%s)", nodeid, nodeid == local_nodeid ? "local" : "remote");
/*  Shouldn't be required...
    update_member(
 	ais_msg->sender.id, membership_seq, -1, 0, ais_msg->sender.uname, NULL);
*/

    if (ais_msg->host.size == 0 || ais_str_eq(ais_msg->host.uname, local_uname)) {
        route_ais_message(ais_msg, FALSE);

    } else {
        ais_trace("Discarding Msg[%d] (dest=%s:%s, from=%s:%s)",
                    ais_msg->id, ais_dest(&(ais_msg->host)),
                    msg_type2text(ais_msg->host.type),
                    ais_dest(&(ais_msg->sender)), msg_type2text(ais_msg->sender.type));
    }
}

void
pcmk_cluster_id_swab(void *msg)
{
    struct crm_identify_msg_s *ais_msg = msg;

    ais_trace("Performing endian conversion...");
    ais_msg->id = swab32(ais_msg->id);
    ais_msg->pid = swab32(ais_msg->pid);
    ais_msg->votes = swab32(ais_msg->votes);
    ais_msg->processes = swab32(ais_msg->processes);
    ais_msg->born_on = swab64(ais_msg->born_on);

    ais_msg->header.size = swab32(ais_msg->header.size);
    ais_msg->header.id = swab32(ais_msg->header.id);
}

void
pcmk_cluster_id_callback(ais_void_ptr * message, unsigned int nodeid)
{
    int changed = 0;
    const struct crm_identify_msg_s *msg = message;

    if (nodeid != msg->id) {
        ais_err("Invalid message: Node %u claimed to be node %d", nodeid, msg->id);
        return;
    }
    ais_debug("Node update: %s (%s)", msg->uname, msg->version);
    changed =
        update_member(nodeid, msg->born_on, membership_seq, msg->votes, msg->processes, msg->uname,
                      NULL, msg->version);

    if (changed) {
        send_member_notification();
    }
}

struct res_overlay {
    cs_ipc_header_response_t header __attribute((aligned(8)));
    char buf[4096];
};

struct res_overlay *res_overlay = NULL;

static void
send_ipc_ack(void *conn)
{
    if (res_overlay == NULL) {
        ais_malloc0(res_overlay, sizeof(struct res_overlay));
    }

    res_overlay->header.id = CRM_MESSAGE_IPC_ACK;
    res_overlay->header.size = sizeof(cs_ipc_header_response_t);
    res_overlay->header.error = CS_OK;
    pcmk_api->ipc_response_send(conn, res_overlay, res_overlay->header.size);
}

/* local callbacks */
void
pcmk_ipc(void *conn, ais_void_ptr * msg)
{
    AIS_Message *mutable;
    int type = 0, size = 0;
    gboolean transient = TRUE;
    const AIS_Message *ais_msg = (const AIS_Message *)msg;
    void *async_conn = conn;

    ais_trace("Message from client %p", conn);

    if (check_message_sanity(msg, ((const AIS_Message *)msg)->data) == FALSE) {
        /* The message is corrupted - ignore */
        send_ipc_ack(conn);
        msg = NULL;
        return;
    }

    /* Make a copy of the message here and ACK it
     * The message is only valid until a response is sent
     * but the response must also be sent _before_ we send anything else
     */

    mutable = ais_msg_copy(ais_msg);
    AIS_ASSERT(check_message_sanity(mutable, mutable->data));

    size = mutable->header.size;
    /* ais_malloc0(ais_msg, size); */
    /* memcpy(ais_msg, msg, size); */

    type = mutable->sender.type;
    ais_trace
        ("type: %d local: %d conn: %p host type: %d ais: %d sender pid: %d child pid: %d size: %d",
         type, mutable->host.local, pcmk_children[type].conn, mutable->host.type, crm_msg_ais,
         mutable->sender.pid, pcmk_children[type].pid, ((int)SIZEOF(pcmk_children)));

    if (type > crm_msg_none && type < SIZEOF(pcmk_children)) {
        /* known child process */
        transient = FALSE;
    }
#if 0
    /* If this check fails, the order of pcmk_children probably 
     *   doesn't match that of the crm_ais_msg_types enum
     */
    AIS_CHECK(transient || mutable->sender.pid == pcmk_children[type].pid,
              ais_err("Sender: %d, child[%d]: %d", mutable->sender.pid, type,
                      pcmk_children[type].pid); ais_free(mutable); return);
#endif

    if (transient == FALSE
        && type > crm_msg_none
        && mutable->host.local
        && pcmk_children[type].conn == NULL && mutable->host.type == crm_msg_ais) {
        AIS_CHECK(mutable->sender.type != mutable->sender.pid,
                  ais_err("Pid=%d, type=%d", mutable->sender.pid, mutable->sender.type));

        ais_info("Recorded connection %p for %s/%d",
                 conn, pcmk_children[type].name, pcmk_children[type].pid);
        pcmk_children[type].conn = conn;
        pcmk_children[type].async_conn = async_conn;

        /* Make sure they have the latest membership */
        if (pcmk_children[type].flags & crm_flag_members) {
            char *update = pcmk_generate_membership_data();

            g_hash_table_replace(membership_notify_list, async_conn, async_conn);
            ais_info("Sending membership update " U64T " to %s",
                     membership_seq, pcmk_children[type].name);
            send_client_msg(async_conn, crm_class_members, crm_msg_none, update);
        }

    } else if (transient) {
        AIS_CHECK(mutable->sender.type == mutable->sender.pid,
                  ais_err("Pid=%d, type=%d", mutable->sender.pid, mutable->sender.type));
        g_hash_table_replace(ipc_client_list, async_conn, GUINT_TO_POINTER(mutable->sender.pid));
    }

    mutable->sender.id = local_nodeid;
    mutable->sender.size = local_uname_len;
    memset(mutable->sender.uname, 0, MAX_NAME);
    memcpy(mutable->sender.uname, local_uname, mutable->sender.size);

    route_ais_message(mutable, TRUE);
    send_ipc_ack(conn);
    msg = NULL;
    ais_free(mutable);
}

int
pcmk_shutdown(void)
{
    int lpc = 0;
    static int phase = 0;
    static int max_wait = 0;
    static time_t next_log = 0;
    static int max = SIZEOF(pcmk_children);

    if (use_mcp) {
        if (pcmk_children[crm_msg_crmd].conn || pcmk_children[crm_msg_stonith_ng].conn) {
            time_t now = time(NULL);

            if (now > next_log) {
                next_log = now + 300;
                ais_notice
                    ("Preventing Corosync shutdown.  Please ensure Pacemaker is stopped first.");
            }
            return -1;
        }
        ais_notice("Unloading Pacemaker plugin");
        return 0;
    }

    if (phase == 0) {
        ais_notice("Shuting down Pacemaker");
        phase = max;
    }

    wait_active = FALSE;        /* stop the wait loop */

    for (; phase > 0; phase--) {
        /* dont stop anything with start_seq < 1 */

        for (lpc = max - 1; lpc >= 0; lpc--) {
            if (phase != pcmk_children[lpc].start_seq) {
                continue;
            }

            if (pcmk_children[lpc].pid) {
                pid_t pid = 0;
                int status = 0;
                time_t now = time(NULL);

                if (pcmk_children[lpc].respawn) {
                    max_wait = 5;       /* 5 * 30s = 2.5 minutes... plenty once the crmd is gone */
                    next_log = now + 30;
                    pcmk_children[lpc].respawn = FALSE;
                    stop_child(&(pcmk_children[lpc]), SIGTERM);
                }

                pid = wait4(pcmk_children[lpc].pid, &status, WNOHANG, NULL);
                if (pid < 0) {
                    ais_perror("Call to wait4(%s/%d) failed - treating it as stopped",
                               pcmk_children[lpc].name, pcmk_children[lpc].pid);

                } else if (pid == 0) {
                    if (now >= next_log) {
                        max_wait--;
                        next_log = now + 30;
                        ais_notice("Still waiting for %s (pid=%d, seq=%d) to terminate...",
                                   pcmk_children[lpc].name, pcmk_children[lpc].pid,
                                   pcmk_children[lpc].start_seq);
                        if (max_wait <= 0 && phase < pcmk_children[crm_msg_crmd].start_seq) {
                            ais_err("Child %s taking too long to terminate, sending SIGKILL",
                                    pcmk_children[lpc].name);
                            stop_child(&(pcmk_children[lpc]), SIGKILL);
                        }
                    }
                    /* Return control to corosync */
                    return -1;
                }
            }

            /* cleanup */
            ais_notice("%s confirmed stopped", pcmk_children[lpc].name);
            pcmk_children[lpc].async_conn = NULL;
            pcmk_children[lpc].conn = NULL;
            pcmk_children[lpc].pid = 0;
        }
    }

    send_cluster_id();
    ais_notice("Shutdown complete");
    /* TODO: Add back the logsys flush call once its written */

    return 0;
}

struct member_loop_data {
    char *string;
};

static void
member_vote_count_fn(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;

    if (ais_str_eq(CRM_NODE_MEMBER, node->state)) {
        plugin_has_votes += node->votes;
    }
}

void
member_loop_fn(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    struct member_loop_data *data = user_data;

    ais_trace("Dumping node %u", node->id);
    data->string = append_member(data->string, node);
}

char *
pcmk_generate_membership_data(void)
{
    int size = 0;
    struct member_loop_data data;

    size = 256;
    ais_malloc0(data.string, size);

    /* Ensure the list of active processes is up-to-date */
    update_member(local_nodeid, 0, 0, -1, get_process_list(), local_uname, CRM_NODE_MEMBER, NULL);

    plugin_has_votes = 0;
    g_hash_table_foreach(membership_list, member_vote_count_fn, NULL);
    if (plugin_has_votes > plugin_expected_votes) {
        update_expected_votes(plugin_has_votes);
    }

    snprintf(data.string, size,
             "<nodes id=\"" U64T "\" quorate=\"%s\" expected=\"%u\" actual=\"%u\">",
             membership_seq, plugin_has_quorum()? "true" : "false",
             plugin_expected_votes, plugin_has_votes);

    g_hash_table_foreach(membership_list, member_loop_fn, &data);
    size = strlen(data.string);
    data.string = realloc(data.string, size + 9);       /* 9 = </nodes> + nul */
    sprintf(data.string + size, "</nodes>");
    return data.string;
}

void
pcmk_nodes(void *conn, ais_void_ptr * msg)
{
    char *data = pcmk_generate_membership_data();
    void *async_conn = conn;

    /* send the ACK before we send any other messages
     * - but after we no longer need to access the message
     */
    send_ipc_ack(conn);
    msg = NULL;

    if (async_conn) {
        send_client_msg(async_conn, crm_class_members, crm_msg_none, data);
    }
    ais_free(data);
}

void
pcmk_remove_member(void *conn, ais_void_ptr * msg)
{
    const AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);

    send_ipc_ack(conn);
    msg = NULL;

    if (data != NULL) {
        char *bcast = ais_concat("remove-peer", data, ':');

        send_cluster_msg(crm_msg_ais, NULL, bcast);
        ais_info("Sent: %s", bcast);
        ais_free(bcast);
    }

    ais_free(data);
}

static void
send_quorum_details(void *conn)
{
    int size = 256;
    char *data = NULL;

    ais_malloc0(data, size);

    snprintf(data, size, "<quorum id=\"" U64T "\" quorate=\"%s\" expected=\"%u\" actual=\"%u\"/>",
             membership_seq, plugin_has_quorum()? "true" : "false",
             plugin_expected_votes, plugin_has_votes);

    send_client_msg(conn, crm_class_quorum, crm_msg_none, data);
    ais_free(data);
}

void
pcmk_quorum(void *conn, ais_void_ptr * msg)
{
    char *dummy = NULL;
    const AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);

    send_ipc_ack(conn);
    msg = NULL;

    /* Make sure the current number of votes is accurate */
    dummy = pcmk_generate_membership_data();
    ais_free(dummy);

    /* Calls without data just want the current quorum details */
    if (data != NULL && strlen(data) > 0) {
        int value = ais_get_int(data, NULL);

        update_expected_votes(value);
    }

    send_quorum_details(conn);
    ais_free(data);
}

void
pcmk_notify(void *conn, ais_void_ptr * msg)
{
    const AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);
    void *async_conn = conn;

    int enable = 0;
    int sender = ais_msg->sender.pid;

    send_ipc_ack(conn);
    msg = NULL;

    if (ais_str_eq("true", data)) {
        enable = 1;
    }

    ais_info("%s node notifications for child %d (%p)",
             enable ? "Enabling" : "Disabling", sender, async_conn);
    if (enable) {
        g_hash_table_replace(membership_notify_list, async_conn, async_conn);
    } else {
        g_hash_table_remove(membership_notify_list, async_conn);
    }
    ais_free(data);
}

void
pcmk_nodeid(void *conn, ais_void_ptr * msg)
{
    static int counter = 0;
    struct crm_ais_nodeid_resp_s resp;

    ais_trace("Sending local nodeid: %d to %p[%d]", local_nodeid, conn, counter);

    resp.header.id = crm_class_nodeid;
    resp.header.size = sizeof(struct crm_ais_nodeid_resp_s);
    resp.header.error = CS_OK;
    resp.id = local_nodeid;
    resp.counter = counter++;
    memset(resp.uname, 0, MAX_NAME);
    memcpy(resp.uname, local_uname, local_uname_len);
    memset(resp.cname, 0, MAX_NAME);
    memcpy(resp.cname, local_cname, local_cname_len);

    pcmk_api->ipc_response_send(conn, &resp, resp.header.size);
}

static gboolean
ghash_send_update(gpointer key, gpointer value, gpointer data)
{
    if (send_client_msg(value, crm_class_members, crm_msg_none, data) != 0) {
        /* remove it */
        return TRUE;
    }
    return FALSE;
}

void
send_member_notification(void)
{
    char *update = pcmk_generate_membership_data();

    ais_info("Sending membership update " U64T " to %d children",
             membership_seq, g_hash_table_size(membership_notify_list));

    g_hash_table_foreach_remove(membership_notify_list, ghash_send_update, update);
    ais_free(update);
}

gboolean
check_message_sanity(const AIS_Message * msg, const char *data)
{
    gboolean sane = TRUE;
    gboolean repaired = FALSE;
    int dest = msg->host.type;
    int tmp_size = msg->header.size - sizeof(AIS_Message);

    if (sane && msg->header.size == 0) {
        ais_err("Message with no size");
        sane = FALSE;
    }

    if (sane && msg->header.error != CS_OK) {
        ais_err("Message header contains an error: %d", msg->header.error);
        sane = FALSE;
    }

    AIS_CHECK(msg->header.size > sizeof(AIS_Message),
              ais_err("Message %d size too small: %d < %zu",
                      msg->header.id, msg->header.size, sizeof(AIS_Message)); return FALSE);

    if (sane && ais_data_len(msg) != tmp_size) {
        ais_warn("Message payload size is incorrect: expected %d, got %d", ais_data_len(msg),
                 tmp_size);
        sane = TRUE;
    }

    if (sane && ais_data_len(msg) == 0) {
        ais_err("Message with no payload");
        sane = FALSE;
    }

    if (sane && data && msg->is_compressed == FALSE) {
        int str_size = strlen(data) + 1;

        if (ais_data_len(msg) != str_size) {
            int lpc = 0;

            ais_err("Message payload is corrupted: expected %d bytes, got %d",
                    ais_data_len(msg), str_size);
            sane = FALSE;
            for (lpc = (str_size - 10); lpc < msg->size; lpc++) {
                if (lpc < 0) {
                    lpc = 0;
                }
                ais_trace("bad_data[%d]: %d / '%c'", lpc, data[lpc], data[lpc]);
            }
        }
    }

    if (sane == FALSE) {
        AIS_CHECK(sane,
                  ais_err
                  ("Invalid message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
                   msg->id, ais_dest(&(msg->host)), msg_type2text(dest), ais_dest(&(msg->sender)),
                   msg_type2text(msg->sender.type), msg->sender.pid, msg->is_compressed,
                   ais_data_len(msg), msg->header.size));

    } else if (repaired) {
        ais_err
            ("Repaired message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
             msg->id, ais_dest(&(msg->host)), msg_type2text(dest), ais_dest(&(msg->sender)),
             msg_type2text(msg->sender.type), msg->sender.pid, msg->is_compressed,
             ais_data_len(msg), msg->header.size);
    } else {
        ais_trace
            ("Verified message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
             msg->id, ais_dest(&(msg->host)), msg_type2text(dest), ais_dest(&(msg->sender)),
             msg_type2text(msg->sender.type), msg->sender.pid, msg->is_compressed,
             ais_data_len(msg), msg->header.size);
    }
    return sane;
}

static int delivered_transient = 0;
static void
deliver_transient_msg(gpointer key, gpointer value, gpointer user_data)
{
    int pid = GPOINTER_TO_INT(value);
    AIS_Message *mutable = user_data;

    if (pid == mutable->host.type) {
        int rc = send_client_ipc(key, mutable);

        delivered_transient++;

        ais_info("Sent message to %s.%d (rc=%d)", ais_dest(&(mutable->host)), pid, rc);
        if (rc != 0) {
            ais_warn("Sending message to %s.%d failed (rc=%d)",
                     ais_dest(&(mutable->host)), pid, rc);
            log_ais_message(LOG_DEBUG, mutable);
        }
    }
}

gboolean
route_ais_message(const AIS_Message * msg, gboolean local_origin)
{
    int rc = 0;
    int dest = msg->host.type;
    const char *reason = "unknown";
    AIS_Message *mutable = ais_msg_copy(msg);
    static int service_id = SERVICE_ID_MAKE(PCMK_SERVICE_ID, 0);

    ais_trace("Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d)",
                mutable->id, ais_dest(&(mutable->host)), msg_type2text(dest),
                ais_dest(&(mutable->sender)), msg_type2text(mutable->sender.type),
                mutable->sender.pid, local_origin ? "false" : "true", ais_data_len((mutable)));

    if (local_origin == FALSE) {
        if (mutable->host.size == 0 || ais_str_eq(local_uname, mutable->host.uname)) {
            mutable->host.local = TRUE;
        }
    }

    if (check_message_sanity(mutable, mutable->data) == FALSE) {
        /* Dont send this message to anyone */
        rc = 1;
        goto bail;
    }

    if (mutable->host.local) {
        void *conn = NULL;
        const char *lookup = NULL;

        if (dest == crm_msg_ais) {
            process_ais_message(mutable);
            goto bail;

        } else if (dest == crm_msg_lrmd) {
            /* lrmd messages are routed via the crm */
            dest = crm_msg_crmd;

        } else if (dest == crm_msg_te) {
            /* te messages are routed via the crm */
            dest = crm_msg_crmd;

        } else if (dest >= SIZEOF(pcmk_children)) {
            /* Transient client */

            delivered_transient = 0;
            g_hash_table_foreach(ipc_client_list, deliver_transient_msg, mutable);
            if (delivered_transient) {
                ais_trace("Sent message to %d transient clients: %d", delivered_transient, dest);
                goto bail;

            } else {
                /* try the crmd */
                ais_trace("Sending message to transient client %d via crmd", dest);
                dest = crm_msg_crmd;
            }

        } else if (dest == 0) {
            ais_err("Invalid destination: %d", dest);
            log_ais_message(LOG_ERR, mutable);
            log_printf(LOG_ERR, "%s", get_ais_data(mutable));
            rc = 1;
            goto bail;
        }

        lookup = msg_type2text(dest);
        conn = pcmk_children[dest].async_conn;

        /* the cluster fails in weird and wonderfully obscure ways when this is not true */
        AIS_ASSERT(ais_str_eq(lookup, pcmk_children[dest].name));

        if (mutable->header.id == service_id) {
            mutable->header.id = 0;     /* reset this back to zero for IPC messages */

        } else if (mutable->header.id != 0) {
            ais_err("reset header id back to zero from %d", mutable->header.id);
            mutable->header.id = 0;     /* reset this back to zero for IPC messages */
        }

        reason = "ipc delivery failed";
        rc = send_client_ipc(conn, mutable);

    } else if (local_origin) {
        /* forward to other hosts */
        ais_trace("Forwarding to cluster");
        reason = "cluster delivery failed";
        rc = send_cluster_msg_raw(mutable);
    }

    if (rc != 0) {
        ais_warn("Sending message to %s.%s failed: %s (rc=%d)",
                 ais_dest(&(mutable->host)), msg_type2text(dest), reason, rc);
        log_ais_message(LOG_DEBUG, mutable);
    }

  bail:
    ais_free(mutable);
    return rc == 0 ? TRUE : FALSE;
}

int
send_cluster_msg_raw(const AIS_Message * ais_msg)
{
    int rc = 0;
    struct iovec iovec;
    static uint32_t msg_id = 0;
    AIS_Message *mutable = ais_msg_copy(ais_msg);

    AIS_ASSERT(local_nodeid != 0);
    AIS_ASSERT(ais_msg->header.size == (sizeof(AIS_Message) + ais_data_len(ais_msg)));

    if (mutable->id == 0) {
        msg_id++;
        AIS_CHECK(msg_id != 0 /* detect wrap-around */ ,
                  msg_id++;
                  ais_err("Message ID wrapped around"));
        mutable->id = msg_id;
    }

    mutable->header.error = CS_OK;
    mutable->header.id = SERVICE_ID_MAKE(PCMK_SERVICE_ID, 0);

    mutable->sender.id = local_nodeid;
    mutable->sender.size = local_uname_len;
    memset(mutable->sender.uname, 0, MAX_NAME);
    memcpy(mutable->sender.uname, local_uname, mutable->sender.size);

    iovec.iov_base = (char *)mutable;
    iovec.iov_len = mutable->header.size;

    ais_trace("Sending message (size=%u)", (unsigned int)iovec.iov_len);
    rc = pcmk_api->totem_mcast(&iovec, 1, TOTEMPG_SAFE);

    if (rc == 0 && mutable->is_compressed == FALSE) {
        ais_trace("Message sent: %.80s", mutable->data);
    }

    AIS_CHECK(rc == 0, ais_err("Message not sent (%d): %.120s", rc, mutable->data));

    ais_free(mutable);
    return rc;
}

#define min(x,y) (x)<(y)?(x):(y)

void
send_cluster_id(void)
{
    int rc = 0;
    int len = 0;
    time_t now = time(NULL);
    struct iovec iovec;
    struct crm_identify_msg_s *msg = NULL;

    static time_t started = 0;
    static uint64_t first_seq = 0;

    AIS_ASSERT(local_nodeid != 0);

    if (started == 0) {
        started = now;
        first_seq = membership_seq;
    }

    if (local_born_on == 0) {
        if (started + 15 < now) {
            ais_debug("Born-on set to: " U64T " (age)", first_seq);
            local_born_on = first_seq;

        } else if (have_reliable_membership_id) {
            ais_debug("Born-on set to: " U64T " (peer)", membership_seq);
            local_born_on = membership_seq;

        } else {
            ais_debug("Leaving born-on unset: " U64T, membership_seq);
        }
    }

    ais_malloc0(msg, sizeof(struct crm_identify_msg_s));
    msg->header.size = sizeof(struct crm_identify_msg_s);

    msg->id = local_nodeid;
    /* msg->header.error = CS_OK; */
    msg->header.id = SERVICE_ID_MAKE(PCMK_SERVICE_ID, 1);

    len = min(local_uname_len, MAX_NAME - 1);
    memset(msg->uname, 0, MAX_NAME);
    memcpy(msg->uname, local_uname, len);

    len = min(strlen(VERSION), MAX_NAME - 1);
    memset(msg->version, 0, MAX_NAME);
    memcpy(msg->version, VERSION, len);

    msg->votes = 1;
    msg->pid = getpid();
    msg->processes = get_process_list();
    msg->born_on = local_born_on;

    ais_debug("Local update: id=%u, born=" U64T ", seq=" U64T "",
              local_nodeid, local_born_on, membership_seq);
    update_member(local_nodeid, local_born_on, membership_seq, msg->votes, msg->processes, NULL,
                  NULL, VERSION);

    iovec.iov_base = (char *)msg;
    iovec.iov_len = msg->header.size;

    rc = pcmk_api->totem_mcast(&iovec, 1, TOTEMPG_SAFE);

    AIS_CHECK(rc == 0, ais_err("Message not sent (%d)", rc));

    ais_free(msg);
}

static gboolean
ghash_send_removal(gpointer key, gpointer value, gpointer data)
{
    send_quorum_details(value);
    if (send_client_msg(value, crm_class_rmpeer, crm_msg_none, data) != 0) {
        /* remove it */
        return TRUE;
    }
    return FALSE;
}

void
ais_remove_peer(char *node_id)
{
    uint32_t id = ais_get_int(node_id, NULL);
    crm_node_t *node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(id));

    if (node == NULL) {
        ais_info("Peer %u is unknown", id);

    } else if (ais_str_eq(CRM_NODE_MEMBER, node->state)) {
        ais_warn("Peer %u/%s is still active", id, node->uname);

    } else if (g_hash_table_remove(membership_list, GUINT_TO_POINTER(id))) {
        plugin_expected_votes--;
        ais_notice("Removed dead peer %u from the membership list", id);
        ais_info("Sending removal of %u to %d children",
                 id, g_hash_table_size(membership_notify_list));

        g_hash_table_foreach_remove(membership_notify_list, ghash_send_removal, node_id);

    } else {
        ais_warn("Peer %u/%s was not removed", id, node->uname);
    }
}

gboolean
process_ais_message(const AIS_Message * msg)
{
    int len = ais_data_len(msg);
    char *data = get_ais_data(msg);

    do_ais_log(LOG_DEBUG,
               "Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d): %.90s",
               msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
               ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
               msg->sender.pid,
               msg->sender.uname == local_uname ? "false" : "true", ais_data_len(msg), data);

    if (data && len > 12 && strncmp("remove-peer:", data, 12) == 0) {
        char *node = data + 12;

        ais_remove_peer(node);
    }

    ais_free(data);
    return TRUE;
}

static void
member_dump_fn(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;

    ais_info(" node id:%u, uname=%s state=%s processes=%.16x born=" U64T " seen=" U64T
             " addr=%s version=%s", node->id, node->uname ? node->uname : "-unknown-", node->state,
             node->processes, node->born, node->last_seen, node->addr ? node->addr : "-unknown-",
             node->version ? node->version : "-unknown-");
}

void
pcmk_exec_dump(void)
{
    /* Called after SIG_USR2 */
    process_ais_conf();
    ais_info("Local id: %u, uname: %s, born: " U64T, local_nodeid, local_uname, local_born_on);
    ais_info("Membership id: " U64T ", quorate: %s, expected: %u, actual: %u",
             membership_seq, plugin_has_quorum()? "true" : "false",
             plugin_expected_votes, plugin_has_votes);

    g_hash_table_foreach(membership_list, member_dump_fn, NULL);
}
