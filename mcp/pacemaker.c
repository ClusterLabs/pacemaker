/*
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
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
#include <pacemaker.h>

#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/reboot.h>

#include <crm/msg_xml.h>
#include <crm/common/ipcs.h>
#include <crm/common/mainloop.h>
#include <crm/cluster/internal.h>
#include <crm/cluster.h>

#include <dirent.h>
#include <ctype.h>
gboolean fatal_error = FALSE;
GMainLoop *mainloop = NULL;

#define PCMK_PROCESS_CHECK_INTERVAL 5

const char *local_name = NULL;
uint32_t local_nodeid = 0;
crm_trigger_t *shutdown_trigger = NULL;
const char *pid_file = "/var/run/pacemaker.pid";

typedef struct pcmk_child_s {
    int pid;
    long flag;
    int start_seq;
    int respawn_count;
    gboolean respawn;
    const char *name;
    const char *uid;
    const char *command;

    gboolean active_before_startup;
} pcmk_child_t;

/* Index into the array below */
#define pcmk_child_crmd  4
#define pcmk_child_mgmtd 8
/* *INDENT-OFF* */
static pcmk_child_t pcmk_children[] = {
    { 0, crm_proc_none,       0, 0, FALSE, "none",       NULL,            NULL },
    { 0, crm_proc_plugin,     0, 0, FALSE, "ais",        NULL,            NULL },
    { 0, crm_proc_lrmd,       3, 0, TRUE,  "lrmd",       NULL,            CRM_DAEMON_DIR"/lrmd" },
    { 0, crm_proc_cib,        1, 0, TRUE,  "cib",        CRM_DAEMON_USER, CRM_DAEMON_DIR"/cib" },
    { 0, crm_proc_crmd,       6, 0, TRUE,  "crmd",       CRM_DAEMON_USER, CRM_DAEMON_DIR"/crmd" },
    { 0, crm_proc_attrd,      4, 0, TRUE,  "attrd",      CRM_DAEMON_USER, CRM_DAEMON_DIR"/attrd" },
    { 0, crm_proc_stonithd,   0, 0, TRUE,  "stonithd",   NULL,            NULL },
    { 0, crm_proc_pe,         5, 0, TRUE,  "pengine",    CRM_DAEMON_USER, CRM_DAEMON_DIR"/pengine" },
    { 0, crm_proc_mgmtd,      0, 0, TRUE,  "mgmtd",      NULL,            HB_DAEMON_DIR"/mgmtd" },
    { 0, crm_proc_stonith_ng, 2, 0, TRUE,  "stonith-ng", NULL,            CRM_DAEMON_DIR"/stonithd" },
};
/* *INDENT-ON* */

static gboolean start_child(pcmk_child_t * child);
static gboolean check_active_before_startup_processes(gpointer user_data);
void update_process_clients(crm_client_t *client);
void update_process_peers(void);

void
enable_crmd_as_root(gboolean enable)
{
    if (enable) {
        pcmk_children[pcmk_child_crmd].uid = NULL;
    } else {
        pcmk_children[pcmk_child_crmd].uid = CRM_DAEMON_USER;
    }
}

void
enable_mgmtd(gboolean enable)
{
    if (enable) {
        pcmk_children[pcmk_child_mgmtd].start_seq = 7;
    } else {
        pcmk_children[pcmk_child_mgmtd].start_seq = 0;
    }
}

static uint32_t
get_process_list(void)
{
    int lpc = 0;
    uint32_t procs = 0;

    if(is_classic_ais_cluster()) {
        procs |= crm_proc_plugin;
    }

    for (lpc = 0; lpc < SIZEOF(pcmk_children); lpc++) {
        if (pcmk_children[lpc].pid != 0) {
            procs |= pcmk_children[lpc].flag;
        }
    }
    return procs;
}

static void
pcmk_process_exit(pcmk_child_t * child)
{
    child->pid = 0;
    child->active_before_startup = FALSE;

    /* Broadcast the fact that one of our processes died ASAP
     *
     * Try to get some logging of the cause out first though
     * because we're probably about to get fenced
     *
     * Potentially do this only if respawn_count > N
     * to allow for local recovery
     */
    update_node_processes(local_nodeid, NULL, get_process_list());

    child->respawn_count += 1;
    if (child->respawn_count > MAX_RESPAWN) {
        crm_err("Child respawn count exceeded by %s", child->name);
        child->respawn = FALSE;
    }

    if (shutdown_trigger) {
        mainloop_set_trigger(shutdown_trigger);
        update_node_processes(local_nodeid, NULL, get_process_list());

    } else if (child->respawn) {
        gboolean fail_fast = crm_is_true(getenv("PCMK_fail_fast"));

        crm_notice("Respawning failed child process: %s", child->name);

#ifdef RB_HALT_SYSTEM
        if (fail_fast) {
            crm_err("Rebooting system", child->name);
            sync();
            reboot(RB_HALT_SYSTEM);
            crm_exit(DAEMON_RESPAWN_STOP);
        }
#endif
        start_child(child);
    }
}

static void
pcmk_child_exit(mainloop_child_t * p, pid_t pid, int core, int signo, int exitcode)
{
    pcmk_child_t *child = mainloop_child_userdata(p);
    const char *name = mainloop_child_name(p);

    if (signo) {
        crm_notice("Child process %s terminated with signal %d (pid=%d, core=%d)",
                   name, signo, pid, core);

    } else {
        do_crm_log(exitcode == 0 ? LOG_INFO : LOG_ERR,
                   "Child process %s (%d) exited: %s (%d)", name, pid, pcmk_strerror(exitcode), exitcode);
    }

    if (exitcode == 100) {
        crm_warn("Pacemaker child process %s no longer wishes to be respawned. "
                 "Shutting ourselves down.", name);
        child->respawn = FALSE;
        fatal_error = TRUE;
        pcmk_shutdown(15);
    }

    pcmk_process_exit(child);
}

static gboolean
stop_child(pcmk_child_t * child, int signal)
{
    if (signal == 0) {
        signal = SIGTERM;
    }

    if (child->command == NULL) {
        crm_debug("Nothing to do for child \"%s\"", child->name);
        return TRUE;
    }

    if (child->pid <= 0) {
        crm_trace("Client %s not running", child->name);
        return TRUE;
    }

    errno = 0;
    if (kill(child->pid, signal) == 0) {
        crm_notice("Stopping %s: Sent -%d to process %d", child->name, signal, child->pid);

    } else {
        crm_perror(LOG_ERR, "Stopping %s: Could not send -%d to process %d failed",
                   child->name, signal, child->pid);
    }

    return TRUE;
}

static char *opts_default[] = { NULL, NULL };
static char *opts_vgrind[] = { NULL, NULL, NULL, NULL, NULL };

static gboolean
start_child(pcmk_child_t * child)
{
    int lpc = 0;
    uid_t uid = 0;
    gid_t gid = 0;
    struct rlimit oflimits;
    gboolean use_valgrind = FALSE;
    gboolean use_callgrind = FALSE;
    const char *devnull = "/dev/null";
    const char *env_valgrind = getenv("PCMK_valgrind_enabled");
    const char *env_callgrind = getenv("PCMK_callgrind_enabled");
    enum cluster_type_e stack = get_cluster_type();

    child->active_before_startup = FALSE;

    if (child->command == NULL) {
        crm_info("Nothing to do for child \"%s\"", child->name);
        return TRUE;
    }

    if (env_callgrind != NULL && crm_is_true(env_callgrind)) {
        use_callgrind = TRUE;
        use_valgrind = TRUE;

    } else if (env_callgrind != NULL && strstr(env_callgrind, child->name)) {
        use_callgrind = TRUE;
        use_valgrind = TRUE;

    } else if (env_valgrind != NULL && crm_is_true(env_valgrind)) {
        use_valgrind = TRUE;

    } else if (env_valgrind != NULL && strstr(env_valgrind, child->name)) {
        use_valgrind = TRUE;
    }

    if (use_valgrind && strlen(VALGRIND_BIN) == 0) {
        crm_warn("Cannot enable valgrind for %s:"
                 " The location of the valgrind binary is unknown", child->name);
        use_valgrind = FALSE;
    }

    if (child->uid) {
        if (crm_user_lookup(child->uid, &uid, &gid) < 0) {
            crm_err("Invalid user (%s) for %s: not found", child->uid, child->name);
            return FALSE;
        }
        crm_info("Using uid=%u and group=%u for process %s", uid, gid, child->name);
    }

    child->pid = fork();
    CRM_ASSERT(child->pid != -1);

    if (child->pid > 0) {
        /* parent */
        mainloop_child_add(child->pid, 0, child->name, child, pcmk_child_exit);

        crm_info("Forked child %d for process %s%s", child->pid, child->name,
                 use_valgrind ? " (valgrind enabled: " VALGRIND_BIN ")" : "");
        update_node_processes(local_nodeid, NULL, get_process_list());
        return TRUE;

    } else {
        /* Start a new session */
        (void)setsid();

        /* Setup the two alternate arg arrarys */
        opts_vgrind[0] = strdup(VALGRIND_BIN);
        if (use_callgrind) {
            opts_vgrind[1] = strdup("--tool=callgrind");
            opts_vgrind[2] = strdup("--callgrind-out-file=" CRM_STATE_DIR "/callgrind.out.%p");
            opts_vgrind[3] = strdup(child->command);
            opts_vgrind[4] = NULL;
        } else {
            opts_vgrind[1] = strdup(child->command);
            opts_vgrind[2] = NULL;
            opts_vgrind[3] = NULL;
            opts_vgrind[4] = NULL;
        }
        opts_default[0] = strdup(child->command);;

        if(gid) {
            if(stack == pcmk_cluster_corosync) {
                /* Drop root privileges completely
                 *
                 * We can do this because we set uidgid.gid.${gid}=1
                 * via CMAP which allows these processes to connect to
                 * corosync
                 */
                if (setgid(gid) < 0) {
                    crm_perror(LOG_ERR, "Could not set group to %d", gid);
                }

                /* Keep the root group (so we can access corosync), but add the haclient group (so we can access ipc) */
            } else if (initgroups(child->uid, gid) < 0) {
                crm_err("Cannot initalize groups for %s: %s (%d)", child->uid, pcmk_strerror(errno), errno);
            }
        }

        if (uid && setuid(uid) < 0) {
            crm_perror(LOG_ERR, "Could not set user to %d (%s)", uid, child->uid);
        }

        /* Close all open file descriptors */
        getrlimit(RLIMIT_NOFILE, &oflimits);
        for (lpc = 0; lpc < oflimits.rlim_cur; lpc++) {
            close(lpc);
        }

        (void)open(devnull, O_RDONLY);  /* Stdin:  fd 0 */
        (void)open(devnull, O_WRONLY);  /* Stdout: fd 1 */
        (void)open(devnull, O_WRONLY);  /* Stderr: fd 2 */

        if (use_valgrind) {
            (void)execvp(VALGRIND_BIN, opts_vgrind);
        } else {
            (void)execvp(child->command, opts_default);
        }
        crm_perror(LOG_ERR, "FATAL: Cannot exec %s", child->command);
        crm_exit(DAEMON_RESPAWN_STOP);
    }
    return TRUE;                /* never reached */
}

static gboolean
escalate_shutdown(gpointer data)
{

    pcmk_child_t *child = data;

    if (child->pid) {
        /* Use SIGSEGV instead of SIGKILL to create a core so we can see what it was up to */
        crm_err("Child %s not terminating in a timely manner, forcing", child->name);
        stop_child(child, SIGSEGV);
    }
    return FALSE;
}

static gboolean
pcmk_shutdown_worker(gpointer user_data)
{
    static int phase = 0;
    static time_t next_log = 0;
    static int max = SIZEOF(pcmk_children);

    int lpc = 0;

    if (phase == 0) {
        crm_notice("Shuting down Pacemaker");
        phase = max;

        /* Add a second, more frequent, check to speed up shutdown */
        g_timeout_add_seconds(5, check_active_before_startup_processes, NULL);
    }

    for (; phase > 0; phase--) {
        /* dont stop anything with start_seq < 1 */

        for (lpc = max - 1; lpc >= 0; lpc--) {
            pcmk_child_t *child = &(pcmk_children[lpc]);

            if (phase != child->start_seq) {
                continue;
            }

            if (child->pid) {
                time_t now = time(NULL);

                if (child->respawn) {
                    next_log = now + 30;
                    child->respawn = FALSE;
                    stop_child(child, SIGTERM);
                    if (phase < pcmk_children[pcmk_child_crmd].start_seq) {
                        g_timeout_add(180000 /* 3m */ , escalate_shutdown, child);
                    }

                } else if (now >= next_log) {
                    next_log = now + 30;
                    crm_notice("Still waiting for %s (pid=%d, seq=%d) to terminate...",
                               child->name, child->pid, child->start_seq);
                }
                return TRUE;
            }

            /* cleanup */
            crm_debug("%s confirmed stopped", child->name);
            child->pid = 0;
        }
    }

    /* send_cluster_id(); */
    crm_notice("Shutdown complete");
    g_main_loop_quit(mainloop);

    if (fatal_error) {
        crm_notice("Attempting to inhibit respawning after fatal error");
        crm_exit(DAEMON_RESPAWN_STOP);
    }

    return TRUE;
}

void
pcmk_shutdown(int nsig)
{
    if (shutdown_trigger == NULL) {
        shutdown_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, pcmk_shutdown_worker, NULL);
    }
    mainloop_set_trigger(shutdown_trigger);
}

static int32_t
pcmk_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
pcmk_ipc_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

/* Exit code means? */
static int32_t
pcmk_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    const char *task = NULL;
    crm_client_t *c = crm_client_get(qbc);
    xmlNode *msg = crm_ipcs_recv(c, data, size, &id, &flags);

    crm_ipcs_send_ack(c, id, flags, "ack", __FUNCTION__, __LINE__);
    if (msg == NULL) {
        return 0;
    }

    task = crm_element_value(msg, F_CRM_TASK);
    if (crm_str_eq(task, CRM_OP_QUIT, TRUE)) {
        /* Time to quit */
        crm_notice("Shutting down in responce to ticket %s (%s)",
                   crm_element_value(msg, F_CRM_REFERENCE), crm_element_value(msg, F_CRM_ORIGIN));
        pcmk_shutdown(15);

    } else if (crm_str_eq(task, CRM_OP_RM_NODE_CACHE, TRUE)) {
        /* Send to everyone */
        struct iovec *iov;
        int id = 0;
        const char *name = NULL;

        crm_element_value_int(msg, XML_ATTR_ID, &id);
        name = crm_element_value(msg, XML_ATTR_UNAME);
        crm_notice("Instructing peers to remove references to node %s/%u", name, id);

        iov = calloc(1, sizeof(struct iovec));
        iov->iov_base = dump_xml_unformatted(msg);
        iov->iov_len = 1 + strlen(iov->iov_base);
        send_cpg_iov(iov);

    } else {
        update_process_clients(c);
    }

    free_xml(msg);
    return 0;
}

/* Error code means? */
static int32_t
pcmk_ipc_closed(qb_ipcs_connection_t * c)
{
    crm_client_t *client = crm_client_get(c);

    crm_trace("Connection %p", c);
    crm_client_destroy(client);
    return 0;
}

static void
pcmk_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

struct qb_ipcs_service_handlers mcp_ipc_callbacks = {
    .connection_accept = pcmk_ipc_accept,
    .connection_created = pcmk_ipc_created,
    .msg_process = pcmk_ipc_dispatch,
    .connection_closed = pcmk_ipc_closed,
    .connection_destroyed = pcmk_ipc_destroy
};

void
update_process_clients(crm_client_t *client)
{
    GHashTableIter iter;
    crm_node_t *node = NULL;
    xmlNode *update = create_xml_node(NULL, "nodes");

    crm_trace("Sending process list to %d children", crm_hash_table_size(client_connections));

    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & node)) {
        xmlNode *xml = create_xml_node(update, "node");

        crm_xml_add_int(xml, "id", node->id);
        crm_xml_add(xml, "uname", node->uname);
        crm_xml_add(xml, "state", node->state);
        crm_xml_add_int(xml, "processes", node->processes);
    }

    if(client) {
        crm_ipcs_send(client, 0, update, crm_ipc_server_event);

    } else {
        g_hash_table_iter_init(&iter, client_connections);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & client)) {
            crm_ipcs_send(client, 0, update, crm_ipc_server_event);
        }
    }

    free_xml(update);
}

void
update_process_peers(void)
{
    /* Do nothing for corosync-2 based clusters */

    char buffer[1024];
    struct iovec *iov;
    int rc = 0;

    memset(buffer, 0, SIZEOF(buffer));

    if (local_name) {
        rc = snprintf(buffer, SIZEOF(buffer) - 1, "<node uname=\"%s\" proclist=\"%u\"/>",
                      local_name, get_process_list());
    } else {
        rc = snprintf(buffer, SIZEOF(buffer) - 1, "<node proclist=\"%u\"/>", get_process_list());
    }

    crm_trace("Sending %s", buffer);
    iov = calloc(1, sizeof(struct iovec));
    iov->iov_base = strdup(buffer);
    iov->iov_len = rc + 1;
    send_cpg_iov(iov);
}

gboolean
update_node_processes(uint32_t id, const char *uname, uint32_t procs)
{
    gboolean changed = FALSE;
    crm_node_t *node = crm_get_peer(id, uname);

    if (procs != 0) {
        if (procs != node->processes) {
            crm_debug("Node %s now has process list: %.32x (was %.32x)",
                      node->uname, procs, node->processes);
            node->processes = procs;
            changed = TRUE;

        } else {
            crm_trace("Node %s still has process list: %.32x", node->uname, procs);
        }
    }

    if (changed && id == local_nodeid) {
        update_process_clients(NULL);
        update_process_peers();
    }
    return changed;
}


/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",           0, 0, '?', "\tThis text"},
    {"version",        0, 0, '$', "\tVersion information"  },
    {"verbose",        0, 0, 'V', "\tIncrease debug output"},
    {"shutdown",       0, 0, 'S', "\tInstruct Pacemaker to shutdown on this machine"},
    {"features",       0, 0, 'F', "\tDisplay the full version and list of features Pacemaker was built with"},

    {"-spacer-",       1, 0, '-', "\nAdditional Options:"},
    {"foreground",     0, 0, 'f', "\t(Ignored) Pacemaker always runs in the foreground"},
    {"pid-file",       1, 0, 'p', "\t(Ignored) Daemon pid file location"},

    {NULL, 0, 0, 0}
};
/* *INDENT-ON* */

static void
mcp_chown(const char *path, uid_t uid, gid_t gid)
{
    int rc = chown(path, uid, gid);

    if (rc < 0) {
        crm_warn("Cannot change the ownership of %s to user %s and gid %d: %s",
                 path, CRM_DAEMON_USER, gid, pcmk_strerror(errno));
    }
}

static gboolean
check_active_before_startup_processes(gpointer user_data)
{
    int start_seq = 1, lpc = 0;
    static int max = SIZEOF(pcmk_children);
    gboolean keep_tracking = FALSE;

    for (start_seq = 1; start_seq < max; start_seq++) {
        for (lpc = 0; lpc < max; lpc++) {
            if (pcmk_children[lpc].active_before_startup == FALSE) {
                /* we are already tracking it as a child process. */
                continue;
            } else if (start_seq != pcmk_children[lpc].start_seq) {
                continue;
            } else if (crm_pid_active(pcmk_children[lpc].pid) != 1) {
                crm_notice("Process %s terminated (pid=%d)",
                           pcmk_children[lpc].name, pcmk_children[lpc].pid);
                pcmk_process_exit(&(pcmk_children[lpc]));
                continue;
            }
            /* at least one of the processes found at startup
             * is still going, so keep this recurring timer around */
            keep_tracking = TRUE;
        }
    }

    return keep_tracking;
}

static void
find_and_track_existing_processes(void)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    int start_tracker = 0;

    dp = opendir("/proc");
    if (!dp) {
        /* no proc directory to search through */
        crm_notice("Can not read /proc directory to track existing components");
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        char procpath[128];
        char value[64];
        char key[16];
        FILE *file;
        int pid;
        int max = SIZEOF(pcmk_children);
        int i;

        strcpy(procpath, "/proc/");
        /* strlen("/proc/") + strlen("/status") + 1 = 14
         * 128 - 14 = 114 */
        strncat(procpath, entry->d_name, 114);

        if (lstat(procpath, &statbuf)) {
            continue;
        }
        if (!S_ISDIR(statbuf.st_mode) || !isdigit(entry->d_name[0])) {
            continue;
        }

        strcat(procpath, "/status");

        file = fopen(procpath, "r");
        if (!file) {
            continue;
        }
        if (fscanf(file, "%15s%63s", key, value) != 2) {
            fclose(file);
            continue;
        }
        fclose(file);

        pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        for (i = 0; i < max; i++) {
            const char *name = pcmk_children[i].name;

            if (pcmk_children[i].start_seq == 0) {
                continue;
            }
            if (pcmk_children[i].flag == crm_proc_stonith_ng) {
                name = "stonithd";
            }
            if (safe_str_eq(name, value)) {
                if (crm_pid_active(pid) != 1) {
                    continue;
                }
                crm_notice("Tracking existing %s process (pid=%d)", value, pid);
                pcmk_children[i].pid = pid;
                pcmk_children[i].active_before_startup = TRUE;
                start_tracker = 1;
            }
        }
    }

    if (start_tracker) {
        g_timeout_add_seconds(PCMK_PROCESS_CHECK_INTERVAL, check_active_before_startup_processes,
                              NULL);
    }
    closedir(dp);
}

static void
init_children_processes(void)
{
    int start_seq = 1, lpc = 0;
    static int max = SIZEOF(pcmk_children);

    /* start any children that have not been detected */
    for (start_seq = 1; start_seq < max; start_seq++) {
        /* dont start anything with start_seq < 1 */
        for (lpc = 0; lpc < max; lpc++) {
            if (pcmk_children[lpc].pid) {
                /* we are already tracking it */
                continue;
            }

            if (start_seq == pcmk_children[lpc].start_seq) {
                start_child(&(pcmk_children[lpc]));
            }
        }
    }
}

static void
mcp_cpg_destroy(gpointer user_data)
{
    crm_err("Connection destroyed");
    crm_exit(ENOTCONN);
}

static void
mcp_cpg_deliver(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    xmlNode *xml = string2xml(msg);
    const char *task = crm_element_value(xml, F_CRM_TASK);

    crm_trace("Received %s %.200s", task, msg);
    if (task == NULL && nodeid != local_nodeid) {
        uint32_t procs = 0;
        const char *uname = crm_element_value(xml, "uname");

        crm_element_value_int(xml, "proclist", (int *)&procs);
        /* crm_debug("Got proclist %.32x from %s", procs, uname); */
        if (update_node_processes(nodeid, uname, procs)) {
            update_process_clients(NULL);
        }

    } else if (crm_str_eq(task, CRM_OP_RM_NODE_CACHE, TRUE)) {
        int id = 0;
        const char *name = NULL;

        crm_element_value_int(xml, XML_ATTR_ID, &id);
        name = crm_element_value(xml, XML_ATTR_UNAME);
        reap_crm_member(id, name);
    }
}

static void
mcp_cpg_membership(cpg_handle_t handle,
                    const struct cpg_name *groupName,
                    const struct cpg_address *member_list, size_t member_list_entries,
                    const struct cpg_address *left_list, size_t left_list_entries,
                    const struct cpg_address *joined_list, size_t joined_list_entries)
{
    /* Don't care about CPG membership, but we do want to broadcast our own presence */
    update_process_peers();
}

static gboolean
mcp_quorum_callback(unsigned long long seq, gboolean quorate)
{
    /* Nothing to do */
    return TRUE;
}

static void
mcp_quorum_destroy(gpointer user_data)
{
    crm_info("connection closed");
}

int
main(int argc, char **argv)
{
    int rc;
    int flag;
    int argerr = 0;

    int option_index = 0;
    gboolean shutdown = FALSE;

    uid_t pcmk_uid = 0;
    gid_t pcmk_gid = 0;
    struct rlimit cores;
    crm_ipc_t *old_instance = NULL;
    qb_ipcs_service_t *ipcs = NULL;
    const char *facility = daemon_option("logfacility");
    static crm_cluster_t cluster;

    setenv("LC_ALL", "C", 1);
    setenv("HA_LOGD", "no", 1);

    set_daemon_option("mcp", "true");
    set_daemon_option("use_logd", "off");

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "mode [options]", long_options, "Start/Stop Pacemaker\n");

    /* Restore the original facility so that mcp_read_config() does the right thing */
    set_daemon_option("logfacility", facility);

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
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
                pid_file = optarg;
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'S':
                shutdown = TRUE;
                break;
            case 'F':
                printf("Pacemaker %s (Build: %s)\n Supporting v%s: %s\n", VERSION, BUILD_VERSION,
                       CRM_FEATURE_SET, CRM_FEATURES);
                crm_exit(pcmk_ok);
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
        crm_help('?', EX_USAGE);
    }

    crm_debug("Checking for old instances of %s", CRM_SYSTEM_MCP);
    old_instance = crm_ipc_new(CRM_SYSTEM_MCP, 0);
    crm_ipc_connect(old_instance);

    if (shutdown) {
        crm_debug("Terminating previous instance");
        while (crm_ipc_connected(old_instance)) {
            xmlNode *cmd =
                create_request(CRM_OP_QUIT, NULL, NULL, CRM_SYSTEM_MCP, CRM_SYSTEM_MCP, NULL);

            crm_debug(".");
            crm_ipc_send(old_instance, cmd, 0, 0, NULL);
            free_xml(cmd);

            sleep(2);
        }
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_exit(pcmk_ok);

    } else if (crm_ipc_connected(old_instance)) {
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("Pacemaker is already active, aborting startup");
        crm_exit(DAEMON_RESPAWN_STOP);
    }

    crm_ipc_close(old_instance);
    crm_ipc_destroy(old_instance);

    if (mcp_read_config() == FALSE) {
        crm_notice("Could not obtain corosync config data, exiting");
        crm_exit(ENODATA);
    }

    crm_notice("Starting Pacemaker %s (Build: %s): %s", VERSION, BUILD_VERSION, CRM_FEATURES);
    mainloop = g_main_new(FALSE);

    rc = getrlimit(RLIMIT_CORE, &cores);
    if (rc < 0) {
        crm_perror(LOG_ERR, "Cannot determine current maximum core size.");
    } else {
        if (cores.rlim_max == 0 && geteuid() == 0) {
            cores.rlim_max = RLIM_INFINITY;
        } else {
            crm_info("Maximum core file size is: %lu", (unsigned long)cores.rlim_max);
        }
        cores.rlim_cur = cores.rlim_max;

        rc = setrlimit(RLIMIT_CORE, &cores);
        if (rc < 0) {
            crm_perror(LOG_ERR,
                       "Core file generation will remain disabled."
                       " Core files are an important diagnositic tool,"
                       " please consider enabling them by default.");
        }
#if 0
        /* system() is not thread-safe, can't call from here
         * Actually, its a pretty hacky way to try and achieve this anyway
         */
        if (system("echo 1 > /proc/sys/kernel/core_uses_pid") != 0) {
            crm_perror(LOG_ERR, "Could not enable /proc/sys/kernel/core_uses_pid");
        }
#endif
    }

    if (crm_user_lookup(CRM_DAEMON_USER, &pcmk_uid, &pcmk_gid) < 0) {
        crm_err("Cluster user %s does not exist, aborting Pacemaker startup", CRM_DAEMON_USER);
        crm_exit(ENOKEY);
    }

    mkdir(CRM_STATE_DIR, 0750);
    mcp_chown(CRM_STATE_DIR, pcmk_uid, pcmk_gid);

    /* Used to store core files in */
    crm_build_path(CRM_CORE_DIR, 0775);
    mcp_chown(CRM_CORE_DIR, pcmk_uid, pcmk_gid);

    /* Used to store blackbox dumps in */
    crm_build_path(CRM_BLACKBOX_DIR, 0755);
    mcp_chown(CRM_BLACKBOX_DIR, pcmk_uid, pcmk_gid);

    /* Used to store policy engine inputs in */
    crm_build_path(PE_STATE_DIR, 0755);
    mcp_chown(PE_STATE_DIR, pcmk_uid, pcmk_gid);

    /* Used to store the cluster configuration */
    crm_build_path(CRM_CONFIG_DIR, 0755);
    mcp_chown(CRM_CONFIG_DIR, pcmk_uid, pcmk_gid);

    /* Resource agent paths are constructed by the lrmd */

    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_MCP, QB_IPC_NATIVE, &mcp_ipc_callbacks);
    if (ipcs == NULL) {
        crm_err("Couldn't start IPC server");
        crm_exit(EIO);
    }

    /* Allows us to block shutdown */
    if (cluster_connect_cfg(&local_nodeid) == FALSE) {
        crm_err("Couldn't connect to Corosync's CFG service");
        crm_exit(ENOPROTOOPT);
    }

    cluster.destroy = mcp_cpg_destroy;
    cluster.cpg.cpg_deliver_fn = mcp_cpg_deliver;
    cluster.cpg.cpg_confchg_fn = mcp_cpg_membership;

    if(cluster_connect_cpg(&cluster) == FALSE) {
        crm_err("Couldn't connect to Corosync's CPG service");
        crm_exit(ENOPROTOOPT);
    }

    if (is_corosync_cluster()) {
        /* Keep the membership list up-to-date for crm_node to query */
        rc = cluster_connect_quorum(mcp_quorum_callback, mcp_quorum_destroy);
    }

    local_name = get_local_node_name();
    update_node_processes(local_nodeid, local_name, get_process_list());

    mainloop_add_signal(SIGTERM, pcmk_shutdown);
    mainloop_add_signal(SIGINT, pcmk_shutdown);

    find_and_track_existing_processes();
    init_children_processes();

    crm_info("Starting mainloop");

    g_main_run(mainloop);

    if (ipcs) {
        crm_trace("Closing IPC server");
        mainloop_del_ipc_server(ipcs);
        ipcs = NULL;
    }

    g_main_destroy(mainloop);

    cluster_disconnect_cpg(&cluster);
    cluster_disconnect_cfg();

    crm_info("Exiting %s", crm_system_name);

    crm_exit(pcmk_ok);
}
