/* 
 * Copyright (C) 2010 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>
#include <pacemaker.h>

#include <pwd.h>
#include <sys/utsname.h>

#include <crm/common/ipc.h>


GMainLoop *mainloop = NULL;
GHashTable *client_list = NULL;
GHashTable *peers = NULL;

char ipc_name[] = "pcmk";
uint32_t local_nodeid = 0;
crm_trigger_t  *shutdown_trigger = NULL;
const char *pid_file = "/var/run/pacemaker.pid";

enum crm_proc_flag {
    crm_proc_none       = 0x00000001,
    crm_proc_ais        = 0x00000002,
    crm_proc_lrmd       = 0x00000010,
    crm_proc_cib        = 0x00000100,
    crm_proc_crmd       = 0x00000200,
    crm_proc_attrd      = 0x00001000,
    crm_proc_stonithd   = 0x00002000,
    crm_proc_pe         = 0x00010000,
    crm_proc_te         = 0x00020000,
    crm_proc_mgmtd      = 0x00040000,
    crm_proc_stonith_ng = 0x00100000,
};

/* order here matters - its used to index into the crm_children array */
enum crm_ais_msg_types {
    crm_msg_none     = 0,
    crm_msg_ais      = 1,
    crm_msg_lrmd     = 2,
    crm_msg_cib      = 3,
    crm_msg_crmd     = 4,
    crm_msg_attrd    = 5,
    crm_msg_stonithd = 6,
    crm_msg_te       = 7,
    crm_msg_pe       = 8,
    crm_msg_stonith_ng = 9,
};

typedef struct pcmk_child_s {
	int pid;
	long flag;
	long flags;
	int start_seq;
	int respawn_count;
	gboolean respawn;
	const char *name;
	const char *uid;
	const char *command;
    
} pcmk_child_t;

static pcmk_child_t pcmk_children[] = {
    { 0, crm_proc_none,     crm_flag_none,    0, 0, FALSE, "none",     NULL,		NULL },
    { 0, crm_proc_ais,      crm_flag_none,    0, 0, FALSE, "ais",      NULL,		NULL },
    { 0, crm_proc_lrmd,     crm_flag_none,    3, 0, TRUE,  "lrmd",     NULL,		HB_DAEMON_DIR"/lrmd" },
    { 0, crm_proc_cib,      crm_flag_members, 2, 0, TRUE,  "cib",      CRM_DAEMON_USER, CRM_DAEMON_DIR"/cib" },
    { 0, crm_proc_crmd,     crm_flag_members, 6, 0, TRUE,  "crmd",     CRM_DAEMON_USER, CRM_DAEMON_DIR"/crmd" },
    { 0, crm_proc_attrd,    crm_flag_none,    4, 0, TRUE,  "attrd",    CRM_DAEMON_USER, CRM_DAEMON_DIR"/attrd" },
    { 0, crm_proc_stonithd, crm_flag_none,    0, 0, TRUE,  "stonithd", NULL,		"/bin/false" },
    { 0, crm_proc_pe,       crm_flag_none,    5, 0, TRUE,  "pengine",  CRM_DAEMON_USER, CRM_DAEMON_DIR"/pengine" },
    { 0, crm_proc_mgmtd,    crm_flag_none,    7, 0, TRUE,  "mgmtd",    NULL,		HB_DAEMON_DIR"/mgmtd" },
    { 0, crm_proc_stonith_ng, crm_flag_none,  1, 0, TRUE,  "stonith-ng", NULL,		CRM_DAEMON_DIR"/stonithd" },
};

static gboolean start_child(pcmk_child_t *child);

static uint32_t get_process_list(void) 
{
    int lpc = 0;
    uint32_t procs = crm_proc_ais;
    for (lpc = 0; lpc < SIZEOF(pcmk_children); lpc++) {
	if(pcmk_children[lpc].pid != 0) {
	    procs |= pcmk_children[lpc].flag;
	}
    }
    return procs;
}

static int pcmk_user_lookup(const char *name, uid_t *uid, gid_t *gid)
{
    int rc = -1;
    char *buffer = NULL;
    struct passwd pwd;
    struct passwd *pwentry = NULL;

    crm_malloc0(buffer, PW_BUFFER_LEN);
    getpwnam_r(name, &pwd, buffer, PW_BUFFER_LEN, &pwentry);
    if(pwentry) {
	rc = 0;
	if(uid) { *uid = pwentry->pw_uid; }
	if(gid) { *gid = pwentry->pw_gid; }
	crm_debug("Cluster user %s has uid=%d gid=%d",
		  name, pwentry->pw_uid, pwentry->pw_gid);

    } else {
	crm_err("Cluster user %s does not exist", name);
    }

    crm_free(buffer);
    return rc;
}

static void
pcmk_child_exit(
    ProcTrack* p, int status, int signo, int exitcode, int waslogged)
{
    pcmk_child_t *child = p->privatedata;
    p->privatedata = NULL;
	
    crm_notice("Process %s [%d] exited (signal=%d, exitcode=%d)",
	       child->name, child->pid, signo, exitcode);

    child->pid = 0;
    if(exitcode == 100) {
	crm_notice("Child process %s no longer wishes"
		   " to be respawned", child->name);
	child->respawn = FALSE;
    }

    child->respawn_count += 1;
    if(child->respawn_count > MAX_RESPAWN) {
	crm_err("Child respawn count exceeded by %s", child->name);
	child->respawn = FALSE;
    }

    if(shutdown_trigger) {
	mainloop_set_trigger(shutdown_trigger);
	update_node_processes(local_nodeid, NULL, get_process_list());

    } else if(child->respawn) {
	crm_notice("Respawning failed child process: %s", child->name);
	start_child(child);
    }	
}

static void
pcmkManagedChildRegistered(ProcTrack* p)
{
    pcmk_child_t *child = p->privatedata;
    child->pid = p->pid;
}

static const char *
pcmkManagedChildName(ProcTrack* p)
{
    pcmk_child_t *child = p->privatedata;
    return child->name;
}

static ProcTrack_ops pcmk_managed_child_ops = {
    pcmk_child_exit,
    pcmkManagedChildRegistered,
    pcmkManagedChildName
};

static gboolean
stop_child(pcmk_child_t *child, int signal)
{
    if(signal == 0) {
	signal = SIGTERM;
    }
	
    if(child->command == NULL) {
	crm_debug("Nothing to do for child \"%s\"", child->name);
	return TRUE;
    }
    
    crm_info("Stopping CRM child \"%s\"", child->name);
    
    if (child->pid <= 0) {
	crm_debug_2("Client %s not running", child->name);
	return TRUE;
    }
	
    errno = 0;
    if(kill(child->pid, signal) == 0) {
	crm_notice("Sent -%d to %s: [%d]", signal, child->name, child->pid);
	    
    } else {
	crm_perror(LOG_ERR, "Sent -%d to %s: [%d]", signal, child->name, child->pid);
    }
    
    return TRUE;
}

static char *opts_default[] = { NULL, NULL };
static char *opts_vgrind[]  = { NULL, NULL, NULL };

static gboolean
start_child(pcmk_child_t *child)
{
    int lpc = 0;
    uid_t uid = 0;
    struct rlimit oflimits;
    gboolean use_valgrind = FALSE;
    const char *devnull = "/dev/null";
    const char *env_valgrind = getenv("HA_VALGRIND_ENABLED");
    
    if(child->command == NULL) {
	crm_info("Nothing to do for child \"%s\"", child->name);
	return TRUE;
    }
    
    if(env_valgrind == NULL) {
	use_valgrind = FALSE;

    } else if(crm_is_true(env_valgrind)) {
	use_valgrind = TRUE;

    } else if(strstr(env_valgrind, child->name)) {
	use_valgrind = TRUE;
    }

    if(use_valgrind && strlen(VALGRIND_BIN) == 0) {
	crm_warn("Cannot enable valgrind for %s:"
		 " The location of the valgrind binary is unknown", child->name);
	use_valgrind = FALSE;
    }

    child->pid = fork();
    CRM_ASSERT(child->pid != -1);

    if(child->pid > 0) {
	/* parent */
	NewTrackedProc(child->pid, 0, PT_LOGNORMAL, child, &pcmk_managed_child_ops);
	crm_info("Forked child %d for process %s%s", child->pid, child->name,
		 use_valgrind?" (valgrind enabled: "VALGRIND_BIN")":"");
	update_node_processes(local_nodeid, NULL, get_process_list());
	return TRUE;

    } else {
	/* Start a new session */
	(void)setsid();

	/* Setup the two alternate arg arrarys */ 
	opts_vgrind[0] = crm_strdup(VALGRIND_BIN);
	opts_vgrind[1] = crm_strdup(child->command);
	opts_default[0] = opts_vgrind[1];
	
#if 0
	/* Dont set the group for now - it prevents connection to the cluster */
	if(gid && setgid(gid) < 0) {
	    crm_perror("Could not set group to %d", gid);
	}
#endif

	if(child->uid) {
	    if(pcmk_user_lookup(child->uid, &uid, NULL) < 0) {
		crm_err("Invalid uid (%s) specified for %s",
			child->uid, child->name);
		return TRUE;
	    }
	}
	
	if(uid && setuid(uid) < 0) {
	    crm_perror(LOG_ERR, "Could not set user to %d (%s)", uid, child->uid);
	}
	
	/* Close all open file descriptors */
	getrlimit(RLIMIT_NOFILE, &oflimits);
	for (lpc = 0; lpc < oflimits.rlim_cur; lpc++) {
	    close(lpc);
	}
	
	(void)open(devnull, O_RDONLY);	/* Stdin:  fd 0 */
	(void)open(devnull, O_WRONLY);	/* Stdout: fd 1 */
	(void)open(devnull, O_WRONLY);	/* Stderr: fd 2 */

	setenv("HA_COMPRESSION",	"bz2",             1);
	setenv("HA_cluster_type",	"openais",	   1);
/*
	setenv("HA_debug",		pcmk_env.debug,    1);
	setenv("HA_logfacility",	pcmk_env.syslog,   1);
	setenv("HA_LOGFACILITY",	pcmk_env.syslog,   1);
	setenv("HA_use_logd",		pcmk_env.use_logd, 1);
	setenv("HA_quorum_type",	pcmk_env.quorum,   1);
	if(pcmk_env.logfile) {
	    setenv("HA_debugfile", pcmk_env.logfile, 1);
	}
*/  
	
	if(use_valgrind) {
	    (void)execvp(VALGRIND_BIN, opts_vgrind);
	} else {
	    (void)execvp(child->command, opts_default);
	}
	crm_perror(LOG_ERR, "FATAL: Cannot exec %s", child->command);
	exit(100);
    }
    return TRUE; /* never reached */
}

static gboolean
escalate_shutdown(gpointer data)
{
    
    pcmk_child_t *child = data;
    if(child->pid) {
	crm_err("Child %s not terminating in a timely manner, forcing", child->name);
	stop_child(child, SIGKILL);
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
	
    if(phase == 0) {
	crm_notice("Shuting down Pacemaker");    
	phase = max;
    }
	
    for (; phase > 0; phase--) {
	/* dont stop anything with start_seq < 1 */
	    
	for (lpc = max - 1; lpc >= 0; lpc--) {
	    pcmk_child_t *child = &(pcmk_children[lpc]);
	    if(phase != child->start_seq) {
		continue;
	    }
		
	    if(child->pid) {
		time_t now = time(NULL);
		    
		if(child->respawn) {
		    next_log = now + 30;
		    child->respawn = FALSE;
		    stop_child(child, SIGTERM);
		    if(phase < pcmk_children[crm_msg_crmd].start_seq) {
			g_timeout_add(180000/* 3m */, escalate_shutdown, child);
		    }

		} else if(now >= next_log) {
		    next_log = now + 30;
		    crm_notice("Still waiting for %s (pid=%d, seq=%d) to terminate...",
			       child->name, child->pid, child->start_seq);
		}		    
		return TRUE;
	    }
		
	    /* cleanup */
	    crm_notice("%s confirmed stopped", child->name);
	    child->pid = 0;
	}
    }
	
    /* send_cluster_id(); */
    crm_notice("Shutdown complete");
    g_main_loop_quit(mainloop);
    return TRUE;	
}

static void
pcmk_shutdown(int nsig)
{
    shutdown_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, pcmk_shutdown_worker, NULL);
    mainloop_set_trigger(shutdown_trigger);
}


static void build_path(const char *path_c, mode_t mode)
{
    int offset = 1, len = 0;
    char *path = crm_strdup(path_c);

    CRM_CHECK(path != NULL, return);
    for(len = strlen(path); offset < len; offset++) {
	if(path[offset] == '/') {
	    path[offset] = 0;
	    if(mkdir(path, mode) < 0 && errno != EEXIST) {
		crm_perror(LOG_ERR, "Could not create directory '%s'", path);
		break;
	    }
	    path[offset] = '/';
	}
    }
    if(mkdir(path, mode) < 0 && errno != EEXIST) {
	crm_perror(LOG_ERR, "Could not create directory '%s'", path);
    }
    crm_free(path);
}

static void
pcmk_server_destroy(gpointer user_data)
{
    crm_info("Server destroyed");
    return;
}

static void
pcmk_client_destroy(gpointer user_data)
{
    crm_debug("Client %p disconnected", user_data);
    g_hash_table_remove(client_list, user_data);
    return;
}

static gboolean
pcmk_client_msg(IPC_Channel *client, gpointer user_data)
{
    xmlNode *msg = NULL;
    gboolean stay_connected = TRUE;
	
    while(IPC_ISRCONN(client)) {
	if(client->ops->is_message_pending(client) == 0) {
	    break;
	}

	msg = xmlfromIPC(client, MAX_IPC_DELAY);
	free_xml(msg);

	if(client->ch_status != IPC_CONNECT) {
	    break;
	}
    }
	
    if (client->ch_status != IPC_CONNECT) {
	stay_connected = FALSE;
    }
    return stay_connected;
}

static gboolean
pcmk_client_connect(IPC_Channel *ch, gpointer user_data)
{
    if (ch == NULL) {
	crm_err("Channel was invalid");

    } else if (ch->ch_status == IPC_DISCONNECT) {
	crm_err("Channel was disconnected");

    } else {
	ch->ops->set_recv_qlen(ch, 1024);
	ch->ops->set_send_qlen(ch, 1024);

	g_hash_table_insert(client_list, ch, user_data);
	update_process_clients();
	
	G_main_add_IPC_Channel(
	    G_PRIORITY_LOW, ch, FALSE,  pcmk_client_msg, ch, pcmk_client_destroy);
    }
    return TRUE;
}

static gboolean
ghash_send_proc_details(gpointer key, gpointer value, gpointer data)
{
    if(send_ipc_message(key, data) == FALSE) {
	/* remove it */
	return TRUE;
    }
    return FALSE;
}

static void peer_loop_fn(gpointer key, gpointer value, gpointer user_data)
{
    pcmk_peer_t *node = value;
    xmlNode *update = user_data;    

    xmlNode *xml = create_xml_node(update, "node");
    crm_xml_add_int(xml, "id", node->id);
    crm_xml_add(xml, "uname", node->uname);
    crm_xml_add_int(xml, "processes", node->processes);
}

void update_process_clients(void)
{
    xmlNode *update = create_xml_node(NULL, "nodes");
    
    crm_debug("Sending process list to %d children",
	      g_hash_table_size(client_list));

    g_hash_table_foreach(peers, peer_loop_fn, update);
    g_hash_table_foreach_remove(client_list, ghash_send_proc_details, update);

    crm_log_xml_debug(update, "update");
    free_xml(update);
}

void update_process_peers(pcmk_peer_t *node) 
{
    char buffer[1024];
    struct iovec iov;
    int rc = 0;

    memset(buffer, SIZEOF(buffer), 0);

    if(node->uname) {
	rc = snprintf(buffer, SIZEOF(buffer) - 1, "<node uname=\"%s\" proclist=\"%u\"/>", node->uname, get_process_list());
    } else {
	rc = snprintf(buffer, SIZEOF(buffer) - 1, "<node proclist=\"%u\"/>", get_process_list());
    }
    
    iov.iov_base = buffer;
    iov.iov_len = rc + 1;
    
    send_cpg_message(&iov);
}

gboolean update_node_processes(uint32_t id, const char *uname, uint32_t procs) 
{
    gboolean changed = FALSE;
    pcmk_peer_t *node = g_hash_table_lookup(peers, GUINT_TO_POINTER(id));	
    if(node == NULL) {	
	changed = TRUE;
	
	crm_malloc0(node, sizeof(pcmk_peer_t));
	node->id = id;
	
	g_hash_table_insert(peers, GUINT_TO_POINTER(id), node);
	node = g_hash_table_lookup(peers, GUINT_TO_POINTER(id));
	CRM_ASSERT(node != NULL);
    }

    if(uname != NULL) {
	if(node->uname == NULL || safe_str_eq(node->uname, uname) == FALSE) {
	    crm_info("%p Node %u now known as %s (was: %s)",
		     node, id, uname, node->uname);
	    crm_free(node->uname);
	    node->uname = crm_strdup(uname);
	    changed = TRUE;
	}
    }
    
    if(procs != 0 && procs != node->processes) {
	crm_info("Node %s now has process list: %.32x (was %.32x)",
		 node->uname, procs, node->processes);
	node->processes = procs;
	changed = TRUE;
    }

    if(changed && id == local_nodeid) {
	update_process_clients();
	update_process_peers(node);	
    }
    return changed;
}

static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",           0, 0, '?', "\tThis text"},
    {"version",        0, 0, '$', "\tVersion information"  },
    {"verbose",        0, 0, 'V', "\tIncrease debug output"},

    {"-spacer-",       1, 0, '-', "\nAdditional Options:"},
    {"foreground",     0, 0, 'f', "\tRun in the foreground instead of as a daemon"},
    {"pid-file",       1, 0, 'p', "\t(Advanced) Daemon pid file location"},

    {NULL, 0, 0, 0}
};

int
main(int argc, char **argv)
{
    int rc;
    int flag;
    int argerr = 0;

    int option_index = 0;	
    gboolean daemonize = TRUE;

    int start_seq = 1, lpc = 0;
    static int max = SIZEOF(pcmk_children);
    
    uid_t pcmk_uid = 0;
    gid_t pcmk_gid = 0;
    struct rlimit cores;
    struct utsname name;
    
    crm_log_init(NULL, LOG_INFO, FALSE, FALSE, argc, argv, TRUE);
    crm_set_options("V?$fp:", "mode [options]", long_options,
		    "Start/Stop Pacemaker\n");

#ifndef ON_DARWIN
    /* prevent zombies */
    signal(SIGCLD, SIG_IGN);
#endif
    
    while (1) {
	flag = crm_get_option(argc, argv, &option_index);
	if (flag == -1)
	    break;

	switch(flag) {
	    case 'V':
		cl_log_enable_stderr(TRUE);
		alter_debug(DEBUG_INC);
		break;
	    case 'f':
		daemonize = FALSE;
		break;
	    case 'p':
		pid_file = optarg;
		break;
	    case '$':
	    case '?':
		crm_help(flag, LSB_EXIT_OK);
		break;
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
	crm_help('?', LSB_EXIT_GENERIC);
    }
    
    if(daemonize) {
	cl_log_enable_stderr(FALSE);
	crm_make_daemon(crm_system_name, TRUE, pid_file);
    }

    crm_info("Starting %s", crm_system_name);
    mainloop = g_main_new(FALSE);

    rc = getrlimit(RLIMIT_CORE, &cores);
    if(rc < 0) {
	crm_perror(LOG_ERR, "Cannot determine current maximum core size.");
    }
    
    if(cores.rlim_max <= 0) {
	cores.rlim_max = RLIM_INFINITY;
	
	rc = setrlimit(RLIMIT_CORE, &cores);
	if(rc < 0) {
	    crm_perror(LOG_ERR,
		       "Core file generation will remain disabled."
		       " Core files are an important diagnositic tool,"
		       " please consider enabling them by default.");
	}
	
    } else {
	crm_info("Maximum core file size is: %lu", cores.rlim_max);
#if 0
	/* system() is not thread-safe, can't call from here
	 * Actually, its a pretty hacky way to try and achieve this anyway
	 */
	if(system("echo 1 > /proc/sys/kernel/core_uses_pid") != 0) {
	    crm_perror(LOG_ERR, "Could not enable /proc/sys/kernel/core_uses_pid");
	}
#endif
    }

    if(pcmk_user_lookup(CRM_DAEMON_USER, &pcmk_uid, &pcmk_gid) < 0) {
	crm_err("Cluster user %s does not exist, aborting Pacemaker startup", CRM_DAEMON_USER);
	return TRUE;
    }
    
    mkdir(CRM_STATE_DIR, 0750);
    chown(CRM_STATE_DIR, pcmk_uid, pcmk_gid);
    
    /* Used by stonithd */
    build_path(HA_STATE_DIR"/heartbeat", 0755); 

    /* Used by RAs - Leave owned by root */
    build_path(CRM_RSCTMP_DIR, 0755);    

    if(uname(&name) < 0) {
	crm_perror(LOG_ERR,"uname(2) call failed");
	exit(100);
    }
    
    if(read_config() == FALSE) {
	return 1;
    }

    client_list = g_hash_table_new(g_direct_hash, g_direct_equal);
    peers = g_hash_table_new(g_direct_hash, g_direct_equal);

    if(init_server_ipc_comms(ipc_name, pcmk_client_connect, pcmk_server_destroy)) {
	crm_err("Couldn't start IPC server");
	return 1;
    }

    if(cluster_connect_cfg(&local_nodeid) == FALSE) {
	return 1;
    }

    if(cluster_connect_cpg() == FALSE) {
	return 1;
    }

    update_node_processes(local_nodeid, name.nodename, get_process_list());    
    
    mainloop_add_signal(SIGTERM, pcmk_shutdown);
    mainloop_add_signal(SIGINT, pcmk_shutdown);
    set_sigchld_proctrack(G_PRIORITY_HIGH, DEFAULT_MAXDISPATCHTIME);
    
    for (start_seq = 1; start_seq < max; start_seq++) {
	/* dont start anything with start_seq < 1 */
	for (lpc = 0; lpc < max; lpc++) {
	    if(start_seq == pcmk_children[lpc].start_seq) {
		start_child(&(pcmk_children[lpc]));
	    }
	}
    }

    crm_info("Starting mainloop");	

    g_main_run(mainloop);
    g_main_destroy(mainloop);

    cluster_disconnect_cpg();
    cluster_disconnect_cfg();
    
    crm_info("Exiting %s", crm_system_name);	

    return 0;
}
