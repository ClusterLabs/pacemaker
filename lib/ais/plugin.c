/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <config.h>
#include <crm/ais_common.h>
#include "plugin.h"
#include "utils.h"

#ifdef AIS_COROSYNC
#  include <corosync/totem/totempg.h>
#endif

#include <glib/ghash.h>

#include <sys/utsname.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/wait.h>
#include <bzlib.h>

plugin_init_type *pcmk_api = NULL;

uint32_t plugin_has_votes = 0;
uint32_t plugin_expected_votes = 1024;

int use_mgmtd = 0;
int plugin_log_level = LOG_DEBUG;
char *local_uname = NULL;
int local_uname_len = 0;
uint32_t local_nodeid = 0;
char *ipc_channel_name = NULL;

uint64_t membership_seq = 0;
pthread_t pcmk_wait_thread;

gboolean wait_active = TRUE;
gboolean have_reliable_membership_id = FALSE;
GHashTable *membership_list = NULL;
GHashTable *membership_notify_list = NULL;

#define MAX_RESPAWN		100
#define crm_flag_none		0x00000000
#define crm_flag_members	0x00000001

struct crm_identify_msg_s
{
	mar_req_header_t	header __attribute__((aligned(8)));
	uint32_t		id;
	uint32_t		pid;
	 int32_t		votes;
	uint32_t		processes;
	char			uname[256];
	char			version[256];
	uint64_t		born_on;
} __attribute__((packed));

static crm_child_t pcmk_children[] = {
    { 0, crm_proc_none,     crm_flag_none,    0, 0, FALSE, "none",     NULL,       NULL,		   NULL, NULL },
    { 0, crm_proc_ais,      crm_flag_none,    0, 0, FALSE, "ais",      NULL,       NULL,		   NULL, NULL },
    { 0, crm_proc_lrmd,     crm_flag_none,    3, 0, TRUE,  "lrmd",     NULL,       HA_LIBHBDIR"/lrmd",     NULL, NULL },
    { 0, crm_proc_cib,      crm_flag_members, 2, 0, TRUE,  "cib",      HA_CCMUSER, HA_LIBHBDIR"/cib",      NULL, NULL },
    { 0, crm_proc_crmd,     crm_flag_members, 6, 0, TRUE,  "crmd",     HA_CCMUSER, HA_LIBHBDIR"/crmd",     NULL, NULL },
    { 0, crm_proc_attrd,    crm_flag_none,    4, 0, TRUE,  "attrd",    HA_CCMUSER, HA_LIBHBDIR"/attrd",    NULL, NULL },
    { 0, crm_proc_stonithd, crm_flag_none,    1, 0, TRUE,  "stonithd", NULL,       HA_LIBHBDIR"/stonithd", NULL, NULL },
    { 0, crm_proc_pe,       crm_flag_none,    5, 0, TRUE,  "pengine",  HA_CCMUSER, HA_LIBHBDIR"/pengine",  NULL, NULL },
    { 0, crm_proc_mgmtd,    crm_flag_none,    7, 0, TRUE,  "mgmtd",    NULL,	   HA_LIBHBDIR"/mgmtd",    NULL, NULL },
};

void send_cluster_id(void);
int send_cluster_msg_raw(AIS_Message *ais_msg);
char *pcmk_generate_membership_data(void);

extern totempg_groups_handle openais_group_handle;

void pcmk_peer_update (
    enum totem_configuration_type configuration_type,
    unsigned int *member_list, int member_list_entries,
    unsigned int *left_list, int left_list_entries,
    unsigned int *joined_list, int joined_list_entries,
    struct memb_ring_id *ring_id);

#ifdef AIS_WHITETANK
int pcmk_exec_init (struct objdb_iface_ver0 *objdb);
int pcmk_exec_exit (struct objdb_iface_ver0 *objdb);
int pcmk_config_init(struct objdb_iface_ver0 *objdb);
#endif
#ifdef AIS_COROSYNC
int pcmk_exec_init (struct corosync_api_v1 *corosync_api);
int pcmk_exec_exit (void);
int pcmk_config_init(struct corosync_api_v1 *corosync_api);
#endif

int pcmk_ipc_connect (void *conn);
int pcmk_ipc_exit (void *conn);

void pcmk_cluster_swab(void *msg);
void pcmk_cluster_callback(void *message, unsigned int nodeid);

void pcmk_ipc(void *conn, void *msg);

void pcmk_nodeid(void *conn, void *msg);
void pcmk_nodes(void *conn, void *msg);
void pcmk_notify(void *conn, void *msg);
void pcmk_remove_member(void *conn, void *msg);
void pcmk_quorum(void *conn, void *msg);

void pcmk_cluster_id_swab(void *msg);
void pcmk_cluster_id_callback(void *message, unsigned int nodeid);

static plugin_lib_handler pcmk_lib_service[] =
{
    { /* 0 */
	.lib_handler_fn		= pcmk_ipc,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 1 */
	.lib_handler_fn		= pcmk_nodes,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 2 */
	.lib_handler_fn		= pcmk_notify,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 3 */
	.lib_handler_fn		= pcmk_nodeid,
	.response_size		= sizeof (struct crm_ais_nodeid_resp_s),
	.response_id		= crm_class_nodeid,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 4 */
	.lib_handler_fn		= pcmk_remove_member,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 5 */
	.lib_handler_fn		= pcmk_quorum,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED
    },
};

static plugin_exec_handler pcmk_exec_service[] =
{
    { /* 0 */
	.exec_handler_fn	= pcmk_cluster_callback,
	.exec_endian_convert_fn = pcmk_cluster_swab
    },
    { /* 1 */
	.exec_handler_fn	= pcmk_cluster_id_callback,
	.exec_endian_convert_fn = pcmk_cluster_id_swab
    }
};

static void pcmk_exec_dump(void) 
{
    ais_err("Called after SIG_USR2");
}

/*
 * Exports the interface for the service
 */
plugin_service_handler pcmk_service_handler = {
    .name			= (unsigned char *)"Pacemaker Cluster Manager",
    .id				= CRM_SERVICE,
    .private_data_size		= 0,
    .flow_control		= COROSYNC_LIB_FLOW_CONTROL_NOT_REQUIRED, 
    .lib_init_fn		= pcmk_ipc_connect,
    .lib_exit_fn		= pcmk_ipc_exit,
    .exec_init_fn		= pcmk_exec_init,
    .exec_exit_fn		= pcmk_exec_exit,
    .config_init_fn		= pcmk_config_init,
#ifdef AIS_WHITETANK
    .lib_service		= pcmk_lib_service,
    .lib_service_count		= sizeof (pcmk_lib_service) / sizeof (plugin_lib_handler),
    .exec_service		= pcmk_exec_service,
    .exec_service_count		= sizeof (pcmk_exec_service) / sizeof (plugin_exec_handler),
#endif
#ifdef AIS_COROSYNC
    .lib_engine			= pcmk_lib_service,
    .lib_engine_count		= sizeof (pcmk_lib_service) / sizeof (plugin_lib_handler),
    .exec_engine		= pcmk_exec_service,
    .exec_engine_count		= sizeof (pcmk_exec_service) / sizeof (plugin_exec_handler),
#endif
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
plugin_service_handler *pcmk_get_handler_ver0 (void);

#ifdef AIS_WHITETANK
struct openais_service_handler_iface_ver0 pcmk_service_handler_iface = {
    .openais_get_service_handler_ver0 = pcmk_get_handler_ver0
};
#endif
#ifdef AIS_COROSYNC
struct corosync_service_engine_iface_ver0 pcmk_service_handler_iface = {
    .corosync_get_service_engine_ver0 = pcmk_get_handler_ver0
};
#endif

static struct lcr_iface openais_pcmk_ver0[1] = {
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
    }
};

static struct lcr_comp pcmk_comp_ver0 = {
    .iface_count				= 1,
    .ifaces					= openais_pcmk_ver0
};

plugin_service_handler *pcmk_get_handler_ver0 (void)
{
    return (&pcmk_service_handler);
}

__attribute__ ((constructor)) static void register_this_component (void) {
    lcr_interfaces_set (&openais_pcmk_ver0[0], &pcmk_service_handler_iface);

    lcr_component_register (&pcmk_comp_ver0);
}

static int plugin_has_quorum(void) 
{
    if(plugin_expected_votes < (2 * plugin_has_votes) + 1) {
	return 1;
    }
    return 0;
}

static void update_expected_votes(int value) 
{
    if(value > 0 && plugin_expected_votes != value) {
	ais_info("Expected quorum votes %d -> %d", plugin_expected_votes, value);
	plugin_expected_votes = value;
    }
}

#ifdef AIS_COROSYNC
#include <corosync/engine/config.h>
#endif

/* Create our own local copy of the config so we can navigate it */
static void process_ais_conf(void)
{
    char *value = NULL;
    unsigned int top_handle = 0;
    unsigned int local_handle = 0;
    
    ais_info("Reading configure");
    top_handle = config_find_init(pcmk_api, "logging");
    local_handle = config_find_next(pcmk_api, "logging", top_handle);
    
    get_config_opt(pcmk_api, local_handle, "debug", &value, "on");
    if(ais_get_boolean(value)) {
	plugin_log_level = LOG_DEBUG;
	setenv("HA_debug",  "1", 1);
	
    } else {
	plugin_log_level = LOG_INFO;
	setenv("HA_debug",  "0", 1);
    }    
    
    get_config_opt(pcmk_api, local_handle, "to_syslog", &value, "on");
    if(ais_get_boolean(value)) {
	get_config_opt(pcmk_api, local_handle, "syslog_facility", &value, "daemon");
	setenv("HA_logfacility",  value, 1);
	
    } else {
	setenv("HA_logfacility",  "none", 1);
    }

    get_config_opt(pcmk_api, local_handle, "to_file", &value, "off");
    if(ais_get_boolean(value)) {
	get_config_opt(pcmk_api, local_handle, "logfile", &value, NULL);

	if(value == NULL) {
	    ais_err("Logging to a file requested but no log file specified");
	} else {
	    setenv("HA_logfile",  value, 1);
	}
    }

    config_find_done(pcmk_api, local_handle);
    
    top_handle = config_find_init(pcmk_api, "service");
    local_handle = config_find_next(pcmk_api, "service", top_handle);
    while(local_handle) {
	value = NULL;
	pcmk_api->object_key_get(local_handle, "name", strlen("name"), (void**)&value, NULL);
	if(ais_str_eq("pacemaker", value)) {
	    break;
	}
	local_handle = config_find_next(pcmk_api, "service", top_handle);
    }

    get_config_opt(pcmk_api, local_handle, "use_logd", &value, "no");
    setenv("HA_use_logd", value, 1);

    get_config_opt(pcmk_api, local_handle, "use_mgmtd", &value, "no");
    if(ais_get_boolean(value) == FALSE) {
	int lpc = 0;
	for (; lpc < SIZEOF(pcmk_children); lpc++) {
	    if(crm_proc_mgmtd & pcmk_children[lpc].flag) {
		/* Disable mgmtd startup */
		pcmk_children[lpc].start_seq = 0;
		break;
	    }
	}
    }
    
    config_find_done(pcmk_api, local_handle);
}


static void pcmk_plugin_init(void) 
{
    int rc = 0;
    struct utsname us;

#ifdef AIS_WHITETANK 
    log_init ("crm");
#endif

    process_ais_conf();
    
    membership_list = g_hash_table_new_full(
	g_direct_hash, g_direct_equal, NULL, destroy_ais_node);
    membership_notify_list = g_hash_table_new(g_direct_hash, g_direct_equal);
    
    setenv("HA_COMPRESSION",  "bz2", 1);
    setenv("HA_cluster_type", "openais", 1);
    
    if(system("echo 1 > /proc/sys/kernel/core_uses_pid") != 0) {
	ais_perror("Could not enable /proc/sys/kernel/core_uses_pid");
    }
    
    ais_info("CRM: Initialized");
    log_printf(LOG_INFO, "Logging: Initialized %s\n", __PRETTY_FUNCTION__);
    
    rc = uname(&us);
    AIS_ASSERT(rc == 0);
    local_uname = ais_strdup(us.nodename);
    local_uname_len = strlen(local_uname);

#if AIS_WHITETANK
    local_nodeid = totempg_my_nodeid_get();
#endif
#if AIS_COROSYNC
    local_nodeid = pcmk_api->totem_nodeid_get();
#endif

    ais_info("Service: %d", CRM_SERVICE);
    ais_info("Local node id: %u", local_nodeid);
    ais_info("Local hostname: %s", local_uname);
    
    update_member(local_nodeid, 0, 0, 1, 0, local_uname, CRM_NODE_MEMBER, NULL);
    
}

int pcmk_config_init(plugin_init_type *unused)
{
    return 0;
}

static void *pcmk_wait_dispatch (void *arg)
{
    struct timespec waitsleep = {
	.tv_sec = 0,
	.tv_nsec = 100000 /* 100 msec */
    };
    
    while(wait_active) {
	int lpc = 0;
	for (; lpc < SIZEOF(pcmk_children); lpc++) {
	    if(pcmk_children[lpc].pid > 0) {
		int status;
		pid_t pid = wait4(
		    pcmk_children[lpc].pid, &status, WNOHANG, NULL);

		if(pid == 0) {
		    continue;
		    
		} else if(pid < 0) {
		    ais_perror("Call to wait4(%s) failed", pcmk_children[lpc].name);
		    continue;
		}

		/* cleanup */
		pcmk_children[lpc].pid = 0;
		pcmk_children[lpc].conn = NULL;
		pcmk_children[lpc].async_conn = NULL;

		if(WIFSIGNALED(status)) {
		    int sig = WTERMSIG(status);
		    ais_err("Child process %s terminated with signal %d"
			     " (pid=%d, core=%s)",
			     pcmk_children[lpc].name, sig, pid,
			     WCOREDUMP(status)?"true":"false");

		} else if (WIFEXITED(status)) {
		    int rc = WEXITSTATUS(status);
		    do_ais_log(rc==0?LOG_NOTICE:LOG_ERR, "Child process %s exited (pid=%d, rc=%d)",
			       pcmk_children[lpc].name, pid, rc);

		    if(rc == 100) {
			ais_notice("Child process %s no longer wishes"
				   " to be respawned", pcmk_children[lpc].name);
			pcmk_children[lpc].respawn = FALSE;
		    }
		}

		pcmk_children[lpc].respawn_count += 1;
		if(pcmk_children[lpc].respawn_count > MAX_RESPAWN) {
		    ais_err("Child respawn count exceeded by %s",
			       pcmk_children[lpc].name);
		    pcmk_children[lpc].respawn = FALSE;
		}
		if(pcmk_children[lpc].respawn) {
		    ais_notice("Respawning failed child process: %s",
			       pcmk_children[lpc].name);
		    spawn_child(&(pcmk_children[lpc]));
		} else {
		    send_cluster_id();
		}
	    }
	}
	sched_yield ();
	nanosleep (&waitsleep, 0);
    }
    return 0;
}

#include <sys/stat.h>
#include <pwd.h>

int pcmk_exec_init(plugin_init_type *init_with)
{
    int lpc = 0;
    int start_seq = 1;
    static gboolean need_init = TRUE;
    static int max = SIZEOF(pcmk_children);
    
    pcmk_api = init_with;
    
    if(need_init) {
	struct passwd *pwentry = NULL;
	
	need_init = FALSE;
	pcmk_plugin_init();
	
	pthread_create (&pcmk_wait_thread, NULL, pcmk_wait_dispatch, NULL);

	pwentry = getpwnam(HA_CCMUSER);
	AIS_CHECK(pwentry != NULL,
		  ais_err("Cluster user %s does not exist", HA_CCMUSER);
		  return TRUE);
	
	mkdir(HA_VARRUNDIR, 750);
	mkdir(HA_VARRUNDIR"/crm", 750);
	mkdir(HA_VARRUNHBDIR"/rsctmp", 755); /* Used by RAs - Leave owned by root */
	chown(HA_VARRUNDIR"/crm", pwentry->pw_uid, pwentry->pw_gid);
	chown(HA_VARRUNDIR, pwentry->pw_uid, pwentry->pw_gid);
	
	for (start_seq = 1; start_seq < max; start_seq++) {
	    /* dont start anything with start_seq < 1 */
	    for (lpc = 0; lpc < max; lpc++) {
		if(start_seq == pcmk_children[lpc].start_seq) {
		    spawn_child(&(pcmk_children[lpc]));
		}
	    }
	}
    }
    
    ais_info("CRM: Initialized");
    
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
char *totempg_ifaces_print (unsigned int nodeid)
{
    static char iface_string[256 * INTERFACE_MAX];
    char one_iface[64];
    struct totem_ip_address interfaces[INTERFACE_MAX];
    char **status;
    unsigned int iface_count;
    unsigned int i;
    int res;

    iface_string[0] = '\0';

    res = totempg_ifaces_get (nodeid, interfaces, &status, &iface_count);
    if (res == -1) {
	return ("no interface found for nodeid");
    }

    for (i = 0; i < iface_count; i++) {
	sprintf (one_iface, "r(%d) ip(%s), ",
		 i, totemip_print (&interfaces[i]));
	strcat (iface_string, one_iface);
    }
    return (iface_string);
}
#endif

static void ais_mark_unseen_peer_dead(
    gpointer key, gpointer value, gpointer user_data)
{
    int *changed = user_data;
    crm_node_t *node = value;
    if(node->last_seen != membership_seq
       && ais_str_eq(CRM_NODE_LOST, node->state) == FALSE) {
	ais_info("Node %s was not seen in the previous transition", node->uname);
	*changed += update_member(node->id, 0, membership_seq, node->votes,
				  node->processes, node->uname, CRM_NODE_LOST, NULL);
    }
}

void pcmk_peer_update (
    enum totem_configuration_type configuration_type,
    unsigned int *member_list, int member_list_entries,
    unsigned int *left_list, int left_list_entries,
    unsigned int *joined_list, int joined_list_entries,
    struct memb_ring_id *ring_id)
{
    int lpc = 0;
    int changed = 0;
    int do_update = 0;
    
    AIS_ASSERT(ring_id != NULL);
    switch(configuration_type) {
	case TOTEM_CONFIGURATION_REGULAR:
	    do_update = 1;
	    break;
	case TOTEM_CONFIGURATION_TRANSITIONAL:
	    break;
    }

    membership_seq = ring_id->seq;
    ais_notice("%s membership event on ring %lld: memb=%d, new=%d, lost=%d",
	       do_update?"Stable":"Transitional", ring_id->seq, member_list_entries,
	       joined_list_entries, left_list_entries);

    if(do_update == 0) {
	for(lpc = 0; lpc < joined_list_entries; lpc++) {
	    const char *prefix = "new: ";
	    uint32_t nodeid = joined_list[lpc];
	    ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
	}
	for(lpc = 0; lpc < member_list_entries; lpc++) {
	    const char *prefix = "memb:";
	    uint32_t nodeid = member_list[lpc];
	    ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
	}
	for(lpc = 0; lpc < left_list_entries; lpc++) {
	    const char *prefix = "lost:";
	    uint32_t nodeid = left_list[lpc];
	    ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
	}
	return;
    }
    
    for(lpc = 0; lpc < joined_list_entries; lpc++) {
	const char *prefix = "NEW: ";
	uint32_t nodeid = joined_list[lpc];
	crm_node_t *node = NULL;
	changed += update_member(
	    nodeid, 0, membership_seq, -1, 0, NULL, CRM_NODE_MEMBER, NULL);

	ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);

	node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(nodeid));	
	if(node->addr == NULL) {
	    const char *addr = totempg_ifaces_print(nodeid);
	    node->addr = ais_strdup(addr);
	    ais_debug("Node %u has address %s", nodeid, node->addr);	    
	}
    }

    plugin_has_votes = 0;
    for(lpc = 0; lpc < member_list_entries; lpc++) {
	const char *prefix = "MEMB:";
	uint32_t nodeid = member_list[lpc];
	plugin_has_votes++;
	changed += update_member(
	    nodeid, 0, membership_seq, -1, 0, NULL, CRM_NODE_MEMBER, NULL);

	ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
    }
    
    for(lpc = 0; lpc < left_list_entries; lpc++) {
	const char *prefix = "LOST:";
	uint32_t nodeid = left_list[lpc];
	changed += update_member(
	    nodeid, 0, membership_seq, -1, 0, NULL, CRM_NODE_LOST, NULL);
	ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
    }    

    if(changed && joined_list_entries == 0 && left_list_entries == 0) {
	ais_err("Something strange happened: %d", changed);
	changed = 0;
    }
    
    ais_debug_2("Reaping unseen nodes...");
    g_hash_table_foreach(membership_list, ais_mark_unseen_peer_dead, &changed);

    if(plugin_has_votes > plugin_expected_votes) {
	update_expected_votes(plugin_has_votes);
	changed = 1;
    }
    
    if(member_list_entries > 1) {
	/* Used to set born-on in send_cluster_id())
	 * We need to wait until we have at least one peer since first
	 * membership id is based on the one before we stopped and isn't reliable
	 */
	have_reliable_membership_id = TRUE;
    }
    
    if(changed) {
	ais_debug("%d nodes changed", changed);
	send_member_notification();
    }
    
    send_cluster_id();
}

int pcmk_ipc_exit (void *conn)
{
    int lpc = 0;
    const char *client = NULL;
    void *async_conn = openais_conn_partner_get(conn);
    
    for (; lpc < SIZEOF(pcmk_children); lpc++) {
	if(pcmk_children[lpc].conn == conn) {
	    if(wait_active == FALSE) {
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

    do_ais_log(client?LOG_INFO:(LOG_DEBUG+1), "Client %s (conn=%p, async-conn=%p) left",
	     client?client:"unknown-transient", conn, async_conn);

    return (0);
}

int pcmk_ipc_connect (void *conn)
{
    /* OpenAIS hasn't finished setting up the connection at this point
     * Sending messages now messes up the protocol!
     */
    return (0);
}

/*
 * Executive message handlers
 */
void pcmk_cluster_swab(void *msg)
{
    AIS_Message *ais_msg = msg;

    ais_debug_3("Performing endian conversion...");
    ais_msg->id                = swab32 (ais_msg->id);
    ais_msg->size              = swab32 (ais_msg->size);
    ais_msg->is_compressed     = swab32 (ais_msg->is_compressed);
    ais_msg->compressed_size   = swab32 (ais_msg->compressed_size);
    
    ais_msg->host.id      = swab32 (ais_msg->host.id);
    ais_msg->host.pid     = swab32 (ais_msg->host.pid);
    ais_msg->host.type    = swab32 (ais_msg->host.type);
    ais_msg->host.size    = swab32 (ais_msg->host.size);
    ais_msg->host.local   = swab32 (ais_msg->host.local);
    
    ais_msg->sender.id    = swab32 (ais_msg->sender.id);
    ais_msg->sender.pid   = swab32 (ais_msg->sender.pid);
    ais_msg->sender.type  = swab32 (ais_msg->sender.type);
    ais_msg->sender.size  = swab32 (ais_msg->sender.size);
    ais_msg->sender.local = swab32 (ais_msg->sender.local);
}

void pcmk_cluster_callback (
    void *message, unsigned int nodeid)
{
    AIS_Message *ais_msg = message;

    ais_debug_2("Message from node %u (%s)",
		nodeid, nodeid==local_nodeid?"local":"remote");
/*  Shouldn't be required...
    update_member(
 	ais_msg->sender.id, membership_seq, -1, 0, ais_msg->sender.uname, NULL);
*/

    if(ais_msg->host.size == 0
       || ais_str_eq(ais_msg->host.uname, local_uname)) {
	route_ais_message(ais_msg, FALSE);

    } else {
	ais_debug_3("Discarding Msg[%d] (dest=%s:%s, from=%s:%s)",
		    ais_msg->id, ais_dest(&(ais_msg->host)),
		    msg_type2text(ais_msg->host.type),
		    ais_dest(&(ais_msg->sender)),
		    msg_type2text(ais_msg->sender.type));
    }
}

void pcmk_cluster_id_swab(void *msg)
{
    struct crm_identify_msg_s *ais_msg = msg;

    ais_debug_3("Performing endian conversion...");
    ais_msg->id        = swab32 (ais_msg->id);
    ais_msg->pid       = swab32 (ais_msg->pid);
    ais_msg->votes     = swab32 (ais_msg->votes);
    ais_msg->processes = swab32 (ais_msg->processes);
}

void pcmk_cluster_id_callback (void *message, unsigned int nodeid)
{
    int changed = 0;
    struct crm_identify_msg_s *msg = message;
    if(nodeid != msg->id) {
	ais_err("Invalid message: Node %u claimed to be node %d",
		nodeid, msg->id);
	return;
    }
    ais_debug("Node update: %s (%s)", msg->uname, msg->version);
    changed = update_member(
	nodeid, msg->born_on, membership_seq, msg->votes, msg->processes, msg->uname, NULL, msg->version);

    if(changed) {
	send_member_notification();
    }
}

struct res_overlay {
	mar_res_header_t header __attribute((aligned(8)));
	char buf[4096];
};

struct res_overlay *res_overlay = NULL;

static void send_ipc_ack(void *conn, int class)
{
    if(res_overlay == NULL) {
	ais_malloc0(res_overlay, sizeof(struct res_overlay));
    }
    
    res_overlay->header.size = pcmk_lib_service[class].response_size;
    res_overlay->header.id = pcmk_lib_service[class].response_id;
    res_overlay->header.error = SA_AIS_OK;
#ifdef AIS_WHITETANK
    openais_response_send (conn, res_overlay, res_overlay->header.size);
#endif
#ifdef AIS_COROSYNC
    pcmk_api->ipc_conn_send_response (conn, res_overlay, res_overlay->header.size);
#endif
}


/* local callbacks */
void pcmk_ipc(void *conn, void *msg)
{
    gboolean transient = TRUE;
    AIS_Message *ais_msg = msg;
    int type = ais_msg->sender.type;
    void *async_conn = openais_conn_partner_get(conn);
    ais_debug_2("Message from client %p", conn);
    send_ipc_ack(conn, crm_class_cluster);

    ais_debug_3("type: %d local: %d conn: %p host type: %d ais: %d sender pid: %d child pid: %d size: %d",
		type, ais_msg->host.local, pcmk_children[type].conn, ais_msg->host.type, crm_msg_ais,
		ais_msg->sender.pid, pcmk_children[type].pid, ((int)SIZEOF(pcmk_children)));
    
    if(type > crm_msg_none && type < SIZEOF(pcmk_children)) {
	/* known child process */
	transient = FALSE;
    }
    
    /* If this check fails, the order of pcmk_children probably 
     *   doesn't match that of the crm_ais_msg_types enum
     */
    AIS_CHECK(transient || ais_msg->sender.pid == pcmk_children[type].pid,
	      ais_err("Sender: %d, child[%d]: %d", ais_msg->sender.pid, type, pcmk_children[type].pid);
	      return);
    
    if(transient == FALSE
       && type > crm_msg_none
       && ais_msg->host.local
       && pcmk_children[type].conn == NULL
       && ais_msg->host.type == crm_msg_ais) {
	
	ais_info("Recorded connection %p for %s/%d",
		 conn, pcmk_children[type].name, pcmk_children[type].pid);
	pcmk_children[type].conn = conn;
	pcmk_children[type].async_conn = async_conn;

	/* Make sure they have the latest membership */
	if(pcmk_children[type].flags & crm_flag_members) {
	    char *update = pcmk_generate_membership_data();
	    g_hash_table_replace(membership_notify_list, async_conn, async_conn);
	    ais_info("Sending membership update "U64T" to %s",
		     membership_seq, pcmk_children[type].name);
 	    send_client_msg(async_conn, crm_class_members, crm_msg_none,update);
	}	
    }
    
    ais_msg->sender.id = local_nodeid;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);

    route_ais_message(msg, TRUE);
}

int pcmk_exec_exit (
#ifdef AIS_WHITETANK
    struct objdb_iface_ver0 *objdb
#endif
#ifdef AIS_COROSYNC
    void
#endif
    )
{
    int lpc = 0;
    int start_seq = 1;
    static int max = SIZEOF(pcmk_children);
    
    struct timespec waitsleep = {
	.tv_sec = 1,
	.tv_nsec = 0
    };

    ais_notice("Begining shutdown");

    in_shutdown = TRUE;
    wait_active = FALSE; /* stop the wait loop */
 
    for (start_seq = max; start_seq > 0; start_seq--) {
	/* dont stop anything with start_seq < 1 */
   
	for (lpc = max - 1; lpc >= 0; lpc--) {
	    int orig_pid = 0, iter = 0;
	    if(start_seq != pcmk_children[lpc].start_seq) {
		continue;
	    }
		
	    orig_pid = pcmk_children[lpc].pid;
	    pcmk_children[lpc].respawn = FALSE;
	    stop_child(&(pcmk_children[lpc]), SIGTERM);
	    while(pcmk_children[lpc].command && pcmk_children[lpc].pid) {
		int status;
		pid_t pid = 0;
		
		pid = wait4(
		    pcmk_children[lpc].pid, &status, WNOHANG, NULL);
		
		if(pid == 0) {
		    if((++iter % 30) == 0) {
			ais_notice("Still waiting for %s (pid=%d) to terminate...",
				   pcmk_children[lpc].name, orig_pid);
		    }

		    sched_yield ();
		    nanosleep (&waitsleep, 0);
		    continue;
		    
		} else if(pid < 0) {
		    ais_perror("Call to wait4(%s) failed", pcmk_children[lpc].name);
		}
		
		/* cleanup */
		pcmk_children[lpc].pid = 0;
		pcmk_children[lpc].conn = NULL;
		pcmk_children[lpc].async_conn = NULL;
		break;
	    }
	    ais_notice("%s (pid=%d) confirmed dead",
		       pcmk_children[lpc].name, orig_pid);
	}
    }
    
    send_cluster_id();

    ais_notice("Shutdown complete");
#ifndef AIS_WHITETANK
    logsys_flush ();
#endif
    return 0;
}

struct member_loop_data 
{
	char *string;
};

void member_loop_fn(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    struct member_loop_data *data = user_data;    

    ais_debug_2("Dumping node %u", node->id);
    data->string = append_member(data->string, node);
}

char *pcmk_generate_membership_data(void)
{
    int size = 0;
    struct member_loop_data data;
    size = 256; 
    ais_malloc0(data.string, size);

    snprintf(data.string, size,
	     "<nodes id=\""U64T"\" quorate=\"%s\" expected=\"%u\" actual=\"%u\">",
	     membership_seq, plugin_has_quorum()?"true":"false",
	     plugin_expected_votes, plugin_has_votes);
    
    g_hash_table_foreach(membership_list, member_loop_fn, &data);

    size = strlen(data.string);
    data.string = realloc(data.string, size + 9) ;/* 9 = </nodes> + nul */
    sprintf(data.string + size, "</nodes>");
    return data.string;
}

void pcmk_nodes(void *conn, void *msg)
{
    char *data = pcmk_generate_membership_data();
    void *async_conn = openais_conn_partner_get(conn);

    /* send the ACK before we send any other messages */
    send_ipc_ack(conn, crm_class_members);

    if(async_conn) {
	send_client_msg(async_conn, crm_class_members, crm_msg_none, data);
    }
    ais_free(data);
}

void pcmk_remove_member(void *conn, void *msg)
{
    AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);
    
    if(data != NULL) {
	char *bcast = ais_concat("remove-peer", data, ':');
	send_cluster_msg(crm_msg_ais, NULL, bcast);
	ais_info("Sent: %s", bcast);
	ais_free(bcast);
    }
    
    send_ipc_ack(conn, crm_class_rmpeer);
    ais_free(data);
}

static void send_quorum_details(void *conn) 
{
    int size = 256;
    char *data = NULL;
    ais_malloc0(data, size);
    
    snprintf(data, size, "<quorum id=\""U64T"\" quorate=\"%s\" expected=\"%u\" actual=\"%u\"/>",
	    membership_seq, plugin_has_quorum()?"true":"false",
	    plugin_expected_votes, plugin_has_votes);

    send_client_msg(conn, crm_class_quorum, crm_msg_none, data);
    ais_free(data);
}

void pcmk_quorum(void *conn, void *msg)
{
    AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);
    
    if(data != NULL) {
	int value = 0;

	value = ais_get_int(data, NULL);
	update_expected_votes(value);
    }
    send_ipc_ack(conn, crm_class_quorum);

    send_quorum_details(conn);
    ais_free(data);
}

void pcmk_notify(void *conn, void *msg)
{
    int enable = 0;
    AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);
    void *async_conn = openais_conn_partner_get(conn);

    if(ais_str_eq("true", data)) {
	enable = 1;
    }
    
    ais_info("%s node notifications for child %d (%p)",
	     enable?"Enabling":"Disabling", ais_msg->sender.pid, async_conn);
    if(enable) {
	g_hash_table_replace(membership_notify_list, async_conn, async_conn);
    } else {
	g_hash_table_remove(membership_notify_list, async_conn);
    }
    send_ipc_ack(conn, crm_class_notify);
    ais_free(data);
}

void pcmk_nodeid(void *conn, void *msg)
{
    static int counter = 0;
    struct crm_ais_nodeid_resp_s resp;
    ais_debug_2("Sending local nodeid: %d to %p[%d]", local_nodeid, conn, counter);
    
    resp.header.size = pcmk_lib_service[crm_class_nodeid].response_size;
    resp.header.id = pcmk_lib_service[crm_class_nodeid].response_id;
    resp.header.error = SA_AIS_OK;
    resp.id = local_nodeid;
    resp.counter = counter++;
    memset(resp.uname, 0, 256);
    memcpy(resp.uname, local_uname, local_uname_len);
    
#ifdef AIS_WHITETANK
    openais_response_send (conn, &resp, resp.header.size);
#endif
#ifdef AIS_COROSYNC
    crm_api->ipc_conn_send_response (conn, &resp, resp.header.size);
#endif
}

static gboolean
ghash_send_update(gpointer key, gpointer value, gpointer data)
{
    if(send_client_msg(value, crm_class_members, crm_msg_none, data) != 0) {
	/* remove it */
	return TRUE;
    }
    return FALSE;
}

void send_member_notification(void)
{
    char *update = pcmk_generate_membership_data();

    ais_info("Sending membership update "U64T" to %d children",
	     membership_seq,
	     g_hash_table_size(membership_notify_list));

    g_hash_table_foreach_remove(membership_notify_list, ghash_send_update, update);
    ais_free(update);
}

static gboolean check_message_sanity(AIS_Message *msg, char *data) 
{
    gboolean sane = TRUE;
    gboolean repaired = FALSE;
    int dest = msg->host.type;
    int tmp_size = msg->header.size - sizeof(AIS_Message);

    if(sane && msg->header.size == 0) {
	ais_warn("Message with no size");
	sane = FALSE;
    }

    if(sane && msg->header.error != SA_AIS_OK) {
	ais_warn("Message header contains an error: %d", msg->header.error);
	sane = FALSE;
    }

    if(sane && tmp_size < 0) {
	/* not an AIS message */
	return TRUE;
    }

    if(sane && ais_data_len(msg) != tmp_size) {
	int cur_size = ais_data_len(msg);

	repaired = TRUE;
	if(msg->is_compressed) {
	    msg->compressed_size = tmp_size;
	    
	} else {
	    msg->size = tmp_size;
	}
	
	ais_warn("Repaired message payload size %d -> %d", cur_size, tmp_size);
    }

    if(sane && ais_data_len(msg) == 0) {
	ais_warn("Message with no payload");
	sane = FALSE;
    }

    if(sane && data && msg->is_compressed == FALSE) {
	int str_size = strlen(data) + 1;
	if(ais_data_len(msg) != str_size) {
	    int lpc = 0;
	    ais_warn("Message payload is corrupted: expected %d bytes, got %d",
		    ais_data_len(msg), str_size);
	    sane = FALSE;
	    for(lpc = (str_size - 10); lpc < msg->size; lpc++) {
		if(lpc < 0) {
		    lpc = 0;
		}
		ais_debug_2("bad_data[%d]: %d / '%c'", lpc, data[lpc], data[lpc]);
	    }
	}
    }
    
    if(sane == FALSE) {
	ais_err("Invalid message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
		msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		msg->sender.pid, msg->is_compressed, ais_data_len(msg),
		msg->header.size);
	
    } else if(repaired) {
	ais_err("Repaired message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
		msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		msg->sender.pid, msg->is_compressed, ais_data_len(msg),
		msg->header.size);
    } else {
	ais_debug_3("Verified message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
		    msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		    ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		    msg->sender.pid, msg->is_compressed, ais_data_len(msg),
		    msg->header.size);
    }
    return sane;
}

gboolean route_ais_message(AIS_Message *msg, gboolean local_origin) 
{
    int rc = 0;
    int dest = msg->host.type;
    const char *reason = "unknown";
    static int service_id =  SERVICE_ID_MAKE(CRM_SERVICE, 0);
    
    ais_debug_3("Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d)",
		msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
		ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
		msg->sender.pid, local_origin?"false":"true", ais_data_len(msg));
    
    if(local_origin == FALSE) {
       if(msg->host.size == 0
	  || ais_str_eq(local_uname, msg->host.uname)) {
	   msg->host.local = TRUE;
       }
    }

    if(check_message_sanity(msg, msg->data) == FALSE) {
	/* Dont send this message to anyone */
	return FALSE;
    }
    
    if(msg->host.local) {
	void *conn = NULL;
	const char *lookup = NULL;

	if(dest == crm_msg_ais) {
	    process_ais_message(msg);
	    return TRUE;

	} else if(dest == crm_msg_lrmd) {
	    /* lrmd messages are routed via the crm */
	    dest = crm_msg_crmd;

	} else if(dest == crm_msg_te) {
	    /* te messages are routed via the crm */
	    dest = crm_msg_crmd;
	}

	AIS_CHECK(dest > 0 && dest < SIZEOF(pcmk_children),
		  ais_err("Invalid destination: %d", dest);
		  log_ais_message(LOG_ERR, msg);
		  return FALSE;
	    );

	lookup = msg_type2text(dest);
	conn = pcmk_children[dest].async_conn;

	/* the cluster fails in weird and wonderfully obscure ways when this is not true */
	AIS_ASSERT(ais_str_eq(lookup, pcmk_children[dest].name));

	if(msg->header.id == service_id) {
	    msg->header.id = 0; /* reset this back to zero for IPC messages */

	} else if(msg->header.id != 0) {
	    ais_err("reset header id back to zero from %d", msg->header.id);
	    msg->header.id = 0; /* reset this back to zero for IPC messages */
	}
	
	rc = send_client_ipc(conn, msg);

    } else if(local_origin) {
	/* forward to other hosts */
	ais_debug_3("Forwarding to cluster");
	reason = "cluster delivery failed";
	rc = send_cluster_msg_raw(msg);    
    }

    if(rc != 0) {
	ais_warn("Sending message to %s.%s failed: %s (rc=%d)",
		 ais_dest(&(msg->host)), msg_type2text(dest), reason, rc);
	log_ais_message(LOG_DEBUG, msg);
	return FALSE;
    }
    return TRUE;
}

int send_cluster_msg_raw(AIS_Message *ais_msg) 
{
    int rc = 0;
    struct iovec iovec;
    static uint32_t msg_id = 0;
    AIS_Message *bz2_msg = NULL;

    AIS_ASSERT(local_nodeid != 0);

    if(ais_msg->header.size != (sizeof(AIS_Message) + ais_data_len(ais_msg))) {
	ais_err("Repairing size mismatch: %u + %d = %d",
		(unsigned int)sizeof(AIS_Message),
		ais_data_len(ais_msg), ais_msg->header.size);
	ais_msg->header.size = sizeof(AIS_Message) + ais_data_len(ais_msg);
    }

    if(ais_msg->id == 0) {
	msg_id++;
	AIS_CHECK(msg_id != 0 /* detect wrap-around */,
		  msg_id++; ais_err("Message ID wrapped around"));
	ais_msg->id = msg_id;
    }
    
    ais_msg->header.error = SA_AIS_OK;
    ais_msg->header.id = SERVICE_ID_MAKE(CRM_SERVICE, 0);	

    ais_msg->sender.id = local_nodeid;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);

    iovec.iov_base = (char *)ais_msg;
    iovec.iov_len = ais_msg->header.size;

    ais_debug_3("Sending message (size=%u)", (unsigned int)iovec.iov_len);
    rc = totempg_groups_mcast_joined (
	openais_group_handle, &iovec, 1, TOTEMPG_SAFE);

    if(rc == 0 && ais_msg->is_compressed == FALSE) {
	ais_debug_2("Message sent: %.80s", ais_msg->data);
    }
    
    AIS_CHECK(rc == 0, ais_err("Message not sent (%d): %.120s", rc, ais_msg->data));

    ais_free(bz2_msg);
    return rc;	
}

#define min(x,y) (x)<(y)?(x):(y)

void send_cluster_id(void) 
{
    int rc = 0;
    int lpc = 0;
    int len = 0;
    struct iovec iovec;
    struct crm_identify_msg_s *msg = NULL;
    static uint64_t local_born_on = 0;
    
    AIS_ASSERT(local_nodeid != 0);

    if(local_born_on == 0 && have_reliable_membership_id) {
	local_born_on = membership_seq;
    }
    
    ais_malloc0(msg, sizeof(struct crm_identify_msg_s));
    msg->header.size = sizeof(struct crm_identify_msg_s);

    msg->id = local_nodeid;
    /* msg->header.error = SA_AIS_OK; */
    msg->header.id = SERVICE_ID_MAKE(CRM_SERVICE, 1);	

    len = min(local_uname_len, MAX_NAME-1);
    memset(msg->uname, 0, MAX_NAME);
    memcpy(msg->uname, local_uname, len);

    len = min(strlen(VERSION), MAX_NAME-1);
    memset(msg->version, 0, MAX_NAME);
    memcpy(msg->version, VERSION, len);
    
    msg->votes = 1;
    msg->pid = getpid();
    msg->processes = crm_proc_ais;
    msg->born_on = local_born_on;

    for (lpc = 0; lpc < SIZEOF(pcmk_children); lpc++) {
	if(pcmk_children[lpc].pid != 0) {
	    msg->processes |= pcmk_children[lpc].flag;
	}
    }
    
    ais_debug("Local update: id=%u, born="U64T", seq="U64T"",
	      local_nodeid, local_born_on, membership_seq);
    update_member(
	local_nodeid, local_born_on, membership_seq, msg->votes, msg->processes, NULL, NULL, VERSION);

    iovec.iov_base = (char *)msg;
    iovec.iov_len = msg->header.size;
    
    rc = totempg_groups_mcast_joined (
	openais_group_handle, &iovec, 1, TOTEMPG_SAFE);

    AIS_CHECK(rc == 0, ais_err("Message not sent (%d)", rc));

    ais_free(msg);
}

static gboolean
ghash_send_removal(gpointer key, gpointer value, gpointer data)
{
    send_quorum_details(value);
    if(send_client_msg(value, crm_class_rmpeer, crm_msg_none, data) != 0) {
	/* remove it */
	return TRUE;
    }
    return FALSE;
}

static void ais_remove_peer(char *node_id)
{
    uint32_t id = ais_get_int(node_id, NULL);    
    crm_node_t *node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(id));
    if(node == NULL) {
	ais_info("Peer %u is unknown", id);

    } else if(ais_str_eq(CRM_NODE_MEMBER, node->state)) {
	ais_warn("Peer %u/%s is still active", id, node->uname);

    } else if(g_hash_table_remove(membership_list, GUINT_TO_POINTER(id))) {
	plugin_expected_votes--;
	ais_notice("Removed dead peer %u from the membership list", id);
	ais_info("Sending removal of %u to %d children",
		 id, g_hash_table_size(membership_notify_list));
	
	g_hash_table_foreach_remove(membership_notify_list, ghash_send_removal, node_id);
	
    } else {
	ais_warn("Peer %u/%s was not removed", id, node->uname);
    }

}

gboolean process_ais_message(AIS_Message *msg) 
{
    int len = ais_data_len(msg);
    char *data = get_ais_data(msg);
    do_ais_log(LOG_DEBUG,
	       "Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d): %.90s",
	       msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	       ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	       msg->sender.pid,
	       msg->sender.uname==local_uname?"false":"true",
	       ais_data_len(msg), data);

    if(data && len > 12 && strncmp("remove-peer:", data, 12) == 0) {
	char *node = data+12;
	ais_remove_peer(node);
    }
    
    ais_free(data);
    return TRUE;
}
