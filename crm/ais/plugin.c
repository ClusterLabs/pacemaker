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

#include <openais/service/objdb.h>

#define OPENAIS_EXTERNAL_SERVICE insane_ais_header_hack_in__totem_h
#include <openais/saAis.h>
#include <openais/service/swab.h>
#include <openais/totem/totempg.h>
#include <openais/service/service.h>
#ifndef AIS_WHITETANK 
#  include <openais/service/ipc.h>
#endif
#include <openais/lcr/lcr_comp.h>

#include <glib/ghash.h>

#include <sys/utsname.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/wait.h>
#include <bzlib.h>

int plugin_log_level = LOG_DEBUG;
char *local_uname = NULL;
int local_uname_len = 0;
unsigned int local_nodeid = 0;
char *ipc_channel_name = NULL;

unsigned long long membership_seq = 0;
pthread_t crm_wait_thread;

gboolean wait_active = TRUE;
GHashTable *membership_list = NULL;

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

} __attribute__((packed));

static crm_child_t crm_children[] = {
    { 0, crm_proc_none,     crm_flag_none,    0, 0, FALSE, "none",     0, NULL, NULL },
    { 0, crm_proc_ais,      crm_flag_none,    0, 0, FALSE, "ais",      0, NULL, NULL },
    { 0, crm_proc_lrmd,     crm_flag_none,    3, 0, TRUE,  "lrmd",     0,         HA_LIBHBDIR"/lrmd",     NULL },
    { 0, crm_proc_cib,      crm_flag_members, 2, 0, TRUE,  "cib",      HA_CCMUID, HA_LIBHBDIR"/cib",      NULL },
    { 0, crm_proc_crmd,     crm_flag_members, 5, 0, TRUE,  "crmd",     HA_CCMUID, HA_LIBHBDIR"/crmd",     NULL },
    { 0, crm_proc_attrd,    crm_flag_none,    4, 0, TRUE,  "attrd",    HA_CCMUID, HA_LIBHBDIR"/attrd",    NULL },
    { 0, crm_proc_stonithd, crm_flag_none,    1, 0, TRUE,  "stonithd", 0,         HA_LIBHBDIR"/stonithd", NULL },
};

void send_cluster_id(void);
int send_cluster_msg_raw(AIS_Message *ais_msg);
char *ais_generate_membership_data(void);

extern totempg_groups_handle openais_group_handle;

void global_confchg_fn (
    enum totem_configuration_type configuration_type,
    unsigned int *member_list, int member_list_entries,
    unsigned int *left_list, int left_list_entries,
    unsigned int *joined_list, int joined_list_entries,
    struct memb_ring_id *ring_id);

int crm_exec_exit_fn (struct objdb_iface_ver0 *objdb);
int crm_exec_init_fn (struct objdb_iface_ver0 *objdb);
int crm_config_init_fn(struct objdb_iface_ver0 *objdb);

int ais_ipc_client_connect_callback (void *conn);
int ais_ipc_client_exit_callback (void *conn);

void ais_cluster_message_swab(void *msg);
void ais_cluster_message_callback(void *message, unsigned int nodeid);

void ais_ipc_message_callback(void *conn, void *msg);

void ais_quorum_query(void *conn, void *msg);
void ais_node_list_query(void *conn, void *msg);
void ais_manage_notification(void *conn, void *msg);

void ais_cluster_id_swab(void *msg);
void ais_cluster_id_callback(void *message, unsigned int nodeid);

static struct openais_lib_handler crm_lib_service[] =
{
    { /* 0 */
	.lib_handler_fn		= ais_ipc_message_callback,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= OPENAIS_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 1 */
	.lib_handler_fn		= ais_node_list_query,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= OPENAIS_FLOW_CONTROL_NOT_REQUIRED
    },
    { /* 2 */
	.lib_handler_fn		= ais_manage_notification,
	.response_size		= sizeof (mar_res_header_t),
	.response_id		= CRM_MESSAGE_IPC_ACK,
	.flow_control		= OPENAIS_FLOW_CONTROL_NOT_REQUIRED
    },
};

static struct openais_exec_handler crm_exec_service[] =
{
    { /* 0 */
	.exec_handler_fn	= ais_cluster_message_callback,
	.exec_endian_convert_fn = ais_cluster_message_swab
    },
    { /* 1 */
	.exec_handler_fn	= ais_cluster_id_callback,
	.exec_endian_convert_fn = ais_cluster_id_swab
    }
};

static void crm_exec_dump_fn(void) 
{
    ENTER("");
    ais_err("Called after SIG_USR2");
    LEAVE("");
}

/*
 * Exports the interface for the service
 */
struct openais_service_handler crm_service_handler = {
    .name			= "LHA Cluster Manager",
    .id				= CRM_SERVICE,
    .private_data_size		= 0,
    .flow_control		= OPENAIS_FLOW_CONTROL_NOT_REQUIRED, 
    .lib_init_fn		= ais_ipc_client_connect_callback,
    .lib_exit_fn		= ais_ipc_client_exit_callback,
    .lib_service		= crm_lib_service,
    .lib_service_count	= sizeof (crm_lib_service) / sizeof (struct openais_lib_handler),
    .exec_init_fn		= crm_exec_init_fn,
    .exec_exit_fn		= crm_exec_exit_fn,
    .exec_service		= crm_exec_service,
    .exec_service_count	= sizeof (crm_exec_service) / sizeof (struct openais_exec_handler),
    .config_init_fn		= crm_config_init_fn,
    .confchg_fn			= global_confchg_fn,
    .exec_dump_fn		= crm_exec_dump_fn,
/* 	void (*sync_init) (void); */
/* 	int (*sync_process) (void); */
/* 	void (*sync_activate) (void); */
/* 	void (*sync_abort) (void); */
};


/*
 * Dynamic Loader definition
 */
struct openais_service_handler *crm_get_handler_ver0 (void);

static struct openais_service_handler_iface_ver0 crm_service_handler_iface = {
    .openais_get_service_handler_ver0	= crm_get_handler_ver0
};

static struct lcr_iface openais_crm_ver0[1] = {
    {
	.name				= "lha_crm",
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

static struct lcr_comp crm_comp_ver0 = {
    .iface_count				= 1,
    .ifaces					= openais_crm_ver0
};

struct openais_service_handler *crm_get_handler_ver0 (void)
{
    return (&crm_service_handler);
}

__attribute__ ((constructor)) static void register_this_component (void) {
    lcr_interfaces_set (&openais_crm_ver0[0], &crm_service_handler_iface);

    lcr_component_register (&crm_comp_ver0);
}

static void crm_plugin_init(struct objdb_iface_ver0 *objdb) 
{
    int rc = 0;
    struct utsname us;
    char *value = NULL;
    unsigned int object_service_handle = 0;

    membership_list = g_hash_table_new_full(
	g_direct_hash, g_direct_equal, NULL, destroy_ais_node);

    setenv("HA_COMPRESSION",  "bz2", 1);
    setenv("HA_cluster_type", "openais", 1);
    
#if 0
    objdb->object_find_reset (OBJECT_PARENT_HANDLE);
    
    if (objdb->object_find (
	    OBJECT_PARENT_HANDLE, "pacemaker", strlen ("pacemaker"),
	    &object_service_handle) != 0) {
	object_service_handle = 0;
	ais_info("No configuration supplied for pacemaker");
    }
#endif
    
    objdb_get_string(
	objdb, object_service_handle, "logfacility", &value, "daemon");
    setenv("HA_logfacility",  value, 1);
    
    objdb_get_string(objdb, object_service_handle, "initdead", &value, "20");
    setenv("HA_initdead",  value, 1);
    
    objdb_get_string(objdb, object_service_handle, "debug", &value, "1");
    setenv("HA_debug",  value, 1);

    rc = atoi(value);
    plugin_log_level = LOG_INFO+rc;

    if(system("echo 1 > /proc/sys/kernel/core_uses_pid") != 0) {
	ais_perror("Could not enable /proc/sys/kernel/core_uses_pid");
    }
    
    ais_info("CRM: Initialized");
    log_printf(LOG_INFO, "Logging: Initialized %s\n", __PRETTY_FUNCTION__);
    
    rc = uname(&us);
    AIS_ASSERT(rc == 0);
    local_uname = ais_strdup(us.nodename);
    local_uname_len = strlen(local_uname);

    ais_info("Local hostname: %s", local_uname);

    local_nodeid = totempg_my_nodeid_get();
    update_member(local_nodeid, 0, 1, 0, local_uname, CRM_NODE_LOST);
    
}

/* IMPL */
int crm_config_init_fn(struct objdb_iface_ver0 *objdb)
{
    ENTER("");
    LEAVE("");
    return 0;
}

static void *crm_wait_dispatch (void *arg)
{
    struct timespec waitsleep = {
	.tv_sec = 0,
	.tv_nsec = 100000 /* 100 msec */
    };
    
    while(wait_active) {
	int lpc = 0;
	for (; lpc < SIZEOF(crm_children); lpc++) {
	    if(crm_children[lpc].pid > 0) {
		int status;
		pid_t pid = wait4(
		    crm_children[lpc].pid, &status, WNOHANG, NULL);

		if(pid == 0) {
		    continue;
		    
		} else if(pid < 0) {
		    ais_perror("crm_wait_dispatch: Call to wait4(%s) failed",
			crm_children[lpc].name);
		    continue;
		}

		/* cleanup */
		crm_children[lpc].pid = 0;
		crm_children[lpc].conn = NULL;
		crm_children[lpc].async_conn = NULL;

		if(WIFSIGNALED(status)) {
		    int sig = WTERMSIG(status);
		    ais_warn("Child process %s terminated with signal %d"
			     " (pid=%d, core=%s)",
			     crm_children[lpc].name, sig, pid,
			     WCOREDUMP(status)?"true":"false");

		} else if (WIFEXITED(status)) {
		    int rc = WEXITSTATUS(status);
		    ais_notice("Child process %s exited (pid=%d, rc=%d)",
			       crm_children[lpc].name, pid, rc);

		    if(rc == 100) {
			ais_notice("Child process %s no longer wishes"
				   " to be respawned", crm_children[lpc].name);
			crm_children[lpc].respawn = FALSE;
		    }
		}

		crm_children[lpc].respawn_count += 1;
		if(crm_children[lpc].respawn_count > MAX_RESPAWN) {
		    ais_notice("Child respawn count exceeded by %s",
			       crm_children[lpc].name);
		    crm_children[lpc].respawn = FALSE;
		}
		if(crm_children[lpc].respawn) {
		    ais_info("Respawning failed child process: %s",
			     crm_children[lpc].name);
		    spawn_child(&(crm_children[lpc]));
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

int crm_exec_init_fn (struct objdb_iface_ver0 *objdb)
{
    int lpc = 0;
    int start_seq = 1;
    static gboolean need_init = TRUE;
    static int max = SIZEOF(crm_children);

#ifdef AIS_WHITETANK 
    log_init ("crm");
#endif
    
    ENTER("");
    if(need_init) {
	need_init = FALSE;
	crm_plugin_init(objdb);
    
	pthread_create (&crm_wait_thread, NULL, crm_wait_dispatch, NULL);

	mkdir(HA_VARRUNDIR, 750);
	mkdir(HA_VARRUNDIR"/crm", 750);
	chown(HA_VARRUNDIR"/crm", HA_CCMUID, HA_APIGID);
	chown(HA_VARRUNDIR, HA_CCMUID, HA_APIGID);
	
	for (start_seq = 1; start_seq < max; start_seq++) {
	    /* dont start anything with start_seq < 1 */
	    for (lpc = 0; lpc < max; lpc++) {
		if(start_seq == crm_children[lpc].start_seq) {
		    spawn_child(&(crm_children[lpc]));
		}
	    }
	}
    }
    
    ais_info("CRM: Initialized");
    
    LEAVE("");
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
	sprintf (one_iface, "r(%d) ip(%s) ",
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
	ais_info("Node %s was not seen in the previous transition",
		 node->uname);
	*changed += update_member(node->id, membership_seq, node->votes,
				 node->processes, node->uname, CRM_NODE_LOST);
	ais_info("Node %s marked dead", node->uname);
    }
}

void global_confchg_fn (
    enum totem_configuration_type configuration_type,
    unsigned int *member_list, int member_list_entries,
    unsigned int *left_list, int left_list_entries,
    unsigned int *joined_list, int joined_list_entries,
    struct memb_ring_id *ring_id)
{
    int lpc = 0;
    int changed = 0;
    int do_update = 0;
    
    ENTER("");
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
	    nodeid, membership_seq, -1, 0, NULL, CRM_NODE_MEMBER);

	ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);

	node = g_hash_table_lookup(membership_list, GUINT_TO_POINTER(nodeid));	
	if(node->addr == NULL) {
	    const char *addr = totempg_ifaces_print(nodeid);
	    node->addr = ais_strdup(addr);
	    ais_debug("Node %u has address %s", nodeid, node->addr);	    
	}
    }

    for(lpc = 0; lpc < member_list_entries; lpc++) {
	const char *prefix = "MEMB:";
	uint32_t nodeid = member_list[lpc];
	changed += update_member(
	    nodeid, membership_seq, -1, 0, NULL, CRM_NODE_MEMBER);

	ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
    }

    for(lpc = 0; lpc < left_list_entries; lpc++) {
	const char *prefix = "LOST:";
	uint32_t nodeid = left_list[lpc];
	changed += update_member(
	    nodeid, membership_seq, -1, 0, NULL, CRM_NODE_LOST);
	ais_info("%s %s %u", prefix, member_uname(nodeid), nodeid);
    }    
    
    if(do_update) {
	ais_debug_2("Reaping unseen nodes...");
	g_hash_table_foreach(
	    membership_list, ais_mark_unseen_peer_dead, &changed);
    }
    
    if(changed) {
	ais_debug("%d nodes changed", changed);
	send_member_notification();
    }
    
    send_cluster_id();
    LEAVE("");
}

int ais_ipc_client_exit_callback (void *conn)
{
    int lpc = 0;
    const char *client = NULL;
    
    ENTER("Client=%p", conn);
    for (; lpc < SIZEOF(crm_children); lpc++) {
	if(crm_children[lpc].conn == conn) {
	    crm_children[lpc].conn = NULL;
	    crm_children[lpc].async_conn = NULL;
	    client = crm_children[lpc].name;
	    break;
	}
    }
    
    ais_info("Client %p/%s left", conn, client?client:"unknown-transient");
    LEAVE("");

    return (0);
}

int ais_ipc_client_connect_callback (void *conn)
{
    void *async_conn = openais_conn_partner_get(conn);
    ENTER("Client=%p", conn);
    ais_debug("Client %p/%p joined", conn, async_conn);
#ifndef AIS_WHITETANK
    /* Whitetank hasn't finished setting up the connection at this point
     * Sending messages now messes up the protocol!
     */
    if(async_conn) {
	send_client_msg(async_conn, crm_class_cluster, crm_msg_none, "identify");
    } else {
	ais_err("No async connection");
    }
#endif
    LEAVE("");

    return (0);
}

/*
 * Executive message handlers
 */
void ais_cluster_message_swab(void *msg)
{
    AIS_Message *ais_msg = msg;
    ENTER("");

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

    LEAVE("");
}

void ais_cluster_message_callback (
    void *message, unsigned int nodeid)
{
    AIS_Message *ais_msg = message;

    ENTER("Node=%u (%s)", nodeid, nodeid==local_nodeid?"local":"remote");
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
    LEAVE("");
}

void ais_cluster_id_swab(void *msg)
{
    struct crm_identify_msg_s *ais_msg = msg;
    ENTER("");

    ais_debug_3("Performing endian conversion...");
    ais_msg->id        = swab32 (ais_msg->id);
    ais_msg->pid       = swab32 (ais_msg->pid);
    ais_msg->votes     = swab32 (ais_msg->votes);
    ais_msg->processes = swab32 (ais_msg->processes);

    LEAVE("");
}

void ais_cluster_id_callback (void *message, unsigned int nodeid)
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
	nodeid, membership_seq, msg->votes, msg->processes, msg->uname, NULL);

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
    
    res_overlay->header.size = crm_lib_service[class].response_size;
    res_overlay->header.id = crm_lib_service[class].response_id;
    res_overlay->header.error = SA_AIS_OK;
#ifdef AIS_WHITETANK
    openais_response_send (conn, res_overlay, res_overlay->header.size);
#else
    openais_conn_send_response (conn, res_overlay, res_overlay->header.size);
#endif
}


/* local callbacks */
void ais_ipc_message_callback(void *conn, void *msg)
{
    gboolean transient = TRUE;
    AIS_Message *ais_msg = msg;
    int type = ais_msg->sender.type;
    void *async_conn = openais_conn_partner_get(conn);
    ENTER("Client=%p", conn);
    ais_debug_2("Message from client %p", conn);
    send_ipc_ack(conn, 0);

    ais_debug_3("type: %d local: %d conn: %p host type: %d ais: %d sender pid: %d child pid: %d size: %d",
		type, ais_msg->host.local, crm_children[type].conn, ais_msg->host.type, crm_msg_ais,
		ais_msg->sender.pid, crm_children[type].pid, ((int)SIZEOF(crm_children)));
    
    if(type > crm_msg_none && type < SIZEOF(crm_children)) {
	/* known child process */
	transient = FALSE;
    }
    
    /* If this check fails, the order of crm_children probably 
     *   doesn't match that of the crm_ais_msg_types enum
     */
    AIS_CHECK(transient || ais_msg->sender.pid == crm_children[type].pid,
	      ais_err("Sender: %d, child[%d]: %d", ais_msg->sender.pid, type, crm_children[type].pid);
	      return);
    
    if(transient == FALSE
       && type > crm_msg_none
       && ais_msg->host.local
       && crm_children[type].conn == NULL
       && ais_msg->host.type == crm_msg_ais) {
	
	ais_info("Recorded connection %p for %s/%d",
		 conn, crm_children[type].name, crm_children[type].pid);
	crm_children[type].conn = conn;
	crm_children[type].async_conn = async_conn;

	/* Make sure they have the latest membership */
	if(crm_children[type].flags & crm_flag_members) {
	    char *update = ais_generate_membership_data();
	    ais_info("Sending membership update %llu to %s",
		     membership_seq, crm_children[type].name);
 	    send_client_msg(async_conn, crm_class_members, crm_msg_none,update);
	}	
    }
    
    ais_msg->sender.id = local_nodeid;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);

    route_ais_message(msg, TRUE);
    
    LEAVE("");
}

int crm_exec_exit_fn (struct objdb_iface_ver0 *objdb)
{
    int lpc = 0;
    int start_seq = 1;
    static int max = SIZEOF(crm_children);
    
    struct timespec waitsleep = {
	.tv_sec = 1,
	.tv_nsec = 0
    };

    ENTER("");
    ais_notice("Begining shutdown");

    in_shutdown = TRUE;
    wait_active = FALSE; /* stop the wait loop */
 
    for (start_seq = max; start_seq > 0; start_seq--) {
	/* dont stop anything with start_seq < 1 */
   
	for (lpc = max - 1; lpc >= 0; lpc--) {
	    if(start_seq != crm_children[lpc].start_seq) {
		continue;
	    }
		
	    crm_children[lpc].respawn = FALSE;
	    stop_child(&(crm_children[lpc]), SIGTERM);
	    while(crm_children[lpc].command && crm_children[lpc].pid) {
		int status;
		pid_t pid = 0;
		
		pid = wait4(
		    crm_children[lpc].pid, &status, WNOHANG, NULL);
		
		if(pid == 0) {
		    sched_yield ();
		    nanosleep (&waitsleep, 0);
		    continue;
		    
		} else if(pid < 0) {
		    ais_perror("crm_wait_dispatch: Call to wait4(%s) failed",
			       crm_children[lpc].name);
		}
		
		ais_notice("%s (pid=%d) confirmed dead",
			   crm_children[lpc].name, crm_children[lpc].pid);
		
		/* cleanup */
		crm_children[lpc].pid = 0;
		crm_children[lpc].conn = NULL;
		crm_children[lpc].async_conn = NULL;
		break;
	    }
	}
    }
    
    send_cluster_id();

    ais_notice("Shutdown complete");
    LEAVE("");
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

char *ais_generate_membership_data(void)
{
    int size = 0;
    struct member_loop_data data;
    size = 14 + 32; /* <nodes id=""> + int */
    ais_malloc0(data.string, size);
    sprintf(data.string, "<nodes id=\"%llu\">", membership_seq);
    
    g_hash_table_foreach(membership_list, member_loop_fn, &data);

    size = strlen(data.string);
    data.string = realloc(data.string, size + 9) ;/* 9 = </nodes> + nul */
    sprintf(data.string + size, "</nodes>");
    return data.string;
}

void ais_node_list_query(void *conn, void *msg)
{
    char *data = ais_generate_membership_data();
    void *async_conn = openais_conn_partner_get(conn);

    /* send the ACK before we send any other messages */
    send_ipc_ack(conn, 1);

    if(async_conn) {
	send_client_msg(async_conn, crm_class_members, crm_msg_none, data);
    }
    ais_free(data);
}

void ais_manage_notification(void *conn, void *msg)
{
    int lpc = 0;
    int enable = 0;
    AIS_Message *ais_msg = msg;
    char *data = get_ais_data(ais_msg);

    if(ais_str_eq("true", data)) {
	enable = 1;
    }
    
    for (; lpc < SIZEOF(crm_children); lpc++) {
	if(crm_children[lpc].conn == conn) {
	    ais_info("%s node notifications for %s",
		     enable?"Enabling":"Disabling", crm_children[lpc].name);
	    if(enable) {
		crm_children[lpc].flags |= crm_flag_members;
	    } else {
		crm_children[lpc].flags |= crm_flag_members;
		crm_children[lpc].flags ^= crm_flag_members;
	    }
	    break;
	}
    }
    send_ipc_ack(conn, 2);
}

void send_member_notification(void)
{
    int lpc = 0;
    char *update = ais_generate_membership_data();

    for (; lpc < SIZEOF(crm_children); lpc++) {
	if(crm_children[lpc].flags & crm_flag_members) {

	    if(crm_children[lpc].async_conn == NULL) {
		continue;
	    }
	    
	    ais_info("Sending membership update %llu to %s",
		     membership_seq, crm_children[lpc].name);
	    
 	    send_client_msg(crm_children[lpc].async_conn,
			    crm_class_members, crm_msg_none, update);
	}
    }
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

    if(sane && msg->header.error != 0) {
	ais_warn("Message header contains an error: %d", msg->header.error);
	sane = FALSE;
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
    int level = LOG_WARNING;
    int dest = msg->host.type;

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
	    /* te messages are routed via the crm - for now */
	    dest = crm_msg_crmd;
	}

	if(in_shutdown) {
	    level = LOG_INFO;
	}
	
	AIS_CHECK(dest > 0 && dest < SIZEOF(crm_children),
		  ais_err("Invalid destination: %d", dest);
		  log_ais_message(LOG_ERR, msg);
		  return FALSE;
	    );

	rc = 1;
	lookup = msg_type2text(dest);
	conn = crm_children[dest].async_conn;

	/* the cluster fails in weird and wonderfully obscure ways when this is not true */
	AIS_ASSERT(ais_str_eq(lookup, crm_children[dest].name));
	
	if (conn == NULL) {
	    do_ais_log(level, "No connection to %s", crm_children[dest].name);
	    
	} else if (!libais_connection_active(conn)) {
	    do_ais_log(level, "Connection to %s is no longer active",
		       crm_children[dest].name);
	    crm_children[dest].async_conn = NULL;
	    
/* 	} else if ((queue->size - 1) == queue->used) { */
/* 	    ais_err("Connection is throttled: %d", queue->size); */

	} else {
	    level = LOG_ERR;
	    ais_debug_3("Delivering locally to %s (size=%d)",
			crm_children[dest].name, msg->header.size);
#ifdef AIS_WHITETANK
	    rc = openais_dispatch_send(conn, msg, msg->header.size);
#else
	    rc = openais_conn_send_response(conn, msg, msg->header.size);
#endif
	}

    } else if(local_origin) {
	/* forward to other hosts */
	ais_debug_3("Forwarding to cluster");
	rc = send_cluster_msg_raw(msg);    

    } else {
	ais_debug_3("Ignoring...");
    }

    if(rc != 0) {
	do_ais_log(level, "Sending message to %s.%s failed (rc=%d)",
		   ais_dest(&(msg->host)), msg_type2text(dest), rc);
	log_ais_message(level, msg);
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

    ENTER("");
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
    
    ais_msg->header.id = SERVICE_ID_MAKE(CRM_SERVICE, 0);	

    ais_msg->sender.id = local_nodeid;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);

    iovec.iov_base = (char *)ais_msg;
    iovec.iov_len = ais_msg->header.size;

#if 0
    if(ais_msg->is_compressed == FALSE && ais_msg->size > 1024) {
	char *compressed = NULL;
	unsigned int len = (ais_msg->size * 1.1) + 600; /* recomended size */
	
	ais_debug_2("Creating compressed message");
	ais_malloc0(compressed, len);
	
	rc = BZ2_bzBuffToBuffCompress(
	    compressed, &len, ais_msg->data, ais_msg->size, 3, 0, 30);
	
	if(rc != BZ_OK) {
	    ais_err("Compression failed: %d", rc);
	    ais_free(compressed);
	    goto send;  
	}

	ais_malloc0(bz2_msg, sizeof(AIS_Message) + len + 1);
	memcpy(bz2_msg, ais_msg, sizeof(AIS_Message));
	memcpy(bz2_msg->data, compressed, len);
	ais_free(compressed);

	bz2_msg->is_compressed = TRUE;
	bz2_msg->compressed_size = len;
	bz2_msg->header.size = sizeof(AIS_Message) + ais_data_len(bz2_msg);

	ais_debug("Compression details: %d -> %d",
		  bz2_msg->size, ais_data_len(bz2_msg));

	iovec.iov_base = (char *)bz2_msg;
	iovec.iov_len = bz2_msg->header.size;
    }    

  send:
#endif
    ais_debug_3("Sending message (size=%u)", (unsigned int)iovec.iov_len);
    rc = totempg_groups_mcast_joined (
	openais_group_handle, &iovec, 1, TOTEMPG_SAFE);

    if(rc == 0 && ais_msg->is_compressed == FALSE) {
	ais_debug_2("Message sent: %.80s", ais_msg->data);
    }
    
    AIS_CHECK(rc == 0, ais_err("Message not sent (%d)", rc));

    ais_free(bz2_msg);
    LEAVE("");
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
    
    ENTER("");
    AIS_ASSERT(local_nodeid != 0);

    ais_malloc0(msg, sizeof(struct crm_identify_msg_s));
    msg->header.size = sizeof(struct crm_identify_msg_s);

    msg->id = local_nodeid;
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

    for (lpc = 0; lpc < SIZEOF(crm_children); lpc++) {
	if(crm_children[lpc].pid != 0) {
	    msg->processes |= crm_children[lpc].flag;
	}
    }

    ais_debug("Local update: %u", local_nodeid);
    update_member(
	local_nodeid, membership_seq, msg->votes, msg->processes, NULL, NULL);

    iovec.iov_base = (char *)msg;
    iovec.iov_len = msg->header.size;
    
    rc = totempg_groups_mcast_joined (
	openais_group_handle, &iovec, 1, TOTEMPG_SAFE);

    AIS_CHECK(rc == 0, ais_err("Message not sent (%d)", rc));

    ais_free(msg);
    LEAVE("");
}
