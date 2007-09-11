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

#include <lha_internal.h>
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

#define OPENAIS_EXTERNAL_SERVICE insane_ais_header_hack_in__totem_h

#include <crm/ais_common.h>
#include "plugin.h"

#include <openais/saAis.h>
#include <openais/service/swab.h>
#include <openais/totem/totem.h>

#include <openais/service/print.h>
#include <openais/service/objdb.h>
#include <openais/service/service.h>

#include <openais/totem/totempg.h>

#include <openais/lcr/lcr_comp.h>

#include <glib/ghash.h>

#include <sys/utsname.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/wait.h>
#include <bzlib.h>

static char *
ais_strdup(const char *src)
{
	char *dup = NULL;
	if(src == NULL) {
	    return NULL;
	}
	ais_malloc0(dup, strlen(src) + 1);
	return strcpy(dup, src);
}

static gboolean
ais_str_eq(const char *a, const char *b) 
{
    if(a == NULL || b == NULL) {
	return FALSE;
	
    } else if(a == b) {
	return TRUE;
	
    } else if(strcasecmp(a, b) == 0) {
	return TRUE;
    }
    return FALSE;
}

int plugin_log_level = LOG_DEBUG;
char *local_uname = NULL;
int local_uname_len = 0;
uint32_t local_nodeid = 0;
char *ipc_channel_name = NULL;
enum crm_ais_msg_types crm_system_type = crm_msg_ais;

extern char *uname_lookup(uint32_t nodeid);
extern uint32_t nodeid_lookup(const char *uname);
extern void update_uname_table(const char *uname, uint32_t nodeid);
#define 	SIZEOF(a)   (sizeof(a) / sizeof(a[0]))

typedef struct crm_child_s {
	int pid;
	int flag;
	gboolean respawn;
	const char *name;
	const char *command;
	void *conn;
    
} crm_child_t;

static crm_child_t crm_children[] = {
    { 0, 0, FALSE, "none", NULL, NULL },
    { 0, 0, FALSE, "ais",  NULL, NULL },
    { 0, 0, TRUE,  "cib",  HA_LIBHBDIR"/cib", NULL },
};

gboolean stop_child(crm_child_t *child, int signal);
gboolean spawn_child(crm_child_t *child);
gboolean route_ais_message(AIS_Message *msg, gboolean local);

extern totempg_groups_handle openais_group_handle;

static void global_confchg_fn (
    enum totem_configuration_type configuration_type,
    unsigned int *member_list, int member_list_entries,
    unsigned int *left_list, int left_list_entries,
    unsigned int *joined_list, int joined_list_entries,
    struct memb_ring_id *ring_id);

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb);
static int crm_config_init_fn(struct objdb_iface_ver0 *objdb);

static int ais_ipc_client_connect_callback (void *conn);

static int ais_ipc_client_exit_callback (void *conn);

static void ais_cluster_message_swab(void *msg);
static void ais_cluster_message_callback(void *message, unsigned int nodeid);

static void ais_ipc_message_callback(void *conn, void *msg);

/* from exec/ipc.h */
extern int openais_conn_send_response (void *conn, void *msg, int mlen);
extern int libais_connection_active (void *conn);

#define CRM_MESSAGE_TEST_ID 1
#define CRM_SERVICE         16

static struct openais_lib_handler crm_lib_service[] =
{
    {
	.lib_handler_fn		= ais_ipc_message_callback,
	.response_size		= sizeof (AIS_Message),
	.response_id		= CRM_MESSAGE_TEST_ID,
	.flow_control		= OPENAIS_FLOW_CONTROL_NOT_REQUIRED
    },
};

static struct openais_exec_handler crm_exec_service[] =
{
    {
	.exec_handler_fn	= ais_cluster_message_callback,
	.exec_endian_convert_fn = ais_cluster_message_swab
    }
};


static void crm_exec_dump_fn(void) 
{
    ENTER("");
    ais_err("here");
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
static struct openais_service_handler *crm_get_handler_ver0 (void);

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

static struct openais_service_handler *crm_get_handler_ver0 (void)
{
    return (&crm_service_handler);
}

__attribute__ ((constructor)) static void register_this_component (void) {
    lcr_interfaces_set (&openais_crm_ver0[0], &crm_service_handler_iface);

    lcr_component_register (&crm_comp_ver0);
}

/* IMPL */
static int crm_config_init_fn(struct objdb_iface_ver0 *objdb)
{
    int rc = 0;
    struct utsname us;
/* 	struct totem_ip_address localhost; */

    setenv("HA_debugfile", "/var/log/openais.log", 1);
    setenv("HA_debug", "1", 1);
    setenv("HA_logfacility", "local7", 1);
    
    log_init ("CRM");
    plugin_log_level = LOG_DEBUG;
    log_printf(LOG_INFO, "AIS logging: Initialized\n");

    ENTER("");

    ais_info("CRM Logging: Initialized");

    rc = uname(&us);
    AIS_ASSERT(rc == 0);
    local_uname = ais_strdup(us.nodename);
    local_uname_len = strlen(local_uname);

    ais_info("Local hostname: %s", local_uname);

    LEAVE("");
    return 0;
}


static int send_client_msg(
    void *conn, enum crm_ais_msg_types type, const char *data) 
{
    int rc = 0;
    int data_len = 0;
    int total_size = sizeof(AIS_Message);
    AIS_Message *ais_msg = NULL;
    static int msg_id = 0;

    ENTER("");
    AIS_ASSERT(local_nodeid != 0);

    msg_id++;
    AIS_ASSERT(msg_id != 0 /* wrap-around */);

    if(data != NULL) {
	data_len = 1 + strlen(data);
    }
    total_size += data_len;
    
    ais_malloc0(ais_msg, total_size);
	
    ais_msg->id = msg_id;
    ais_msg->header.size = total_size;
    ais_msg->header.id = 0;
	
    ais_msg->size = data_len;
    memcpy(ais_msg->data, data, data_len);
    ais_debug("%s -> %s", data, ais_msg->data);
    
    ais_msg->host.type = type;
    ais_msg->host.size = 0;
    memset(ais_msg->host.uname, 0, MAX_NAME);
    ais_msg->host.id = 0;

    ais_msg->sender.type = crm_system_type;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);
    ais_msg->sender.id = local_nodeid;

    rc = 1;
    if (conn == NULL) {
	ais_err("No connection");
	    
    } else if (!libais_connection_active(conn)) {
	ais_err("Connection no longer active");
	    
/* 	} else if ((queue->size - 1) == queue->used) { */
/* 	    ais_err("Connection is throttled: %d", queue->size); */

    } else {
	rc = openais_conn_send_response (conn, ais_msg, total_size);
	AIS_CHECK(rc == 0,
		  ais_err("Message not sent (%d): %s", rc, data?data:"<null>"));
    }

    ais_debug("done");
    LEAVE("");
    return rc;    
}

static int send_cluster_msg_raw(AIS_Message *ais_msg) 
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

    msg_id++;
    AIS_ASSERT(msg_id != 0 /* detect wrap-around */);

    ais_msg->id = msg_id;
    ais_msg->header.id = SERVICE_ID_MAKE(CRM_SERVICE, 0);	

    ais_msg->sender.id = local_nodeid;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);

    iovec.iov_base = (char *)ais_msg;
    iovec.iov_len = ais_msg->header.size;
    
    if(ais_msg->is_compressed == FALSE && ais_msg->size > 1024) {
	char *compressed = NULL;
	unsigned int len = (ais_msg->size * 1.1) + 600; /* recomended size */
	
	ais_debug("Creating compressed message");
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
    ais_debug("Sending message (size=%u)", (unsigned int)iovec.iov_len);
    rc = totempg_groups_mcast_joined (
	openais_group_handle, &iovec, 1, TOTEMPG_SAFE);

    if(rc == 0 && ais_msg->is_compressed == FALSE) {
	ais_debug("Message sent: %.80s", ais_msg->data);
    }
    
    AIS_CHECK(rc == 0, ais_err("Message not sent (%d)", rc));

    ais_free(bz2_msg);
    LEAVE("");
    return rc;	
}

static int send_cluster_msg(
    enum crm_ais_msg_types type, const char *host, const char *data) 
{
    int rc = 0;
    int data_len = 0;
    AIS_Message *ais_msg = NULL;
    int total_size = sizeof(AIS_Message);

    ENTER("");
    AIS_ASSERT(local_nodeid != 0);

    if(data != NULL) {
	data_len = 1 + strlen(data);
	total_size += data_len;
    } 
    ais_malloc0(ais_msg, total_size);
	
    ais_msg->header.size = total_size;
    ais_msg->header.id = 0;
    
    ais_msg->size = data_len;
    memcpy(ais_msg->data, data, data_len);
    ais_msg->sender.type = crm_msg_ais;

    ais_msg->host.type = type;
    if(host) {
	ais_msg->host.size = strlen(host);
	memset(ais_msg->host.uname, 0, MAX_NAME);
	memcpy(ais_msg->host.uname, host, ais_msg->host.size);
	ais_msg->host.id = nodeid_lookup(host);
		
    } else {
	ais_msg->host.type = type;
	ais_msg->host.size = 0;
	memset(ais_msg->host.uname, 0, MAX_NAME);
	ais_msg->host.id = 0;
    }
    
    rc = send_cluster_msg_raw(ais_msg);

    LEAVE("");
    return rc;	
}

pthread_t crm_wait_thread;
gboolean wait_active = TRUE;

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
		crm_children[lpc].pid = -1;
		crm_children[lpc].conn = NULL;

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

		if(crm_children[lpc].respawn) {
		    ais_info("Respawning failed child process: %s",
			     crm_children[lpc].name);
		    spawn_child(&(crm_children[lpc]));
		}
	    }
	}
	sched_yield ();
	nanosleep (&waitsleep, 0);
    }
    return 0;
}

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb)
{
    int lpc = 0;

    ENTER("");
    local_nodeid = totempg_my_nodeid_get();
    update_uname_table(local_uname, local_nodeid);

    ais_info("CRM: Initialized");

    for (; lpc < SIZEOF(crm_children); lpc++) {
	spawn_child(&(crm_children[lpc]));
    }

    pthread_create (&crm_wait_thread, NULL, crm_wait_dispatch, NULL);
    
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

static void global_confchg_fn (
    enum totem_configuration_type configuration_type,
    unsigned int *member_list, int member_list_entries,
    unsigned int *left_list, int left_list_entries,
    unsigned int *joined_list, int joined_list_entries,
    struct memb_ring_id *ring_id)
{
    int lpc = 0;
	
    ENTER("");
    AIS_ASSERT(ring_id != NULL);
    switch(configuration_type) {
	case TOTEM_CONFIGURATION_REGULAR:
	    break;
	case TOTEM_CONFIGURATION_TRANSITIONAL:
	    ais_info("Transitional membership event on ring %lld",
		     ring_id->seq);
	    return;
	    break;
    }

    ais_notice("Membership event on ring %lld: memb=%d, new=%d, lost=%d",
	       ring_id->seq, member_list_entries,
	       joined_list_entries, left_list_entries);

    for(lpc = 0; lpc < joined_list_entries; lpc++) {
	uint32_t nodeid = joined_list[lpc];
	const char *prefix = "NEW: ";
	const char *host = totempg_ifaces_print(nodeid);
	const char *uname = uname_lookup(nodeid);
	ais_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
    }
    for(lpc = 0; lpc < member_list_entries; lpc++) {
	uint32_t nodeid = member_list[lpc];
	const char *prefix = "MEMB:";
	const char *host = totempg_ifaces_print(nodeid);
	const char *uname = uname_lookup(nodeid);
	ais_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
    }
    for(lpc = 0; lpc < left_list_entries; lpc++) {
	uint32_t nodeid = left_list[lpc];
	const char *prefix = "LOST:";
	const char *host = totempg_ifaces_print(nodeid);
	const char *uname = uname_lookup(nodeid);
	ais_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
    }
	
/*     send_cluster_msg(crm_msg_ais, "somewhere.else", "Global membership changed"); */
    send_cluster_msg(crm_msg_ais, NULL, "I'm alive!");
	
    LEAVE("");
}

int ais_ipc_client_exit_callback (void *conn)
{
    ENTER("Client=%p", conn);
    ais_notice("Client left");
    LEAVE("");

    return (0);
}

static int ais_ipc_client_connect_callback (void *conn)
{
    ENTER("Client=%p", conn);
    ais_debug("Client %p joined", conn);
    send_client_msg(conn, crm_msg_none, "identify");
    LEAVE("");

    return (0);
}

/*
 * Executive message handlers
 */
static void ais_cluster_message_swab(void *msg)
{
    AIS_Message *ais_msg = msg;
    ENTER("");

    ais_info("Performing endian conversion...");
    ais_msg->id                = swab32 (ais_msg->id);
    ais_msg->is_compressed     = swab32 (ais_msg->is_compressed);
    ais_msg->compressed_size   = swab32 (ais_msg->compressed_size);
    ais_msg->size = swab32 (ais_msg->size);
    
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

static void ais_cluster_message_callback (
    void *message, unsigned int nodeid)
{
    AIS_Message *ais_msg = message;

    ENTER("Node=%u (%s)", nodeid, nodeid==local_nodeid?"local":"remote");
    ais_debug("Message from node %u (%s)",
	      nodeid, nodeid==local_nodeid?"local":"remote");
    update_uname_table(ais_msg->sender.uname, ais_msg->sender.id);
    if(ais_msg->host.size == 0
       || ais_str_eq(ais_msg->host.uname, local_uname)) {
	route_ais_message(ais_msg, FALSE);

    } else {
	ais_debug("Discarding Msg[%d] (dest=%s:%s, from=%s:%s)",
		  ais_msg->id, ais_dest(&(ais_msg->host)),
		  msg_type2text(ais_msg->host.type),
		  ais_dest(&(ais_msg->sender)),
		  msg_type2text(ais_msg->sender.type));
    }
    LEAVE("");
}

static void ais_ipc_message_callback(void *conn, void *msg)
{
    AIS_Message *ais_msg = msg;
    int type = ais_msg->sender.type;
    ENTER("Client=%p", conn);
    ais_debug("Message from client %p", conn);

    if(type > 0
       && ais_msg->host.local
       && crm_children[type].conn == NULL
       && ais_msg->host.type == crm_msg_ais
       && ais_msg->sender.pid == crm_children[type].pid
       && type < SIZEOF(crm_children)) {
	ais_info("Recorded connection %p for %s/%d",
		 conn, crm_children[type].name, crm_children[type].pid);
	crm_children[type].conn = conn;
    }
    
    ais_msg->sender.id = local_nodeid;
    ais_msg->sender.size = local_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);

    route_ais_message(msg, TRUE);

    LEAVE("");
}

static void swap_sender(AIS_Message *msg) 
{
    int tmp = 0;
    char tmp_s[256];
    tmp = msg->host.type;
    msg->host.type = msg->sender.type;
    msg->sender.type = tmp;

    tmp = msg->host.type;
    msg->host.size = msg->sender.type;
    msg->sender.type = tmp;

    memcpy(tmp_s, msg->host.uname, 256);
    memcpy(msg->host.uname, msg->sender.uname, 256);
    memcpy(msg->sender.uname, tmp_s, 256);
}

static char *get_ais_data(AIS_Message *msg)
{
    int rc = BZ_OK;
    char *uncompressed = NULL;
    unsigned int new_size = msg->size;
    
    if(msg->is_compressed == FALSE) {
	uncompressed = strdup(msg->data);

    } else {
	ais_malloc0(uncompressed, new_size);
	
	rc = BZ2_bzBuffToBuffDecompress(
	    uncompressed, &new_size, msg->data, msg->compressed_size, 1, 0);
	
	AIS_ASSERT(rc = BZ_OK);
	AIS_ASSERT(new_size == msg->size);
    }
    
    return uncompressed;
}

static gboolean process_ais_message(AIS_Message *msg) 
{
    char *data = get_ais_data(msg);
    do_ais_log(LOG_NOTICE,
	       "Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d): %s",
	       msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	       ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	       msg->sender.pid,
	       msg->sender.uname==local_uname?"false":"true",
	       ais_data_len(msg), data);
    ais_free(data);
    return TRUE;
}

gboolean route_ais_message(AIS_Message *msg, gboolean local_origin) 
{
    int rc = 0;
    
    ais_debug("Msg[%d] (dest=%s:%s, from=%s:%s.%d, remote=%s, size=%d)",
	      msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
	      ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
	      msg->sender.pid, local_origin?"false":"true", ais_data_len(msg));
    
    if(local_origin == FALSE) {
       if(msg->host.size == 0
	  || ais_str_eq(local_uname, msg->host.uname)) {
	   msg->host.local = TRUE;
       }
    }

    if(msg->host.local) {
	void *conn = NULL;

	if(msg->host.type == crm_msg_ais) {
	    process_ais_message(msg);
	    return TRUE;
	}
	
	AIS_CHECK(msg->host.type > 0 && msg->host.type < SIZEOF(crm_children),
		  ais_err("Invalid destination: %d", msg->host.type);
		  return FALSE;
	    );

	conn = crm_children[msg->host.type].conn;
	rc = 1;
	if (conn == NULL) {
	    ais_err("No connection to %s", crm_children[msg->host.type].name);
	    
	} else if (!libais_connection_active(conn)) {
	    ais_err("Connection to %s is no longer active",
		    crm_children[msg->host.type].name);
	    
/* 	} else if ((queue->size - 1) == queue->used) { */
/* 	    ais_err("Connection is throttled: %d", queue->size); */

	} else {
	    ais_debug("Delivering locally to %s (size=%d)",
		      crm_children[msg->host.type].name, msg->header.size);
	    rc = openais_conn_send_response(conn, msg, msg->header.size);
	}

    } else if(local_origin) {
	/* forward to other hosts */
	ais_debug("Forwarding to cluster");
	rc = send_cluster_msg_raw(msg);    

    } else {
	ais_debug("Ignoring...");
    }

    if(rc != 0) {
	ais_debug("Sending message to %s.%s failed (rc=%d)",
		  ais_dest(&(msg->host)), msg_type2text(msg->host.type), rc);
	return FALSE;
    }
    return TRUE;
}

gboolean spawn_child(crm_child_t *child)
{
    int lpc = 0;
    struct rlimit	oflimits;
    const char 	*devnull = "/dev/null";

    if(child->command == NULL) {
	ais_info("Nothing to do for child \"%s\"", child->name);
	return TRUE;
    }
    
    child->pid = fork();
    AIS_ASSERT(child->pid != -1);

    if(child->pid > 0) {
	/* parent */
	ais_info("Forked child %d for process %s", child->pid, child->name);
	return TRUE;
    }
    
    /* Child */
    ais_debug("Executing \"%s (%s)\" (pid %d)",
	      child->command, child->name, (int) getpid());
    
    /* A precautionary measure */
    getrlimit(RLIMIT_NOFILE, &oflimits);
    for (; lpc < oflimits.rlim_cur; lpc++) {
	close(lpc);
    }

    (void)open(devnull, O_RDONLY);	/* Stdin:  fd 0 */
    (void)open(devnull, O_WRONLY);	/* Stdout: fd 1 */
    (void)open(devnull, O_WRONLY);	/* Stderr: fd 2 */
    
    if(getenv("HA_VALGRIND_ENABLED") != NULL) {
	char *opts[] = { ais_strdup(VALGRIND_BIN),
			 ais_strdup("--show-reachable=yes"),
			 ais_strdup("--leak-check=full"),
			 ais_strdup("--time-stamp=yes"),
			 ais_strdup("--suppressions="VALGRIND_SUPP),
/* 				 ais_strdup("--gen-suppressions=all"), */
			 ais_strdup(VALGRIND_LOG),
			 ais_strdup(child->command),
			 NULL
	};
	(void)execvp(VALGRIND_BIN, opts);

    } else {
	char *opts[] = { ais_strdup(child->command), NULL };
	(void)execvp(child->command, opts);
    }

    ais_perror("FATAL: Cannot exec %s", child->command);
    exit(100);
    return TRUE; /* never reached */
}

gboolean
stop_child(crm_child_t *child, int signal)
{
    if(signal == 0) {
	signal = SIGTERM;
    }

    if(child->command == NULL) {
	ais_info("Nothing to do for child \"%s\"", child->name);
	return TRUE;
    }
    
    ais_debug_2("Stopping CRM child \"%s\"", child->name);
    
    if (child->pid <= 0) {
	ais_debug_2("Client %s not running", child->name);
	return TRUE;
    }
    
    errno = 0;
    if(kill(child->pid, signal) == 0) {
	ais_info("Sent -%d to %s: [%d]", signal, child->name, child->pid);
	
    } else {
	ais_perror("Sent -%d to %s: [%d]", signal, child->name, child->pid);
    }
    
    return TRUE;
}
