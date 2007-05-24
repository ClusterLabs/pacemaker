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

#include <openais/saAis.h>
#include <openais/service/swab.h>
#include <openais/totem/totem.h>

#include <openais/service/print.h>
#include <openais/service/objdb.h>
#include <openais/service/service.h>

#include <openais/totem/totempg.h>

#include <openais/lcr/lcr_comp.h>

#include <lha_internal.h>
#include <crm/crm.h>

#define MAX_NAME	256

typedef struct crm_ais_host_s AIS_Host;
typedef struct crm_ais_msg_s AIS_Message;

struct crm_ais_host_s
{
		uint32_t	id;
		uint32_t	size;
		char      uname[256];
} __attribute__((packed));


struct crm_ais_msg_s
{
		uint32_t	id;
		uint32_t	type;

		AIS_Host	host;
		AIS_Host	sender;
		
		uint32_t	size;
		char      data[0];
} __attribute__((packed));

static struct totempg_group crm_group[] = {
        {
		.group		= "CRM",
		.group_len	= 3
	},
};

totempg_groups_handle crm_group_handle;
extern poll_handle aisexec_poll_handle;
extern struct totem_ip_address *this_ip;
extern struct totem_ip_address this_non_loopback_ip;

static void crm_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id);

static void global_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id);

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb);
static int crm_config_init_fn(struct objdb_iface_ver0 *objdb);

static int crm_lib_init_fn (void *conn);

static int crm_lib_exit_fn (void *conn);

static void message_handler_req_exec_crm_test(void *message, unsigned int nodeid);

static void message_handler_req_lib_crm_test(void *conn, void *msg);

#define CRM_MESSAGE_TEST_ID 1
#define CRM_SERVICE         16

static struct openais_lib_handler crm_lib_service[] =
{
	{
		.lib_handler_fn		= message_handler_req_lib_crm_test,
		.response_size		= sizeof (AIS_Message),
		.response_id		= CRM_MESSAGE_TEST_ID,
		.flow_control		= OPENAIS_FLOW_CONTROL_REQUIRED
	},
};

static struct openais_exec_handler crm_exec_service[] =
{
	{
		message_handler_req_exec_crm_test
	}
};

static void crm_exec_dump_fn(void) 
{
	ENTER("");
	crm_err("here");
	LEAVE("");
}

/*
 * Exports the interface for the service
 */
struct openais_service_handler crm_service_handler = {
	.name			= "LHA Cluster Manager",
	.id			= CRM_SERVICE,
	.private_data_size	= 0,
	.flow_control		= OPENAIS_FLOW_CONTROL_REQUIRED, 
	.lib_init_fn		= crm_lib_init_fn,
	.lib_exit_fn		= crm_lib_exit_fn,
	.lib_service		= crm_lib_service,
	.lib_service_count	= sizeof (crm_lib_service) / sizeof (struct openais_lib_handler),
	.exec_init_fn		= crm_exec_init_fn,
	.exec_service		= crm_exec_service,
	.exec_service_count	= sizeof (crm_exec_service) / sizeof (struct openais_exec_handler),
	.config_init_fn		= crm_config_init_fn,
	.confchg_fn		= global_confchg_fn,
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

char *local_uname = NULL;
int local_uname_len = 0;
uint32_t local_nodeid = 0;

#include <sys/utsname.h>
#include <sys/socket.h>


/* int totemip_localhost(int family, struct totem_ip_address *localhost) */

GHashTable *uname_table = NULL;

static char *uname_lookup(uint32_t nodeid) 
{
	if(uname_table == NULL) {
		uname_table = g_hash_table_new_full(
			g_direct_hash, g_direct_equal, NULL, g_hash_destroy_str);
	}
	return g_hash_table_lookup(uname_table, GINT_TO_POINTER(nodeid));
}

static void update_uname_table(const char *uname, uint32_t nodeid) 
{
	const char *mapping = NULL;
	if(uname_table == NULL) {
		uname_table = g_hash_table_new_full(
			g_direct_hash, g_direct_equal, NULL, g_hash_destroy_str);
	}

	mapping = uname_lookup(nodeid);
	if(mapping == NULL) {
		CRM_ASSERT(uname != NULL);
		crm_info("Mapping %u -> %s", nodeid, uname);
		g_hash_table_insert(uname_table, GINT_TO_POINTER(nodeid), crm_strdup(uname));

	} else if(safe_str_neq(mapping, uname)) {
		crm_err("%s is now claiming to be node %u (current %s)", uname, nodeid, mapping);
	}
 	
	return;
}

/* IMPL */
static int crm_config_init_fn(struct objdb_iface_ver0 *objdb)
{
	int rc = 0;
	struct utsname us;
/* 	struct totem_ip_address localhost; */
	
	log_init ("CRM");
	log_printf(LOG_INFO, "AIS logging: Initialized\n");

	ENTER("");

	crm_log_init("crm_plugin");
	cl_log_enable_stderr(TRUE);
	set_crm_log_level(LOG_DEBUG);
	crm_info("CRM Logging: Initialized");

	rc = uname(&us);
	CRM_ASSERT(rc == 0);
	local_uname = crm_strdup(us.nodename);
	local_uname_len = strlen(local_uname);

	crm_info("Local hostname: %s", local_uname);

	LEAVE("");
	return 0;
}

static int send_cluster_msg(int type, const char *host, const char *data) 
{
	int rc = 0;
	int data_len = 0;
	struct iovec iovec;
	AIS_Message *ais_msg = NULL;
	static int msg_id = 0;

	ENTER("");
	CRM_ASSERT(local_nodeid != 0);

	msg_id++;
	CRM_ASSERT(msg_id != 0 /* wrap-around */);

	if(data != NULL) {
		data_len = strlen(data);
	} 
	crm_malloc0(ais_msg, sizeof(AIS_Message) + data_len + 1);
	
	ais_msg->type = type;
	ais_msg->id = msg_id;
	
	ais_msg->size = data_len;
	memcpy(ais_msg->data, data, ais_msg->size);

	if(host) {
		ais_msg->host.size = strlen(host);
		memset(ais_msg->host.uname, 0, MAX_NAME);
		memcpy(ais_msg->host.uname, host, ais_msg->host.size);
		ais_msg->host.id = 0;
		
	} else {
		ais_msg->host.size = 0;
		memset(ais_msg->host.uname, 0, MAX_NAME);
/* 		ais_msg->host.uname = NULL; */
		ais_msg->host.id = 0;
	}

	ais_msg->sender.size = local_uname_len;
	memset(ais_msg->sender.uname, 0, MAX_NAME);
	memcpy(ais_msg->sender.uname, local_uname, ais_msg->sender.size);
	ais_msg->sender.id = local_nodeid;

	iovec.iov_base = (char *)ais_msg;
	iovec.iov_len = sizeof (AIS_Message) + ais_msg->size + 1;

	rc = totempg_groups_mcast_joined (
		crm_group_handle, &iovec, 1, TOTEMPG_SAFE);

	CRM_CHECK(rc == 0,
		  crm_err("Message not sent (%d): %s", rc, crm_str(data)));

	LEAVE("");
	return rc;	
}

int send_cluster_xml(int type, const char *host, crm_data_t *xml);

int send_cluster_xml(int type, const char *host, crm_data_t *xml) 
{
	int rc = 0;
	char *data = dump_xml_unformatted(xml);
	CRM_CHECK(data != NULL, return -1);
	
	rc = send_cluster_msg(type, host, data);
	crm_free(data);
	return rc;
}


static void crm_deliver_fn (
	unsigned int nodeid,
	struct iovec *iovec,
	int iov_len,
	int endian_conversion_required)
{
	char *data = NULL;
	AIS_Message *ais_msg;
	gboolean process = TRUE;
	int log_level = LOG_DEBUG;

	ENTER("iov_len: %d", iov_len);
	if (iov_len > 1) {
		int i = 0;
		int pos = 0;
		crm_err("Combining multiple iovec entries - untested");
		for (i = 0; i < iov_len; i++) {
			crm_realloc(data, pos+iovec[i].iov_len+1);
			memcpy (data+pos, iovec[i].iov_base, iovec[i].iov_len);
			pos += iovec[i].iov_len;
		}
		ais_msg = (AIS_Message*)data;
		
	} else {
		ais_msg = iovec[0].iov_base;
	}

	if (endian_conversion_required) {
		crm_info("Performing endian conversion...");
		ais_msg->id = swab32 (ais_msg->id);
		ais_msg->type = swab32 (ais_msg->type);
		ais_msg->size = swab32 (ais_msg->size);
		ais_msg->host.id = swab32 (ais_msg->host.id);
		ais_msg->host.size = swab32 (ais_msg->host.size);
		ais_msg->sender.id = swab32 (ais_msg->sender.id);
		ais_msg->sender.size = swab32 (ais_msg->sender.size);
	}

	update_uname_table(ais_msg->sender.uname, ais_msg->sender.id);

	if(ais_msg->host.size == 0) {
		/* bcast - process */

	} else if(local_uname_len != ais_msg->host.size
		  || strncmp(local_uname, ais_msg->host.uname, ais_msg->host.size) != 0) {
		/* ucast - ignore */
		process = FALSE;
		log_level++;
	}

	do_crm_log(log_level, "Msg (id=%d, type=%d, dest=%s, from=%s, size=%d, remote=%s): %s",
		   ais_msg->id, ais_msg->type,
		   ais_msg->host.uname?ais_msg->host.uname:"<all>",
		   ais_msg->sender.uname, ais_msg->size,
		   ais_msg->sender.uname==local_uname?"false":"true",
		   crm_str(ais_msg->data));
	
	crm_free(data);
	LEAVE("");
}

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb)
{
	ENTER("");
	totempg_groups_initialize(
		&crm_group_handle, crm_deliver_fn, crm_confchg_fn);
	totempg_groups_join(crm_group_handle, crm_group, 1);
	
	crm_info("CRM Group: Initialized");
	CRM_ASSERT(this_ip);
	local_nodeid = this_ip->nodeid;
	update_uname_table(local_uname, local_nodeid);

	send_cluster_msg(0, NULL, "I'm alive!");
	
	LEAVE("");
	return 0;
}

static void ais_print_node(const char *prefix, struct totem_ip_address *host) 
{
	int len = 0;
	char *buffer = NULL;

	crm_malloc0(buffer, INET6_ADDRSTRLEN+1);
	
	inet_ntop(host->family, host->addr, buffer, INET6_ADDRSTRLEN);

	len = strlen(buffer);
	crm_info("%s: %.*s", prefix, len, buffer);
	crm_free(buffer);
}


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
	CRM_ASSERT(ring_id != NULL);
	switch(configuration_type) {
		case TOTEM_CONFIGURATION_REGULAR:
			break;
		case TOTEM_CONFIGURATION_TRANSITIONAL:
			crm_info("Transitional membership event on ring %lld",
				 ring_id->seq);
			return;
			break;
	}

	crm_notice("Membership event on ring %lld: memb=%d, new=%d, lost=%d",
		   ring_id->seq, member_list_entries,
		   joined_list_entries, left_list_entries);

	for(lpc = 0; lpc < joined_list_entries; lpc++) {
		uint32_t nodeid = joined_list[lpc];
		const char *prefix = "NEW: ";
		const char *host = totempg_ifaces_print(nodeid);
		const char *uname = uname_lookup(nodeid);
		crm_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
	}
	for(lpc = 0; lpc < member_list_entries; lpc++) {
		uint32_t nodeid = member_list[lpc];
		const char *prefix = "MEMB:";
		const char *host = totempg_ifaces_print(nodeid);
		const char *uname = uname_lookup(nodeid);
		crm_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
	}
	for(lpc = 0; lpc < left_list_entries; lpc++) {
		uint32_t nodeid = left_list[lpc];
		const char *prefix = "LOST:";
		const char *host = totempg_ifaces_print(nodeid);
		const char *uname = uname_lookup(nodeid);
		crm_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
	}
	
	send_cluster_msg(0, "somewhere.else", "Global membership changed");
	
	LEAVE("");
}

static void crm_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id)
{
	int lpc = 0;
	
	ENTER("");
	CRM_ASSERT(ring_id != NULL);
	switch(configuration_type) {
		case TOTEM_CONFIGURATION_REGULAR:
			break;
		case TOTEM_CONFIGURATION_TRANSITIONAL:
			crm_info("Transitional membership event on ring %lld",
				 ring_id->seq);
			return;
			break;
	}
	
	ais_print_node("Host", &(ring_id->rep));
	crm_notice("Membership event on ring %lld: memb=%d, new=%d, lost=%d",
		   ring_id->seq, member_list_entries,
		   joined_list_entries, left_list_entries);

	for(lpc = 0; lpc < joined_list_entries; lpc++) {
		uint32_t nodeid = joined_list[lpc];
		const char *prefix = "NEW: ";
		const char *host = totempg_ifaces_print(nodeid);
		const char *uname = uname_lookup(nodeid);
		crm_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
	}
	for(lpc = 0; lpc < member_list_entries; lpc++) {
		uint32_t nodeid = member_list[lpc];
		const char *prefix = "MEMB:";
		const char *host = totempg_ifaces_print(nodeid);
		const char *uname = uname_lookup(nodeid);
		crm_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
	}
	for(lpc = 0; lpc < left_list_entries; lpc++) {
		uint32_t nodeid = left_list[lpc];
		const char *prefix = "LOST:";
		const char *host = totempg_ifaces_print(nodeid);
		const char *uname = uname_lookup(nodeid);
		crm_info("%s %s %s %u", prefix, host, uname?uname:"<pending>", nodeid);
	}

	send_cluster_msg(0, NULL, "CRM membership changed");
	LEAVE("");
}

int crm_lib_exit_fn (void *conn)
{
	ENTER("");
	LEAVE("");

	return (0);
}

static int crm_lib_init_fn (void *conn)
{
	ENTER("");
/*
	totempg_ifaces_get (
		this_ip->nodeid,
		interfaces,
		&status,
		&iface_count);
*/
	LEAVE("");

        return (0);
}

/*
 * Executive message handlers
 */
static void message_handler_req_exec_crm_test (
        void *message,
        unsigned int nodeid)
{
	ENTER("");
/* 	internal_log_printf (__FUNCTION__, __LINE__, LOG_ERR, "Here I am: %p", message) */
	LEAVE("");
}

static void message_handler_req_lib_crm_test(void *conn, void *msg)
{
//	struct req_lib_crm_statetrack *req_lib_crm_statetrack = (struct req_lib_crm_statetrack *)message;

	ENTER("");
/* 	internal_log_printf (__FUNCTION__, __LINE__, LOG_ERR, "Here I am: %p", msg) */
	LEAVE("");
}

