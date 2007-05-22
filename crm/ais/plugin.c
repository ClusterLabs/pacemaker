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

#include <crm/crm.h>

typedef struct crm_ais_msg_s
{
		int		id;
		int		type;

		int		host_size;
		const char     *host;

		int		size;
		const char     *data;
} AIS_Message;

static struct totempg_group crm_group[] = {
        {
		.group		= "CRM",
		.group_len	= 3
	},
};

totempg_groups_handle crm_group_handle;
extern poll_handle aisexec_poll_handle;

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
static void message_handler_req_lib_crm_example(void *conn, void *msg);

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
	ENTER("");
	crm_err("here");
	LEAVE("");
	return (&crm_service_handler);
}

__attribute__ ((constructor)) static void register_this_component (void) {
	lcr_interfaces_set (&openais_crm_ver0[0], &crm_service_handler_iface);

	lcr_component_register (&crm_comp_ver0);
}

/* IMPL */
static int crm_config_init_fn(struct objdb_iface_ver0 *objdb)
{
	ENTER("");
	LEAVE("");
	return 0;
}

static int send_cluster_msg(int type, const char *host, const char *data) 
{
	int rc = 0;
	struct iovec iovec;
	AIS_Message ais_msg;
	static int msg_id = 0;

	ENTER("");
	if(data == NULL) {
		rc = -1;
		goto bail;
	}

	msg_id++;
	
	ais_msg.type = type;
	ais_msg.id = msg_id;
	
	ais_msg.size = strlen(data);
	ais_msg.data = data;

	if(host) {
		ais_msg.host_size = strlen(host);
		ais_msg.host = host;
	} else {
		ais_msg.host_size = 0;
		ais_msg.host = NULL;
	}
	
	iovec.iov_base = (char *)&ais_msg;
	iovec.iov_len = sizeof (AIS_Message);

	rc = totempg_groups_mcast_joined (
		crm_group_handle, &iovec, 1, TOTEMPG_SAFE);
  bail:
	CRM_CHECK(rc == 0,
		  crm_err("Message not sent (%d): %s", rc, crm_str(data)));

	LEAVE("");
	return rc;	
}

static int send_cluster_xml(int type, const char *host, crm_data_t *xml) 
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
	void *data = NULL;
	AIS_Message *ais_msg;

	ENTER("iov_len: %d", iov_len);
	if (iov_len > 1) {
		int i = 0;
		int pos = 0;
		crm_err("Combining multiple iovec entries");
		for (i = 0; i < iov_len; i++) {
			crm_realloc(data, pos+iovec[i].iov_len+1);
			memcpy (data+pos, iovec[i].iov_base, iovec[i].iov_len);
			pos += iovec[i].iov_len;
		}
		ais_msg = data;
		
	} else {
		ais_msg = iovec[0].iov_base;
	}

	if (endian_conversion_required) {
		crm_info("Performing endian conversion...");
		ais_msg->id = swab32 (ais_msg->id);
		ais_msg->type = swab32 (ais_msg->type);
		ais_msg->size = swab32 (ais_msg->size);
		ais_msg->host_size = swab32 (ais_msg->host_size);
	}
	crm_info("dump");

	crm_info("Msg (id=%d, type=%d, host=%s, size=%d): %s",
		 ais_msg->id, ais_msg->type,
		 ais_msg->host?ais_msg->host:"<all>",
		 ais_msg->size, crm_str(ais_msg->data));

	crm_free(data);
	LEAVE("");
}

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb)
{
	log_init ("CRM");
	ENTER("");
	log_printf(LOG_INFO, "AIS logging: Initialized\n");

	crm_log_init("crm_plugin");
	cl_log_enable_stderr(TRUE);
	set_crm_log_level(LOG_DEBUG);
	crm_info("CRM-AIS Plugin: Initialized");

	totempg_groups_initialize(
		&crm_group_handle, crm_deliver_fn, crm_confchg_fn);
	totempg_groups_join(crm_group_handle, crm_group, 1);
	
	crm_info("CRM Group: Initialized");
	send_cluster_msg(0, NULL, "I'm alive!");
	
	LEAVE("");
	return 0;
}

static void ais_pint_node() 
{
}

static void global_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id)
{
	ENTER("");
	
	send_cluster_msg(0, "this_host", "Global config changed");
	
	LEAVE("");
}

static void crm_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id)
{
	ENTER("");
	send_cluster_msg(0, NULL, "CRM config changed");
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
	int iface_count = 0;
	int msg_data = 999;
	
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

static void message_handler_req_lib_crm_example(void *conn, void *msg)
{
//	struct req_lib_crm_statetrack *req_lib_crm_statetrack = (struct req_lib_crm_statetrack *)message;

	ENTER("");
	LEAVE("");
}
