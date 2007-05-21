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

static void crm_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id);

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb);

static int crm_lib_init_fn (void *conn);

static int crm_lib_exit_fn (void *conn);

static void message_handler_req_exec_crm_test(void *message, unsigned int nodeid);

static void message_handler_req_lib_crm_test(void *conn, void *msg);
static void message_handler_req_lib_crm_example(void *conn, void *msg);

#define CRM_MESSAGE_TEST_ID 1
#define CRM_SERVICE         666

static struct openais_lib_handler crm_lib_service[] =
{
	{
		.lib_handler_fn		= message_handler_req_lib_crm_test,
		.response_size		= sizeof (int),
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
	.confchg_fn		= crm_confchg_fn,
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

static int crm_exec_init_fn (struct objdb_iface_ver0 *objdb)
{
	log_init ("CRM");
	return (0);
}
static void crm_confchg_fn (
	enum totem_configuration_type configuration_type,
	unsigned int *member_list, int member_list_entries,
	unsigned int *left_list, int left_list_entries,
	unsigned int *joined_list, int joined_list_entries,
	struct memb_ring_id *ring_id)
{
	ENTER("");
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
