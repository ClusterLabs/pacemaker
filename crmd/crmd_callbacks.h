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

#include <clplumbing/ipc.h>
#include <crm/ais_common.h>
#include <crm/common/cluster.h>

#if SUPPORT_HEARTBEAT
#include <hb_api.h>
extern void ccm_event_detail(const oc_ev_membership_t *oc, oc_ed_t event);
extern gboolean ccm_dispatch(int fd, gpointer user_data);
extern void crmd_ccm_msg_callback(
	oc_ed_t event, void *cookie, size_t size, const void *data);
extern gboolean crmd_ha_msg_dispatch(
	ll_cluster_t *cluster_conn, gpointer user_data);
#endif
/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */

extern void crmd_ipc_connection_destroy(gpointer user_data);
 
extern void crmd_ha_msg_callback(
	HA_Message *hamsg, void* private_data);

extern gboolean crmd_ipc_msg_callback(
	IPC_Channel *client, gpointer user_data);

extern gboolean crmd_ipc_msg_callback(
	IPC_Channel *client, gpointer user_data);

extern gboolean lrm_dispatch(IPC_Channel*src, gpointer user_data);

extern void lrm_op_callback (lrm_op_t* op);

extern void crmd_ha_status_callback(
	const char *node, const char * status,	void* private_data);

extern void crmd_client_status_callback(
	const char * node, const char * client, const char * status, void * private);

extern void msg_ccm_join(const xmlNode *msg, void *foo);

extern gboolean crmd_client_connect(
	IPC_Channel *newclient, gpointer user_data);

extern void crmd_cib_connection_destroy(gpointer user_data);

extern gboolean crm_fsa_trigger(gpointer user_data);

extern void ais_status_callback(enum crm_status_type type, crm_node_t *node, const void *data);
