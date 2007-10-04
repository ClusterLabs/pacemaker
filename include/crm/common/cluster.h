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
#ifndef CRM_COMMON_CLUSTER__H
#define CRM_COMMON_CLUSTER__H

#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>

#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/ais.h>

extern gboolean send_ha_message(ll_cluster_t *hb_conn, HA_Message *msg,
				const char *node, gboolean force_ordered);

#ifdef WITH_NATIVE_AIS
#  include <crm/ais.h> 
#  define send_cluster_message(node, service, data, ordered) send_ais_message( \
	data, FALSE, node, service)
#else
extern ll_cluster_t *hb_conn;
#  define send_cluster_message(node, service, data, ordered) send_ha_message( \
	hb_conn, data, node, ordered)
#endif

extern gboolean crm_have_quorum;
extern GHashTable *crm_peer_cache;
extern unsigned long long crm_peer_seq;

extern void crm_peer_init(void);
extern void crm_peer_destroy(void);

extern void destroy_crm_node(gpointer data);

extern crm_node_t *crm_update_ais_node(crm_data_t *member, long long seq);
extern void crm_update_peer_proc(
    const char *uname, uint32_t flag, const char *status);
extern crm_node_t *crm_update_ccm_node(
    ll_cluster_t *cluster, 
    const oc_ev_membership_t *oc, int offset, const char *state);
extern crm_node_t *crm_update_peer(
    unsigned int id, unsigned long long born, int32_t votes, uint32_t children,
    const char *uuid, const char *uname, const char *addr, const char *state);

extern gboolean crm_is_member_active(const crm_node_t *node);
extern guint crm_active_members(void);
extern guint reap_crm_membership(void);
extern guint crm_active_members(void);
extern guint crm_active_peers(uint32_t peer);
extern gboolean crm_calculate_quorum(void);

#endif
