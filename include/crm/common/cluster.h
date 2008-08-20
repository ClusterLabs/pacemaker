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
#include <crm/ais_common.h>

#if SUPPORT_HEARTBEAT
#  include <heartbeat/hb_api.h>
#endif

extern gboolean crm_have_quorum;
extern GHashTable *crm_peer_cache;
extern unsigned long long crm_peer_seq;

extern void crm_peer_init(void);
extern void crm_peer_destroy(void);

extern gboolean crm_cluster_connect(
    char **our_uname, char **our_uuid, void *dispatch, void *destroy,
#if SUPPORT_HEARTBEAT
    ll_cluster_t **hb_conn
#else
    void **unused
#endif
    );

extern gboolean send_cluster_message(
    const char *node, enum crm_ais_msg_types service, xmlNode *data, gboolean ordered);

extern void destroy_crm_node(gpointer data);

extern crm_node_t *crm_get_peer(unsigned int id, const char *uname);

extern crm_node_t *crm_update_ais_node(xmlNode *member, long long seq);
extern void crm_update_peer_proc(
    const char *uname, uint32_t flag, const char *status);
extern crm_node_t *crm_update_peer(
    unsigned int id, uint64_t born, uint64_t seen, int32_t votes, uint32_t children,
    const char *uuid, const char *uname, const char *addr, const char *state);

extern gboolean crm_is_member_active(const crm_node_t *node);
extern guint crm_active_members(void);
extern guint reap_crm_membership(void);
extern guint crm_active_members(void);
extern guint crm_active_peers(uint32_t peer);
extern gboolean crm_calculate_quorum(void);

#if SUPPORT_HEARTBEAT
extern gboolean ccm_have_quorum(oc_ed_t event);
extern const char *ccm_event_name(oc_ed_t event);
extern crm_node_t *crm_update_ccm_node(
    const oc_ev_membership_t *oc, int offset, const char *state, uint64_t seq);
#endif

#if SUPPORT_AIS
extern int ais_fd_sync;
extern GFDSource *ais_source;
extern gboolean send_ais_text(
    int class, const char *data, gboolean local,
    const char *node, enum crm_ais_msg_types dest);
extern int32_t get_ais_nodeid(void);
#endif

extern void empty_uuid_cache(void);
extern const char *get_uuid(const char *uname);
extern const char *get_uname(const char *uuid);
extern void set_uuid(xmlNode *node, const char *attr, const char *uname);
extern void unget_uuid(const char *uname);

enum crm_ais_msg_types text2msg_type(const char *text);

#endif
