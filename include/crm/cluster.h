/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMMON_CLUSTER__H
#  define CRM_COMMON_CLUSTER__H

#  include <crm/common/xml.h>
#  include <crm/common/util.h>

#  if SUPPORT_HEARTBEAT
#    include <heartbeat/hb_api.h>
#    include <ocf/oc_event.h>
#  endif

#  if SUPPORT_COROSYNC
#    include <corosync/cpg.h>
#  endif

extern gboolean crm_have_quorum;
extern GHashTable *crm_peer_cache;
extern unsigned long long crm_peer_seq;

#  ifndef CRM_SERVICE
#    define CRM_SERVICE PCMK_SERVICE_ID
#  endif

/* *INDENT-OFF* */
#define CRM_NODE_LOST      "lost"
#define CRM_NODE_MEMBER    "member"
#define CRM_NODE_ACTIVE    CRM_NODE_MEMBER
#define CRM_NODE_EVICTED   "evicted"

enum crm_join_phase
{
    crm_join_nack       = -1,
    crm_join_none       = 0,
    crm_join_welcomed   = 1,
    crm_join_integrated = 2,
    crm_join_finalized  = 3,
    crm_join_confirmed  = 4,
};

/* *INDENT-ON* */

typedef struct crm_peer_node_s {
    uint32_t id;                /* Only used by corosync derivatives */
    uint64_t born;              /* Only used by heartbeat and the legacy plugin */
    uint64_t last_seen;

    int32_t votes;              /* Only used by the legacy plugin */
    uint32_t processes;
    enum crm_join_phase join;

    char *uname;
    char *uuid;
    char *state;
    char *expected;

    char *addr;                 /* Only used by the legacy plugin */
    char *version;              /* Unused */
} crm_node_t;

void crm_peer_init(void);
void crm_peer_destroy(void);

typedef struct crm_cluster_s {
    char *uuid;
    char *uname;
    uint32_t nodeid;

    void (*destroy) (gpointer);

#  if SUPPORT_HEARTBEAT
    ll_cluster_t *hb_conn;
    void (*hb_dispatch) (HA_Message * msg, void *private);
#  endif

#  if SUPPORT_COROSYNC
    struct cpg_name group;
    cpg_callbacks_t cpg;
    cpg_handle_t cpg_handle;
#  endif

} crm_cluster_t;

gboolean crm_cluster_connect(crm_cluster_t * cluster);
void crm_cluster_disconnect(crm_cluster_t * cluster);

/* *INDENT-OFF* */
enum crm_ais_msg_class {
    crm_class_cluster = 0,
    crm_class_members = 1,
    crm_class_notify  = 2,
    crm_class_nodeid  = 3,
    crm_class_rmpeer  = 4,
    crm_class_quorum  = 5,
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
/* *INDENT-ON* */

gboolean send_cluster_message(crm_node_t * node, enum crm_ais_msg_types service,
                              xmlNode * data, gboolean ordered);

crm_node_t *crm_get_peer(unsigned int id, const char *uname);

guint crm_active_peers(void);
gboolean crm_is_peer_active(const crm_node_t * node);
guint reap_crm_member(uint32_t id, const char *name);
int crm_terminate_member(int nodeid, const char *uname, void *unused);
int crm_terminate_member_no_mainloop(int nodeid, const char *uname, int *connection);

#  if SUPPORT_HEARTBEAT
gboolean crm_is_heartbeat_peer_active(const crm_node_t * node);
#  endif

#  if SUPPORT_COROSYNC
extern int ais_fd_sync;
uint32_t get_local_nodeid(cpg_handle_t handle);

gboolean cluster_connect_cpg(crm_cluster_t *cluster);
void cluster_disconnect_cpg(crm_cluster_t * cluster);

void pcmk_cpg_membership(cpg_handle_t handle,
                         const struct cpg_name *groupName,
                         const struct cpg_address *member_list, size_t member_list_entries,
                         const struct cpg_address *left_list, size_t left_list_entries,
                         const struct cpg_address *joined_list, size_t joined_list_entries);
gboolean crm_is_corosync_peer_active(const crm_node_t * node);
gboolean send_cluster_text(int class, const char *data, gboolean local,
                       crm_node_t * node, enum crm_ais_msg_types dest);
#  endif

const char *crm_peer_uuid(crm_node_t *node);
const char *crm_peer_uname(const char *uuid);
void set_uuid(xmlNode *xml, const char *attr, crm_node_t *node);

enum crm_status_type {
    crm_status_uname,
    crm_status_nstate,
    crm_status_processes,
};

enum crm_ais_msg_types text2msg_type(const char *text);
void crm_set_status_callback(void (*dispatch) (enum crm_status_type, crm_node_t *, const void *));

/* *INDENT-OFF* */
enum cluster_type_e
{
    pcmk_cluster_unknown     = 0x0001,
    pcmk_cluster_invalid     = 0x0002,
    pcmk_cluster_heartbeat   = 0x0004,
    pcmk_cluster_classic_ais = 0x0010,
    pcmk_cluster_corosync    = 0x0020,
    pcmk_cluster_cman        = 0x0040,
};
/* *INDENT-ON* */

enum cluster_type_e get_cluster_type(void);
const char *name_for_cluster_type(enum cluster_type_e type);

gboolean is_corosync_cluster(void);
gboolean is_cman_cluster(void);
gboolean is_openais_cluster(void);
gboolean is_classic_ais_cluster(void);
gboolean is_heartbeat_cluster(void);

const char *get_local_node_name(void);
char *get_node_name(uint32_t nodeid);

char *pcmk_message_common_cs(cpg_handle_t handle, uint32_t nodeid, uint32_t pid, void *msg,
                        uint32_t *kind, const char **from);

#endif
