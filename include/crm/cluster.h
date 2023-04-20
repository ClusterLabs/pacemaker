/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CLUSTER__H
#  define PCMK__CRM_CLUSTER__H

#  include <stdint.h>           // uint32_t, uint64_t
#  include <glib.h>             // gboolean, GHashTable
#  include <libxml/tree.h>      // xmlNode
#  include <crm/common/xml.h>
#  include <crm/common/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#  if SUPPORT_COROSYNC
#    include <corosync/cpg.h>
#  endif

extern gboolean crm_have_quorum;
extern GHashTable *crm_peer_cache;
extern GHashTable *crm_remote_peer_cache;
extern unsigned long long crm_peer_seq;

#define CRM_NODE_LOST      "lost"
#define CRM_NODE_MEMBER    "member"

enum crm_join_phase {
    /* @COMPAT: crm_join_nack_quiet can be replaced by crm_node_t:user_data
     *          at a compatibility break.
     */
    //! Not allowed to join, but don't send a nack message
    crm_join_nack_quiet = -2,

    crm_join_nack       = -1,
    crm_join_none       = 0,
    crm_join_welcomed   = 1,
    crm_join_integrated = 2,
    crm_join_finalized  = 3,
    crm_join_confirmed  = 4,
};

enum crm_node_flags {
    /* node is not a cluster node and should not be considered for cluster membership */
    crm_remote_node          = 0x0001,

    /* node's cache entry is dirty */
    crm_node_dirty           = 0x0010,
};

typedef struct crm_peer_node_s {
    char *uname;                // Node name as known to cluster
    char *uuid;                 // Node UUID to ensure uniqueness
    char *state;                // @TODO change to enum
    uint64_t flags;             // Bitmask of crm_node_flags
    uint64_t last_seen;         // Only needed by cluster nodes
    uint32_t processes;         // @TODO most not needed, merge into flags

    /* @TODO When we can break public API compatibility, we can make the rest of
     * these members separate structs and use void *cluster_data and
     * void *user_data here instead, to abstract the cluster layer further.
     */

    // Currently only needed by corosync stack
    uint32_t id;                // Node ID
    time_t when_lost;           // When CPG membership was last lost

    // Only used by controller
    enum crm_join_phase join;
    char *expected;

    time_t peer_lost;
    char *conn_host;
} crm_node_t;

void crm_peer_init(void);
void crm_peer_destroy(void);

typedef struct crm_cluster_s {
    char *uuid;
    char *uname;
    uint32_t nodeid;

    void (*destroy) (gpointer);

#  if SUPPORT_COROSYNC
    /* @TODO When we can break public API compatibility, make these members a
     * separate struct and use void *cluster_data here instead, to abstract the
     * cluster layer further.
     */
    struct cpg_name group;
    cpg_callbacks_t cpg;
    cpg_handle_t cpg_handle;
#  endif

} crm_cluster_t;

gboolean crm_cluster_connect(crm_cluster_t *cluster);
void crm_cluster_disconnect(crm_cluster_t *cluster);

crm_cluster_t *pcmk_cluster_new(void);
void pcmk_cluster_free(crm_cluster_t *cluster);

enum crm_ais_msg_class {
    crm_class_cluster = 0,
};

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

/* used with crm_get_peer_full */
enum crm_get_peer_flags {
    CRM_GET_PEER_CLUSTER   = 0x0001,
    CRM_GET_PEER_REMOTE    = 0x0002,
    CRM_GET_PEER_ANY       = CRM_GET_PEER_CLUSTER|CRM_GET_PEER_REMOTE,
};

gboolean send_cluster_message(const crm_node_t *node,
                              enum crm_ais_msg_types service, xmlNode *data,
                              gboolean ordered);

int crm_remote_peer_cache_size(void);

/* Initialize and refresh the remote peer cache from a cib config */
void crm_remote_peer_cache_refresh(xmlNode *cib);
crm_node_t *crm_remote_peer_get(const char *node_name);
void crm_remote_peer_cache_remove(const char *node_name);

/* allows filtering of remote and cluster nodes using crm_get_peer_flags */
crm_node_t *crm_get_peer_full(unsigned int id, const char *uname, int flags);

/* only searches cluster nodes */
crm_node_t *crm_get_peer(unsigned int id, const char *uname);

guint crm_active_peers(void);
gboolean crm_is_peer_active(const crm_node_t * node);
guint reap_crm_member(uint32_t id, const char *name);

#  if SUPPORT_COROSYNC
uint32_t get_local_nodeid(cpg_handle_t handle);

gboolean cluster_connect_cpg(crm_cluster_t *cluster);
void cluster_disconnect_cpg(crm_cluster_t * cluster);

void pcmk_cpg_membership(cpg_handle_t handle,
                         const struct cpg_name *groupName,
                         const struct cpg_address *member_list, size_t member_list_entries,
                         const struct cpg_address *left_list, size_t left_list_entries,
                         const struct cpg_address *joined_list, size_t joined_list_entries);
gboolean crm_is_corosync_peer_active(const crm_node_t * node);
gboolean send_cluster_text(enum crm_ais_msg_class msg_class, const char *data,
                           gboolean local, const crm_node_t *node,
                           enum crm_ais_msg_types dest);
char *pcmk_message_common_cs(cpg_handle_t handle, uint32_t nodeid, uint32_t pid, void *msg,
                        uint32_t *kind, const char **from);
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
void crm_set_autoreap(gboolean autoreap);

enum cluster_type_e {
    pcmk_cluster_unknown     = 0x0001,
    pcmk_cluster_invalid     = 0x0002,
    // 0x0004 was heartbeat
    // 0x0010 was corosync 1 with plugin
    pcmk_cluster_corosync    = 0x0020,
    // 0x0040 was corosync 1 with CMAN
};

enum cluster_type_e get_cluster_type(void);
const char *name_for_cluster_type(enum cluster_type_e type);

gboolean is_corosync_cluster(void);

const char *get_local_node_name(void);
char *get_node_name(uint32_t nodeid);

/*!
 * \brief Get log-friendly string equivalent of a join phase
 *
 * \param[in] phase  Join phase
 *
 * \return Log-friendly string equivalent of \p phase
 */
static inline const char *
crm_join_phase_str(enum crm_join_phase phase)
{
    switch (phase) {
        case crm_join_nack_quiet:   return "nack_quiet";
        case crm_join_nack:         return "nack";
        case crm_join_none:         return "none";
        case crm_join_welcomed:     return "welcomed";
        case crm_join_integrated:   return "integrated";
        case crm_join_finalized:    return "finalized";
        case crm_join_confirmed:    return "confirmed";
        default:                    return "invalid";
    }
}

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/cluster/compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
