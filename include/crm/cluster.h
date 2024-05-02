/*
 * Copyright 2004-2024 the Pacemaker project contributors
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

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
extern gboolean crm_have_quorum;

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
extern GHashTable *crm_peer_cache;

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
extern GHashTable *crm_remote_peer_cache;

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
extern unsigned long long crm_peer_seq;

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
#define CRM_NODE_LOST      "lost"

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
#define CRM_NODE_MEMBER    "member"

// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
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
//!@}

// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum crm_node_flags {
    /* Node is not a cluster node and should not be considered for cluster
     * membership
     */
    crm_remote_node = (1U << 0),

    // Node's cache entry is dirty
    crm_node_dirty  = (1U << 1),
};
//!@}

typedef struct crm_peer_node_s {
    char *uname;                // Node name as known to cluster

    /* @COMPAT This is less than ideal since the value is not a valid XML ID
     * (for Corosync, it's the string equivalent of the node's numeric node ID,
     * but XML IDs can't start with a number) and the three elements should have
     * different IDs.
     *
     * Ideally, we would use something like node-NODEID, node_state-NODEID, and
     * transient_attributes-NODEID as the element IDs. Unfortunately changing it
     * would be impractical due to backward compatibility; older nodes in a
     * rolling upgrade will always write and expect the value in the old format.
     *
     * This is also named poorly, since the value is not a UUID, but at least
     * that can be changed at an API compatibility break.
     */
    /*! Value of the PCMK_XA_ID XML attribute to use with the node's
     * PCMK_XE_NODE, PCMK_XE_NODE_STATE, and PCMK_XE_TRANSIENT_ATTRIBUTES
     * XML elements in the CIB
     */
    char *uuid;

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

    time_t when_member;         // Since when node has been a cluster member
    time_t when_online;         // Since when peer has been online in CPG
} crm_node_t;

// Implementation of pcmk_cluster_t
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct crm_cluster_s {
    char *uuid;
    char *uname;
    uint32_t nodeid;

    //! \deprecated Call pcmk_cluster_set_destroy_fn() to set this
    void (*destroy) (gpointer);

#  if SUPPORT_COROSYNC
    /* @TODO When we can break public API compatibility, make these members a
     * separate struct and use void *cluster_data here instead, to abstract the
     * cluster layer further.
     */
    struct cpg_name group;

    /*!
     * \deprecated Call pcmk_cpg_set_deliver_fn() and pcmk_cpg_set_confchg_fn()
     *             to set these
     */
    cpg_callbacks_t cpg;

    cpg_handle_t cpg_handle;
#  endif

};
//!@}

//! Connection to a cluster layer
typedef struct crm_cluster_s pcmk_cluster_t;

int pcmk_cluster_connect(pcmk_cluster_t *cluster);
int pcmk_cluster_disconnect(pcmk_cluster_t *cluster);

pcmk_cluster_t *pcmk_cluster_new(void);
void pcmk_cluster_free(pcmk_cluster_t *cluster);

int pcmk_cluster_set_destroy_fn(pcmk_cluster_t *cluster, void (*fn)(gpointer));
#if SUPPORT_COROSYNC
int pcmk_cpg_set_deliver_fn(pcmk_cluster_t *cluster, cpg_deliver_fn_t fn);
int pcmk_cpg_set_confchg_fn(pcmk_cluster_t *cluster, cpg_confchg_fn_t fn);
#endif  // SUPPORT_COROSYNC

enum crm_ais_msg_class {
    crm_class_cluster = 0,
};

// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
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
//!@}

const char *crm_peer_uname(const char *uuid);

// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum crm_status_type {
    crm_status_uname,
    crm_status_nstate,
    crm_status_processes,
};
//!@}

void crm_set_status_callback(void (*dispatch) (enum crm_status_type, crm_node_t *, const void *));
void crm_set_autoreap(gboolean autoreap);

/*!
 * \enum pcmk_cluster_layer
 * \brief Types of cluster layer
 */
enum pcmk_cluster_layer {
    pcmk_cluster_layer_unknown  = 1,    //!< Unknown cluster layer
    pcmk_cluster_layer_invalid  = 2,    //!< Invalid cluster layer
    pcmk_cluster_layer_corosync = 32,   //!< Corosync Cluster Engine
};

enum pcmk_cluster_layer pcmk_get_cluster_layer(void);
const char *pcmk_cluster_layer_text(enum pcmk_cluster_layer layer);

const char *get_local_node_name(void);

/*
 * \brief Get log-friendly string equivalent of a join phase
 *
 * \param[in] phase  Join phase
 *
 * \return Log-friendly string equivalent of \p phase
 */
//! \deprecated Do not use (public access will be removed in a future release)
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
