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
    /* @COMPAT: crm_join_nack_quiet can be replaced by
     * pcmk__node_status_t:user_data at a compatibility break
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

// Implementation of pcmk_cluster_t
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct crm_cluster_s {
    char *uuid;
    char *uname;
    uint32_t nodeid;

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_cluster_set_destroy_fn() to set this
    void (*destroy) (gpointer);

#  if SUPPORT_COROSYNC
    /* @TODO When we can break public API compatibility, make these members a
     * separate struct and use void *cluster_data here instead, to abstract the
     * cluster layer further.
     */
    struct cpg_name group;

    // NOTE: sbd (as of at least 1.5.2) uses this
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

/* @COMPAT Make this internal when we can break API backward compatibility. Also
 * evaluate whether we can drop this entirely. Since 2.0.0, we have sent only
 * messages with crm_class_cluster.
 */
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum crm_ais_msg_class {
    crm_class_cluster = 0,
};
//!@}

// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum crm_ais_msg_types {
    crm_msg_none     = 0,
    crm_msg_ais      = 1,   // Unused
    crm_msg_lrmd     = 2,
    crm_msg_cib      = 3,
    crm_msg_crmd     = 4,
    crm_msg_attrd    = 5,
    crm_msg_stonithd = 6,   // Unused
    crm_msg_te       = 7,   // Unused
    crm_msg_pe       = 8,   // Unused
    crm_msg_stonith_ng = 9,
};
//!@}

// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum crm_status_type {
    crm_status_uname,
    crm_status_nstate,
    crm_status_processes,
};
//!@}

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

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/cluster/compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
