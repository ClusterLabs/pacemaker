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

#if SUPPORT_COROSYNC
#include <corosync/cpg.h>       // cpg_callbacks_t
#endif

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

//! \internal Do not use
typedef struct pcmk__cluster_private pcmk__cluster_private_t;

// Implementation of pcmk_cluster_t
// @COMPAT Make contents internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pcmk__cluster {
    /* @COMPAT Once all members are moved to pcmk__cluster_private_t, we can
     * make that the pcmk_cluster_t implementation and drop this struct
     * altogether, leaving pcmk_cluster_t as an opaque public type.
     */
    //! \internal Do not use
    pcmk__cluster_private_t *priv;

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_cluster_set_destroy_fn() to set this
    void (*destroy) (gpointer);

#if SUPPORT_COROSYNC
    // NOTE: sbd (as of at least 1.5.2) uses this
    /*!
     * \deprecated Call pcmk_cpg_set_deliver_fn() and pcmk_cpg_set_confchg_fn()
     *             to set these
     */
    cpg_callbacks_t cpg;
#endif  // SUPPORT_COROSYNC
};
//!@}

//! Connection to a cluster layer
typedef struct pcmk__cluster pcmk_cluster_t;

int pcmk_cluster_connect(pcmk_cluster_t *cluster);
int pcmk_cluster_disconnect(pcmk_cluster_t *cluster);

pcmk_cluster_t *pcmk_cluster_new(void);
void pcmk_cluster_free(pcmk_cluster_t *cluster);

int pcmk_cluster_set_destroy_fn(pcmk_cluster_t *cluster, void (*fn)(gpointer));
#if SUPPORT_COROSYNC
int pcmk_cpg_set_deliver_fn(pcmk_cluster_t *cluster, cpg_deliver_fn_t fn);
int pcmk_cpg_set_confchg_fn(pcmk_cluster_t *cluster, cpg_confchg_fn_t fn);
#endif  // SUPPORT_COROSYNC

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

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/cluster/compat.h>
#endif

#endif
