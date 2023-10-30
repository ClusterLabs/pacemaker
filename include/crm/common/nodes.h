/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NODES__H
#  define PCMK__CRM_COMMON_NODES__H

#include <glib.h>                       // gboolean, GList, GHashTable

#include <crm/common/scheduler_types.h> // pcmk_resource_t, pcmk_scheduler_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for nodes
 * \ingroup core
 */

// Special node attributes

#define PCMK_NODE_ATTR_TERMINATE    "terminate"


//! Possible node types
enum node_type {
    pcmk_node_variant_cluster  = 1,     //!< Cluster layer node
    pcmk_node_variant_remote   = 2,     //!< Pacemaker Remote node

    node_ping   = 0,      //!< \deprecated Do not use
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_node_variant_cluster instead
    node_member = pcmk_node_variant_cluster,

    //! \deprecated Use pcmk_node_variant_remote instead
    node_remote = pcmk_node_variant_remote,
#endif
};

//! When to probe a resource on a node (as specified in location constraints)
enum pe_discover_e {
    pcmk_probe_always       = 0,    //! Always probe resource on node
    pcmk_probe_never        = 1,    //! Never probe resource on node
    pcmk_probe_exclusive    = 2,    //! Probe only on designated nodes

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_probe_always instead
    pe_discover_always      = pcmk_probe_always,

    //! \deprecated Use pcmk_probe_never instead
    pe_discover_never       = pcmk_probe_never,

    //! \deprecated Use pcmk_probe_exclusive instead
    pe_discover_exclusive   = pcmk_probe_exclusive,
#endif
};

//! Basic node information (all node objects for the same node share this)
struct pe_node_shared_s {
    const char *id;             //!< Node ID at the cluster layer
    const char *uname;          //!< Node name in cluster
    enum node_type type;        //!< Node variant

    // @TODO Convert these into a flag group
    gboolean online;            //!< Whether online
    gboolean standby;           //!< Whether in standby mode
    gboolean standby_onfail;    //!< Whether in standby mode due to on-fail
    gboolean pending;           //!< Whether controller membership is pending
    gboolean unclean;           //!< Whether node requires fencing
    gboolean unseen;            //!< Whether node has never joined cluster
    gboolean shutdown;          //!< Whether shutting down
    gboolean expected_up;       //!< Whether expected join state is member
    gboolean is_dc;             //!< Whether node is cluster's DC
    gboolean maintenance;       //!< Whether in maintenance mode
    gboolean rsc_discovery_enabled; //!< Whether probes are allowed on node

    /*!
     * Whether this is a guest node whose guest resource must be recovered or a
     * remote node that must be fenced
     */
    gboolean remote_requires_reset;

    /*!
     * Whether this is a Pacemaker Remote node that was fenced since it was last
     * connected by the cluster
     */
    gboolean remote_was_fenced;

    /*!
     * Whether this is a Pacemaker Remote node previously marked in its
     * node state as being in maintenance mode
     */
    gboolean remote_maintenance;

    gboolean unpacked;              //!< Whether node history has been unpacked

    /*!
     * Number of resources active on this node (valid after CIB status section
     * has been unpacked, as long as pcmk_sched_no_counts was not set)
     */
    int num_resources;

    //! Remote connection resource for node, if it is a Pacemaker Remote node
    pcmk_resource_t *remote_rsc;

    GList *running_rsc;             //!< List of resources active on node
    GList *allocated_rsc;           //!< List of resources assigned to node
    GHashTable *attrs;              //!< Node attributes
    GHashTable *utilization;        //!< Node utilization attributes
    GHashTable *digest_cache;       //!< Cache of calculated resource digests

    /*!
     * Sum of priorities of all resources active on node and on any guest nodes
     * connected to this node, with +1 for promoted instances (used to compare
     * nodes for priority-fencing-delay)
     */
    int priority;

    pcmk_scheduler_t *data_set;     //!< Cluster that node is part of
};

//! Implementation of pcmk_node_t
struct pe_node_s {
    int weight;         //!< Node score for a given resource
    gboolean fixed;     //!< \deprecated Do not use
    int count;          //!< Counter reused by assignment and promotion code
    struct pe_node_shared_s *details;   //!< Basic node information

    // @COMPAT This should be enum pe_discover_e
    int rsc_discover_mode;              //!< Probe mode (enum pe_discover_e)
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NODES__H
