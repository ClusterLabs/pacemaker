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

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for nodes
 * \ingroup core
 */

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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NODES__H
