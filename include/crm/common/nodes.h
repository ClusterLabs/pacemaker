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

    node_ping   = 0,      //!< \deprecated Do not use
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_node_variant_cluster instead
    node_member = pcmk_node_variant_cluster,
#endif
    node_remote
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NODES__H
