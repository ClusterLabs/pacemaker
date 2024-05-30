/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CLUSTER_COMPAT__H
#define PCMK__CRM_CLUSTER_COMPAT__H

#include <crm/cluster.h>    // pcmk_cluster_t, enum pcmk_cluster_layer

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker cluster API
 * \ingroup cluster
 * \deprecated Do not include this header directly. The cluster APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_cluster_t instead
typedef pcmk_cluster_t crm_cluster_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_cluster_connect() instead
gboolean crm_cluster_connect(pcmk_cluster_t *cluster);

// NOTE: sbd (as of at least 1.5.2) uses this enum
//!@{
//! \deprecated Use <tt>enum pcmk_cluster_layer</tt> instead
enum cluster_type_e {
    // NOTE: sbd (as of at least 1.5.2) uses this value
    pcmk_cluster_unknown    = pcmk_cluster_layer_unknown,

    pcmk_cluster_invalid    = pcmk_cluster_layer_invalid,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    pcmk_cluster_corosync   = pcmk_cluster_layer_corosync,
};
//!@}

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_cluster_layer_text() instead
const char *name_for_cluster_type(enum cluster_type_e type);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use \c pcmk_get_cluster_layer() instead
enum cluster_type_e get_cluster_type(void);

#ifdef __cplusplus
}
#endif

#endif // PCMK_CLUSTER_COMPAT__H
