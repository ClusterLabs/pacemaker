/*
 * Copyright 2017-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_BUNDLES_INTERNAL__H
#  define PCMK__CRM_COMMON_BUNDLES_INTERNAL__H

#include <crm/common/scheduler_types.h> // pcmk_resource_t, pcmk_node_t

#ifdef __cplusplus
extern "C" {
#endif

//! A single instance of a bundle
typedef struct {
    int offset;                 //!< 0-origin index of this instance in bundle
    char *ipaddr;               //!< IP address associated with this instance
    pcmk_node_t *node;          //!< Node created for this instance
    pcmk_resource_t *ip;        //!< IP address resource for ipaddr
    pcmk_resource_t *child;     //!< Instance of bundled resource
    pcmk_resource_t *container; //!< Container associated with this instance
    pcmk_resource_t *remote;    //!< Pacemaker Remote connection into container
} pcmk__bundle_replica_t;

/*!
 * \internal
 * \brief Check whether a resource is part of a bundle
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is part of a bundle, otherwise false
 */
static inline bool
pcmk__is_bundled(const pcmk_resource_t *rsc)
{
    if (rsc == NULL) {
        return false;
    }
    while (rsc->parent != NULL) {
        rsc = rsc->parent;
    }
    return rsc->variant == pcmk_rsc_variant_bundle;
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_BUNDLES_INTERNAL__H
