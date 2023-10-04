/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H
#  define PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

// Options when getting resource fail counts
enum pcmk__fc_flags {
    pcmk__fc_default   = (1 << 0),
    pcmk__fc_effective = (1 << 1),  // Don't count expired failures
    pcmk__fc_fillers   = (1 << 2),  // If container, include filler failures
};

/*!
 * \internal
 * \enum pcmk__rsc_node
 * \brief Type of resource location lookup to perform
 */
enum pcmk__rsc_node {
    pcmk__rsc_node_assigned = 0,  //!< Where resource is assigned
    pcmk__rsc_node_current  = 1,  //!< Where resource is running

    // @COMPAT: Use in native_location() at a compatibility break
    pcmk__rsc_node_pending  = 2,  //!< Where resource is pending
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H
