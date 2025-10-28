/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H
#define PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H

#include <stdint.h>       // UINT32_C

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Options when getting resource fail counts
 */
enum pcmk__fc_flags {
    pcmk__fc_default   = (UINT32_C(1) << 0),

    //! Don't count expired failures
    pcmk__fc_effective = (UINT32_C(1) << 1),

    //! If resource is a launcher, include failures of launched resources
    pcmk__fc_launched  = (UINT32_C(1) << 2),
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H
