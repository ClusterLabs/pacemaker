/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_CLONE_INTERNAL__H
#  define PCMK__CRM_COMMON_CLONE_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

// Clone resource flags (used in variant data)
enum pcmk__clone_flags {
    // Whether instances should be started sequentially
    pcmk__clone_ordered                 = (1 << 0),

    // Whether promotion scores have been added
    pcmk__clone_promotion_added         = (1 << 1),

    // Whether promotion constraints have been added
    pcmk__clone_promotion_constrained   = (1 << 2),
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_CLONE_INTERNAL__H
