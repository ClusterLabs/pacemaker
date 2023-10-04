/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_GROUP_INTERNAL__H
#  define PCMK__CRM_COMMON_GROUP_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

// Group resource flags (used in variant data)
enum pcmk__group_flags {
    pcmk__group_ordered     = (1 << 0), // Members start sequentially
    pcmk__group_colocated   = (1 << 1), // Members must be on same node
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_GROUP_INTERNAL__H
