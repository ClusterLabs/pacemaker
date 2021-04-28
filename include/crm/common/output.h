/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__COMMON_OUTPUT__H
#  define PCMK__COMMON_OUTPUT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Control output from tools
 * \ingroup core
 */

/*!
 * \brief Control which sections are output
 */
typedef enum {
    pcmk_section_stack         = 1 << 0,
    pcmk_section_dc            = 1 << 1,
    pcmk_section_times         = 1 << 2,
    pcmk_section_counts        = 1 << 3,
    pcmk_section_options       = 1 << 4,
    pcmk_section_nodes         = 1 << 5,
    pcmk_section_resources     = 1 << 6,
    pcmk_section_attributes    = 1 << 7,
    pcmk_section_failcounts    = 1 << 8,
    pcmk_section_operations    = 1 << 9,
    pcmk_section_fence_failed  = 1 << 10,
    pcmk_section_fence_pending = 1 << 11,
    pcmk_section_fence_worked  = 1 << 12,
    pcmk_section_tickets       = 1 << 13,
    pcmk_section_bans          = 1 << 14,
    pcmk_section_failures      = 1 << 15,
} pcmk_section_e;

#define pcmk_section_fencing_all    (pcmk_section_fence_failed | pcmk_section_fence_pending | pcmk_section_fence_worked)
#define pcmk_section_summary        (pcmk_section_stack | pcmk_section_dc | pcmk_section_times | pcmk_section_counts)
#define pcmk_section_all            (pcmk_section_summary | pcmk_section_options | pcmk_section_nodes | \
                                     pcmk_section_resources | pcmk_section_attributes | pcmk_section_failcounts | \
                                     pcmk_section_operations | pcmk_section_fencing_all | pcmk_section_tickets | \
                                     pcmk_section_bans | pcmk_section_failures)

#ifdef __cplusplus
}
#endif

#endif // PCMK__COMMON_OUTPUT__H
