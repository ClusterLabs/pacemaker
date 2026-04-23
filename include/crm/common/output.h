/*
 * Copyright 2021-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_OUTPUT__H
#define PCMK__CRM_COMMON_OUTPUT__H

#include <stdint.h>                     // UINT32_C

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
    pcmk_section_stack         = UINT32_C(1) << 0,
    pcmk_section_dc            = UINT32_C(1) << 1,
    pcmk_section_times         = UINT32_C(1) << 2,
    pcmk_section_counts        = UINT32_C(1) << 3,
    pcmk_section_options       = UINT32_C(1) << 4,
    pcmk_section_nodes         = UINT32_C(1) << 5,
    pcmk_section_resources     = UINT32_C(1) << 6,
    pcmk_section_attributes    = UINT32_C(1) << 7,
    pcmk_section_failcounts    = UINT32_C(1) << 8,
    pcmk_section_operations    = UINT32_C(1) << 9,
    pcmk_section_fence_failed  = UINT32_C(1) << 10,
    pcmk_section_fence_pending = UINT32_C(1) << 11,
    pcmk_section_fence_worked  = UINT32_C(1) << 12,
    pcmk_section_tickets       = UINT32_C(1) << 13,
    pcmk_section_bans          = UINT32_C(1) << 14,
    pcmk_section_failures      = UINT32_C(1) << 15,
    pcmk_section_maint_mode    = UINT32_C(1) << 16,
} pcmk_section_e;

#define pcmk_section_fencing_all    (pcmk_section_fence_failed | pcmk_section_fence_pending | pcmk_section_fence_worked)
#define pcmk_section_summary        (pcmk_section_stack | pcmk_section_dc | pcmk_section_times | \
                                     pcmk_section_counts | pcmk_section_maint_mode)
#define pcmk_section_all            (pcmk_section_summary | pcmk_section_options | pcmk_section_nodes | \
                                     pcmk_section_resources | pcmk_section_attributes | pcmk_section_failcounts | \
                                     pcmk_section_operations | pcmk_section_fencing_all | pcmk_section_tickets | \
                                     pcmk_section_bans | pcmk_section_failures | pcmk_section_maint_mode)

/*!
 * \brief Further modify the output of sections
 */
typedef enum {
    pcmk_show_brief         = UINT32_C(1) << 0,
    pcmk_show_clone_detail  = UINT32_C(1) << 1,
    pcmk_show_node_id       = UINT32_C(1) << 2,
    pcmk_show_implicit_rscs = UINT32_C(1) << 3,
    pcmk_show_timing        = UINT32_C(1) << 4,
    pcmk_show_inactive_rscs = UINT32_C(1) << 5,
    pcmk_show_rscs_by_node  = UINT32_C(1) << 6,
    pcmk_show_pending       = UINT32_C(1) << 7,
    pcmk_show_rsc_only      = UINT32_C(1) << 8,
    pcmk_show_failed_detail = UINT32_C(1) << 9,
    pcmk_show_feature_set   = UINT32_C(1) << 10,
    pcmk_show_description   = UINT32_C(1) << 11,
} pcmk_show_opt_e;

#define pcmk_show_details   ((pcmk_show_clone_detail)     \
                             | (pcmk_show_node_id)        \
                             | (pcmk_show_implicit_rscs)  \
                             | (pcmk_show_failed_detail)  \
                             | (pcmk_show_feature_set)    \
                             | (pcmk_show_description))

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_OUTPUT__H
