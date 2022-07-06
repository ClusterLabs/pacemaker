/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_OUTPUT__H
#  define PCMK__CRM_COMMON_OUTPUT__H

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
    pcmk_section_maint_mode    = 1 << 16,
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
    pcmk_show_brief         = 1 << 0,
    pcmk_show_clone_detail  = 1 << 1,
    pcmk_show_node_id       = 1 << 2,
    pcmk_show_implicit_rscs = 1 << 3,
    pcmk_show_timing        = 1 << 4,
    pcmk_show_inactive_rscs = 1 << 5,
    pcmk_show_rscs_by_node  = 1 << 6,
    pcmk_show_pending       = 1 << 7,
    pcmk_show_rsc_only      = 1 << 8,
    pcmk_show_failed_detail = 1 << 9,
    pcmk_show_feature_set   = 1 << 10,
} pcmk_show_opt_e;

#define pcmk_show_details   (pcmk_show_clone_detail     \
                             | pcmk_show_node_id        \
                             | pcmk_show_implicit_rscs  \
                             | pcmk_show_failed_detail  \
                             | pcmk_show_feature_set)

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_OUTPUT__H
