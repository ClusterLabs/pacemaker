/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEDULER_TYPES__H
#  define PCMK__CRM_COMMON_SCHEDULER_TYPES__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Type aliases needed to define scheduler objects
 * \ingroup core
 */

//! Node object (including information that may vary depending on resource)
typedef struct pe_node_s pcmk_node_t;

//! Resource object
typedef struct pe_resource_s pcmk_resource_t;

//! Action object
typedef struct pe_action_s pcmk_action_t;

//! Scheduler object
typedef struct pe_working_set_s pcmk_scheduler_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEDULER_TYPES__H
