/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES__H
#  define PCMK__CRM_COMMON_RESOURCES__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for resources
 * \ingroup core
 */

//! How to recover a resource that is incorrectly active on multiple nodes
enum rsc_recovery_type {
    pcmk_multiply_active_restart    = 0,    //!< Stop on all, start on desired
    pcmk_multiply_active_stop       = 1,    //!< Stop on all and leave stopped
    pcmk_multiply_active_block      = 2,    //!< Do nothing to resource

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_multiply_active_restart instead
    recovery_stop_start             = pcmk_multiply_active_restart,

    //! \deprecated Use pcmk_multiply_active_stop instead
    recovery_stop_only              = pcmk_multiply_active_stop,
#endif
    recovery_block                  = pcmk_multiply_active_block,
    recovery_stop_unexpected        = 3,
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES__H
