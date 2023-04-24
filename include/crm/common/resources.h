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

//! Resource variants supported by Pacemaker
enum pe_obj_types {
    // Order matters: some code compares greater or lesser than
    pcmk_rsc_variant_unknown    = -1,   //!< Unknown resource variant
    pcmk_rsc_variant_primitive  = 0,    //!< Primitive resource
    pcmk_rsc_variant_group      = 1,    //!< Group resource
    pcmk_rsc_variant_clone      = 2,    //!< Clone resource
    pcmk_rsc_variant_bundle     = 3,    //!< Bundle resource

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_rsc_variant_unknown instead
    pe_unknown      = pcmk_rsc_variant_unknown,

    //! \deprecated Use pcmk_rsc_variant_primitive instead
    pe_native       = pcmk_rsc_variant_primitive,

    //! \deprecated Use pcmk_rsc_variant_group instead
    pe_group        = pcmk_rsc_variant_group,

    //! \deprecated Use pcmk_rsc_variant_clone instead
    pe_clone        = pcmk_rsc_variant_clone,

    //! \deprecated Use pcmk_rsc_variant_bundle instead
    pe_container    = pcmk_rsc_variant_bundle,
#endif
};

//! What resource needs before it can be recovered from a failed node
enum rsc_start_requirement {
    pcmk_requires_nothing   = 0,    //!< Resource can be recovered immediately
    pcmk_requires_quorum    = 1,    //!< Resource can be recovered if quorate
    pcmk_requires_fencing   = 2,    //!< Resource can be recovered after fencing

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_requires_nothing instead
    rsc_req_nothing         = pcmk_requires_nothing,

    //! \deprecated Use pcmk_requires_quorum instead
    rsc_req_quorum          = pcmk_requires_quorum,

    //! \deprecated Use pcmk_requires_fencing instead
    rsc_req_stonith         = pcmk_requires_fencing,
#endif
};

//! How to recover a resource that is incorrectly active on multiple nodes
enum rsc_recovery_type {
    pcmk_multiply_active_restart    = 0,    //!< Stop on all, start on desired
    pcmk_multiply_active_stop       = 1,    //!< Stop on all and leave stopped
    pcmk_multiply_active_block      = 2,    //!< Do nothing to resource
    pcmk_multiply_active_unexpected = 3,    //!< Stop unexpected instances

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_multiply_active_restart instead
    recovery_stop_start             = pcmk_multiply_active_restart,

    //! \deprecated Use pcmk_multiply_active_stop instead
    recovery_stop_only              = pcmk_multiply_active_stop,

    //! \deprecated Use pcmk_multiply_active_block instead
    recovery_block                  = pcmk_multiply_active_block,

    //! \deprecated Use pcmk_multiply_active_unexpected instead
    recovery_stop_unexpected        = pcmk_multiply_active_unexpected,
#endif
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES__H
