/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ROLES__H
#  define PCMK__CRM_COMMON_ROLES__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for resource roles
 * \ingroup core
 */

/*!
 * Possible roles that a resource can be in
 * (order matters; values can be compared with less than and greater than)
 */
enum rsc_role_e {
    pcmk_role_unknown       = 0, //!< Resource role is unknown
    pcmk_role_stopped       = 1, //!< Stopped
    pcmk_role_started       = 2, //!< Started
    pcmk_role_unpromoted    = 3, //!< Unpromoted

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_role_unknown instead
    RSC_ROLE_UNKNOWN        = pcmk_role_unknown,

    //! \deprecated Use pcmk_role_stopped instead
    RSC_ROLE_STOPPED        = pcmk_role_stopped,

    //! \deprecated Use pcmk_role_started instead
    RSC_ROLE_STARTED        = pcmk_role_started,

    //! \deprecated Use pcmk_role_unpromoted instead
    RSC_ROLE_UNPROMOTED         = pcmk_role_unpromoted,

    //! \deprecated Use pcmk_role_unpromoted instead
    RSC_ROLE_SLAVE              = pcmk_role_unpromoted,
#endif
    RSC_ROLE_PROMOTED   = 4,

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use RSC_ROLE_PROMOTED instead
    RSC_ROLE_MASTER     = RSC_ROLE_PROMOTED,
#endif
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ROLES__H
