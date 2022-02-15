/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_COMMON_COMPAT__H
#  define PCMK__CRM_PENGINE_COMMON_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker scheduler utilities
 * \ingroup pengine
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use RSC_ROLE_UNPROMOTED_LEGACY_S instead
#  define RSC_ROLE_SLAVE_S   RSC_ROLE_UNPROMOTED_LEGACY_S

//! \deprecated Use RSC_ROLE_PROMOTED_LEGACY_S instead
#  define RSC_ROLE_MASTER_S  RSC_ROLE_PROMOTED_LEGACY_S


#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_COMMON_COMPAT__H
