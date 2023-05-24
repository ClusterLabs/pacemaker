/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_COMMON_COMPAT__H
#  define PCMK__CRM_PENGINE_COMMON_COMPAT__H

#include <crm/common/scheduler.h>

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

//! \deprecated Use (pcmk_role_promoted + 1) instead
#define RSC_ROLE_MAX    (pcmk_role_promoted + 1)

//! \deprecated Use pcmk_role_text(pcmk_role_unknown) instead
#define RSC_ROLE_UNKNOWN_S      pcmk_role_text(pcmk_role_unknown)

//! \deprecated Use pcmk_role_text(pcmk_role_stopped) instead
#define RSC_ROLE_STOPPED_S      pcmk_role_text(pcmk_role_stopped)

//! \deprecated Use pcmk_role_text(pcmk_role_started) instead
#define RSC_ROLE_STARTED_S      pcmk_role_text(pcmk_role_started)

//! \deprecated Use pcmk_role_text(pcmk_role_unpromoted) instead
#define RSC_ROLE_UNPROMOTED_S   pcmk_role_text(pcmk_role_unpromoted)

//! \deprecated Use pcmk_role_text(pcmk_role_promoted) instead
#define RSC_ROLE_PROMOTED_S     pcmk_role_text(pcmk_role_promoted)

//! \deprecated Do not use
#define RSC_ROLE_UNPROMOTED_LEGACY_S    "Slave"

//! \deprecated Do not use
#define RSC_ROLE_SLAVE_S                RSC_ROLE_UNPROMOTED_LEGACY_S

//! \deprecated Do not use
#define RSC_ROLE_PROMOTED_LEGACY_S      "Master"

//! \deprecated Do not use
#define RSC_ROLE_MASTER_S               RSC_ROLE_PROMOTED_LEGACY_S

//! \deprecated Use pcmk_role_text() instead
const char *role2text(enum rsc_role_e role);

//! \deprecated Use pcmk_multiply_active_text() instead
static inline const char *
recovery2text(enum rsc_recovery_type type)
{
    return pcmk_multiply_active_text(type);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_COMMON_COMPAT__H
