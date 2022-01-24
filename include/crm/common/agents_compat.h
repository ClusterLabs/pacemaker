/*
 * Copyright 2017-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_AGENTS_COMPAT__H
#  define PCMK__CRM_COMMON_AGENTS_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker resource agent API
 * \ingroup core
 * \deprecated Do not include this header directly. The agent APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

#include <stdbool.h>

//! \deprecated Use pcmk_get_ra_caps() instead
bool crm_provider_required(const char *standard);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_AGENTS_COMPAT__H
