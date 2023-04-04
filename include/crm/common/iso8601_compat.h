/*
 * Copyright 2005-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ISO8601_COMPAT__H
#define PCMK__CRM_COMMON_ISO8601_COMPAT__H

#include <stdint.h>             // uint32_t

#include <crm/common/iso8601.h> // crm_time_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker ISO 8601 API
 * \ingroup core
 * \deprecated Do not include this header directly. The ISO 8601 APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use Pacemaker for general-purpose date and time
int crm_time_get_timezone(const crm_time_t *dt, uint32_t *h, uint32_t *m);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ISO8601_COMPAT__H
