/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_STRINGS__H
#define PCMK__CRM_COMMON_STRINGS__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief API for strings
 * \ingroup core
 */

int pcmk_parse_interval_spec(const char *input, unsigned int *result_ms);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/strings_compat.h>
#endif

#endif // PCMK__CRM_COMMON_STRINGS__H
