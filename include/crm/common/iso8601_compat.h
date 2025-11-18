/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ISO8601_COMPAT__H
#define PCMK__CRM_COMMON_ISO8601_COMPAT__H

#include <stdbool.h>
#include <stdint.h>             // uint32_t

#include <crm/common/iso8601.h> // crm_time_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker time API
 * \ingroup core
 * \deprecated Do not include this header directly. The time APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
bool crm_time_leapyear(int year);

//! \deprecated Do not use
int crm_time_days_in_month(int month, int year);

//! \deprecated Do not use
int crm_time_get_timezone(const crm_time_t *dt, uint32_t *h, uint32_t *m);

//! \deprecated Do not use
int crm_time_weeks_in_year(int year);

//! \deprecated Do not use
int crm_time_january1_weekday(int year);

//! \deprecated Do not use
void crm_time_set(crm_time_t *target, const crm_time_t *source);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ISO8601_COMPAT__H
