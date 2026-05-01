/*
 * Copyright 2005-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ISO8601__H
#define PCMK__CRM_COMMON_ISO8601__H

#include <ctype.h>
#include <stdbool.h>  // bool
#include <stdint.h>   // uint32_t
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief ISO_8601 Date handling
 * \ingroup date
 */

/*
 * See https://en.wikipedia.org/wiki/ISO_8601
 */

/*!
 * \brief An opaque date and time object
 *
 * \note Negative years are treated inconsistently and should not be relied
 *       upon.
 * \deprecated Use \c crm_time_t instead of <tt>struct crm_time_s</tt>.
 */
typedef struct crm_time_s crm_time_t;

/* Creates a new date/time object conforming to ISO 8601, for example:
 *   Ordinal:   2010-01 12:00:00 +10:00
 *   Gregorian: 2010-01-01 12:00:00 +10:00
 *   ISO Week:  2010-W53-6 12:00:00 +10:00
 *
 * Notes:
 *   Only one of date, time is required
 *   If date or timezone is unspecified, they default to the current one
 *   Supplying NULL results in the current date/time
 *   Dashes may be omitted from dates
 *   Colons may be omitted from times and timezones
 *   A timezone of 'Z' denotes UTC time
 */
crm_time_t *crm_time_new(const char *string);
void crm_time_free(crm_time_t * dt);

/* Time in seconds since 1970-01-01 00:00:00Z */
long long crm_time_get_seconds_since_epoch(const crm_time_t *dt);

/* Returns a new time object */
crm_time_t *pcmk_copy_time(const crm_time_t *source);
crm_time_t *crm_time_add(const crm_time_t *dt, const crm_time_t *value);
crm_time_t *crm_time_subtract(const crm_time_t *dt, const crm_time_t *value);

/* All crm_time_add_... functions support negative values */
void crm_time_add_seconds(crm_time_t * dt, int value);
void crm_time_add_minutes(crm_time_t * dt, int value);
void crm_time_add_hours(crm_time_t * dt, int value);
void crm_time_add_days(crm_time_t * dt, int value);
void crm_time_add_weeks(crm_time_t * dt, int value);
void crm_time_add_months(crm_time_t * dt, int value);
void crm_time_add_years(crm_time_t * dt, int value);

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/iso8601_compat.h>
#endif

#endif
