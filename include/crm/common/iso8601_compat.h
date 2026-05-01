/*
 * Copyright 2004-2026 the Pacemaker project contributors
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
#include <time.h>               // time_t

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
#define crm_time_log_date 0x001

//! \deprecated Do not use
#define crm_time_log_timeofday 0x002

//! \deprecated Do not use
#define crm_time_log_with_timezone 0x004

//! \deprecated Do not use
typedef struct crm_time_period_s {
    crm_time_t *start;
    crm_time_t *end;
    crm_time_t *diff;
} crm_time_period_t;

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

//! \deprecated Do not use
bool crm_time_check(const crm_time_t *dt);

//! \deprecated Do not use
void crm_time_set_timet(crm_time_t *target, const time_t *source_sec);

//! \deprecated Do not use
int crm_time_get_isoweek(const crm_time_t *dt, uint32_t *y, uint32_t *w,
                         uint32_t *d);

//! \deprecated Do not use
#define crm_time_log(level, prefix, dt, flags)  \
    crm_time_log_alias(level, __FILE__, __func__, __LINE__, prefix, dt, flags)

//! \deprecated Do not use
void crm_time_log_alias(int log_level, const char *file, const char *function,
                        int line, const char *prefix,
                        const crm_time_t *date_time, int flags);

//! \deprecated Do not use
void crm_time_free_period(crm_time_period_t *period);

//! \deprecated Do not use
crm_time_period_t *crm_time_parse_period(const char *period_str);

//! \deprecated Do not use
crm_time_t *crm_time_calculate_duration(const crm_time_t *dt,
                                        const crm_time_t *value);

//! \deprecated Do not use
crm_time_t *crm_time_parse_duration(const char *duration_str);

//! \deprecated Do not use
crm_time_t *crm_time_new_undefined(void);

//! \deprecated Do not use
bool crm_time_is_defined(const crm_time_t *t);

//! \deprecated Do not use
char *crm_time_as_string(const crm_time_t *dt, int flags);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ISO8601_COMPAT__H
