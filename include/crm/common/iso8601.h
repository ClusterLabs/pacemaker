/* 
 * Copyright (C) 2005 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * \file
 * \brief ISO_8601 Date handling
 * \ingroup date
 */

/*
 * http://en.wikipedia.org/wiki/ISO_8601
 *
 */

#ifndef CRM_COMMON_ISO8601
#  define CRM_COMMON_ISO8601

#  include <time.h>
#  include <ctype.h>
#  include <stdbool.h>

typedef struct crm_time_s crm_time_t;

typedef struct crm_time_period_s {
    crm_time_t *start;
    crm_time_t *end;
    crm_time_t *diff;
} crm_time_period_t;

/* Creates a new date/time object conforming to iso8601:
 *     http://en.wikipedia.org/wiki/ISO_8601
 *
 * Eg.
 *   Ordinal:   2010-01 12:00:00 +10:00
 *   Gregorian: 2010-01-01 12:00:00 +10:00
 *   ISO Week:  2010-W53-6 12:00:00 +10:00
 *
 * Notes:
 *   Only one of date, time is required
 *   If date or timezone is unspecified, they default to the current one
 *   Supplying NULL results in the current date/time
 *   Dashes may be ommitted from dates
 *   Colons may be ommitted from times and timezones
 *   A timezone of 'Z' denoted UTC time
 */
crm_time_t *crm_time_new(const char *string);
void crm_time_free(crm_time_t * dt);

char *crm_time_as_string(crm_time_t * dt, int flags);

#  define crm_time_log(level, prefix, dt, flags) crm_time_log_alias(level, __FILE__, __FUNCTION__, __LINE__, prefix, dt, flags)
void crm_time_log_alias(int log_level, const char *file, const char *function, int line,
                        const char *prefix, crm_time_t * date_time, int flags);

#  define crm_time_log_date          0x001
#  define crm_time_log_timeofday     0x002
#  define crm_time_log_with_timezone 0x004
#  define crm_time_log_duration      0x008

#  define crm_time_ordinal           0x010
#  define crm_time_weeks             0x020
#  define crm_time_seconds           0x100
#  define crm_time_epoch             0x200

crm_time_t *crm_time_parse_duration(const char *duration_str);
crm_time_t *crm_time_calculate_duration(crm_time_t * dt, crm_time_t * value);
crm_time_period_t *crm_time_parse_period(const char *period_str);

int crm_time_compare(crm_time_t * dt, crm_time_t * rhs);

int crm_time_get_timeofday(crm_time_t * dt, uint32_t * h, uint32_t * m, uint32_t * s);
int crm_time_get_timezone(crm_time_t * dt, uint32_t * h, uint32_t * m);
int crm_time_get_gregorian(crm_time_t * dt, uint32_t * y, uint32_t * m, uint32_t * d);
int crm_time_get_ordinal(crm_time_t * dt, uint32_t * y, uint32_t * d);
int crm_time_get_isoweek(crm_time_t * dt, uint32_t * y, uint32_t * w, uint32_t * d);

/* Time in seconds since 0000-01-01 00:00:00Z */
long long int crm_time_get_seconds(crm_time_t * dt);

/* Time in seconds since 1970-01-01 00:00:00Z */
long long int crm_time_get_seconds_since_epoch(crm_time_t * dt);

void crm_time_set(crm_time_t * target, crm_time_t * source);
void crm_time_set_timet(crm_time_t * target, time_t * source);

/* Returns a new time object */
crm_time_t *crm_time_add(crm_time_t * dt, crm_time_t * value);
crm_time_t *crm_time_subtract(crm_time_t * dt, crm_time_t * value);

/* All crm_time_add_... functions support negative values */
void crm_time_add_seconds(crm_time_t * dt, int value);
void crm_time_add_minutes(crm_time_t * dt, int value);
void crm_time_add_hours(crm_time_t * dt, int value);
void crm_time_add_days(crm_time_t * dt, int value);
void crm_time_add_weekdays(crm_time_t * dt, int value);
void crm_time_add_weeks(crm_time_t * dt, int value);
void crm_time_add_months(crm_time_t * dt, int value);
void crm_time_add_years(crm_time_t * dt, int value);
void crm_time_add_ordinalyears(crm_time_t * dt, int value);
void crm_time_add_weekyears(crm_time_t * dt, int value);

/* Useful helper functions */
int crm_time_january1_weekday(int year);
int crm_time_weeks_in_year(int year);
int crm_time_days_in_month(int month, int year);

bool crm_time_leapyear(int year);
bool crm_time_check(crm_time_t * dt);

#endif
