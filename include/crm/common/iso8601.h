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

/*
 * http://en.wikipedia.org/wiki/ISO_8601
 *
 */

#ifndef CRM_COMMON_ISO8601
#  define CRM_COMMON_ISO8601

#  include <crm/crm.h>
#  include <time.h>
#  include <ctype.h>

typedef struct ha_has_time_s {
    gboolean years;

    gboolean months;
    gboolean days;

    gboolean weeks;
    gboolean weekdays;
    gboolean weekyears;

    gboolean yeardays;

    gboolean hours;
    gboolean minutes;
    gboolean seconds;
} ha_has_time_t;

typedef struct ha_time_s {
    time_t tm_now;

    int years;

    int months;
    int days;

    int weeks;
    int weekdays;
    int weekyears;

    int yeardays;

    int hours;
    int minutes;
    int seconds;

    struct ha_time_s *offset;
    struct ha_time_s *normalized;
    struct ha_has_time_s *has;
} ha_time_t;

enum date_fields {
    date_month,
    date_day
};

typedef struct ha_time_period_s {
    ha_time_t *start;
    ha_time_t *end;
    ha_time_t *diff;
} ha_time_period_t;

#  define ha_log_date    0x01
#  define ha_log_time    0x02
#  define ha_log_local   0x04

#  define ha_date_ordinal 0x10
#  define ha_date_weeks   0x20

int str_lookup(const char *str, enum date_fields);

char *date_to_string(ha_time_t * dt, int flags);
void log_date(int log_level, const char *prefix, ha_time_t * dt, int flags);
void log_time_period(int log_level, ha_time_period_t * dtp, int flags);

ha_time_t *parse_time(char **time_str, ha_time_t * atime, gboolean with_offset);
ha_time_t *parse_time_offset(char **offset_str);
ha_time_t *parse_date(char **date_str);
ha_time_t *parse_time_duration(char **duration_str);
ha_time_period_t *parse_time_period(char **period_str);

/* ha_time_interval_t *parse_time_interval(char **interval_str); */

unsigned long long int date_in_seconds(ha_time_t * a_date);
unsigned long long int date_in_seconds_since_epoch(ha_time_t * a_date);
int compare_date(ha_time_t * lhs, ha_time_t * rhs);

gboolean parse_int(char **str, int field_width, int uppper_bound, int *result);
gboolean check_for_ordinal(const char *str);

void ha_set_time(ha_time_t * lhs, ha_time_t * rhs, gboolean offset);
void ha_set_tm_time(ha_time_t * lhs, struct tm *rhs);
void ha_set_timet_time(ha_time_t * lhs, time_t * rhs);
ha_time_t *add_time(ha_time_t * lhs, ha_time_t * rhs);
ha_time_t *subtract_time(ha_time_t * lhs, ha_time_t * rhs);
ha_time_t *subtract_duration(ha_time_t * time, ha_time_t * duration);
void reset_tm(struct tm *some_tm);
void add_seconds(ha_time_t * a_time, int extra);
void add_minutes(ha_time_t * a_time, int extra);
void add_hours(ha_time_t * a_time, int extra);
void add_days(ha_time_t * a_time, int extra);
void add_weekdays(ha_time_t * a_time, int extra);
void add_yeardays(ha_time_t * a_time, int extra);
void add_weeks(ha_time_t * a_time, int extra);
void add_months(ha_time_t * a_time, int extra);
void add_years(ha_time_t * a_time, int extra);
void add_ordinalyears(ha_time_t * a_time, int extra);
void add_weekyears(ha_time_t * a_time, int extra);
void sub_seconds(ha_time_t * a_time, int extra);
void sub_minutes(ha_time_t * a_time, int extra);
void sub_hours(ha_time_t * a_time, int extra);
void sub_days(ha_time_t * a_time, int extra);
void sub_weekdays(ha_time_t * a_time, int extra);
void sub_yeardays(ha_time_t * a_time, int extra);
void sub_weeks(ha_time_t * a_time, int extra);
void sub_months(ha_time_t * a_time, int extra);
void sub_years(ha_time_t * a_time, int extra);
void sub_ordinalyears(ha_time_t * a_time, int extra);
void sub_weekyears(ha_time_t * a_time, int extra);

/* conversion functions */
int january1(int year);

gboolean convert_from_weekdays(ha_time_t * a_date);
gboolean convert_from_ordinal(ha_time_t * a_date);
gboolean convert_from_gregorian(ha_time_t * a_date);

gboolean is_leap_year(int year);

int weeks_in_year(int year);
int days_per_month(int month, int year);

gboolean is_date_sane(ha_time_t * a_date);

ha_time_t *new_ha_date(gboolean set_to_now);
void free_ha_date(ha_time_t * a_date);

void reset_time(ha_time_t * a_time);
void log_tm_date(int log_level, struct tm *some_tm);

#endif
