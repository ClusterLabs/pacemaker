/*
 * Copyright (C) 2005 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 * Primary reference:
 *	http://en.wikipedia.org/wiki/ISO_8601 (as at 2005-08-01)
 *
 * Secondary references:
 *	http://hydracen.com/dx/iso8601.htm
 *	http://www.personal.ecu.edu/mccartyr/ISOwdALG.txt
 *	http://www.personal.ecu.edu/mccartyr/isowdcal.html
 *	http://www.phys.uu.nl/~vgent/calendar/isocalendar.htm
 *
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <time.h>
#include <ctype.h>
#include <crm/common/iso8601.h>

/*
 * Andrew's code was originally written for OSes whose "struct tm" contains:
 *	long tm_gmtoff;		:: Seconds east of UTC
 *	const char *tm_zone;	:: Timezone abbreviation
 * Some OSes lack these, instead having:
 *	time_t (or long) timezone;
		:: "difference between UTC and local standard time"
 *	char *tzname[2] = { "...", "..." };
 * I (David Lee) confess to not understanding the details.  So my attempted
 * generalisations for where their use is necessary may be flawed.
 *
 * 1. Does "difference between ..." subtract the same or opposite way?
 * 2. Should it use "altzone" instead of "timezone"?
 * 3. Should it use tzname[0] or tzname[1]?  Interaction with timezone/altzone?
 */
#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
#  define GMTOFF(tm) ((tm)->tm_gmtoff)
#else
/* Note: extern variable; macro argument not actually used.  */
#  define GMTOFF(tm) (timezone)
#endif

struct crm_time_s {
    int years;
    int months;                 /* Only for durations */
    int days;
    int seconds;
    int offset;                 /* Seconds */
};

char *crm_time_as_string(crm_time_t * date_time, int flags);
crm_time_t *parse_date(const char *date_str);

gboolean check_for_ordinal(const char *str);

static crm_time_t *
crm_get_utc_time(crm_time_t * dt)
{
    crm_time_t *utc = calloc(1, sizeof(crm_time_t));

    utc->years = dt->years;
    utc->days = dt->days;
    utc->seconds = dt->seconds;
    utc->offset = 0;

    if (dt->offset) {
        crm_time_add_seconds(utc, -dt->offset);
    } else {
        /* Durations (which are the only things that can include months, never have a timezone */
        utc->months = dt->months;
    }

    crm_time_log(LOG_TRACE, "utc-source", dt,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_log(LOG_TRACE, "utc-target", utc,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    return utc;
}

crm_time_t *
crm_time_new(const char *date_time)
{
    time_t tm_now;
    crm_time_t *dt = NULL;

    tzset();
    if (date_time == NULL) {
        tm_now = time(NULL);
        dt = calloc(1, sizeof(crm_time_t));
        crm_time_set_timet(dt, &tm_now);
    } else {
        dt = parse_date(date_time);
    }
    return dt;
}

void
crm_time_free(crm_time_t * dt)
{
    if (dt == NULL) {
        return;
    }
    free(dt);
}

static int
year_days(int year)
{
    int d = 365;

    if (crm_time_leapyear(year)) {
        d++;
    }
    return d;
}

/* http://www.personal.ecu.edu/mccartyr/ISOwdALG.txt
 *
 * 5. Find the Jan1Weekday for Y (Monday=1, Sunday=7)
 *  YY = (Y-1) % 100
 *  C = (Y-1) - YY
 *  G = YY + YY/4
 *  Jan1Weekday = 1 + (((((C / 100) % 4) x 5) + G) % 7)
 */
int
crm_time_january1_weekday(int year)
{
    int YY = (year - 1) % 100;
    int C = (year - 1) - YY;
    int G = YY + YY / 4;
    int jan1 = 1 + (((((C / 100) % 4) * 5) + G) % 7);

    crm_trace("YY=%d, C=%d, G=%d", YY, C, G);
    crm_trace("January 1 %.4d: %d", year, jan1);
    return jan1;
}

int
crm_time_weeks_in_year(int year)
{
    int weeks = 52;
    int jan1 = crm_time_january1_weekday(year);

    /* if jan1 == thursday */
    if (jan1 == 4) {
        weeks++;
    } else {
        jan1 = crm_time_january1_weekday(year + 1);
        /* if dec31 == thursday aka. jan1 of next year is a friday */
        if (jan1 == 5) {
            weeks++;
        }

    }
    return weeks;
}

int month_days[14] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 29 };

int
crm_time_days_in_month(int month, int year)
{
    if (month == 2 && crm_time_leapyear(year)) {
        month = 13;
    }
    return month_days[month];
}

bool
crm_time_leapyear(int year)
{
    gboolean is_leap = FALSE;

    if (year % 4 == 0) {
        is_leap = TRUE;
    }
    if (year % 100 == 0 && year % 400 != 0) {
        is_leap = FALSE;
    }
    return is_leap;
}

static uint32_t
get_ordinal_days(uint32_t y, uint32_t m, uint32_t d)
{
    int lpc;

    for (lpc = 1; lpc < m; lpc++) {
        d += crm_time_days_in_month(lpc, y);
    }
    return d;
}

void
crm_time_log_alias(int log_level, const char *file, const char *function, int line,
                   const char *prefix, crm_time_t * date_time, int flags)
{
    char *date_s = crm_time_as_string(date_time, flags);

    if (log_level < LOG_CRIT) {
        printf("%s%s%s\n",
               prefix ? prefix : "", prefix ? ": " : "", date_s ? date_s : "__invalid_date__");
    } else {
        do_crm_log_alias(log_level, file, function, line, "%s%s%s",
                         prefix ? prefix : "", prefix ? ": " : "",
                         date_s ? date_s : "__invalid_date__");
    }
    free(date_s);
}

static int
crm_time_get_sec(int sec, uint * h, uint * m, uint * s)
{
    uint hours, minutes, seconds;

    if (sec < 0) {
        seconds = 0 - sec;
    } else {
        seconds = sec;
    }

    hours = seconds / (60 * 60);
    seconds -= 60 * 60 * hours;

    minutes = seconds / (60);
    seconds -= 60 * minutes;

    crm_trace("%d == %.2d:%.2d:%.2d", sec, hours, minutes, seconds);

    *h = hours;
    *m = minutes;
    *s = seconds;

    return TRUE;
}

int
crm_time_get_timeofday(crm_time_t * dt, uint * h, uint * m, uint * s)
{
    return crm_time_get_sec(dt->seconds, h, m, s);
}

int
crm_time_get_timezone(crm_time_t * dt, uint * h, uint * m)
{
    uint s;

    return crm_time_get_sec(dt->seconds, h, m, &s);
}

unsigned long long
crm_time_get_seconds(crm_time_t * dt)
{
    int lpc;
    crm_time_t *utc = NULL;
    unsigned long long in_seconds = 0;

    utc = crm_get_utc_time(dt);

    for (lpc = 1; lpc < utc->years; lpc++) {
        int dmax = year_days(lpc);

        in_seconds += 60 * 60 * 24 * dmax;
    }

    /* utc->months is an offset that can only be set for a duration
     * By definiton, the value is variable depending on the date to
     * which it is applied
     *
     * Force 30-day months so that something vaguely sane happens
     * for anyone that tries to use a month in this way
     */
    if (utc->months > 0) {
        in_seconds += 60 * 60 * 24 * 30 * utc->months;
    }

    if (utc->days > 0) {
        in_seconds += 60 * 60 * 24 * (utc->days - 1);
    }
    in_seconds += utc->seconds;

    crm_time_free(utc);
    return in_seconds;
}

#define EPOCH_SECONDS 62135596800ULL    /* Calculated using crm_time_get_seconds() */
unsigned long long
crm_time_get_seconds_since_epoch(crm_time_t * dt)
{
    return crm_time_get_seconds(dt) - EPOCH_SECONDS;
}

int
crm_time_get_gregorian(crm_time_t * dt, uint * y, uint * m, uint * d)
{
    int months = 1;
    int days = dt->days;

    if (dt->months) {
        /* This is a duration including months, don't convert the days field */
        months = dt->months;

    } else {
        for (; months <= 12 && days > 0; months++) {
            int mdays = crm_time_days_in_month(months, dt->years);

            if (mdays >= days) {
                break;
            } else {
                days -= mdays;
            }
        }
    }

    *y = dt->years;
    *m = months;
    *d = days;
    crm_trace("%.4d-%.3d -> %.4d-%.2d-%.2d", dt->years, dt->days, dt->years, months, days);
    return TRUE;
}

int
crm_time_get_ordinal(crm_time_t * dt, uint * y, uint * d)
{
    *y = dt->years;
    *d = dt->days;
    return TRUE;
}

int
crm_time_get_isoweek(crm_time_t * dt, uint * y, uint * w, uint * d)
{
    /*
     * Monday 29 December 2008 is written "2009-W01-1"
     * Sunday 3 January 2010 is written "2009-W53-7"
     */
    int year_num = 0;
    int jan1 = crm_time_january1_weekday(dt->years);
    int h = -1;

    CRM_CHECK(dt->days > 0, return FALSE);

/* 6. Find the Weekday for Y M D */
    h = dt->days + jan1 - 1;
    *d = 1 + ((h - 1) % 7);

/* 7. Find if Y M D falls in YearNumber Y-1, WeekNumber 52 or 53 */
    if (dt->days <= (8 - jan1) && jan1 > 4) {
        crm_trace("year--, jan1=%d", jan1);
        year_num = dt->years - 1;
        *w = crm_time_weeks_in_year(year_num);

    } else {
        year_num = dt->years;
    }

/* 8. Find if Y M D falls in YearNumber Y+1, WeekNumber 1 */
    if (year_num == dt->years) {
        int dmax = year_days(year_num);
        int correction = 4 - *d;

        if ((dmax - dt->days) < correction) {
            crm_trace("year++, jan1=%d, i=%d vs. %d", jan1, dmax - dt->days, correction);
            year_num = dt->years + 1;
            *w = 1;
        }
    }

/* 9. Find if Y M D falls in YearNumber Y, WeekNumber 1 through 53 */
    if (year_num == dt->years) {
        int j = dt->days + (7 - *d) + (jan1 - 1);

        *w = j / 7;
        if (jan1 > 4) {
            *w -= 1;
        }
    }

    *y = year_num;
    crm_trace("Converted %.4d-%.3d to %.4d-W%.2d-%d", dt->years, dt->days, *y, *w, *d);
    return TRUE;
}

char *
crm_time_as_string(crm_time_t * date_time, int flags)
{
    char *date_s = NULL;
    char *time_s = NULL;
    char *offset_s = NULL;
    char *result_s = NULL;
    crm_time_t *dt = NULL;
    crm_time_t *utc = NULL;

    if (date_time == NULL) {
        return strdup("");

    } else if (date_time->offset && (flags & crm_time_log_with_timezone) == 0) {
        crm_trace("UTC conversion");
        utc = crm_get_utc_time(date_time);
        dt = utc;
    } else {
        dt = date_time;
    }

    CRM_CHECK(dt != NULL, return NULL);

    if (flags & crm_time_log_date) {
        date_s = calloc(1, 32);
        if (date_s == NULL) {
            return NULL;

        } else if (flags & crm_time_seconds) {
            unsigned long long s = crm_time_get_seconds(date_time);

            snprintf(date_s, 31, "%llu", s);
            goto done;

        } else if (flags & crm_time_epoch) {
            unsigned long long s = crm_time_get_seconds_since_epoch(date_time);

            snprintf(date_s, 31, "%llu", s);
            goto done;

        } else if (flags & crm_time_weeks) {
            /* YYYY-Www-D */
            uint y, w, d;

            if (crm_time_get_isoweek(dt, &y, &w, &d)) {
                snprintf(date_s, 31, "%d-W%.2d-%d", y, w, d);
            }

        } else if (flags & crm_time_ordinal) {
            /* YYYY-DDD */
            uint y, d;

            if (crm_time_get_ordinal(dt, &y, &d)) {
                snprintf(date_s, 31, "%d-%.3d", y, d);
            }

        } else {
            /* YYYY-MM-DD */
            uint y, m, d;

            if (crm_time_get_gregorian(dt, &y, &m, &d)) {
                snprintf(date_s, 31, "%.4d-%.2d-%.2d", y, m, d);
            }
        }
    }

    if (flags & crm_time_log_timeofday) {
        uint h, m, s;

        time_s = calloc(1, 32);
        if (time_s == NULL) {
            goto cleanup;
        }

        if (crm_time_get_timeofday(dt, &h, &m, &s)) {
            snprintf(time_s, 31, "%.2d:%.2d:%.2d", h, m, s);
        }

        if (dt->offset != 0) {
            crm_time_get_sec(dt->offset, &h, &m, &s);
        }

        offset_s = calloc(1, 32);
        if ((flags & crm_time_log_with_timezone) == 0 || dt->offset == 0) {
            crm_trace("flags %6x %6x", flags, crm_time_log_with_timezone);
            snprintf(offset_s, 31, "Z");

        } else {
            snprintf(offset_s, 31, " %c%.2d:%.2d", dt->offset < 0 ? '-' : '+', h, m);
        }
    }

  done:
    result_s = calloc(1, 100);

    snprintf(result_s, 100, "%s%s%s%s",
             date_s ? date_s : "", (date_s != NULL && time_s != NULL) ? " " : "",
             time_s ? time_s : "", offset_s ? offset_s : "");

  cleanup:
    free(date_s);
    free(time_s);
    free(offset_s);
    crm_time_free(utc);

    return result_s;
}

static int
crm_time_parse_sec(const char *time_str)
{
    int rc;
    uint hour = 0;
    uint minute = 0;
    uint second = 0;

    rc = sscanf(time_str, "%d:%d:%d", &hour, &minute, &second);
    if (rc == 1) {
        rc = sscanf(time_str, "%2d%2d%2d", &hour, &minute, &second);
    }

    if (rc > 0 && rc < 4) {
        crm_trace("Got valid time: %.2d:%.2d:%.2d", hour, minute, second);
        if (hour >= 24) {
            crm_err("Invalid hour: %d", hour);
        } else if (minute >= 60) {
            crm_err("Invalid minute: %d", minute);
        } else if (second >= 60) {
            crm_err("Invalid second: %d", second);
        } else {
            second += (minute * 60);
            second += (hour * 60 * 60);
        }
    } else {
        crm_err("Bad time: %s (%d)", time_str, rc);
    }
    return second;
}

static int
crm_time_parse_offset(const char *offset_str)
{
    int offset = 0;

    tzset();
    if (offset_str == NULL) {
#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        time_t now = time(NULL);
        struct tm *now_tm = localtime(&now);
#endif
        int h_offset = GMTOFF(now_tm) / (3600);
        int m_offset = (GMTOFF(now_tm) - (3600 * h_offset)) / (60);

        if (h_offset < 0 && m_offset < 0) {
            m_offset = 0 - m_offset;
        }
        offset += (60 * 60 * h_offset);
        offset += (60 * m_offset);

    } else if (offset_str[0] == 'Z') {

    } else if (offset_str[0] == '+' || offset_str[0] == '-' || isdigit((int)offset_str[0])) {
        gboolean negate = FALSE;

        if (offset_str[0] == '-') {
            negate = TRUE;
            offset_str++;
        }
        offset = crm_time_parse_sec(offset_str);
        if (negate) {
            offset = 0 - offset;
        }
    }
    return offset;
}

static crm_time_t *
crm_time_parse(const char *time_str, crm_time_t * a_time)
{
    uint h, m, s;
    char *offset_s = NULL;
    crm_time_t *dt = a_time;

    tzset();
    if (a_time == NULL) {
        dt = calloc(1, sizeof(crm_time_t));
    }

    if (time_str) {
        dt->seconds = crm_time_parse_sec(time_str);

        offset_s = strstr(time_str, "Z");
        if (offset_s == NULL) {
            offset_s = strstr(time_str, " ");
        }
    }

    if (offset_s) {
        while (isspace(offset_s[0])) {
            offset_s++;
        }
    }
    dt->offset = crm_time_parse_offset(offset_s);
    crm_time_get_sec(dt->offset, &h, &m, &s);
    crm_trace("Got tz: %c%2.d:%.2d", dt->offset < 0 ? '-' : '+', h, m);
    return dt;
}

crm_time_t *
parse_date(const char *date_str)
{
    char *time_s;
    crm_time_t *dt = NULL;

    int year = 0;
    int month = 0;
    int week = 0;
    int day = 0;
    int rc = 0;

    CRM_CHECK(date_str != NULL, return NULL);
    CRM_CHECK(strlen(date_str) > 0, return NULL);

    if (date_str[0] == 'T' || date_str[2] == ':') {
        /* Just a time supplied - Infer current date */
        dt = crm_time_new(NULL);

        crm_time_parse(date_str, dt);
        goto done;

    } else {
        dt = calloc(1, sizeof(crm_time_t));
    }

    if (safe_str_eq("epoch", date_str)) {
        dt->days = 1;
        dt->years = 1970;
        crm_time_log(LOG_TRACE, "Unpacked", dt, crm_time_log_date | crm_time_log_timeofday);
        return dt;
    }

    /* YYYY-MM-DD */
    rc = sscanf(date_str, "%d-%d-%d", &year, &month, &day);
    if (rc == 1) {
        /* YYYYMMDD */
        rc = sscanf(date_str, "%4d%2d%2d", &year, &month, &day);
    }
    if (rc == 3) {
        if (month > 12) {
            crm_err("Invalid month: %d", month);
        } else if (day > 31) {
            crm_err("Invalid day: %d", day);
        } else {
            dt->years = year;
            dt->days = get_ordinal_days(year, month, day);
            crm_trace("Got gergorian date: %.4d-%.3d", year, dt->days);
        }
        goto done;
    }

    /* YYYY-DDD */
    rc = sscanf(date_str, "%d-%d", &year, &day);
    if (rc == 2) {
        crm_trace("Got ordinal date");
        if (day > year_days(year)) {
            crm_err("Invalid day: %d (max=%d)", day, year_days(year));
        } else {
            dt->days = day;
            dt->years = year;
        }
        goto done;
    }

    /* YYYY-Www-D */
    rc = sscanf(date_str, "%d-W%d-%d", &year, &week, &day);
    if (rc == 3) {
        crm_trace("Got week date");
        if (week > crm_time_weeks_in_year(year)) {
            crm_err("Invalid week: %d (max=%d)", week, crm_time_weeks_in_year(year));
        } else if (day < 1 || day > 7) {
            crm_err("Invalid day: %d", day);
        } else {
            /*
             * http://en.wikipedia.org/wiki/ISO_week_date
             *
             * Monday 29 December 2008 is written "2009-W01-1"
             * Sunday 3 January 2010 is written "2009-W53-7"
             *
             * Saturday 27 September 2008 is written "2008-W37-6"
             *
             * http://en.wikipedia.org/wiki/ISO_week_date
             * If 1 January is on a Monday, Tuesday, Wednesday or Thursday, it is in week 01.
             * If 1 January is on a Friday, Saturday or Sunday, it is in week 52 or 53 of the previous year.
             */
            int jan1 = crm_time_january1_weekday(year);

            crm_trace("Jan 1 = %d", jan1);

            dt->years = year;
            crm_time_add_days(dt, (week - 1) * 7);

            if (jan1 <= 4) {
                crm_time_add_days(dt, 1 - jan1);
            } else {
                crm_time_add_days(dt, 8 - jan1);
            }

            crm_time_add_days(dt, day);
        }
        goto done;
    }

    crm_err("Couldn't parse %s", date_str);
  done:

    time_s = strstr(date_str, " ");
    if (time_s == NULL) {
        time_s = strstr(date_str, "T");
    }

    if (dt && time_s) {
        time_s++;
        crm_time_parse(time_s, dt);
    }

    crm_time_log(LOG_TRACE, "Unpacked", dt, crm_time_log_date | crm_time_log_timeofday);

    CRM_CHECK(crm_time_check(dt), return NULL);

    return dt;
}

static int
parse_int(const char *str, int field_width, int uppper_bound, int *result)
{
    int lpc = 0;
    int offset = 0;
    int intermediate = 0;
    gboolean fraction = FALSE;
    gboolean negate = FALSE;

    CRM_CHECK(str != NULL, return FALSE);
    CRM_CHECK(result != NULL, return FALSE);

    *result = 0;

    if (strlen(str) <= 0) {
        return FALSE;
    }

    if (str[offset] == 'T') {
        offset++;
    }

    if (str[offset] == '.' || str[offset] == ',') {
        fraction = TRUE;
        field_width = -1;
        offset++;
    } else if (str[offset] == '-') {
        negate = TRUE;
        offset++;
    } else if (str[offset] == '+' || str[offset] == ':') {
        offset++;
    }

    for (; (fraction || lpc < field_width) && isdigit((int)str[offset]); lpc++) {
        if (fraction) {
            intermediate = (str[offset] - '0') / (10 ^ lpc);
        } else {
            *result *= 10;
            intermediate = str[offset] - '0';
        }
        *result += intermediate;
        offset++;
    }
    if (fraction) {
        *result = (int)(*result * uppper_bound);

    } else if (uppper_bound > 0 && *result > uppper_bound) {
        *result = uppper_bound;
    }
    if (negate) {
        *result = 0 - *result;
    }
    if (lpc > 0) {
        crm_trace("Found int: %d.  Stopped at str[%d]='%c'", *result, lpc, str[lpc]);
        return offset;
    }
    return 0;
}

crm_time_t *
crm_time_parse_duration(const char *interval_str)
{
    gboolean is_time = FALSE;
    crm_time_t *diff = NULL;

    CRM_CHECK(interval_str != NULL, goto bail);
    CRM_CHECK(strlen(interval_str) > 0, goto bail);
    CRM_CHECK(interval_str[0] == 'P', goto bail);
    interval_str++;

    diff = calloc(1, sizeof(crm_time_t));

    while (isspace((int)interval_str[0]) == FALSE) {
        int an_int = 0, rc;
        char ch = 0;

        if (interval_str[0] == 'T') {
            is_time = TRUE;
            interval_str++;
        }

        rc = parse_int(interval_str, 10, 0, &an_int);
        if (rc == 0) {
            break;
        }
        interval_str += rc;

        ch = interval_str[0];
        interval_str++;

        crm_trace("Testing %c=%d, rc=%d", ch, an_int, rc);

        switch (ch) {
            case 0:
                return diff;
                break;
            case 'Y':
                diff->years = an_int;
                break;
            case 'M':
                if (is_time) {
                    /* Minutes */
                    diff->seconds += an_int * 60;
                } else {
                    diff->months = an_int;
                }
                break;
            case 'W':
                diff->days += an_int * 7;
                break;
            case 'D':
                diff->days += an_int;
                break;
            case 'H':
                diff->seconds += an_int * 60 * 60;
                break;
            case 'S':
                diff->seconds += an_int;
                break;
            default:
                goto bail;
                break;
        }
    }
    return diff;

  bail:
    free(diff);
    return NULL;
}

crm_time_period_t *
crm_time_parse_period(const char *period_str)
{
    gboolean invalid = FALSE;
    const char *original = period_str;
    crm_time_period_t *period = NULL;

    CRM_CHECK(period_str != NULL, return NULL);
    CRM_CHECK(strlen(period_str) > 0, return NULL);

    tzset();
    period = calloc(1, sizeof(crm_time_period_t));

    if (period_str[0] == 'P') {
        period->diff = crm_time_parse_duration(period_str);
    } else {
        period->start = parse_date(period_str);
    }

    period_str = strstr(original, "/");
    if (period_str) {
        CRM_CHECK(period_str[0] == '/', invalid = TRUE;
                  goto bail);
        period_str++;

        if (period_str[0] == 'P') {
            period->diff = crm_time_parse_duration(period_str);
        } else {
            period->end = parse_date(period_str);
        }

    } else if (period->diff != NULL) {
        /* just aduration starting from now */
        period->start = crm_time_new(NULL);

    } else {
        invalid = TRUE;
        CRM_CHECK(period_str != NULL, goto bail);
    }

    /* sanity checks */
    if (period->start == NULL && period->end == NULL) {
        crm_err("Invalid time period: %s", original);
        invalid = TRUE;

    } else if (period->start == NULL && period->diff == NULL) {
        crm_err("Invalid time period: %s", original);
        invalid = TRUE;

    } else if (period->end == NULL && period->diff == NULL) {
        crm_err("Invalid time period: %s", original);
        invalid = TRUE;
    }

  bail:
    if (invalid) {
        free(period->start);
        free(period->end);
        free(period->diff);
        free(period);
        return NULL;
    }
    if (period->end == NULL && period->diff == NULL) {
    }

    if (period->start == NULL) {
        period->start = crm_time_subtract(period->end, period->diff);

    } else if (period->end == NULL) {
        period->end = crm_time_add(period->start, period->diff);
    }

    crm_time_check(period->start);
    crm_time_check(period->end);

    return period;
}

void
crm_time_set(crm_time_t * target, crm_time_t * source)
{
    crm_trace("target=%p, source=%p, offset=%d", target, source);

    CRM_CHECK(target != NULL && source != NULL, return);

    target->years = source->years;
    target->days = source->days;
    target->months = source->months;    /* Only for durations */
    target->seconds = source->seconds;
    target->offset = source->offset;

    crm_time_log(LOG_TRACE, "source", source,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    crm_time_log(LOG_TRACE, "target", target,
                 crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
}

static void
ha_set_tm_time(crm_time_t * target, struct tm *source)
{
    int h_offset = 0;
    int m_offset = 0;

    if (source->tm_year > 0) {
        /* years since 1900 */
        target->years = 1900 + source->tm_year;
    }

    if (source->tm_yday >= 0) {
        /* days since January 1 [0-365] */
        target->days = 1 + source->tm_yday;
    }

    if (source->tm_hour >= 0) {
        target->seconds += 60 * 60 * source->tm_hour;
    }
    if (source->tm_min >= 0) {
        target->seconds += 60 * source->tm_min;
    }
    if (source->tm_sec >= 0) {
        target->seconds += source->tm_sec;
    }

    /* tm_gmtoff == offset from UTC in seconds */
    h_offset = GMTOFF(source) / (3600);
    m_offset = (GMTOFF(source) - (3600 * h_offset)) / (60);
    crm_trace("Offset (s): %ld, offset (hh:mm): %.2d:%.2d", GMTOFF(source), h_offset, m_offset);

    target->offset = 0;
    target->offset += 60 * 60 * h_offset;
    target->offset += 60 * m_offset;
}

void
crm_time_set_timet(crm_time_t * target, time_t * source)
{
    ha_set_tm_time(target, localtime(source));
}

crm_time_t *
crm_time_add(crm_time_t * dt, crm_time_t * value)
{
    crm_time_t *utc = NULL;
    crm_time_t *answer = NULL;

    CRM_CHECK(dt != NULL && value != NULL, return NULL);

    answer = calloc(1, sizeof(crm_time_t));
    crm_time_set(answer, dt);

    utc = crm_get_utc_time(value);

    answer->years += utc->years;
    crm_time_add_months(answer, utc->months);
    crm_time_add_days(answer, utc->days);
    crm_time_add_seconds(answer, utc->seconds);

    crm_time_free(utc);
    return answer;
}

crm_time_t *
crm_time_subtract(crm_time_t * dt, crm_time_t * value)
{
    crm_time_t *utc = NULL;
    crm_time_t *answer = NULL;

    CRM_CHECK(dt != NULL && value != NULL, return NULL);

    answer = calloc(1, sizeof(crm_time_t));
    crm_time_set(answer, dt);

    utc = crm_get_utc_time(value);

    answer->years -= utc->years;
    crm_time_add_months(answer, -utc->months);
    crm_time_add_days(answer, -utc->days);
    crm_time_add_seconds(answer, -utc->seconds);

    return answer;
}

bool
crm_time_check(crm_time_t * dt)
{
    int ydays = 0;

    CRM_CHECK(dt != NULL, return FALSE);

    ydays = year_days(dt->years);
    crm_trace("max ydays: %d", ydays);

    CRM_CHECK(dt->days > 0, return FALSE);
    CRM_CHECK(dt->days <= ydays, return FALSE);

    CRM_CHECK(dt->seconds >= 0, return FALSE);
    CRM_CHECK(dt->seconds < 24 * 60 * 60, return FALSE);

    return TRUE;
}

#define do_cmp_field(l, r, field)					\
    if(rc == 0) {                                                       \
		if(l->field > r->field) {				\
			crm_trace("%s: %d > %d",			\
				    #field, l->field, r->field);	\
			rc = 1;                                         \
		} else if(l->field < r->field) {			\
			crm_trace("%s: %d < %d",			\
				    #field, l->field, r->field);	\
			rc = -1;					\
		}							\
    }

int
crm_time_compare(crm_time_t * a, crm_time_t * b)
{
    int rc = 0;
    crm_time_t *t1 = NULL;
    crm_time_t *t2 = NULL;

    if (a == NULL && b == NULL) {
        return 0;
    } else if (a == NULL) {
        return -1;
    } else if (b == NULL) {
        return 1;
    }

    t1 = crm_get_utc_time(a);
    t2 = crm_get_utc_time(b);

    do_cmp_field(t1, t2, years);
    do_cmp_field(t1, t2, days);
    do_cmp_field(t1, t2, seconds);

    crm_time_free(t1);
    crm_time_free(t2);
    return rc;
}

void
crm_time_add_seconds(crm_time_t * a_time, int extra)
{
    int days = 0;
    int seconds = 24 * 60 * 60;

    crm_trace("Adding %d seconds to %d (max=%d)", extra, a_time->seconds, seconds);

    a_time->seconds += extra;
    while (a_time->seconds >= seconds) {
        a_time->seconds -= seconds;
        days++;
    }

    days = 0;
    while (a_time->seconds < 0) {
        crm_trace("s=%d, d=%d", a_time->seconds, days);
        a_time->seconds += seconds;
        days--;
        crm_trace("s=%d, d=%d", a_time->seconds, days);
    }
    crm_time_add_days(a_time, days);
}

void
crm_time_add_days(crm_time_t * a_time, int extra)
{
    int ydays = crm_time_leapyear(a_time->years) ? 366 : 365;

    crm_trace("Adding %d days to %.4d-%.3d", extra, a_time->years, a_time->days);

    a_time->days += extra;
    while (a_time->days > ydays) {
        a_time->years++;
        a_time->days -= ydays;
        ydays = crm_time_leapyear(a_time->years) ? 366 : 365;
    }

    while (a_time->days <= 0) {
        a_time->years--;
        a_time->days += crm_time_leapyear(a_time->years) ? 366 : 365;
    }
}

void
crm_time_add_months(crm_time_t * a_time, int extra)
{
    int lpc;
    uint32_t y, m, d, dmax;

    crm_time_get_gregorian(a_time, &y, &m, &d);
    crm_trace("Adding %d months to %.4d-%.2d-%.2d", extra, y, m, d);

    if (extra > 0) {
        for (lpc = extra; lpc > 0; lpc--) {
            m++;
            if (m == 13) {
                m = 1;
                y++;
            }
        }
    } else {
        for (lpc = -extra; lpc > 0; lpc--) {
            m--;
            if (m == 0) {
                m = 12;
                y--;
            }
        }
    }

    dmax = crm_time_days_in_month(m, y);
    if (dmax < d) {
        /* Preserve day-of-month unless the month doesn't have enough days */
        d = dmax;
    }

    crm_trace("Calculated %.4d-%.2d-%.2d", y, m, d);

    a_time->years = y;
    a_time->days = get_ordinal_days(y, m, d);

    crm_time_get_gregorian(a_time, &y, &m, &d);
    crm_trace("Got %.4d-%.2d-%.2d", y, m, d);
}

void
crm_time_add_minutes(crm_time_t * a_time, int extra)
{
    crm_time_add_seconds(a_time, extra * 60);
}

void
crm_time_add_hours(crm_time_t * a_time, int extra)
{
    crm_time_add_seconds(a_time, extra * 60 * 60);
}

void
crm_time_add_weeks(crm_time_t * a_time, int extra)
{
    crm_time_add_days(a_time, extra * 7);
}

void
crm_time_add_years(crm_time_t * a_time, int extra)
{
    a_time->years += extra;
}
