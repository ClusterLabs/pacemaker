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


struct ha_time_s {
        int years;
        int months; /* Only for durations */
        int days;
        int seconds;
        int offset; /* Seconds */
};

char *date_to_string(ha_time_t * date_time, int flags);

static int year_days(int year) 
{
    int d = 365;
    if (is_leap_year(year)) {
        d++;
    }
    return d;
}

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

static ha_time_t *
crm_get_utc_time(ha_time_t *dt)
{
    ha_time_t *utc = new_ha_date(FALSE);
    ha_set_time(utc, dt, FALSE);
    sub_seconds(utc, dt->offset);
    crm_trace("utc time");
    return utc;
}

void
log_date(int log_level, const char *prefix, ha_time_t * date_time, int flags)
{
    char *date_s = date_to_string(date_time, flags);

    if(log_level < LOG_CRIT) {
        printf("%s%s%s\n",
               prefix ? prefix : "", prefix ? ": " : "", date_s ? date_s : "__invalid_date__");
    } else {
        do_crm_log(log_level, "%s%s%s",
                   prefix ? prefix : "", prefix ? ": " : "", date_s ? date_s : "__invalid_date__");
    }
    free(date_s);
}

void
log_time_period(int log_level, ha_time_period_t * dtp, int flags)
{
    log_date(log_level, "Period start:", dtp->start, flags);
    log_date(log_level, "Period end:", dtp->end, flags);
}

static int crm_get_time_sec(int sec, uint *h, uint *m, uint *s)
{
    uint hours, minutes, seconds;
    if(sec < 0) {
        seconds = 0 - sec;
    } else {
        seconds = sec;
    }
    
    hours = seconds/(60*60);
    seconds -= 60 * 60 * hours;

    minutes = seconds/(60*60);
    seconds -= 60 * minutes;

    crm_trace("%d == %.2d:%.2d:%.2d", sec, hours, minutes, seconds);

    *h = hours;
    *m = minutes;
    *s = seconds;

    return TRUE;
}

int crm_get_time(ha_time_t *now, uint *h, uint *m, uint *s)
{
    return crm_get_time_sec(now->seconds, h, m, s);
}

    
int crm_get_gregorian_date(ha_time_t *now, uint *y, uint *m, uint *d)
{
    int months = 1;
    int days = now->days;
    for(; months <= 12 && days > 0; months++) {
        int mdays = days_per_month(months, now->years);
        if(mdays >= days) {
            break;
        } else {
            days -= mdays;
        }
    }

    *y = now->years;
    *m = months;
    *d = days;
    crm_trace("%.4d-%.3d -> %.4d-%.2d-%.2d", now->years, now->days, now->years, months, days);
    return TRUE;
}

int crm_get_ordinal_date(ha_time_t *now, uint *y, uint *d)
{
    *y = now->years;
    *d = now->days;
    return TRUE;
}

int crm_get_week_date(ha_time_t *dt, uint *y, uint *w, uint *d)
{
    /*
     * Monday 29 December 2008 is written "2009-W01-1"
     * Sunday 3 January 2010 is written "2009-W53-7"
     */
    int year_num = 0;
    int jan1 = january1(dt->years);
    int h = -1;

    CRM_CHECK(dt->days > 0, return FALSE);

/* 6. Find the Weekday for Y M D */
    h = dt->days + jan1 - 1;
    *d = 1 + ((h - 1) % 7);

/* 7. Find if Y M D falls in YearNumber Y-1, WeekNumber 52 or 53 */
    if (dt->days <= (8 - jan1) && jan1 > 4) {
        crm_trace("year--, jan1=%d", jan1);
        year_num = dt->years - 1;
        *w = weeks_in_year(year_num);

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
    crm_trace("Converted %.4d-%.3d to %.4d-W%.2d-%d",
              dt->years, dt->days, *y, *w, *d);
    return TRUE;
}

char *
date_to_string(ha_time_t * date_time, int flags)
{
    char *date_s = NULL;
    char *time_s = NULL;
    char *offset_s = NULL;
    char *result_s = NULL;
    ha_time_t *dt = NULL;

    if (flags & ha_log_local) {
        crm_trace("Local version");
        dt = calloc(1, sizeof(ha_time_t));
        ha_set_time(dt, date_time, FALSE);
    } else if(date_time->offset) {
        crm_trace("UTC conversion");
        dt = crm_get_utc_time(date_time);
    } else {
        crm_trace("Already UTC");
        dt = calloc(1, sizeof(ha_time_t));
        ha_set_time(dt, date_time, FALSE);
    }

    CRM_CHECK(dt != NULL, return NULL);

    if (flags & ha_log_date) {
        date_s = calloc(1, 32);
        if (date_s == NULL) {
            return NULL;

        } else if (flags & ha_date_seconds) {
            unsigned long long s = date_in_seconds(date_time);
            snprintf(date_s, 31, "%llu", s);
            goto done;

        } else if (flags & ha_date_epoch) {
            unsigned long long s = date_in_seconds_since_epoch(date_time);
            snprintf(date_s, 31, "%llu", s);
            goto done;

        } else if (flags & ha_date_weeks) {
            /* YYYY-Www-D */
            uint y, w, d;
            if(crm_get_week_date(dt, &y, &w, &d)) {
                snprintf(date_s, 31, "%d-W%.2d-%d", y, w, d);
            }

        } else if (flags & ha_date_ordinal) {
            /* YYYY-DDD */
            uint y, d;
            if(crm_get_ordinal_date(dt, &y, &d)) {
                snprintf(date_s, 31, "%d-%.3d", y, d);
            }

        } else {
            /* YYYY-MM-DD */
            uint y, m, d;
            if(crm_get_gregorian_date(dt, &y, &m, &d)) {
                snprintf(date_s, 31, "%.4d-%.2d-%.2d", y, m, d);
            }
        }
    }

    if (flags & ha_log_time) {
        uint h, m, s;

        time_s = calloc(1, 32);
        if (time_s == NULL) {
            goto cleanup;
        }

        if(crm_get_time(dt, &h, &m, &s)) {
            snprintf(time_s, 31, "%.2d:%.2d:%.2d", h, m, s);
        }

        if (dt->offset != 0) {
            crm_get_time_sec(dt->offset, &h, &m, &s);
        }

        offset_s = calloc(1, 32);
        if ((flags & ha_log_local) == 0 || dt->offset == 0) {
            crm_trace("flags %6x %6x", flags, ha_log_local);
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
    free_ha_date(dt);

    return result_s;
}

static int
parse_time_sec(const char *time_str)
{
    int rc;
    uint hour = 0;
    uint minute = 0;
    uint second = 0;
    rc = sscanf(time_str, "%d:%d:%d", &hour, &minute, &second);
    if(rc == 1) {
        rc = sscanf(time_str, "%2d%2d%2d", &hour, &minute, &second);
    }

    if(rc > 0 && rc < 4) {
        crm_trace("Got valid time: %.2d:%.2d:%.2d", hour, minute, second);
        if(hour >= 24) {
            crm_err("Invalid hour: %d", hour);
        } else if(minute >= 60) {
            crm_err("Invalid minute: %d", minute);
        } else if(second >= 60) {
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
parse_time_offset(char *offset_str)
{
    int offset = 0;

    tzset();
    if(offset_str == NULL) {
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
        offset = parse_time_sec(offset_str);
        if (negate) {
            offset = 0 - offset;
        }
    }
    return offset;
}

static ha_time_t *
parse_time(char **time_str, ha_time_t * a_time, gboolean with_offset)
{
    uint h, m, s;
    char *offset_s = NULL;
    ha_time_t *new_time = a_time;

    tzset();
    if (a_time == NULL) {
        new_time = new_ha_date(FALSE);
    }
    
    CRM_CHECK(new_time != NULL, return NULL);
    new_time->seconds = parse_time_sec(*time_str);

    offset_s = strstr(*time_str, "Z");
    if(offset_s == NULL) {
        offset_s = strstr(*time_str, " ");
    }
    if(offset_s) {
        while (isspace(offset_s[0])) {
            offset_s++;
        }
    }
    new_time->offset = parse_time_offset(offset_s);
    crm_get_time_sec(new_time->offset, &h, &m, &s);
    crm_trace("Got tz: %c%2.d:%.2d", new_time->offset<0?'-':'+', h, m);
    return new_time;
}

ha_time_t *
parse_date(char **date_str)
{
    char *time_s;
    ha_time_t *new_time = NULL;

    int year = 0;
    int month = 0;
    int week = 0;
    int day = 0;
    int rc = 0;

    CRM_CHECK(date_str != NULL, return NULL);
    CRM_CHECK(strlen(*date_str) > 0, return NULL);

    if ((*date_str)[0] == 'T' || (*date_str)[2] == ':') {
        /* Just a time supplied - Infer current date */
        new_time = new_ha_date(TRUE);

        parse_time(date_str, new_time, TRUE);
        goto done;

    } else {
        new_time = calloc(1, sizeof(ha_time_t));
    }

    if(safe_str_eq("epoch", *date_str)) {
        new_time->days = 1;
        new_time->years = 1970;
        log_date(LOG_TRACE, "Unpacked", new_time, ha_log_date | ha_log_time);
        return new_time;
    }

    /* YYYY-MM-DD */
    rc = sscanf(*date_str, "%d-%d-%d", &year, &month, &day);
    if(rc == 1) {
        /* YYYYMMDD */
        rc = sscanf(*date_str, "%4d%2d%2d", &year, &month, &day);
    }
    if(rc == 3) {
        if(month > 12) {
            crm_err("Invalid month: %d", month);
        } else if(day > 31) {
            crm_err("Invalid day: %d", day);
        } else {
            int m;
            new_time->days = day;
            new_time->years = year;
            for(m = 1; m < month; m++) {
                new_time->days += days_per_month(year, m);
            }
            crm_trace("Got gergorian date: %.4d-%.3d", year, new_time->days);
        }
        goto done;
    }

    /* YYYY-DDD */
    rc = sscanf(*date_str, "%d-%d", &year, &day);
    if(rc == 2) {
        crm_trace("Got ordinal date");
        if(day > 366) {
            crm_err("Invalid day: %d", day);
        } else {
            new_time->days = day;
            new_time->years = year;
        }
        goto done;
    }

    /* YYYY-Www-D */
    rc = sscanf(*date_str, "%d-W%d-%d", &year, &week, &day);
    if(rc == 3) {
        crm_trace("Got week date");
        if(week > 53) {
            crm_err("Invalid week: %d", week);
        } else if(day > 7) {
            crm_err("Invalid day: %d", day);
        } else {
            /*
             * http://en.wikipedia.org/wiki/ISO_week_date
             * This method requires that one know the weekday of 4 January of the year in question.
             * Add 3 to the number of this weekday, giving a correction to be used for dates within this year.
             *
             * Method: Multiply the week number by 7, then add the weekday.
             * From this sum subtract the correction for the year.
             *
             * Example: year 2008, week 39, Saturday (day 6)
             * Correction for 2008: 5 + 3 = 8
             * (39 * 7) + 6 = 279
             * 279 - 8 = 271
             *
             * http://personal.ecu.edu/mccartyr/ISOwdALG.txt
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
            int jan1 = january1(year);
            crm_trace("Jan 1 = %d", jan1);

            new_time->years = year;
            add_days(new_time, (week - 1) * 7);

            if(jan1 <= 4) {
                sub_days(new_time, jan1 - 1);
            } else {
                add_days(new_time, 8 - jan1);
            }

            add_days(new_time, day);

            /* Handle any underflow */
            sub_days(new_time, 0);
        }
        goto done;
    }

    crm_err("Couldn't parse %s", *date_str);
  done:
    
    time_s = strstr(*date_str, " ");
    if(time_s == NULL) {
        time_s = strstr(*date_str, "T");
    }
    
    if(time_s) {
        time_s++;
        parse_time(&time_s, new_time, TRUE);
    }

    log_date(LOG_TRACE, "Unpacked", new_time, ha_log_date | ha_log_time);

    CRM_CHECK(is_date_sane(new_time), return NULL);

    return new_time;
}

ha_time_t *
parse_time_duration(char **interval_str)
{
    gboolean is_time = FALSE;
    ha_time_t *diff = NULL;

    CRM_CHECK(interval_str != NULL, goto bail);
    CRM_CHECK(strlen(*interval_str) > 0, goto bail);
    CRM_CHECK((*interval_str)[0] == 'P', goto bail);
    (*interval_str)++;

    diff = calloc(1, sizeof(ha_time_t));

    while (isspace((int)(*interval_str)[0]) == FALSE) {
        int an_int = 0;
        char ch = 0;

        if ((*interval_str)[0] == 'T') {
            is_time = TRUE;
            (*interval_str)++;
        }

        if (parse_int(interval_str, 10, 0, &an_int) == FALSE) {
            break;
        }
        ch = (*interval_str)[0];
        (*interval_str)++;

        crm_trace("%c=%d", ch, an_int);

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

ha_time_period_t *
parse_time_period(char **period_str)
{
    gboolean invalid = FALSE;
    const char *original = *period_str;
    ha_time_period_t *period = NULL;

    CRM_CHECK(period_str != NULL, return NULL);
    CRM_CHECK(strlen(*period_str) > 0, return NULL);

    tzset();
    period = calloc(1, sizeof(ha_time_period_t));

    if ((*period_str)[0] == 'P') {
        period->diff = parse_time_duration(period_str);
    } else {
        period->start = parse_date(period_str);
    }

    if ((*period_str)[0] != 0) {
        CRM_CHECK((*period_str)[0] == '/', invalid = TRUE; goto bail);
        (*period_str)++;

        if ((*period_str)[0] == 'P') {
            period->diff = parse_time_duration(period_str);
        } else {
            period->end = parse_date(period_str);
        }

    } else if (period->diff != NULL) {
        /* just aduration starting from now */
        time_t now = time(NULL);

        period->start = calloc(1, sizeof(ha_time_t));

        ha_set_timet_time(period->start, &now);
        /* normalize_time(period->start); */

    } else {
        invalid = TRUE;
        CRM_CHECK((*period_str)[0] == '/', goto bail);
        goto bail;
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
        period->start = subtract_duration(period->end, period->diff);

    } else if (period->end == NULL) {
        period->end = add_time(period->start, period->diff);
    }

    is_date_sane(period->start);
    is_date_sane(period->end);

    return period;
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
january1(int year)
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
weeks_in_year(int year)
{
    int weeks = 52;
    int jan1 = january1(year);

    /* if jan1 == thursday */
    if (jan1 == 4) {
        weeks++;
    } else {
        jan1 = january1(year + 1);
        /* if dec31 == thursday aka. jan1 of next year is a friday */
        if (jan1 == 5) {
            weeks++;
        }

    }
    return weeks;
}

void
ha_set_time(ha_time_t * lhs, ha_time_t * rhs, gboolean offset)
{
    crm_trace("lhs=%p, rhs=%p, offset=%d", lhs, rhs, offset);

    CRM_CHECK(lhs != NULL && rhs != NULL, return);

    lhs->years = rhs->years;
    lhs->days = rhs->days;
    lhs->seconds = rhs->seconds;
    lhs->offset = rhs->offset;
}

void
ha_set_tm_time(ha_time_t * lhs, struct tm *rhs)
{
    int h_offset = 0;
    int m_offset = 0;

    if (rhs->tm_year > 0) {
        /* years since 1900 */
        lhs->years = 1900 + rhs->tm_year;
    }

    if (rhs->tm_yday >= 0) {
        /* days since January 1 [0-365] */
        lhs->days = 1 + rhs->tm_yday;
    }

    if (rhs->tm_hour >= 0) {
        lhs->seconds += 60 * 60 * rhs->tm_hour;
    }
    if (rhs->tm_min >= 0) {
        lhs->seconds += 60 * rhs->tm_min;
    }
    if (rhs->tm_sec >= 0) {
        lhs->seconds += rhs->tm_sec;
    }

    /* tm_gmtoff == offset from UTC in seconds */
    h_offset = GMTOFF(rhs) / (3600);
    m_offset = (GMTOFF(rhs) - (3600 * h_offset)) / (60);
    crm_trace("Offset (s): %ld, offset (hh:mm): %.2d:%.2d", GMTOFF(rhs), h_offset, m_offset);

    lhs->offset = 0;
    lhs->offset += 60 * 60 * h_offset;
    lhs->offset += 60 * m_offset;
}

void
ha_set_timet_time(ha_time_t * lhs, time_t * rhs)
{
    ha_set_tm_time(lhs, localtime(rhs));
}

ha_time_t *
add_time(ha_time_t * dt, ha_time_t * rhs)
{
    ha_time_t *utc = NULL;
    ha_time_t *answer = NULL;

    CRM_CHECK(dt != NULL && rhs != NULL, return NULL);

    answer = new_ha_date(FALSE);
    ha_set_time(answer, dt, TRUE);

    utc = crm_get_utc_time(rhs);

    add_years(answer, utc->years);
    add_months(answer, utc->months);
    add_days(answer, utc->days);
    add_seconds(answer, utc->seconds);

    return answer;
}

ha_time_t *
subtract_time(ha_time_t * dt, ha_time_t * rhs)
{
    ha_time_t *utc = NULL;
    ha_time_t *answer = NULL;

    CRM_CHECK(dt != NULL && rhs != NULL, return NULL);

    answer = new_ha_date(FALSE);
    ha_set_time(answer, dt, TRUE);

    utc = crm_get_utc_time(rhs);

    sub_years(answer, utc->years);
    sub_months(answer, utc->months);
    sub_days(answer, utc->days);
    sub_seconds(answer, utc->seconds);

    return answer;
}

ha_time_t *
subtract_duration(ha_time_t * dt, ha_time_t * rhs)
{
    ha_time_t *utc = NULL;
    ha_time_t *answer = NULL;

    CRM_CHECK(dt != NULL && rhs != NULL, return NULL);

    answer = new_ha_date(FALSE);
    ha_set_time(answer, dt, TRUE);

    utc = crm_get_utc_time(rhs);

    sub_seconds(answer, utc->seconds);
    sub_months(answer, utc->months);
    sub_days(answer, utc->days);
    sub_years(answer, utc->years);

    return answer;
}

int month_days[14] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 29 };

int
days_per_month(int month, int year)
{
    if (month == 2 && is_leap_year(year)) {
        month = 13;
    }
    return month_days[month];
}

gboolean
is_leap_year(int year)
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

gboolean
parse_int(char **str, int field_width, int uppper_bound, int *result)
{
    int lpc = 0;
    int intermediate = 0;
    gboolean fraction = FALSE;
    gboolean negate = FALSE;

    CRM_CHECK(str != NULL, return FALSE);
    CRM_CHECK(*str != NULL, return FALSE);
    CRM_CHECK(result != NULL, return FALSE);

    *result = 0;

    if (strlen(*str) <= 0) {
        return FALSE;
    }

    if ((*str)[0] == 'T') {
        (*str)++;
    }

    if ((*str)[0] == '.' || (*str)[0] == ',') {
        fraction = TRUE;
        field_width = -1;
        (*str)++;
    } else if ((*str)[0] == '-') {
        negate = TRUE;
        (*str)++;
    } else if ((*str)[0] == '+' || (*str)[0] == ':') {
        (*str)++;
    }

    for (; (fraction || lpc < field_width) && isdigit((int)(*str)[0]); lpc++) {
        if (fraction) {
            intermediate = ((*str)[0] - '0') / (10 ^ lpc);
        } else {
            *result *= 10;
            intermediate = (*str)[0] - '0';
        }
        *result += intermediate;
        (*str)++;
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
        crm_trace("Found int: %d.  Stopped at str[%d]='%c'", *result, lpc, (*str)[lpc]);
        return TRUE;
    }
    return FALSE;
}

void
reset_time(ha_time_t * a_time)
{
    a_time->years = 0;
    a_time->days = 0;
    a_time->seconds = 0;
}

void
reset_tm(struct tm *some_tm)
{
    some_tm->tm_sec = -1;       /* seconds after the minute [0-60] */
    some_tm->tm_min = -1;       /* minutes after the hour [0-59] */
    some_tm->tm_hour = -1;      /* hours since midnight [0-23] */
    some_tm->tm_mday = -1;      /* day of the month [1-31] */
    some_tm->tm_mon = -1;       /* months since January [0-11] */
    some_tm->tm_year = -1;      /* years since 1900 */
    some_tm->tm_wday = -1;      /* days since Sunday [0-6] */
    some_tm->tm_yday = -1;      /* days since January 1 [0-365] */
    some_tm->tm_isdst = -1;     /* Daylight Savings Time flag */
#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
    some_tm->tm_gmtoff = -1;    /* offset from CUT in seconds */
#endif
#if defined(HAVE_TM_ZONE)
    some_tm->tm_zone = NULL;    /* timezone abbreviation */
#endif
}

gboolean
is_date_sane(ha_time_t * dt)
{
    int ydays = 0;

    CRM_CHECK(dt != NULL, return FALSE);

    ydays = year_days(dt->years);
    crm_trace("max ydays: %d", ydays);

    CRM_CHECK(dt->days > 0, return FALSE);
    CRM_CHECK(dt->days <= ydays, return FALSE);

    CRM_CHECK(dt->seconds >= 0, return FALSE);
    CRM_CHECK(dt->seconds < 24*60*60, return FALSE);

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
compare_date(ha_time_t * a, ha_time_t * b)
{
    int rc = 0;
    ha_time_t *t1 = NULL;
    ha_time_t *t2 = NULL;

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

    return rc;
}

ha_time_t *
new_ha_date(gboolean set_to_now)
{
    time_t tm_now;
    ha_time_t *now = NULL;

    tzset();
    now = calloc(1, sizeof(ha_time_t));
    if (set_to_now) {
        tm_now = time(NULL);
        ha_set_timet_time(now, &tm_now);
    }
    return now;
}

void
free_ha_date(ha_time_t * dt)
{
    if (dt == NULL) {
        return;
    }
    free(dt);
}

void
log_tm_date(int log_level, struct tm *some_tm)
{
    const char *tzn;

#if defined(HAVE_TM_ZONE)
    tzn = some_tm->tm_zone;
#elif defined(HAVE_TZNAME)
    tzn = tzname[0];
#else
    tzn = NULL;
#endif

    do_crm_log(log_level,
               "%.2d/%.2d/%.4d %.2d:%.2d:%.2d %s"
               " (wday=%d, yday=%d, dst=%d, offset=%ld)",
               some_tm->tm_mday,
               some_tm->tm_mon,
               1900 + some_tm->tm_year,
               some_tm->tm_hour,
               some_tm->tm_min,
               some_tm->tm_sec,
               tzn,
               some_tm->tm_wday == 0 ? 7 : some_tm->tm_wday,
               1 + some_tm->tm_yday, some_tm->tm_isdst, GMTOFF(some_tm));
}

unsigned long long
date_in_seconds(ha_time_t * dt)
{
    int lpc;
    ha_time_t *utc = NULL;
    unsigned long long in_seconds = 0;

    utc = crm_get_utc_time(dt);

    for(lpc = 1; lpc < utc->years; lpc++) {
        int dmax = year_days(lpc);
        in_seconds += 60 * 60 * 24 * dmax;
    }

    in_seconds += 60 * 60 * 24 * utc->days;
    in_seconds += 60 * utc->seconds;

    free_ha_date(utc);
    return in_seconds;
}

#define EPOCH_SECONDS 62135683200 /* Calculated using date_in_seconds() */
unsigned long long
date_in_seconds_since_epoch(ha_time_t * dt)
{
    return date_in_seconds(dt) - EPOCH_SECONDS;
}
