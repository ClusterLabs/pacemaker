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

gboolean gregorian_to_ordinal(ha_time_t * a_date);
gboolean ordinal_to_gregorian(ha_time_t * a_date);
gboolean ordinal_to_weekdays(ha_time_t * a_date);
void normalize_time(ha_time_t * a_time);

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
        dt = date_time;
    } else {
        dt = date_time->normalized;
    }

    CRM_CHECK(dt != NULL, return NULL);

    if (flags & ha_log_date) {
        date_s = calloc(1, 32);
        if (date_s == NULL) {
            return NULL;

        } else if (flags & ha_date_weeks) {
            snprintf(date_s, 31, "%d-W%.2d-%d", dt->weekyears, dt->weeks, dt->weekdays);

        } else if (flags & ha_date_ordinal) {
            snprintf(date_s, 31, "%d-%.3d", dt->years, dt->yeardays);

        } else {
            snprintf(date_s, 31, "%.4d-%.2d-%.2d", dt->years, dt->months, dt->days);
        }
    }
    if (flags & ha_log_time) {
        int offset = 0;

        time_s = calloc(1, 32);
        if (time_s == NULL) {
            goto cleanup;
        }

        snprintf(time_s, 31, "%.2d:%.2d:%.2d", dt->hours, dt->minutes, dt->seconds);

        if (dt->offset != NULL) {
            offset = (dt->offset->hours * 100) + dt->offset->minutes;
        }

        offset_s = calloc(1, 32);
        if ((flags & ha_log_local) == 0 || offset == 0) {
            snprintf(offset_s, 31, "Z");

        } else {
            int hr = dt->offset->hours;
            int mins = dt->offset->minutes;

            if (hr < 0) {
                hr = 0 - hr;
            }
            if (mins < 0) {
                mins = 0 - mins;
            }
            snprintf(offset_s, 31, " %s%.2d:%.2d", offset > 0 ? "+" : "-", hr, mins);
        }
    }

    result_s = calloc(1, 100);

    snprintf(result_s, 100, "%s%s%s%s",
             date_s ? date_s : "", (date_s != NULL && time_s != NULL) ? " " : "",
             time_s ? time_s : "", offset_s ? offset_s : "");

  cleanup:
    free(date_s);
    free(time_s);
    free(offset_s);

    return result_s;
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

ha_time_t *
parse_time_offset(char **offset_str)
{
    ha_time_t *new_time = NULL;

    new_time = calloc(1, sizeof(ha_time_t));
    new_time->has = calloc(1, sizeof(ha_has_time_t));

    if ((*offset_str)[0] == 'Z') {

    } else if ((*offset_str)[0] == '+' || (*offset_str)[0] == '-' || isdigit((int)(*offset_str)[0])) {
        gboolean negate = FALSE;

        if ((*offset_str)[0] == '-') {
            negate = TRUE;
            (*offset_str)++;
        }
        parse_time(offset_str, new_time, FALSE);
        if (negate) {
            new_time->hours = 0 - new_time->hours;
            new_time->minutes = 0 - new_time->minutes;
            new_time->seconds = 0 - new_time->seconds;
        }

    } else {
#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        time_t now = time(NULL);
        struct tm *now_tm = localtime(&now);
#endif
        int h_offset = GMTOFF(now_tm) / (3600);
        int m_offset = (GMTOFF(now_tm) - (3600 * h_offset)) / (60);

        if (h_offset < 0 && m_offset < 0) {
            m_offset = 0 - m_offset;
        }
        new_time->hours = h_offset;
        new_time->minutes = m_offset;
        new_time->has->hours = TRUE;
        new_time->has->minutes = TRUE;
    }
    return new_time;
}

ha_time_t *
parse_time(char **time_str, ha_time_t * a_time, gboolean with_offset)
{
    ha_time_t *new_time = a_time;

    tzset();
    if (a_time == NULL) {
        new_time = new_ha_date(FALSE);
    }

    CRM_CHECK(new_time != NULL, return NULL);
    CRM_CHECK(new_time->has != NULL, free_ha_date(new_time); return NULL);

    /* reset the time fields */
    new_time->hours = 0;
    new_time->minutes = 0;
    new_time->seconds = 0;

    crm_trace("Get hours...");
    new_time->has->hours = FALSE;
    if (parse_int(time_str, 2, 24, &new_time->hours)) {
        new_time->has->hours = TRUE;
    }

    crm_trace("Get minutes...");
    new_time->has->minutes = FALSE;
    if (parse_int(time_str, 2, 60, &new_time->minutes)) {
        new_time->has->minutes = TRUE;
    }

    crm_trace("Get seconds...");
    new_time->has->seconds = FALSE;
    if (parse_int(time_str, 2, 60, &new_time->seconds)) {
        new_time->has->seconds = TRUE;
    }

    if (with_offset) {
        crm_trace("Get offset...");
        while (isspace((int)(*time_str)[0])) {
            (*time_str)++;
        }

        new_time->offset = parse_time_offset(time_str);
        normalize_time(new_time);
    }
    return new_time;
}

void
normalize_time(ha_time_t * a_time)
{
    CRM_CHECK(a_time != NULL, return);
    CRM_CHECK(a_time->has != NULL, return);

    if (a_time->normalized == NULL) {
        a_time->normalized = calloc(1, sizeof(ha_time_t));
    }
    if (a_time->normalized->has == NULL) {
        a_time->normalized->has = calloc(1, sizeof(ha_has_time_t));
    }

    ha_set_time(a_time->normalized, a_time, FALSE);
    if (a_time->offset != NULL) {
        if (a_time->offset->has->hours) {
            sub_hours(a_time->normalized, a_time->offset->hours);
        }
        if (a_time->offset->has->minutes) {
            sub_minutes(a_time->normalized, a_time->offset->minutes);
        }
        if (a_time->offset->has->seconds) {
            sub_seconds(a_time->normalized, a_time->offset->seconds);
        }
    }
    CRM_CHECK(is_date_sane(a_time), return);
}

ha_time_t *
parse_date(char **date_str)
{
    gboolean is_done = FALSE;
    gboolean converted = FALSE;
    ha_time_t *new_time = NULL;

    CRM_CHECK(date_str != NULL, return NULL);
    CRM_CHECK(strlen(*date_str) > 0, return NULL);

    if ((*date_str)[0] == 'T' || (*date_str)[2] == ':') {
        /* Just a time supplied - Infer current date */
        new_time = new_ha_date(TRUE);

        parse_time(date_str, new_time, TRUE);
        normalize_time(new_time);
        is_done = TRUE;

    } else {
        new_time = calloc(1, sizeof(ha_time_t));
        new_time->has = calloc(1, sizeof(ha_has_time_t));
    }

    while (is_done == FALSE) {
        char ch = (*date_str)[0];

        crm_trace("Switching on ch=%c (len=%d)", ch, (int)strlen(*date_str));

        if (ch == 0) {
            /* all done */
            is_done = TRUE;
            break;

        } else if (ch == '/') {
            /* all done - interval marker */
            is_done = TRUE;
            break;

        } else if (ch == 'W') {
            CRM_CHECK(new_time->has->weeks == FALSE,;);
            (*date_str)++;
            if (parse_int(date_str, 2, 53, &new_time->weeks)) {
                new_time->has->weeks = TRUE;
                new_time->weekyears = new_time->years;
                new_time->has->weekyears = new_time->has->years;
            }
            if ((*date_str)[0] == '-') {
                (*date_str)++;
                if (parse_int(date_str, 1, 7, &new_time->weekdays)) {
                    new_time->has->weekdays = TRUE;
                }
            }

            if (new_time->weekdays == 0 || new_time->has->weekdays == FALSE) {
                new_time->weekdays = 1;
                new_time->has->weekdays = TRUE;
            }

        } else if (ch == '-') {
            (*date_str)++;
            if (check_for_ordinal(*date_str)) {
                if (parse_int(date_str, 3, 366, &new_time->yeardays)) {
                    new_time->has->yeardays = TRUE;
                }
            }

        } else if (ch == 'O') {
            /* ordinal date */
            (*date_str)++;
            if (parse_int(date_str, 3, 366, &new_time->yeardays)) {
                new_time->has->yeardays = TRUE;
            }

        } else if (ch == 'T' || ch == ' ') {
            if (new_time->has->yeardays) {
                converted = convert_from_ordinal(new_time);

            } else if (new_time->has->weekdays) {
                converted = convert_from_weekdays(new_time);

            } else {
                converted = convert_from_gregorian(new_time);
            }
            (*date_str)++;
            parse_time(date_str, new_time, TRUE);
            is_done = TRUE;

        } else if (isdigit((int)ch)) {
            if (new_time->has->years == FALSE && parse_int(date_str, 4, 9999, &new_time->years)) {
                new_time->has->years = TRUE;

            } else if (check_for_ordinal(*date_str) && parse_int(date_str, 3,
                                                                 is_leap_year(new_time->years) ? 366
                                                                 : 365, &new_time->yeardays)) {
                new_time->has->yeardays = TRUE;

            } else if (new_time->has->months == FALSE
                       && parse_int(date_str, 2, 12, &new_time->months)) {
                new_time->has->months = TRUE;

            } else if (new_time->has->days == FALSE) {
                if (parse_int(date_str, 2,
                              days_per_month(new_time->months, new_time->years), &new_time->days)) {
                    new_time->has->days = TRUE;
                }
            }

        } else {
            crm_err("Unexpected characters at: %s", *date_str);
            is_done = TRUE;
            break;
        }
    }

    if (converted) {

    } else if (new_time->has->yeardays) {
        convert_from_ordinal(new_time);

    } else if (new_time->has->weekdays) {
        convert_from_weekdays(new_time);

    } else {
        convert_from_gregorian(new_time);
    }

    normalize_time(new_time);

    log_date(LOG_DEBUG_3, "Unpacked", new_time, ha_log_date | ha_log_time);

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
    diff->has = calloc(1, sizeof(ha_has_time_t));

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
                diff->has->years = TRUE;
                break;
            case 'M':
                if (is_time) {
                    diff->minutes = an_int;
                    diff->has->minutes = TRUE;
                } else {
                    diff->months = an_int;
                    diff->has->months = TRUE;
                }
                break;
            case 'W':
                diff->weeks = an_int;
                diff->has->weeks = TRUE;
                break;
            case 'D':
                diff->days = an_int;
                diff->has->days = TRUE;
                diff->yeardays = an_int;
                diff->has->yeardays = TRUE;
                break;
            case 'H':
                diff->hours = an_int;
                diff->has->hours = TRUE;
                break;
            case 'S':
                diff->seconds = an_int;
                diff->has->seconds = TRUE;
                break;
            default:
                goto bail;
                break;
        }
    }
    return diff;

  bail:
    if (diff) {
        free(diff->has);
    }
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
        period->start->has = calloc(1, sizeof(ha_has_time_t));
        period->start->offset = calloc(1, sizeof(ha_time_t));
        period->start->offset->has = calloc(1, sizeof(ha_has_time_t));

        ha_set_timet_time(period->start, &now);
        normalize_time(period->start);

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
        normalize_time(period->start);

    } else if (period->end == NULL) {
        period->end = add_time(period->start, period->diff);
        normalize_time(period->end);
    }

    is_date_sane(period->start);
    is_date_sane(period->end);

    return period;
}

int month2days[13] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };

/* http://www.personal.ecu.edu/mccartyr/ISOwdALG.txt */
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

gboolean
convert_from_gregorian(ha_time_t * a_date)
{
    CRM_CHECK(gregorian_to_ordinal(a_date), return FALSE);
    CRM_CHECK(ordinal_to_weekdays(a_date), return FALSE);
    return TRUE;
}

gboolean
gregorian_to_ordinal(ha_time_t * a_date)
{
    CRM_CHECK(a_date->has->years, return FALSE);
    CRM_CHECK(a_date->has->months, return FALSE);
    CRM_CHECK(a_date->has->days, return FALSE);

    CRM_CHECK(a_date->months > 0, return FALSE);
    CRM_CHECK(a_date->days > 0, return FALSE);

    a_date->yeardays = month2days[a_date->months - 1];
    a_date->yeardays += a_date->days;
    a_date->has->yeardays = TRUE;

    if (is_leap_year(a_date->years) && a_date->months > 2) {
        (a_date->yeardays)++;
    }
    crm_trace("Converted %.4d-%.2d-%.2d to %.4d-%.3d",
              a_date->years, a_date->months, a_date->days, a_date->years, a_date->yeardays);

    return TRUE;
}

gboolean
convert_from_ordinal(ha_time_t * a_date)
{
    CRM_CHECK(ordinal_to_gregorian(a_date), return FALSE);
    CRM_CHECK(ordinal_to_weekdays(a_date), return FALSE);
    return TRUE;
}

gboolean
ordinal_to_gregorian(ha_time_t * a_date)
{
    /* Day of the year this month ends on */
    int m_end = 0;

    CRM_CHECK(a_date->has->years, return FALSE);
    CRM_CHECK(a_date->has->yeardays, return FALSE);

    CRM_CHECK(a_date->yeardays > 0, return FALSE);

    if (is_leap_year(a_date->years) && a_date->yeardays > 366) {
        crm_err("Year %.4d only has 366 days (supplied %.3d)", a_date->years, a_date->yeardays);
        a_date->yeardays = 366;

    } else if (!is_leap_year(a_date->years) && a_date->yeardays > 365) {
        crm_err("Year %.4d only has 365 days (supplied %.3d)", a_date->years, a_date->yeardays);
        a_date->yeardays = 365;
    }

    a_date->days = a_date->yeardays;
    a_date->months = 0;
    do {
        a_date->months++;
        m_end += days_per_month(a_date->months, a_date->years);
        a_date->days -= days_per_month(a_date->months - 1, a_date->years);

        crm_trace("month %d: %d vs. %d - current day: %d",
                  a_date->months, a_date->yeardays, m_end, a_date->days);
    } while (a_date->months < 12 && m_end < a_date->yeardays);

    CRM_CHECK(a_date->months > 0, return FALSE);
    CRM_CHECK(a_date->days <= days_per_month(a_date->months, a_date->years), return FALSE);

    a_date->has->days = TRUE;
    a_date->has->months = TRUE;
    a_date->has->years = TRUE;

    crm_trace("Converted %.4d-%.3d to %.4d-%.2d-%.2d",
              a_date->years, a_date->yeardays, a_date->years, a_date->months, a_date->days);

    return TRUE;
}

gboolean
ordinal_to_weekdays(ha_time_t * a_date)
{
    int year_num = 0;
    int jan1 = january1(a_date->years);
    int h = -1;

    CRM_CHECK(a_date->has->years, return FALSE);
    CRM_CHECK(a_date->has->yeardays, return FALSE);
    CRM_CHECK(a_date->yeardays > 0, return FALSE);

    h = a_date->yeardays + jan1 - 1;
    a_date->weekdays = 1 + ((h - 1) % 7);
    a_date->has->weekdays = TRUE;

    if (a_date->yeardays <= (8 - jan1) && jan1 > 4) {
        year_num = a_date->years - 1;
        a_date->weeks = weeks_in_year(year_num);
        a_date->has->weeks = TRUE;

    } else {
        year_num = a_date->years;
    }

    if (year_num == a_date->years) {
        int i = 365;

        if (is_leap_year(year_num)) {
            i = 366;
        }
        if ((i - a_date->yeardays) < (4 - a_date->weekdays)) {
            year_num = a_date->years + 1;
            a_date->weeks = 1;
            a_date->has->weeks = TRUE;
        }
    }

    if (year_num == a_date->years) {
        int j = a_date->yeardays + (7 - a_date->weekdays) + (jan1 - 1);

        a_date->weeks = j / 7;
        a_date->has->weeks = TRUE;
        if (jan1 > 4) {
            a_date->weeks -= 1;
        }
    }

    a_date->weekyears = year_num;
    a_date->has->weekyears = TRUE;
    crm_trace("Converted %.4d-%.3d to %.4dW%.2d-%d",
              a_date->years, a_date->yeardays, a_date->weekyears, a_date->weeks, a_date->weekdays);
    return TRUE;
}

gboolean
convert_from_weekdays(ha_time_t * a_date)
{
    gboolean conversion = FALSE;
    int jan1 = january1(a_date->weekyears);

    CRM_CHECK(a_date->has->weekyears, return FALSE);
    CRM_CHECK(a_date->has->weeks, return FALSE);
    CRM_CHECK(a_date->has->weekdays, return FALSE);

    CRM_CHECK(a_date->weeks > 0, return FALSE);
    CRM_CHECK(a_date->weekdays > 0, return FALSE);
    CRM_CHECK(a_date->weekdays < 8, return FALSE);

    a_date->has->years = TRUE;
    a_date->years = a_date->weekyears;

    a_date->has->yeardays = TRUE;
    a_date->yeardays = (7 * (a_date->weeks - 1));

    /* break up the addition to make sure overflows are correctly handled */
    if (a_date->yeardays == 0) {
        a_date->yeardays = a_date->weekdays;
    } else {
        add_yeardays(a_date, a_date->weekdays);
    }

    crm_trace("Pre-conversion: %dW%d-%d to %.4d-%.3d",
              a_date->weekyears, a_date->weeks, a_date->weekdays, a_date->years, a_date->yeardays);

    conversion = ordinal_to_gregorian(a_date);

    if (conversion) {
        if (jan1 < 4) {
            sub_days(a_date, jan1 - 1);
        } else if (jan1 > 4) {
            add_days(a_date, jan1 - 4);
        }
    }
    return conversion;
}

void
ha_set_time(ha_time_t * lhs, ha_time_t * rhs, gboolean offset)
{
    crm_trace("lhs=%p, rhs=%p, offset=%d", lhs, rhs, offset);

    CRM_CHECK(lhs != NULL && rhs != NULL, return);
    CRM_CHECK(lhs->has != NULL && rhs->has != NULL, return);

    lhs->years = rhs->years;
    lhs->has->years = rhs->has->years;

    lhs->weekyears = rhs->weekyears;
    lhs->has->weekyears = rhs->has->weekyears;

    lhs->months = rhs->months;
    lhs->has->months = rhs->has->months;

    lhs->weeks = rhs->weeks;
    lhs->has->weeks = rhs->has->weeks;

    lhs->days = rhs->days;
    lhs->has->days = rhs->has->days;

    lhs->weekdays = rhs->weekdays;
    lhs->has->weekdays = rhs->has->weekdays;

    lhs->yeardays = rhs->yeardays;
    lhs->has->yeardays = rhs->has->yeardays;

    lhs->hours = rhs->hours;
    lhs->has->hours = rhs->has->hours;

    lhs->minutes = rhs->minutes;
    lhs->has->minutes = rhs->has->minutes;

    lhs->seconds = rhs->seconds;
    lhs->has->seconds = rhs->has->seconds;

    if (lhs->offset) {
        reset_time(lhs->offset);
    }
    if (offset && rhs->offset) {
        ha_set_time(lhs->offset, rhs->offset, FALSE);
    }

}

void
ha_set_tm_time(ha_time_t * lhs, struct tm *rhs)
{
    int wday = rhs->tm_wday;
    int h_offset = 0;
    int m_offset = 0;

    if (rhs->tm_year > 0) {
        /* years since 1900 */
        lhs->years = 1900 + rhs->tm_year;
        lhs->has->years = TRUE;
    }

    if (rhs->tm_yday >= 0) {
        /* days since January 1 [0-365] */
        lhs->yeardays = 1 + rhs->tm_yday;
        lhs->has->yeardays = TRUE;
    }

    if (rhs->tm_hour >= 0) {
        lhs->hours = rhs->tm_hour;
        lhs->has->hours = TRUE;
    }
    if (rhs->tm_min >= 0) {
        lhs->minutes = rhs->tm_min;
        lhs->has->minutes = TRUE;
    }
    if (rhs->tm_sec >= 0) {
        lhs->seconds = rhs->tm_sec;
        lhs->has->seconds = TRUE;
    }

    convert_from_ordinal(lhs);

    /* months since January [0-11] */
    CRM_CHECK(rhs->tm_mon < 0 || lhs->months == (1 + rhs->tm_mon), return);

    /* day of the month [1-31] */
    CRM_CHECK(rhs->tm_mday < 0 || lhs->days == rhs->tm_mday, return);

    /* days since Sunday [0-6] */
    if (wday == 0) {
        wday = 7;
    }

    CRM_CHECK(rhs->tm_wday < 0 || lhs->weekdays == wday, return);
    CRM_CHECK(lhs->offset != NULL, return);
    CRM_CHECK(lhs->offset->has != NULL, return);

    /* tm_gmtoff == offset from UTC in seconds */
    h_offset = GMTOFF(rhs) / (3600);
    m_offset = (GMTOFF(rhs) - (3600 * h_offset)) / (60);
    crm_trace("Offset (s): %ld, offset (hh:mm): %.2d:%.2d", GMTOFF(rhs), h_offset, m_offset);

    lhs->offset->hours = h_offset;
    lhs->offset->has->hours = TRUE;

    lhs->offset->minutes = m_offset;
    lhs->offset->has->minutes = TRUE;

    normalize_time(lhs);
}

void
ha_set_timet_time(ha_time_t * lhs, time_t * rhs)
{
    ha_set_tm_time(lhs, localtime(rhs));
}

ha_time_t *
add_time(ha_time_t * lhs, ha_time_t * rhs)
{
    ha_time_t *answer = NULL;

    CRM_CHECK(lhs != NULL && rhs != NULL, return NULL);

    answer = new_ha_date(FALSE);
    ha_set_time(answer, lhs, TRUE);

    normalize_time(lhs);
    normalize_time(answer);

    if (rhs->has->years) {
        add_years(answer, rhs->years);
    }
    if (rhs->has->months) {
        add_months(answer, rhs->months);
    }
    if (rhs->has->weeks) {
        add_weeks(answer, rhs->weeks);
    }
    if (rhs->has->days) {
        add_days(answer, rhs->days);
    }

    add_hours(answer, rhs->hours);
    add_minutes(answer, rhs->minutes);
    add_seconds(answer, rhs->seconds);

    normalize_time(answer);

    return answer;
}

ha_time_t *
subtract_time(ha_time_t * lhs, ha_time_t * rhs)
{
    ha_time_t *answer = NULL;

    CRM_CHECK(lhs != NULL && rhs != NULL, return NULL);

    answer = new_ha_date(FALSE);
    ha_set_time(answer, lhs, TRUE);

    normalize_time(lhs);
    normalize_time(rhs);
    normalize_time(answer);

    sub_seconds(answer, rhs->seconds);
    sub_minutes(answer, rhs->minutes);
    sub_hours(answer, rhs->hours);

    answer->yeardays -= rhs->yeardays;
    while (answer->yeardays < 0) {
        answer->yeardays += is_leap_year(answer->years) ? 356 : 355;
        answer->years--;
    }

    answer->days -= rhs->days;
    while (answer->days < 0) {
        answer->days += days_per_month(answer->months, answer->years);
        answer->months--;
    }

    answer->months -= rhs->months;
    while (answer->months < 0) {
        answer->months += 12;
        /* answer->years--; : done in the yeardays section */
    }

    answer->years -= rhs->years;

    return answer;
}

ha_time_t *
subtract_duration(ha_time_t * lhs, ha_time_t * rhs)
{
    ha_time_t *answer = NULL;

    CRM_CHECK(lhs != NULL && rhs != NULL, return NULL);

    answer = new_ha_date(FALSE);
    ha_set_time(answer, lhs, TRUE);

    normalize_time(lhs);
    normalize_time(rhs);
    normalize_time(answer);

    sub_seconds(answer, rhs->seconds);
    sub_minutes(answer, rhs->minutes);
    sub_hours(answer, rhs->hours);

    sub_days(answer, rhs->days);
    sub_weeks(answer, rhs->weeks);
    sub_months(answer, rhs->months);
    sub_years(answer, rhs->years);

    normalize_time(answer);

    return answer;
}

/* ha_time_interval_t* */
/* parse_time_interval(char **interval_str) */
/* { */
/* 	return NULL; */
/* } */

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

gboolean
check_for_ordinal(const char *str)
{
    if (isdigit((int)str[2]) == FALSE) {
        crm_trace("char 3 == %c", str[2]);
        return FALSE;
    }
    if (isspace((int)str[3])) {
        return TRUE;
    } else if (str[3] == 0) {
        return TRUE;
    } else if (str[3] == 'T') {
        return TRUE;
    } else if (str[3] == '/') {
        return TRUE;
    }
    crm_trace("char 4 == %c", str[3]);
    return FALSE;
}

int
str_lookup(const char *str, enum date_fields field)
{
    return 0;
}

void
reset_time(ha_time_t * a_time)
{
    a_time->years = 0;
    a_time->has->years = FALSE;

    a_time->weekyears = 0;
    a_time->has->weekyears = FALSE;

    a_time->months = 0;
    a_time->has->months = FALSE;

    a_time->weeks = 0;
    a_time->has->weeks = FALSE;

    a_time->days = 0;
    a_time->has->days = FALSE;

    a_time->weekdays = 0;
    a_time->has->weekdays = FALSE;

    a_time->yeardays = 0;
    a_time->has->yeardays = FALSE;

    a_time->hours = 0;
    a_time->has->hours = FALSE;

    a_time->minutes = 0;
    a_time->has->minutes = FALSE;

    a_time->seconds = 0;
    a_time->has->seconds = FALSE;
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
is_date_sane(ha_time_t * a_date)
{
    int ydays = 0;
    int mdays = 0;
    int weeks = 0;

    CRM_CHECK(a_date != NULL, return FALSE);

    ydays = is_leap_year(a_date->years) ? 366 : 365;
    mdays = days_per_month(a_date->months, a_date->years);
    weeks = weeks_in_year(a_date->weekyears);
    crm_trace("max ydays: %d, max mdays: %d, max weeks: %d", ydays, mdays, weeks);

    CRM_CHECK(a_date->has->years, return FALSE);
    CRM_CHECK(a_date->has->weekyears, return FALSE);

    CRM_CHECK(a_date->has->months, return FALSE);
    CRM_CHECK(a_date->months > 0, return FALSE);
    CRM_CHECK(a_date->months <= 12, return FALSE);

    CRM_CHECK(a_date->has->weeks, return FALSE);
    CRM_CHECK(a_date->weeks > 0, return FALSE);
    CRM_CHECK(a_date->weeks <= weeks, return FALSE);

    CRM_CHECK(a_date->has->days, return FALSE);
    CRM_CHECK(a_date->days > 0, return FALSE);
    CRM_CHECK(a_date->days <= mdays, return FALSE);

    CRM_CHECK(a_date->has->weekdays, return FALSE);
    CRM_CHECK(a_date->weekdays > 0, return FALSE);
    CRM_CHECK(a_date->weekdays <= 7, return FALSE);

    CRM_CHECK(a_date->has->yeardays, return FALSE);
    CRM_CHECK(a_date->yeardays > 0, return FALSE);
    CRM_CHECK(a_date->yeardays <= ydays, return FALSE);

    CRM_CHECK(a_date->hours >= 0, return FALSE);
    CRM_CHECK(a_date->hours < 24, return FALSE);

    CRM_CHECK(a_date->minutes >= 0, return FALSE);
    CRM_CHECK(a_date->minutes < 60, return FALSE);

    CRM_CHECK(a_date->seconds >= 0, return FALSE);
    CRM_CHECK(a_date->seconds <= 60, return FALSE);

    return TRUE;
}

#define do_cmp_field(lhs, rhs, field)					\
	{								\
		if(lhs->field > rhs->field) {				\
			crm_trace("%s: %d > %d",			\
				    #field, lhs->field, rhs->field);	\
			return 1;					\
		} else if(lhs->field < rhs->field) {			\
			crm_trace("%s: %d < %d",			\
				    #field, lhs->field, rhs->field);	\
			return -1;					\
		}							\
	}

int
compare_date(ha_time_t * lhs, ha_time_t * rhs)
{
    if (lhs == NULL && rhs == NULL) {
        return 0;
    } else if (lhs == NULL) {
        return -1;
    } else if (rhs == NULL) {
        return 1;
    }

    normalize_time(lhs);
    normalize_time(rhs);

    do_cmp_field(lhs->normalized, rhs->normalized, years);
    do_cmp_field(lhs->normalized, rhs->normalized, yeardays);
    do_cmp_field(lhs->normalized, rhs->normalized, hours);
    do_cmp_field(lhs->normalized, rhs->normalized, minutes);
    do_cmp_field(lhs->normalized, rhs->normalized, seconds);

    return 0;
}

ha_time_t *
new_ha_date(gboolean set_to_now)
{
    time_t tm_now;
    ha_time_t *now = NULL;

    tzset();
    now = calloc(1, sizeof(ha_time_t));
    now->has = calloc(1, sizeof(ha_has_time_t));
    now->offset = calloc(1, sizeof(ha_time_t));
    now->offset->has = calloc(1, sizeof(ha_has_time_t));
    if (set_to_now) {
        tm_now = time(NULL);
        now->tm_now = tm_now;
        ha_set_timet_time(now, &tm_now);
    }
    return now;
}

void
free_ha_date(ha_time_t * a_date)
{
    if (a_date == NULL) {
        return;
    }
    free_ha_date(a_date->normalized);
    free_ha_date(a_date->offset);
    free(a_date->has);
    free(a_date);
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

ha_time_t *the_epoch = NULL;

#define update_seconds(date, field, multiplier) do {		\
	before = in_seconds;					\
	in_seconds += a_date->field;				\
	in_seconds *= multiplier;				\
	if(before > in_seconds) {				\
	    crm_crit("Date wrap detected: %s", #field);		\
	    return 0;						\
	}							\
    } while(0)

unsigned long long
date_in_seconds(ha_time_t * a_date)
{
    unsigned long long before = 0;
    unsigned long long in_seconds = 0;

    /* normalize_time(a_date); */
    update_seconds(a_date, years, 365);
    update_seconds(a_date, yeardays, 24);
    update_seconds(a_date, hours, 60);
    update_seconds(a_date, minutes, 60);
    update_seconds(a_date, seconds, 1);
    return in_seconds;
}

unsigned long long
date_in_seconds_since_epoch(ha_time_t * a_date)
{
    ha_time_t *since_epoch = NULL;
    unsigned long long in_seconds = 0;

    normalize_time(a_date);

    if (the_epoch == NULL) {
        char *EPOCH = crm_strdup("1970-01-01");

        the_epoch = parse_date(&EPOCH);
        normalize_time(the_epoch);
        free(EPOCH);
    }

    since_epoch = subtract_time(a_date, the_epoch);
    in_seconds = date_in_seconds(since_epoch);
    free_ha_date(since_epoch);
    return in_seconds;
}
