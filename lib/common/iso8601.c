/*
 * Copyright 2005-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

/*
 * References:
 *	https://en.wikipedia.org/wiki/ISO_8601
 *	http://www.staff.science.uu.nl/~gent0113/calendar/isocalendar.htm
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
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
#  define GMTOFF(tm) (-timezone+daylight)
#endif

#define HOUR_SECONDS    (60 * 60)
#define DAY_SECONDS     (HOUR_SECONDS * 24)

/*!
 * \internal
 * \brief Validate a seconds/microseconds tuple
 *
 * The microseconds value must be in the correct range, and if both are nonzero
 * they must have the same sign.
 *
 * \param[in] sec   Seconds
 * \param[in] usec  Microseconds
 *
 * \return true if the seconds/microseconds tuple is valid, or false otherwise
 */
#define valid_sec_usec(sec, usec)               \
        ((QB_ABS(usec) < QB_TIME_US_IN_SEC)     \
         && (((sec) == 0) || ((usec) == 0) || (((sec) < 0) == ((usec) < 0))))

// A date/time or duration
struct crm_time_s {
    int years;      // Calendar year (date/time) or number of years (duration)
    int months;     // Number of months (duration only)
    int days;       // Ordinal day of year (date/time) or number of days (duration)
    int seconds;    // Seconds of day (date/time) or number of seconds (duration)
    int offset;     // Seconds offset from UTC (date/time only)
    bool duration;  // True if duration
};

static crm_time_t *parse_date(const char *date_str);

static crm_time_t *
crm_get_utc_time(const crm_time_t *dt)
{
    crm_time_t *utc = NULL;

    if (dt == NULL) {
        errno = EINVAL;
        return NULL;
    }

    utc = crm_time_new_undefined();
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
    tzset();
    if (date_time == NULL) {
        return pcmk__copy_timet(time(NULL));
    }
    return parse_date(date_time);
}

/*!
 * \brief Allocate memory for an uninitialized time object
 *
 * \return Newly allocated time object
 * \note The caller is responsible for freeing the return value using
 *       crm_time_free().
 */
crm_time_t *
crm_time_new_undefined(void)
{
    crm_time_t *result = calloc(1, sizeof(crm_time_t));

    CRM_ASSERT(result != NULL);
    return result;
}

/*!
 * \brief Check whether a time object has been initialized yet
 *
 * \param[in] t  Time object to check
 *
 * \return TRUE if time object has been initialized, FALSE otherwise
 */
bool
crm_time_is_defined(const crm_time_t *t)
{
    // Any nonzero member indicates something has been done to t
    return (t != NULL) && (t->years || t->months || t->days || t->seconds
                           || t->offset || t->duration);
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

/* From http://myweb.ecu.edu/mccartyr/ISOwdALG.txt :
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

// Jan-Dec plus Feb of leap years
static int month_days[13] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 29
};

/*!
 * \brief Return number of days in given month of given year
 *
 * \param[in]  Ordinal month (1-12)
 * \param[in]  Gregorian year
 *
 * \return Number of days in given month (0 if given month is invalid)
 */
int
crm_time_days_in_month(int month, int year)
{
    if ((month < 1) || (month > 12)) {
        return 0;
    }
    if ((month == 2) && crm_time_leapyear(year)) {
        month = 13;
    }
    return month_days[month - 1];
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
crm_time_log_alias(int log_level, const char *file, const char *function,
                   int line, const char *prefix, const crm_time_t *date_time,
                   int flags)
{
    char *date_s = crm_time_as_string(date_time, flags);

    if (log_level == LOG_STDOUT) {
        printf("%s%s%s\n",
               (prefix? prefix : ""), (prefix? ": " : ""), date_s);
    } else {
        do_crm_log_alias(log_level, file, function, line, "%s%s%s",
                         (prefix? prefix : ""), (prefix? ": " : ""), date_s);
    }
    free(date_s);
}

static void
crm_time_get_sec(int sec, uint32_t *h, uint32_t *m, uint32_t *s)
{
    uint32_t hours, minutes, seconds;

    seconds = QB_ABS(sec);

    hours = seconds / HOUR_SECONDS;
    seconds -= HOUR_SECONDS * hours;

    minutes = seconds / 60;
    seconds -= 60 * minutes;

    crm_trace("%d == %.2" PRIu32 ":%.2" PRIu32 ":%.2" PRIu32,
              sec, hours, minutes, seconds);

    *h = hours;
    *m = minutes;
    *s = seconds;
}

int
crm_time_get_timeofday(const crm_time_t *dt, uint32_t *h, uint32_t *m,
                       uint32_t *s)
{
    crm_time_get_sec(dt->seconds, h, m, s);
    return TRUE;
}

int
crm_time_get_timezone(const crm_time_t *dt, uint32_t *h, uint32_t *m)
{
    uint32_t s;

    crm_time_get_sec(dt->seconds, h, m, &s);
    return TRUE;
}

long long
crm_time_get_seconds(const crm_time_t *dt)
{
    int lpc;
    crm_time_t *utc = NULL;
    long long in_seconds = 0;

    if (dt == NULL) {
        return 0;
    }

    utc = crm_get_utc_time(dt);
    if (utc == NULL) {
        return 0;
    }

    for (lpc = 1; lpc < utc->years; lpc++) {
        long long dmax = year_days(lpc);

        in_seconds += DAY_SECONDS * dmax;
    }

    /* utc->months is an offset that can only be set for a duration.
     * By definition, the value is variable depending on the date to
     * which it is applied.
     *
     * Force 30-day months so that something vaguely sane happens
     * for anyone that tries to use a month in this way.
     */
    if (utc->months > 0) {
        in_seconds += DAY_SECONDS * 30 * (long long) (utc->months);
    }

    if (utc->days > 0) {
        in_seconds += DAY_SECONDS * (long long) (utc->days - 1);
    }
    in_seconds += utc->seconds;

    crm_time_free(utc);
    return in_seconds;
}

#define EPOCH_SECONDS 62135596800ULL    /* Calculated using crm_time_get_seconds() */
long long
crm_time_get_seconds_since_epoch(const crm_time_t *dt)
{
    return (dt == NULL)? 0 : (crm_time_get_seconds(dt) - EPOCH_SECONDS);
}

int
crm_time_get_gregorian(const crm_time_t *dt, uint32_t *y, uint32_t *m,
                       uint32_t *d)
{
    int months = 0;
    int days = dt->days;

    if(dt->years != 0) {
        for (months = 1; months <= 12 && days > 0; months++) {
            int mdays = crm_time_days_in_month(months, dt->years);

            if (mdays >= days) {
                break;
            } else {
                days -= mdays;
            }
        }

    } else if (dt->months) {
        /* This is a duration including months, don't convert the days field */
        months = dt->months;

    } else {
        /* This is a duration not including months, still don't convert the days field */
    }

    *y = dt->years;
    *m = months;
    *d = days;
    crm_trace("%.4d-%.3d -> %.4d-%.2d-%.2d", dt->years, dt->days, dt->years, months, days);
    return TRUE;
}

int
crm_time_get_ordinal(const crm_time_t *dt, uint32_t *y, uint32_t *d)
{
    *y = dt->years;
    *d = dt->days;
    return TRUE;
}

int
crm_time_get_isoweek(const crm_time_t *dt, uint32_t *y, uint32_t *w,
                     uint32_t *d)
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
    crm_trace("Converted %.4d-%.3d to %.4" PRIu32 "-W%.2" PRIu32 "-%" PRIu32,
              dt->years, dt->days, *y, *w, *d);
    return TRUE;
}

#define DATE_MAX 128

/*!
 * \internal
 * \brief Print "<seconds>.<microseconds>" to a buffer
 *
 * \param[in]     sec     Seconds
 * \param[in]     usec    Microseconds (must be of same sign as \p sec and of
 *                        absolute value less than \p QB_TIME_US_IN_SEC)
 * \param[in,out] buf     Result buffer
 * \param[in,out] offset  Current offset within \p buf
 */
static inline void
sec_usec_as_string(long long sec, int usec, char *buf, size_t *offset)
{
    *offset += snprintf(buf + *offset, DATE_MAX - *offset, "%s%lld.%06d",
                        ((sec == 0) && (usec < 0))? "-" : "",
                        sec, QB_ABS(usec));
}

/*!
 * \internal
 * \brief Get a string representation of a duration
 *
 * \param[in]  dt         Time object to interpret as a duration
 * \param[in]  usec       Microseconds to add to \p dt
 * \param[in]  show_usec  Whether to include microseconds in \p result
 * \param[out] result     Where to store the result string
 */
static void
crm_duration_as_string(const crm_time_t *dt, int usec, bool show_usec,
                       char *result)
{
    size_t offset = 0;

    CRM_ASSERT(valid_sec_usec(dt->seconds, usec));

    if (dt->years) {
        offset += snprintf(result + offset, DATE_MAX - offset, "%4d year%s ",
                           dt->years, pcmk__plural_s(dt->years));
    }
    if (dt->months) {
        offset += snprintf(result + offset, DATE_MAX - offset, "%2d month%s ",
                           dt->months, pcmk__plural_s(dt->months));
    }
    if (dt->days) {
        offset += snprintf(result + offset, DATE_MAX - offset, "%2d day%s ",
                           dt->days, pcmk__plural_s(dt->days));
    }

    // At least print seconds (and optionally usecs)
    if ((offset == 0) || (dt->seconds != 0) || (show_usec && (usec != 0))) {
        if (show_usec) {
            sec_usec_as_string(dt->seconds, usec, result, &offset);
        } else {
            offset += snprintf(result + offset, DATE_MAX - offset, "%d",
                               dt->seconds);
        }
        offset += snprintf(result + offset, DATE_MAX - offset, " second%s",
                           pcmk__plural_s(dt->seconds));
    }

    // More than one minute, so provide a more readable breakdown into units
    if (QB_ABS(dt->seconds) >= 60) {
        uint32_t h = 0;
        uint32_t m = 0;
        uint32_t s = 0;
        uint32_t u = QB_ABS(usec);
        bool print_sec_component = false;

        crm_time_get_sec(dt->seconds, &h, &m, &s);
        print_sec_component = ((s != 0) || (show_usec && (u != 0)));

        offset += snprintf(result + offset, DATE_MAX - offset, " (");

        if (h) {
            offset += snprintf(result + offset, DATE_MAX - offset,
                               "%" PRIu32 " hour%s%s", h, pcmk__plural_s(h),
                               ((m != 0) || print_sec_component)? " " : "");
        }

        if (m) {
            offset += snprintf(result + offset, DATE_MAX - offset,
                               "%" PRIu32 " minute%s%s", m, pcmk__plural_s(m),
                               print_sec_component? " " : "");
        }

        if (print_sec_component) {
            if (show_usec) {
                sec_usec_as_string(s, u, result, &offset);
            } else {
                offset += snprintf(result + offset, DATE_MAX - offset,
                                   "%" PRIu32, s);
            }
            offset += snprintf(result + offset, DATE_MAX - offset, " second%s",
                               pcmk__plural_s(dt->seconds));
        }

        offset += snprintf(result + offset, DATE_MAX - offset, ")");
    }
}

/*!
 * \internal
 * \brief Get a string representation of a time object
 *
 * \param[in]  dt      Time to convert to string
 * \param[in]  usec    Microseconds to add to \p dt
 * \param[in]  flags   Group of \p crm_time_* string format options
 * \param[out] result  Where to store the result string
 *
 * \note \p result must be of size \p DATE_MAX or larger.
 */
static void
time_as_string_common(const crm_time_t *dt, int usec, uint32_t flags,
                      char *result)
{
    crm_time_t *utc = NULL;
    size_t offset = 0;

    if (!crm_time_is_defined(dt)) {
        strcpy(result, "<undefined time>");
        return;
    }

    CRM_ASSERT(valid_sec_usec(dt->seconds, usec));

    /* Simple cases: as duration, seconds, or seconds since epoch.
     * These never depend on time zone.
     */

    if (pcmk_is_set(flags, crm_time_log_duration)) {
        crm_duration_as_string(dt, usec, pcmk_is_set(flags, crm_time_usecs),
                               result);
        return;
    }

    if (pcmk_any_flags_set(flags, crm_time_seconds|crm_time_epoch)) {
        long long seconds = 0;

        if (pcmk_is_set(flags, crm_time_seconds)) {
            seconds = crm_time_get_seconds(dt);
        } else {
            seconds = crm_time_get_seconds_since_epoch(dt);
        }

        if (pcmk_is_set(flags, crm_time_usecs)) {
            sec_usec_as_string(seconds, usec, result, &offset);
        } else {
            snprintf(result, DATE_MAX, "%lld", seconds);
        }
        return;
    }

    // Convert to UTC if local timezone was not requested
    if ((dt->offset != 0) && !pcmk_is_set(flags, crm_time_log_with_timezone)) {
        crm_trace("UTC conversion");
        utc = crm_get_utc_time(dt);
        dt = utc;
    }

    // As readable string

    if (pcmk_is_set(flags, crm_time_log_date)) {
        if (pcmk_is_set(flags, crm_time_weeks)) { // YYYY-WW-D
            uint32_t y, w, d;

            if (crm_time_get_isoweek(dt, &y, &w, &d)) {
                offset += snprintf(result + offset, DATE_MAX - offset,
                                   "%" PRIu32 "-W%.2" PRIu32 "-%" PRIu32,
                                   y, w, d);
            }

        } else if (pcmk_is_set(flags, crm_time_ordinal)) { // YYYY-DDD
            uint32_t y, d;

            if (crm_time_get_ordinal(dt, &y, &d)) {
                offset += snprintf(result + offset, DATE_MAX - offset,
                                   "%" PRIu32 "-%.3" PRIu32, y, d);
            }

        } else { // YYYY-MM-DD
            uint32_t y, m, d;

            if (crm_time_get_gregorian(dt, &y, &m, &d)) {
                offset += snprintf(result + offset, DATE_MAX - offset,
                                   "%.4" PRIu32 "-%.2" PRIu32 "-%.2" PRIu32,
                                   y, m, d);
            }
        }
    }

    if (pcmk_is_set(flags, crm_time_log_timeofday)) {
        uint32_t h = 0, m = 0, s = 0;

        if (offset > 0) {
            offset += snprintf(result + offset, DATE_MAX - offset, " ");
        }

        if (crm_time_get_timeofday(dt, &h, &m, &s)) {
            offset += snprintf(result + offset, DATE_MAX - offset,
                               "%.2" PRIu32 ":%.2" PRIu32 ":%.2" PRIu32,
                               h, m, s);

            if (pcmk_is_set(flags, crm_time_usecs)) {
                offset += snprintf(result + offset, DATE_MAX - offset,
                                   ".%06" PRIu32, QB_ABS(usec));
            }
        }

        if (pcmk_is_set(flags, crm_time_log_with_timezone)
            && (dt->offset != 0)) {
            crm_time_get_sec(dt->offset, &h, &m, &s);
            offset += snprintf(result + offset, DATE_MAX - offset,
                               " %c%.2" PRIu32 ":%.2" PRIu32,
                               ((dt->offset < 0)? '-' : '+'), h, m);
        } else {
            offset += snprintf(result + offset, DATE_MAX - offset, "Z");
        }
    }

    crm_time_free(utc);
}

/*!
 * \brief Get a string representation of a \p crm_time_t object
 *
 * \param[in]  dt      Time to convert to string
 * \param[in]  flags   Group of \p crm_time_* string format options
 *
 * \note The caller is responsible for freeing the return value using \p free().
 */
char *
crm_time_as_string(const crm_time_t *dt, int flags)
{
    char result[DATE_MAX] = { '\0', };
    char *result_copy = NULL;

    time_as_string_common(dt, 0, flags, result);

    pcmk__str_update(&result_copy, result);
    return result_copy;
}

/*!
 * \internal
 * \brief Determine number of seconds from an hour:minute:second string
 *
 * \param[in]  time_str  Time specification string
 * \param[out] result    Number of seconds equivalent to time_str
 *
 * \return TRUE if specification was valid, FALSE (and set errno) otherwise
 * \note This may return the number of seconds in a day (which is out of bounds
 *       for a time object) if given 24:00:00.
 */
static bool
crm_time_parse_sec(const char *time_str, int *result)
{
    int rc;
    uint32_t hour = 0;
    uint32_t minute = 0;
    uint32_t second = 0;

    *result = 0;

    // Must have at least hour, but minutes and seconds are optional
    rc = sscanf(time_str, "%" SCNu32 ":%" SCNu32 ":%" SCNu32,
                &hour, &minute, &second);
    if (rc == 1) {
        rc = sscanf(time_str, "%2" SCNu32 "%2" SCNu32 "%2" SCNu32,
                    &hour, &minute, &second);
    }
    if (rc == 0) {
        crm_err("%s is not a valid ISO 8601 time specification", time_str);
        errno = EINVAL;
        return FALSE;
    }

    crm_trace("Got valid time: %.2" PRIu32 ":%.2" PRIu32 ":%.2" PRIu32,
              hour, minute, second);

    if ((hour == 24) && (minute == 0) && (second == 0)) {
        // Equivalent to 00:00:00 of next day, return number of seconds in day
    } else if (hour >= 24) {
        crm_err("%s is not a valid ISO 8601 time specification "
                "because %" PRIu32 " is not a valid hour", time_str, hour);
        errno = EINVAL;
        return FALSE;
    }
    if (minute >= 60) {
        crm_err("%s is not a valid ISO 8601 time specification "
                "because %" PRIu32 " is not a valid minute", time_str, minute);
        errno = EINVAL;
        return FALSE;
    }
    if (second >= 60) {
        crm_err("%s is not a valid ISO 8601 time specification "
                "because %" PRIu32 " is not a valid second", time_str, second);
        errno = EINVAL;
        return FALSE;
    }

    *result = (hour * HOUR_SECONDS) + (minute * 60) + second;
    return TRUE;
}

static bool
crm_time_parse_offset(const char *offset_str, int *offset)
{
    tzset();

    if (offset_str == NULL) {
        // Use local offset
#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        time_t now = time(NULL);
        struct tm *now_tm = localtime(&now);
#endif
        int h_offset = GMTOFF(now_tm) / HOUR_SECONDS;
        int m_offset = (GMTOFF(now_tm) - (HOUR_SECONDS * h_offset)) / 60;

        if (h_offset < 0 && m_offset < 0) {
            m_offset = 0 - m_offset;
        }
        *offset = (HOUR_SECONDS * h_offset) + (60 * m_offset);
        return TRUE;
    }

    if (offset_str[0] == 'Z') { // @TODO invalid if anything after?
        *offset = 0;
        return TRUE;
    }

    *offset = 0;
    if ((offset_str[0] == '+') || (offset_str[0] == '-')
        || isdigit((int)offset_str[0])) {

        gboolean negate = FALSE;

        if (offset_str[0] == '+') {
            offset_str++;
        } else if (offset_str[0] == '-') {
            negate = TRUE;
            offset_str++;
        }
        if (crm_time_parse_sec(offset_str, offset) == FALSE) {
            return FALSE;
        }
        if (negate) {
            *offset = 0 - *offset;
        }
    } // @TODO else invalid?
    return TRUE;
}

/*!
 * \internal
 * \brief Parse the time portion of an ISO 8601 date/time string
 *
 * \param[in]     time_str  Time portion of specification (after any 'T')
 * \param[in,out] a_time    Time object to parse into
 *
 * \return TRUE if valid time was parsed, FALSE (and set errno) otherwise
 * \note This may add a day to a_time (if the time is 24:00:00).
 */
static bool
crm_time_parse(const char *time_str, crm_time_t *a_time)
{
    uint32_t h, m, s;
    char *offset_s = NULL;

    tzset();

    if (time_str) {
        if (crm_time_parse_sec(time_str, &(a_time->seconds)) == FALSE) {
            return FALSE;
        }
        offset_s = strstr(time_str, "Z");
        if (offset_s == NULL) {
            offset_s = strstr(time_str, " ");
            if (offset_s) {
                while (isspace(offset_s[0])) {
                    offset_s++;
                }
            }
        }
    }

    if (crm_time_parse_offset(offset_s, &(a_time->offset)) == FALSE) {
        return FALSE;
    }
    crm_time_get_sec(a_time->offset, &h, &m, &s);
    crm_trace("Got tz: %c%2." PRIu32 ":%.2" PRIu32,
              (a_time->offset < 0)? '-' : '+', h, m);

    if (a_time->seconds == DAY_SECONDS) {
        // 24:00:00 == 00:00:00 of next day
        a_time->seconds = 0;
        crm_time_add_days(a_time, 1);
    }
    return TRUE;
}

/*
 * \internal
 * \brief Parse a time object from an ISO 8601 date/time specification
 *
 * \param[in] date_str  ISO 8601 date/time specification (or "epoch")
 *
 * \return New time object on success, NULL (and set errno) otherwise
 */
static crm_time_t *
parse_date(const char *date_str)
{
    const char *time_s = NULL;
    crm_time_t *dt = NULL;

    int year = 0;
    int month = 0;
    int week = 0;
    int day = 0;
    int rc = 0;

    if (pcmk__str_empty(date_str)) {
        crm_err("No ISO 8601 date/time specification given");
        goto invalid;
    }

    if ((date_str[0] == 'T') || (date_str[2] == ':')) {
        /* Just a time supplied - Infer current date */
        dt = crm_time_new(NULL);
        if (date_str[0] == 'T') {
            time_s = date_str + 1;
        } else {
            time_s = date_str;
        }
        goto parse_time;
    }

    dt = crm_time_new_undefined();

    if (!strncasecmp("epoch", date_str, 5)
        && ((date_str[5] == '\0') || (date_str[5] == '/') || isspace(date_str[5]))) {
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
            crm_err("'%s' is not a valid ISO 8601 date/time specification "
                    "because '%d' is not a valid month", date_str, month);
            goto invalid;
        } else if (day > crm_time_days_in_month(month, year)) {
            crm_err("'%s' is not a valid ISO 8601 date/time specification "
                    "because '%d' is not a valid day of the month",
                    date_str, day);
            goto invalid;
        } else {
            dt->years = year;
            dt->days = get_ordinal_days(year, month, day);
            crm_trace("Parsed Gregorian date '%.4d-%.3d' from date string '%s'",
                      year, dt->days, date_str);
        }
        goto parse_time;
    }

    /* YYYY-DDD */
    rc = sscanf(date_str, "%d-%d", &year, &day);
    if (rc == 2) {
        if (day > year_days(year)) {
            crm_err("'%s' is not a valid ISO 8601 date/time specification "
                    "because '%d' is not a valid day of the year (max %d)",
                    date_str, day, year_days(year));
            goto invalid;
        }
        crm_trace("Parsed ordinal year %d and days %d from date string '%s'",
                  year, day, date_str);
        dt->days = day;
        dt->years = year;
        goto parse_time;
    }

    /* YYYY-Www-D */
    rc = sscanf(date_str, "%d-W%d-%d", &year, &week, &day);
    if (rc == 3) {
        if (week > crm_time_weeks_in_year(year)) {
            crm_err("'%s' is not a valid ISO 8601 date/time specification "
                    "because '%d' is not a valid week of the year (max %d)",
                    date_str, week, crm_time_weeks_in_year(year));
            goto invalid;
        } else if (day < 1 || day > 7) {
            crm_err("'%s' is not a valid ISO 8601 date/time specification "
                    "because '%d' is not a valid day of the week",
                    date_str, day);
            goto invalid;
        } else {
            /*
             * See https://en.wikipedia.org/wiki/ISO_week_date
             *
             * Monday 29 December 2008 is written "2009-W01-1"
             * Sunday 3 January 2010 is written "2009-W53-7"
             * Saturday 27 September 2008 is written "2008-W37-6"
             *
             * If 1 January is on a Monday, Tuesday, Wednesday or Thursday, it is in week 01.
             * If 1 January is on a Friday, Saturday or Sunday, it is in week 52 or 53 of the previous year.
             */
            int jan1 = crm_time_january1_weekday(year);

            crm_trace("Got year %d (Jan 1 = %d), week %d, and day %d from date string '%s'",
                      year, jan1, week, day, date_str);

            dt->years = year;
            crm_time_add_days(dt, (week - 1) * 7);

            if (jan1 <= 4) {
                crm_time_add_days(dt, 1 - jan1);
            } else {
                crm_time_add_days(dt, 8 - jan1);
            }

            crm_time_add_days(dt, day);
        }
        goto parse_time;
    }

    crm_err("'%s' is not a valid ISO 8601 date/time specification", date_str);
    goto invalid;

  parse_time:

    if (time_s == NULL) {
        time_s = date_str + strspn(date_str, "0123456789-W");
        if ((time_s[0] == ' ') || (time_s[0] == 'T')) {
            ++time_s;
        } else {
            time_s = NULL;
        }
    }
    if ((time_s != NULL) && (crm_time_parse(time_s, dt) == FALSE)) {
        goto invalid;
    }

    crm_time_log(LOG_TRACE, "Unpacked", dt, crm_time_log_date | crm_time_log_timeofday);
    if (crm_time_check(dt) == FALSE) {
        crm_err("'%s' is not a valid ISO 8601 date/time specification",
                date_str);
        goto invalid;
    }
    return dt;

invalid:
    crm_time_free(dt);
    errno = EINVAL;
    return NULL;
}

// Parse an ISO 8601 numeric value and return number of characters consumed
// @TODO This cannot handle >INT_MAX int values
// @TODO Fractions appear to be not working
// @TODO Error out on invalid specifications
static int
parse_int(const char *str, int field_width, int upper_bound, int *result)
{
    int lpc = 0;
    int offset = 0;
    int intermediate = 0;
    gboolean fraction = FALSE;
    gboolean negate = FALSE;

    *result = 0;
    if (*str == '\0') {
        return 0;
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
        *result = (int)(*result * upper_bound);

    } else if (upper_bound > 0 && *result > upper_bound) {
        *result = upper_bound;
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

/*!
 * \brief Parse a time duration from an ISO 8601 duration specification
 *
 * \param[in] period_s  ISO 8601 duration specification (optionally followed by
 *                      whitespace, after which the rest of the string will be
 *                      ignored)
 *
 * \return New time object on success, NULL (and set errno) otherwise
 * \note It is the caller's responsibility to return the result using
 *       crm_time_free().
 */
crm_time_t *
crm_time_parse_duration(const char *period_s)
{
    gboolean is_time = FALSE;
    crm_time_t *diff = NULL;

    if (pcmk__str_empty(period_s)) {
        crm_err("No ISO 8601 time duration given");
        goto invalid;
    }
    if (period_s[0] != 'P') {
        crm_err("'%s' is not a valid ISO 8601 time duration "
                "because it does not start with a 'P'", period_s);
        goto invalid;
    }
    if ((period_s[1] == '\0') || isspace(period_s[1])) {
        crm_err("'%s' is not a valid ISO 8601 time duration "
                "because nothing follows 'P'", period_s);
        goto invalid;
    }

    diff = crm_time_new_undefined();
    diff->duration = TRUE;

    for (const char *current = period_s + 1;
         current[0] && (current[0] != '/') && !isspace(current[0]);
         ++current) {

        int an_int = 0, rc;

        if (current[0] == 'T') {
            /* A 'T' separates year/month/day from hour/minute/seconds. We don't
             * require it strictly, but just use it to differentiate month from
             * minutes.
             */
            is_time = TRUE;
            continue;
        }

        // An integer must be next
        rc = parse_int(current, 10, 0, &an_int);
        if (rc == 0) {
            crm_err("'%s' is not a valid ISO 8601 time duration "
                    "because no integer at '%s'", period_s, current);
            goto invalid;
        }
        current += rc;

        // A time unit must be next (we're not strict about the order)
        switch (current[0]) {
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
                diff->seconds += an_int * HOUR_SECONDS;
                break;
            case 'S':
                diff->seconds += an_int;
                break;
            case '\0':
                crm_err("'%s' is not a valid ISO 8601 time duration "
                        "because no units after %d", period_s, an_int);
                goto invalid;
            default:
                crm_err("'%s' is not a valid ISO 8601 time duration "
                        "because '%c' is not a valid time unit",
                        period_s, current[0]);
                goto invalid;
        }
    }

    if (!crm_time_is_defined(diff)) {
        crm_err("'%s' is not a valid ISO 8601 time duration "
                "because no amounts and units given", period_s);
        goto invalid;
    }
    return diff;

invalid:
    crm_time_free(diff);
    errno = EINVAL;
    return NULL;
}

/*!
 * \brief Parse a time period from an ISO 8601 interval specification
 *
 * \param[in] period_str  ISO 8601 interval specification (start/end,
 *                        start/duration, or duration/end)
 *
 * \return New time period object on success, NULL (and set errno) otherwise
 * \note The caller is responsible for freeing the result using
 *       crm_time_free_period().
 */
crm_time_period_t *
crm_time_parse_period(const char *period_str)
{
    const char *original = period_str;
    crm_time_period_t *period = NULL;

    if (pcmk__str_empty(period_str)) {
        crm_err("No ISO 8601 time period given");
        goto invalid;
    }

    tzset();
    period = calloc(1, sizeof(crm_time_period_t));
    CRM_ASSERT(period != NULL);

    if (period_str[0] == 'P') {
        period->diff = crm_time_parse_duration(period_str);
        if (period->diff == NULL) {
            goto error;
        }
    } else {
        period->start = parse_date(period_str);
        if (period->start == NULL) {
            goto error;
        }
    }

    period_str = strstr(original, "/");
    if (period_str) {
        ++period_str;
        if (period_str[0] == 'P') {
            if (period->diff != NULL) {
                crm_err("'%s' is not a valid ISO 8601 time period "
                        "because it has two durations",
                        original);
                goto invalid;
            }
            period->diff = crm_time_parse_duration(period_str);
            if (period->diff == NULL) {
                goto error;
            }
        } else {
            period->end = parse_date(period_str);
            if (period->end == NULL) {
                goto error;
            }
        }

    } else if (period->diff != NULL) {
        // Only duration given, assume start is now
        period->start = crm_time_new(NULL);

    } else {
        // Only start given
        crm_err("'%s' is not a valid ISO 8601 time period "
                "because it has no duration or ending time",
                original);
        goto invalid;
    }

    if (period->start == NULL) {
        period->start = crm_time_subtract(period->end, period->diff);

    } else if (period->end == NULL) {
        period->end = crm_time_add(period->start, period->diff);
    }

    if (crm_time_check(period->start) == FALSE) {
        crm_err("'%s' is not a valid ISO 8601 time period "
                "because the start is invalid", period_str);
        goto invalid;
    }
    if (crm_time_check(period->end) == FALSE) {
        crm_err("'%s' is not a valid ISO 8601 time period "
                "because the end is invalid", period_str);
        goto invalid;
    }
    return period;

invalid:
    errno = EINVAL;
error:
    crm_time_free_period(period);
    return NULL;
}

/*!
 * \brief Free a dynamically allocated time period object
 *
 * \param[in,out] period  Time period to free
 */
void
crm_time_free_period(crm_time_period_t *period)
{
    if (period) {
        crm_time_free(period->start);
        crm_time_free(period->end);
        crm_time_free(period->diff);
        free(period);
    }
}

void
crm_time_set(crm_time_t *target, const crm_time_t *source)
{
    crm_trace("target=%p, source=%p", target, source);

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
ha_set_tm_time(crm_time_t *target, const struct tm *source)
{
    int h_offset = 0;
    int m_offset = 0;

    /* Ensure target is fully initialized */
    target->years = 0;
    target->months = 0;
    target->days = 0;
    target->seconds = 0;
    target->offset = 0;
    target->duration = FALSE;

    if (source->tm_year > 0) {
        /* years since 1900 */
        target->years = 1900 + source->tm_year;
    }

    if (source->tm_yday >= 0) {
        /* days since January 1 [0-365] */
        target->days = 1 + source->tm_yday;
    }

    if (source->tm_hour >= 0) {
        target->seconds += HOUR_SECONDS * source->tm_hour;
    }
    if (source->tm_min >= 0) {
        target->seconds += 60 * source->tm_min;
    }
    if (source->tm_sec >= 0) {
        target->seconds += source->tm_sec;
    }

    /* tm_gmtoff == offset from UTC in seconds */
    h_offset = GMTOFF(source) / HOUR_SECONDS;
    m_offset = (GMTOFF(source) - (HOUR_SECONDS * h_offset)) / 60;
    crm_trace("Time offset is %lds (%.2d:%.2d)",
              GMTOFF(source), h_offset, m_offset);

    target->offset += HOUR_SECONDS * h_offset;
    target->offset += 60 * m_offset;
}

void
crm_time_set_timet(crm_time_t *target, const time_t *source)
{
    ha_set_tm_time(target, localtime(source));
}

crm_time_t *
pcmk_copy_time(const crm_time_t *source)
{
    crm_time_t *target = crm_time_new_undefined();

    crm_time_set(target, source);
    return target;
}

/*!
 * \internal
 * \brief Convert a \p time_t time to a \p crm_time_t time
 *
 * \param[in] source  Time to convert
 *
 * \return A \p crm_time_t object representing \p source
 */
crm_time_t *
pcmk__copy_timet(time_t source)
{
    crm_time_t *target = crm_time_new_undefined();

    crm_time_set_timet(target, &source);
    return target;
}

crm_time_t *
crm_time_add(const crm_time_t *dt, const crm_time_t *value)
{
    crm_time_t *utc = NULL;
    crm_time_t *answer = NULL;

    if ((dt == NULL) || (value == NULL)) {
        errno = EINVAL;
        return NULL;
    }

    answer = pcmk_copy_time(dt);

    utc = crm_get_utc_time(value);
    if (utc == NULL) {
        crm_time_free(answer);
        return NULL;
    }

    answer->years += utc->years;
    crm_time_add_months(answer, utc->months);
    crm_time_add_days(answer, utc->days);
    crm_time_add_seconds(answer, utc->seconds);

    crm_time_free(utc);
    return answer;
}

crm_time_t *
crm_time_calculate_duration(const crm_time_t *dt, const crm_time_t *value)
{
    crm_time_t *utc = NULL;
    crm_time_t *answer = NULL;

    if ((dt == NULL) || (value == NULL)) {
        errno = EINVAL;
        return NULL;
    }

    utc = crm_get_utc_time(value);
    if (utc == NULL) {
        return NULL;
    }

    answer = crm_get_utc_time(dt);
    if (answer == NULL) {
        crm_time_free(utc);
        return NULL;
    }
    answer->duration = TRUE;

    answer->years -= utc->years;
    if(utc->months != 0) {
        crm_time_add_months(answer, -utc->months);
    }
    crm_time_add_days(answer, -utc->days);
    crm_time_add_seconds(answer, -utc->seconds);

    crm_time_free(utc);
    return answer;
}

crm_time_t *
crm_time_subtract(const crm_time_t *dt, const crm_time_t *value)
{
    crm_time_t *utc = NULL;
    crm_time_t *answer = NULL;

    if ((dt == NULL) || (value == NULL)) {
        errno = EINVAL;
        return NULL;
    }

    utc = crm_get_utc_time(value);
    if (utc == NULL) {
        return NULL;
    }

    answer = pcmk_copy_time(dt);
    answer->years -= utc->years;
    if(utc->months != 0) {
        crm_time_add_months(answer, -utc->months);
    }
    crm_time_add_days(answer, -utc->days);
    crm_time_add_seconds(answer, -utc->seconds);
    crm_time_free(utc);

    return answer;
}

/*!
 * \brief Check whether a time object represents a sensible date/time
 *
 * \param[in] dt  Date/time object to check
 *
 * \return \c true if years, days, and seconds are sensible, \c false otherwise
 */
bool
crm_time_check(const crm_time_t *dt)
{
    return (dt != NULL)
           && (dt->days > 0) && (dt->days <= year_days(dt->years))
           && (dt->seconds >= 0) && (dt->seconds < DAY_SECONDS);
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
crm_time_compare(const crm_time_t *a, const crm_time_t *b)
{
    int rc = 0;
    crm_time_t *t1 = crm_get_utc_time(a);
    crm_time_t *t2 = crm_get_utc_time(b);

    if ((t1 == NULL) && (t2 == NULL)) {
        rc = 0;
    } else if (t1 == NULL) {
        rc = -1;
    } else if (t2 == NULL) {
        rc = 1;
    } else {
        do_cmp_field(t1, t2, years);
        do_cmp_field(t1, t2, days);
        do_cmp_field(t1, t2, seconds);
    }

    crm_time_free(t1);
    crm_time_free(t2);
    return rc;
}

/*!
 * \brief Add a given number of seconds to a date/time or duration
 *
 * \param[in,out] a_time  Date/time or duration to add seconds to
 * \param[in]     extra   Number of seconds to add
 */
void
crm_time_add_seconds(crm_time_t *a_time, int extra)
{
    int days = 0;

    crm_trace("Adding %d seconds to %d (max=%d)",
              extra, a_time->seconds, DAY_SECONDS);
    a_time->seconds += extra;
    days = a_time->seconds / DAY_SECONDS;
    a_time->seconds %= DAY_SECONDS;

    // Don't have negative seconds
    if (a_time->seconds < 0) {
        a_time->seconds += DAY_SECONDS;
        --days;
    }

    crm_time_add_days(a_time, days);
}

void
crm_time_add_days(crm_time_t * a_time, int extra)
{
    int lower_bound = 1;
    int ydays = crm_time_leapyear(a_time->years) ? 366 : 365;

    crm_trace("Adding %d days to %.4d-%.3d", extra, a_time->years, a_time->days);

    a_time->days += extra;
    while (a_time->days > ydays) {
        a_time->years++;
        a_time->days -= ydays;
        ydays = crm_time_leapyear(a_time->years) ? 366 : 365;
    }

    if(a_time->duration) {
        lower_bound = 0;
    }

    while (a_time->days < lower_bound) {
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
    crm_trace("Adding %d months to %.4" PRIu32 "-%.2" PRIu32 "-%.2" PRIu32,
              extra, y, m, d);

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

    crm_trace("Calculated %.4" PRIu32 "-%.2" PRIu32 "-%.2" PRIu32, y, m, d);

    a_time->years = y;
    a_time->days = get_ordinal_days(y, m, d);

    crm_time_get_gregorian(a_time, &y, &m, &d);
    crm_trace("Got %.4" PRIu32 "-%.2" PRIu32 "-%.2" PRIu32, y, m, d);
}

void
crm_time_add_minutes(crm_time_t * a_time, int extra)
{
    crm_time_add_seconds(a_time, extra * 60);
}

void
crm_time_add_hours(crm_time_t * a_time, int extra)
{
    crm_time_add_seconds(a_time, extra * HOUR_SECONDS);
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

static void
ha_get_tm_time(struct tm *target, const crm_time_t *source)
{
    *target = (struct tm) {
        .tm_year = source->years - 1900,
        .tm_mday = source->days,
        .tm_sec = source->seconds % 60,
        .tm_min = ( source->seconds / 60 ) % 60,
        .tm_hour = source->seconds / HOUR_SECONDS,
        .tm_isdst = -1, /* don't adjust */

#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        .tm_gmtoff = source->offset
#endif
    };
    mktime(target);
}

/* The high-resolution variant of time object was added to meet an immediate
 * need, and is kept internal API.
 *
 * @TODO The long-term goal is to come up with a clean, unified design for a
 *       time type (or types) that meets all the various needs, to replace
 *       crm_time_t, pcmk__time_hr_t, and struct timespec (in lrmd_cmd_t).
 *       Using glib's GDateTime is a possibility (if we are willing to require
 *       glib >= 2.26).
 */

pcmk__time_hr_t *
pcmk__time_hr_convert(pcmk__time_hr_t *target, const crm_time_t *dt)
{
    pcmk__time_hr_t *hr_dt = NULL;

    if (dt) {
        hr_dt = target?target:calloc(1, sizeof(pcmk__time_hr_t));
        CRM_ASSERT(hr_dt != NULL);
        *hr_dt = (pcmk__time_hr_t) {
            .years = dt->years,
            .months = dt->months,
            .days = dt->days,
            .seconds = dt->seconds,
            .offset = dt->offset,
            .duration = dt->duration
        };
    }

    return hr_dt;
}

void
pcmk__time_set_hr_dt(crm_time_t *target, const pcmk__time_hr_t *hr_dt)
{
    CRM_ASSERT((hr_dt) && (target));
    *target = (crm_time_t) {
        .years = hr_dt->years,
        .months = hr_dt->months,
        .days = hr_dt->days,
        .seconds = hr_dt->seconds,
        .offset = hr_dt->offset,
        .duration = hr_dt->duration
    };
}

/*!
 * \internal
 * \brief Return the current time as a high-resolution time
 *
 * \param[out] epoch  If not NULL, this will be set to seconds since epoch
 *
 * \return Newly allocated high-resolution time set to the current time
 */
pcmk__time_hr_t *
pcmk__time_hr_now(time_t *epoch)
{
    struct timespec tv;
    crm_time_t dt;
    pcmk__time_hr_t *hr;

    qb_util_timespec_from_epoch_get(&tv);
    if (epoch != NULL) {
        *epoch = tv.tv_sec;
    }
    crm_time_set_timet(&dt, &(tv.tv_sec));
    hr = pcmk__time_hr_convert(NULL, &dt);
    if (hr != NULL) {
        hr->useconds = tv.tv_nsec / QB_TIME_NS_IN_USEC;
    }
    return hr;
}

pcmk__time_hr_t *
pcmk__time_hr_new(const char *date_time)
{
    pcmk__time_hr_t *hr_dt = NULL;

    if (date_time == NULL) {
        hr_dt = pcmk__time_hr_now(NULL);
    } else {
        crm_time_t *dt;

        dt = parse_date(date_time);
        hr_dt = pcmk__time_hr_convert(NULL, dt);
        crm_time_free(dt);
    }
    return hr_dt;
}

void
pcmk__time_hr_free(pcmk__time_hr_t * hr_dt)
{
    free(hr_dt);
}

char *
pcmk__time_format_hr(const char *format, const pcmk__time_hr_t *hr_dt)
{
    const char *mark_s;
    int max = 128, scanned_pos = 0, printed_pos = 0, fmt_pos = 0,
        date_len = 0, nano_digits = 0;
    char nano_s[10], date_s[max+1], nanofmt_s[5] = "%", *tmp_fmt_s;
    struct tm tm;
    crm_time_t dt;

    if (!format) {
        return NULL;
    }
    pcmk__time_set_hr_dt(&dt, hr_dt);
    ha_get_tm_time(&tm, &dt);
    sprintf(nano_s, "%06d000", hr_dt->useconds);

    while ((format[scanned_pos]) != '\0') {
        mark_s = strchr(&format[scanned_pos], '%');
        if (mark_s) {
            int fmt_len = 1;

            fmt_pos = mark_s - format;
            while ((format[fmt_pos+fmt_len] != '\0') &&
                (format[fmt_pos+fmt_len] >= '0') &&
                (format[fmt_pos+fmt_len] <= '9')) {
                fmt_len++;
            }
            scanned_pos = fmt_pos + fmt_len + 1;
            if (format[fmt_pos+fmt_len] == 'N') {
                nano_digits = atoi(&format[fmt_pos+1]);
                nano_digits = (nano_digits > 6)?6:nano_digits;
                nano_digits = (nano_digits < 0)?0:nano_digits;
                sprintf(&nanofmt_s[1], ".%ds", nano_digits);
            } else {
                if (format[scanned_pos] != '\0') {
                    continue;
                }
                fmt_pos = scanned_pos; /* print till end */
            }
        } else {
            scanned_pos = strlen(format);
            fmt_pos = scanned_pos; /* print till end */
        }
        tmp_fmt_s = strndup(&format[printed_pos], fmt_pos - printed_pos);
#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
        date_len += strftime(&date_s[date_len], max-date_len, tmp_fmt_s, &tm);
#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic pop
#endif
        printed_pos = scanned_pos;
        free(tmp_fmt_s);
        if (nano_digits) {
#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
            date_len += snprintf(&date_s[date_len], max-date_len,
                                 nanofmt_s, nano_s);
#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic pop
#endif
            nano_digits = 0;
        }
    }

    return (date_len == 0)?NULL:strdup(date_s);
}

/*!
 * \internal
 * \brief Return a human-friendly string corresponding to an epoch time value
 *
 * \param[in]  source  Pointer to epoch time value (or \p NULL for current time)
 * \param[in]  flags   Group of \p crm_time_* flags controlling display format
 *                     format (0 to use \p ctime() with newline removed)
 *
 * \return String representation of \p source on success (may be empty depending
 *         on \p flags; guaranteed not to be \p NULL)
 *
 * \note The caller is responsible for freeing the return value using \p free().
 */
char *
pcmk__epoch2str(const time_t *source, uint32_t flags)
{
    time_t epoch_time = (source == NULL)? time(NULL) : *source;
    char *result = NULL;

    if (flags == 0) {
        const char *buf = pcmk__trim(ctime(&epoch_time));

        if (buf != NULL) {
            result = strdup(buf);
            CRM_ASSERT(result != NULL);
        }
    } else {
        crm_time_t dt;

        crm_time_set_timet(&dt, &epoch_time);
        result = crm_time_as_string(&dt, flags);
    }
    return result;
}

/*!
 * \internal
 * \brief Given a millisecond interval, return a log-friendly string
 *
 * \param[in] interval_ms  Interval in milliseconds
 *
 * \return Readable version of \p interval_ms
 *
 * \note The return value is a pointer to static memory that will be
 *       overwritten by later calls to this function.
 */
const char *
pcmk__readable_interval(guint interval_ms)
{
#define MS_IN_S (1000)
#define MS_IN_M (MS_IN_S * 60)
#define MS_IN_H (MS_IN_M * 60)
#define MS_IN_D (MS_IN_H * 24)
#define MAXSTR sizeof("..d..h..m..s...ms")
    static char str[MAXSTR] = { '\0', };
    int offset = 0;

    if (interval_ms > MS_IN_D) {
        offset += snprintf(str + offset, MAXSTR - offset, "%ud",
                           interval_ms / MS_IN_D);
        interval_ms -= (interval_ms / MS_IN_D) * MS_IN_D;
    }
    if (interval_ms > MS_IN_H) {
        offset += snprintf(str + offset, MAXSTR - offset, "%uh",
                           interval_ms / MS_IN_H);
        interval_ms -= (interval_ms / MS_IN_H) * MS_IN_H;
    }
    if (interval_ms > MS_IN_M) {
        offset += snprintf(str + offset, MAXSTR - offset, "%um",
                           interval_ms / MS_IN_M);
        interval_ms -= (interval_ms / MS_IN_M) * MS_IN_M;
    }

    // Ns, N.NNNs, or NNNms
    if (interval_ms > MS_IN_S) {
        offset += snprintf(str + offset, MAXSTR - offset, "%u",
                           interval_ms / MS_IN_S);
        interval_ms -= (interval_ms / MS_IN_S) * MS_IN_S;
        if (interval_ms > 0) {
            offset += snprintf(str + offset, MAXSTR - offset, ".%03u",
                               interval_ms);
        }
        (void) snprintf(str + offset, MAXSTR - offset, "s");

    } else if (interval_ms > 0) {
        (void) snprintf(str + offset, MAXSTR - offset, "%ums", interval_ms);

    } else if (str[0] == '\0') {
        strcpy(str, "0s");
    }
    return str;
}
