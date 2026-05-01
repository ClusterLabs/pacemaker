/*
 * Copyright 2005-2026 the Pacemaker project contributors
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
#include <limits.h>         // INT_MIN, INT_MAX
#include <string.h>
#include <stdbool.h>

#include <glib.h>                           // g_strchomp()

#include <crm/common/iso8601.h>
#include "crmcommon_private.h"

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

#define SECONDS_IN_MINUTE   60
#define MINUTES_IN_HOUR     60
#define SECONDS_IN_HOUR     (SECONDS_IN_MINUTE * MINUTES_IN_HOUR)
#define HOURS_IN_DAY        24
#define SECONDS_IN_DAY      (SECONDS_IN_HOUR * HOURS_IN_DAY)

#define BEGIN_VALID_RANGE_S "0001-01-01T00:00:00"
#define END_VALID_RANGE_S   "9999-12-31T23:59:59"

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

/*!
 * \brief Allocate memory for an uninitialized time object
 *
 * \return Newly allocated time object (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \c crm_time_free().
 */
crm_time_t *
crm_time_new_undefined(void)
{
    return pcmk__assert_alloc(1, sizeof(crm_time_t));
}

/*!
 * \internal
 * \brief Check whether a year is positive and representable by four digits
 *
 * \param[in] year  Year
 *
 * \return \c true if \p year is between 1 and 9999 (inclusive), or \c false
 *         otherwise
 */
bool
pcmk__time_valid_year(int year)
{
    return (year >= 1) && (year <= 9999);
}

static bool
is_leap_year(int year)
{
    /* @COMPAT Remove this fallback when we can ensure that the year argument is
     * always in the range 1 to 9999.
     */
    if (!pcmk__time_valid_year(year)) {
        return ((year % 4) == 0)
                && (((year % 100) != 0) || (year % 400 == 0));
    }

    return g_date_is_leap_year(year);
}

/*!
 * \internal
 * \brief Return number of days in given month of given year
 *
 * \param[in] month  Ordinal month (1-12)
 * \param[in] year   Gregorian year
 *
 * \return Number of days in given month (0 if given month or year is invalid)
 */
static int
days_in_month_year(int month, int year)
{
    if (!g_date_valid_month(month)) {
        return 0;
    }

    if (year < 1) {
        return 0;
    }

    /* @COMPAT Remove this fallback when we can ensure that the year argument is
     * always in the range 1 to 9999. g_date_get_days_in_month() takes a
     * GDateYear, which is defined as guint16.
     */
    if (year > UINT16_MAX) {
        static const int month_days[12] = {
            31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
        };

        if ((month == 2) && is_leap_year(year)) {
            return month_days[1] + 1;
        }

        return month_days[month - 1];
    }

    return g_date_get_days_in_month(month, year);
}

/*!
 * \internal
 * \brief Get ordinal day number of year corresponding to given date
 *
 * \param[in] year   Year
 * \param[in] month  Month (1-12)
 * \param[in] day    Day of month (1-31)
 *
 * \return Day number of year \p year corresponding to month \p month and day
 *         \p day, or 0 for invalid arguments
 */
static int
get_ordinal_days(uint32_t year, uint32_t month, uint32_t day)
{
    int prev_month_days = 0;

    CRM_CHECK((year >= 1) && (year <= INT_MAX)
              && (month >= 1) && (month <= 12)
              && (day >= 1) && (day <= 31), return 0);

    for (int i = 1; i < month; i++) {
        prev_month_days += days_in_month_year(i, year);
    }

    return prev_month_days + day;
}

static int
year_days(int year)
{
    return is_leap_year(year)? 366 : 365;
}

/* From http://myweb.ecu.edu/mccartyr/ISOwdALG.txt :
 *
 * 5. Find the Jan1Weekday for Y (Monday=1, Sunday=7)
 *  YY = (Y-1) % 100
 *  C = (Y-1) - YY
 *  G = YY + YY/4
 *  Jan1Weekday = 1 + (((((C / 100) % 4) x 5) + G) % 7)
 */
static int
jan1_day_of_week(int year)
{
    int YY = (year - 1) % 100;
    int C = (year - 1) - YY;
    int G = YY + YY / 4;
    int jan1 = 1 + (((((C / 100) % 4) * 5) + G) % 7);

    pcmk__trace("YY=%d, C=%d, G=%d", YY, C, G);
    pcmk__trace("January 1 %.4d: %d", year, jan1);
    return jan1;
}

static int
weeks_in_year(int year)
{
    int weeks = 52;
    int jan1 = jan1_day_of_week(year);

    /* if jan1 == thursday */
    if (jan1 == 4) {
        weeks++;
    } else {
        jan1 = jan1_day_of_week(year + 1);
        /* if dec31 == thursday aka. jan1 of next year is a friday */
        if (jan1 == 5) {
            weeks++;
        }

    }
    return weeks;
}

/*!
 * \internal
 * \brief Determine number of seconds from an hour:minute:second string
 *
 * \param[in]  time_str  Time specification string
 * \param[out] result    Number of seconds equivalent to time_str
 *
 * \return \c true if specification was valid, or \c false otherwise
 * \note This may return the number of seconds in a day (which is out of bounds
 *       for a time object) if given 24:00:00.
 */
static bool
parse_hms(const char *time_str, int *result)
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
    if (rc < 1) {
        pcmk__err("'%s' is not a valid ISO 8601 time specification", time_str);
        return false;
    }

    pcmk__trace("Got valid time: %.2" PRIu32 ":%.2" PRIu32 ":%.2" PRIu32,
                hour, minute, second);

    if ((hour == HOURS_IN_DAY) && (minute == 0) && (second == 0)) {
        // Equivalent to 00:00:00 of next day, return number of seconds in day
    } else if (hour >= HOURS_IN_DAY) {
        pcmk__err("%s is not a valid ISO 8601 time specification "
                  "because %" PRIu32 " is not a valid hour", time_str, hour);
        return false;
    }
    if (minute >= MINUTES_IN_HOUR) {
        pcmk__err("%s is not a valid ISO 8601 time specification "
                  "because %" PRIu32 " is not a valid minute", time_str,
                  minute);
        return false;
    }
    if (second >= SECONDS_IN_MINUTE) {
        pcmk__err("%s is not a valid ISO 8601 time specification "
                  "because %" PRIu32 " is not a valid second", time_str,
                  second);
        return false;
    }

    *result = (hour * SECONDS_IN_HOUR) + (minute * SECONDS_IN_MINUTE) + second;
    return true;
}

static bool
parse_offset(const char *offset_str, int *offset)
{
    tzset();

    if (offset_str == NULL) {
        // Use local offset
#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        time_t now = time(NULL);
        struct tm *now_tm = localtime(&now);
#endif
        int h_offset = GMTOFF(now_tm) / SECONDS_IN_HOUR;
        int m_offset = (GMTOFF(now_tm) - (SECONDS_IN_HOUR * h_offset))
                       / SECONDS_IN_MINUTE;

        if (h_offset < 0 && m_offset < 0) {
            m_offset = 0 - m_offset;
        }
        *offset = (SECONDS_IN_HOUR * h_offset) + (SECONDS_IN_MINUTE * m_offset);
        return true;
    }

    if (offset_str[0] == 'Z') { // @TODO invalid if anything after?
        *offset = 0;
        return true;
    }

    *offset = 0;
    if ((offset_str[0] == '+') || (offset_str[0] == '-')
        || isdigit((int)offset_str[0])) {

        bool negate = false;

        if (offset_str[0] == '+') {
            offset_str++;
        } else if (offset_str[0] == '-') {
            negate = true;
            offset_str++;
        }
        if (!parse_hms(offset_str, offset)) {
            return false;
        }
        if (negate) {
            *offset = 0 - *offset;
        }
    } // @TODO else invalid?
    return true;
}

/*!
 * \internal
 * \brief Convert seconds to hours, minutes, and seconds
 *
 * The resulting minutes and seconds are in the range [0, 59]. Accordingly, the
 * number of hours is \p seconds_i divided by \c SECONDS_IN_HOUR.
 *
 * \param[in]  seconds_i  Seconds to convert
 * \param[out] hours      Where to store hours
 * \param[out] minutes    Where to store minutes
 * \param[out] seconds    If not \c NULL, where to store seconds
 */
static void
seconds_to_hms(int seconds_i, uint32_t *hours, uint32_t *minutes,
               uint32_t *seconds)
{
    int hours_i = 0;
    int minutes_i = 0;

    hours_i = seconds_i / SECONDS_IN_HOUR;
    seconds_i %= SECONDS_IN_HOUR;

    minutes_i = seconds_i / SECONDS_IN_MINUTE;
    seconds_i %= SECONDS_IN_MINUTE;

    *hours = (uint32_t) QB_ABS(hours_i);
    *minutes = (uint32_t) QB_ABS(minutes_i);
    if (seconds != NULL) {
        *seconds = (uint32_t) QB_ABS(seconds_i);
    }
}

/*!
 * \internal
 * \brief Parse the time portion of an ISO 8601 date/time string
 *
 * \param[in]     time_str  Time portion of specification (after any 'T')
 * \param[in,out] a_time    Time object to parse into
 *
 * \return \c true if valid time was parsed, \c false otherwise
 * \note This may add a day to a_time (if the time is 24:00:00).
 */
static bool
parse_time(const char *time_str, crm_time_t *a_time)
{
    uint32_t h = 0;
    uint32_t m = 0;
    const char *offset_s = NULL;

    tzset();

    if (!parse_hms(time_str, &(a_time->seconds))) {
        return false;
    }

    offset_s = strchr(time_str, 'Z');

    /* @COMPAT: Spaces between the time and the offset are not supported by the
     * standard according to section 3.4.1 and 4.2.5.2.
     */
    if (offset_s == NULL) {
        offset_s = strpbrk(time_str, " +-");
    }

    if (offset_s != NULL) {
        while (isspace(*offset_s)) {
            offset_s++;
        }
    }

    if (!parse_offset(offset_s, &(a_time->offset))) {
        return false;
    }

    seconds_to_hms(a_time->offset, &h, &m, NULL);
    pcmk__trace("Got tz: %c%2." PRIu32 ":%.2" PRIu32,
                (a_time->offset < 0)? '-' : '+', h, m);

    if (a_time->seconds == SECONDS_IN_DAY) {
        // 24:00:00 == 00:00:00 of next day
        a_time->seconds = 0;
        crm_time_add_days(a_time, 1);
    }
    return true;
}

/*!
 * \internal
 * \brief Check whether a time object represents a sensible date/time
 *
 * \param[in] dt  Date/time object to check
 *
 * \return \c true if days and seconds are valid given the year, or \c false
 *         otherwise
 */
bool
valid_time(const crm_time_t *dt)
{
    return (dt != NULL)
           && (dt->days > 0) && (dt->days <= year_days(dt->years))
           && (dt->seconds >= 0) && (dt->seconds < SECONDS_IN_DAY);
}

/*
 * \internal
 * \brief Parse a time object from an ISO 8601 date/time specification
 *
 * \param[in] date_str  ISO 8601 date/time specification (or
 *                      \c PCMK__VALUE_EPOCH)
 *
 * \return New time object on success, NULL (and set errno) otherwise
 */
static crm_time_t *
parse_date(const char *date_str)
{
    const uint32_t flags = crm_time_log_date|crm_time_log_timeofday;
    const char *time_s = NULL;
    crm_time_t *dt = NULL;

    uint32_t year = 0U;
    uint32_t month = 0U;
    uint32_t day = 0U;
    uint32_t week = 0U;

    int rc = 0;

    if (pcmk__str_empty(date_str)) {
        pcmk__err("No ISO 8601 date/time specification given");
        goto invalid;
    }

    if ((date_str[0] == 'T')
        || ((strlen(date_str) > 2) && (date_str[2] == ':'))) {
        /* Just a time supplied - Infer current date */
        dt = pcmk__copy_timet(time(NULL));
        if (date_str[0] == 'T') {
            time_s = date_str + 1;
        } else {
            time_s = date_str;
        }
        goto parse_time_segment;
    }

    dt = pcmk__assert_alloc(1, sizeof(crm_time_t));

    if ((strncasecmp(PCMK__VALUE_EPOCH, date_str, 5) == 0)
        && ((date_str[5] == '\0')
            || (date_str[5] == '/')
            || isspace(date_str[5]))) {

        dt->days = 1;
        dt->years = 1970;
        pcmk__time_log(LOG_TRACE, "Unpacked", dt, flags);
        return dt;
    }

    /* YYYY-MM-DD */
    rc = sscanf(date_str, "%" SCNu32 "-%" SCNu32 "-%" SCNu32 "",
                &year, &month, &day);
    if (rc == 1) {
        /* YYYYMMDD */
        rc = sscanf(date_str, "%4" SCNu32 "%2" SCNu32 "%2" SCNu32 "",
                    &year, &month, &day);
    }
    if (rc == 3) {
        if ((month < 1U) || (month > 12U)) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid month",
                      date_str, month);
            goto invalid;
        } else if ((year < 1U) || (year > INT_MAX)) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid year",
                      date_str, year);
            goto invalid;
        } else if ((day < 1) || (day > INT_MAX)
                   || (day > days_in_month_year(month, year))) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid day of the month",
                      date_str, day);
            goto invalid;
        } else {
            dt->years = year;
            dt->days = get_ordinal_days(year, month, day);
            pcmk__trace("Parsed Gregorian date '%.4" PRIu32 "-%.3d' "
                        "from date string '%s'", year, dt->days, date_str);
        }
        goto parse_time_segment;
    }

    /* YYYY-DDD */
    rc = sscanf(date_str, "%" SCNu32 "-%" SCNu32, &year, &day);
    if (rc == 2) {
        if ((year < 1U) || (year > INT_MAX)) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid year",
                      date_str, year);
            goto invalid;
        } else if ((day < 1U) || (day > INT_MAX) || (day > year_days(year))) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid day of year %"
                      PRIu32 " (1-%d)",
                      date_str, day, year, year_days(year));
            goto invalid;
        }
        pcmk__trace("Parsed ordinal year %d and days %d from date string '%s'",
                    year, day, date_str);
        dt->days = day;
        dt->years = year;
        goto parse_time_segment;
    }

    /* YYYY-Www-D */
    rc = sscanf(date_str, "%" SCNu32 "-W%" SCNu32 "-%" SCNu32,
                &year, &week, &day);
    if (rc == 3) {
        if ((week < 1U) || (week > weeks_in_year(year))) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid week of year %"
                      PRIu32 " (1-%d)",
                      date_str, week, year, weeks_in_year(year));
            goto invalid;
        } else if ((day < 1U) || (day > 7U)) {
            pcmk__err("'%s' is not a valid ISO 8601 date/time specification "
                      "because '%" PRIu32 "' is not a valid day of the week",
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
             * If 1 January is on a Monday, Tuesday, Wednesday or Thursday, it
             * is in week 1. If 1 January is on a Friday, Saturday or Sunday,
             * it is in week 52 or 53 of the previous year.
             */
            int jan1 = jan1_day_of_week(year);

            pcmk__trace("Parsed year %" PRIu32 " (Jan 1 = %d), week %" PRIu32
                        ", and day %" PRIu32 " from date string '%s'",
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
        goto parse_time_segment;
    }

    pcmk__err("'%s' is not a valid ISO 8601 date/time specification", date_str);
    goto invalid;

parse_time_segment:
    if (time_s == NULL) {
        time_s = date_str + strspn(date_str, "0123456789-W");
        if ((time_s[0] == ' ') || (time_s[0] == 'T')) {
            ++time_s;
        } else {
            time_s = NULL;
        }
    }
    if ((time_s != NULL) && !parse_time(time_s, dt)) {
        goto invalid;
    }

    pcmk__time_log(LOG_TRACE, "Unpacked", dt, flags);

    if (!valid_time(dt)) {
        pcmk__err("'%s' is not a valid ISO 8601 date/time specification",
                  date_str);
        goto invalid;
    }
    return dt;

invalid:
    crm_time_free(dt);
    errno = EINVAL;
    return NULL;
}

// Return value is guaranteed not to be NULL
static crm_time_t *
copy_time_to_utc(const crm_time_t *dt)
{
    const uint32_t flags = crm_time_log_date
                           |crm_time_log_timeofday
                           |crm_time_log_with_timezone;
    crm_time_t *utc = NULL;

    pcmk__assert(dt != NULL);

    utc = pcmk__assert_alloc(1, sizeof(crm_time_t));
    utc->years = dt->years;
    utc->days = dt->days;
    utc->seconds = dt->seconds;
    utc->offset = 0;

    if (dt->offset != 0) {
        crm_time_add_seconds(utc, -dt->offset);

    } else {
        // Durations (the only things that can include months) never have a TZ
        utc->months = dt->months;
    }

    pcmk__time_log(LOG_TRACE, "utc-source", dt, flags);
    pcmk__time_log(LOG_TRACE, "utc-target", utc, flags);
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
 * \brief Check whether a time object has been initialized yet
 *
 * \param[in] t  Time object to check
 *
 * \return \c true if time object has been initialized, \c false otherwise
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

void
pcmk__time_log_as(const char *file, const char *function, int line,
                  uint8_t level, const char *prefix, const crm_time_t *dt,
                  uint32_t flags)
{
    char *date_s = crm_time_as_string(dt, flags);

    if (prefix != NULL) {
        char *old = date_s;

        date_s = pcmk__assert_asprintf("%s: %s", prefix, date_s);
        free(old);
    }

    if (level == PCMK__LOG_STDOUT) {
        printf("%s\n", date_s);
    } else {
        do_crm_log_alias(level, file, function, line, "%s", date_s);
    }
    free(date_s);
}

int
crm_time_get_timeofday(const crm_time_t *dt, uint32_t *h, uint32_t *m,
                       uint32_t *s)
{
    pcmk__assert((dt != NULL) && (h != NULL) && (m != NULL) && (s != NULL));

    seconds_to_hms(dt->seconds, h, m, s);
    return TRUE;
}

long long
crm_time_get_seconds(const crm_time_t *dt)
{
    crm_time_t *utc = NULL;
    long long days = 0;
    long long seconds = 0;

    if (dt == NULL) {
        return 0;
    }

    if (dt->offset != 0) {
        utc = copy_time_to_utc(dt);
        dt = utc;
    }

    if (dt->duration) {
        /* Assume 365-day years and 30-day months. The correct number of days in
         * years and months varies depending on the start date to which the
         * duration will be applied, which is unknown.
         */
        days = (365 * (long long) dt->years)
               + (30 * (long long) dt->months)
               + dt->days;

    } else {
        // The months field can be set only for durations, so ignore it here
        for (int i = 1; i < dt->years; i++) {
            days += year_days(i);
        }

        // This is probably always true
        if (dt->days > 0) {
            days += dt->days - 1;
        }
    }

    seconds = dt->seconds + (SECONDS_IN_DAY * days);

    crm_time_free(utc);
    return seconds;
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

    pcmk__assert((dt != NULL) && (y != NULL) && (m != NULL) && (d != NULL));

    if(dt->years != 0) {
        for (months = 1; months <= 12 && days > 0; months++) {
            int mdays = days_in_month_year(months, dt->years);

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
    pcmk__trace("%.4d-%.3d -> %.4d-%.2d-%.2d", dt->years, dt->days, dt->years,
                months, days);
    return TRUE;
}

int
crm_time_get_ordinal(const crm_time_t *dt, uint32_t *y, uint32_t *d)
{
    pcmk__assert((dt != NULL) && (y != NULL) && (d != NULL));

    *y = dt->years;
    *d = dt->days;
    return TRUE;
}

void
pcmk__time_get_ywd(const crm_time_t *dt, uint32_t *y, uint32_t *w, uint32_t *d)
{
    // Based on ISO week date: https://en.wikipedia.org/wiki/ISO_week_date
    int year_num = 0;
    int jan1 = 0;
    int h = -1;

    pcmk__assert((dt != NULL) && (y != NULL) && (w != NULL) && (d != NULL));

    if (dt->days <= 0) {
        return;
    }

    jan1 = jan1_day_of_week(dt->years);

/* 6. Find the Weekday for Y M D */
    h = dt->days + jan1 - 1;
    *d = 1 + ((h - 1) % 7);

/* 7. Find if Y M D falls in YearNumber Y-1, WeekNumber 52 or 53 */
    if (dt->days <= (8 - jan1) && jan1 > 4) {
        pcmk__trace("year--, jan1=%d", jan1);
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
            pcmk__trace("year++, jan1=%d, i=%d vs. %d", jan1, dmax - dt->days,
                        correction);
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
    pcmk__trace("Converted %.4d-%.3d to %.4" PRIu32 "-W%.2" PRIu32 "-%" PRIu32,
                dt->years, dt->days, *y, *w, *d);
}

/*!
 * \internal
 * \brief Print "<seconds>.<microseconds>" to a buffer
 *
 * \param[in]     sec   Seconds
 * \param[in]     usec  Microseconds (must be of same sign as \p sec and of
 *                      absolute value less than \c QB_TIME_US_IN_SEC)
 * \param[in,out] buf   Result buffer
 */
static inline void
sec_usec_as_string(long long sec, int usec, GString *buf)
{
    /* A negative value smaller than -1 second should have the negative sign
     * before the 0, not before the usec part
     */
    if ((sec == 0) && (usec < 0)) {
        g_string_append_c(buf, '-');
    }
    g_string_append_printf(buf, "%lld.%06d", sec, QB_ABS(usec));
}

/*!
 * \internal
 * \brief Get a string representation of a duration
 *
 * \param[in]     dt         Time object to interpret as a duration
 * \param[in]     usec       Microseconds to add to \p dt
 * \param[in]     show_usec  Whether to include microseconds in \p buf
 * \param[in,out] buf        Result buffer
 */
static void
duration_as_string(const crm_time_t *dt, int usec, bool show_usec, GString *buf)
{
    pcmk__assert(valid_sec_usec(dt->seconds, usec));

    if (dt->years) {
        g_string_append_printf(buf, "%4d year%s ",
                               dt->years, pcmk__plural_s(dt->years));
    }
    if (dt->months) {
        g_string_append_printf(buf, "%2d month%s ",
                               dt->months, pcmk__plural_s(dt->months));
    }
    if (dt->days) {
        g_string_append_printf(buf, "%2d day%s ",
                               dt->days, pcmk__plural_s(dt->days));
    }

    // At least print seconds (and optionally usecs)
    if ((buf->len == 0) || (dt->seconds != 0) || (show_usec && (usec != 0))) {
        if (show_usec) {
            sec_usec_as_string(dt->seconds, usec, buf);
        } else {
            g_string_append_printf(buf, "%d", dt->seconds);
        }
        g_string_append_printf(buf, " second%s", pcmk__plural_s(dt->seconds));
    }

    // More than one minute, so provide a more readable breakdown into units
    if (QB_ABS(dt->seconds) >= SECONDS_IN_MINUTE) {
        uint32_t h = 0;
        uint32_t m = 0;
        uint32_t s = 0;
        uint32_t u = QB_ABS(usec);
        bool print_sec_component = false;

        seconds_to_hms(dt->seconds, &h, &m, &s);
        print_sec_component = ((s != 0) || (show_usec && (u != 0)));

        g_string_append(buf, " (");

        if (h) {
            g_string_append_printf(buf, "%" PRIu32 " hour%s",
                                   h, pcmk__plural_s(h));

            if ((m != 0) || print_sec_component) {
                g_string_append_c(buf, ' ');
            }
        }

        if (m) {
            g_string_append_printf(buf, "%" PRIu32 " minute%s",
                                   m, pcmk__plural_s(m));

            if (print_sec_component) {
                g_string_append_c(buf, ' ');
            }
        }

        if (print_sec_component) {
            if (show_usec) {
                sec_usec_as_string(s, u, buf);
            } else {
                g_string_append_printf(buf, "%" PRIu32, s);
            }
            g_string_append_printf(buf, " second%s",
                                   pcmk__plural_s(dt->seconds));
        }

        g_string_append_c(buf, ')');
    }
}

/*!
 * \internal
 * \brief Get a string representation of a time object
 *
 * \param[in] dt     Time to convert to string
 * \param[in] usec   Microseconds to add to \p dt
 * \param[in] flags  Group of \c crm_time_* string format options
 *
 * \return Newly allocated string representation of \p dt plus \p usec
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
static char *
time_as_string_common(const crm_time_t *dt, int usec, uint32_t flags)
{
    crm_time_t *utc = NULL;
    GString *buf = NULL;
    char *result = NULL;

    if (!crm_time_is_defined(dt)) {
        return pcmk__str_copy("<undefined time>");
    }

    pcmk__assert(valid_sec_usec(dt->seconds, usec));

    buf = g_string_sized_new(128);

    /* Simple cases: as duration, seconds, or seconds since epoch.
     * These never depend on time zone.
     */

    if (pcmk__is_set(flags, crm_time_log_duration)) {
        duration_as_string(dt, usec, pcmk__is_set(flags, crm_time_usecs), buf);
        goto done;
    }

    if (pcmk__any_flags_set(flags, crm_time_seconds|crm_time_epoch)) {
        long long seconds = 0;

        if (pcmk__is_set(flags, crm_time_seconds)) {
            seconds = crm_time_get_seconds(dt);
        } else {
            seconds = crm_time_get_seconds_since_epoch(dt);
        }

        if (pcmk__is_set(flags, crm_time_usecs)) {
            sec_usec_as_string(seconds, usec, buf);
        } else {
            g_string_append_printf(buf, "%lld", seconds);
        }
        goto done;
    }

    // Convert to UTC if local timezone was not requested
    if ((dt->offset != 0) && !pcmk__is_set(flags, crm_time_log_with_timezone)) {
        utc = copy_time_to_utc(dt);
        dt = utc;
    }

    // As readable string

    if (pcmk__is_set(flags, crm_time_log_date)) {
        if (pcmk__is_set(flags, crm_time_weeks)) { // YYYY-WW-D
            if (dt->days > 0) {
                uint32_t y = 0;
                uint32_t w = 0;
                uint32_t d = 0;

                pcmk__time_get_ywd(dt, &y, &w, &d);
                g_string_append_printf(buf,
                                       "%" PRIu32 "-W%.2" PRIu32 "-%" PRIu32,
                                       y, w, d);
            }

        } else if (pcmk__is_set(flags, crm_time_ordinal)) { // YYYY-DDD
            uint32_t y = 0;
            uint32_t d = 0;

            if (crm_time_get_ordinal(dt, &y, &d)) {
                g_string_append_printf(buf, "%" PRIu32 "-%.3" PRIu32, y, d);
            }

        } else { // YYYY-MM-DD
            uint32_t y = 0;
            uint32_t m = 0;
            uint32_t d = 0;

            if (crm_time_get_gregorian(dt, &y, &m, &d)) {
                g_string_append_printf(buf,
                                       "%.4" PRIu32 "-%.2" PRIu32 "-%.2" PRIu32,
                                       y, m, d);
            }
        }
    }

    if (pcmk__is_set(flags, crm_time_log_timeofday)) {
        uint32_t h = 0, m = 0, s = 0;

        if (buf->len > 0) {
            g_string_append_c(buf, ' ');
        }

        if (crm_time_get_timeofday(dt, &h, &m, &s)) {
            g_string_append_printf(buf,
                                   "%.2" PRIu32 ":%.2" PRIu32 ":%.2" PRIu32,
                                   h, m, s);

            if (pcmk__is_set(flags, crm_time_usecs)) {
                g_string_append_printf(buf, ".%06" PRIu32, QB_ABS(usec));
            }
        }

        if (pcmk__is_set(flags, crm_time_log_with_timezone)
            && (dt->offset != 0)) {

            seconds_to_hms(dt->offset, &h, &m, NULL);
            g_string_append_printf(buf, " %c%.2" PRIu32 ":%.2" PRIu32,
                                   ((dt->offset < 0)? '-' : '+'), h, m);

        } else {
            g_string_append_c(buf, 'Z');
        }
    }

done:
    crm_time_free(utc);
    result = pcmk__str_copy(buf->str);
    g_string_free(buf, TRUE);
    return result;
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
    return time_as_string_common(dt, 0, flags);
}

// Parse an ISO 8601 numeric value and return number of characters consumed
static int
parse_int(const char *str, int *result)
{
    unsigned int lpc;
    int offset = 0;
    bool negate = false;

    *result = 0;

    // @TODO This cannot handle combinations of these characters
    switch (str[0]) {
        case '.':
        case ',':
            return 0; // Fractions are not supported

        case '-':
            negate = true;
            offset = 1;
            break;

        case '+':
        case ':':
            offset = 1;
            break;

        default:
            break;
    }

    for (lpc = 0; (lpc < 10) && isdigit(str[offset]); lpc++) {
        const int digit = str[offset++] - '0';

        if ((*result * 10LL + digit) > INT_MAX) {
            return 0; // Overflow
        }
        *result = *result * 10 + digit;
    }
    if (negate) {
        *result = -*result;
    }
    return (lpc > 0)? offset : 0;
}

/*!
 * \internal
 * \brief Parse an element of an ISO 8601 duration string
 *
 * \param[in,out] element     Element to parse (within \p duration_s)
 * \param[in]     duration_s  Full duration string (for logging only)
 * \param[in,out] duration    Where to add result of parsing \p element
 * \param[in]     as_time     If \c true, \c 'M' indicates minutes; otherwise,
 *                            it indicates months
 *
 * \return Standard Pacemaker return code
 *
 * \note On successful return, \p element points to the unit designator of the
 *       element just parsed. This is a bit confusing but will suffice for now.
 * \note \p as_time is set to \c true if the caller has encountered a \c 'T'
 *       already while parsing \p duration_s.
 */
static int
parse_duration_element(const char **element, const char *duration_s,
                       crm_time_t *duration, bool as_time)
{
    int value = 0;
    int consumed = 0;
    long long result = 0;
    const char *start = *element;

    // Component must begin with an integer
    consumed = parse_int(*element, &value);
    if (consumed == 0) {
        pcmk__err("'%s' is not a valid ISO 8601 duration because no valid "
                  "integer at '%s'", duration_s, *element);
        return pcmk_rc_bad_input;
    }

    *element += consumed;

    // A unit designator must be next (we're not strict about the order)
    switch (**element) {
        case 'Y':
            duration->years = value;
            return pcmk_rc_ok;

        case 'M':
            if (!as_time) { // Months
                duration->months = value;
                return pcmk_rc_ok;
            }

            // Minutes
            result = duration->seconds + (value * 60LL);
            if ((result < INT_MIN) || (result > INT_MAX)) {
                break;
            }

            duration->seconds = (int) result;
            return pcmk_rc_ok;

        case 'W':
            result = duration->days + (value * 7LL);
            if ((result < INT_MIN) || (result > INT_MAX)) {
                break;
            }

            duration->days = (int) result;
            return pcmk_rc_ok;

        case 'D':
            result = duration->days + (long long) value;
            if ((result < INT_MIN) || (result > INT_MAX)) {
                break;
            }

            duration->days = (int) result;
            return pcmk_rc_ok;

        case 'H':
            result = duration->seconds + ((long long) value * SECONDS_IN_HOUR);
            if ((result < INT_MIN) || (result > INT_MAX)) {
                break;
            }

            duration->seconds = (int) result;
            return pcmk_rc_ok;

        case 'S':
            result = duration->seconds + (long long) value;
            if ((result < INT_MIN) || (result > INT_MAX)) {
                break;
            }

            duration->seconds = (int) result;
            return pcmk_rc_ok;

        case '\0':
            pcmk__err("'%s' is not a valid ISO 8601 duration because no units "
                      "after %s", duration_s, start);
            return pcmk_rc_bad_input;

        default:
            pcmk__err("'%s' is not a valid ISO 8601 duration because '%c' is "
                      "not a valid time unit", duration_s, **element);
            return pcmk_rc_bad_input;
    }

    pcmk__err("'%s' could not be parsed as an ISO 8601 duration because the "
              "the parsed value for one or more time units is too large",
              duration_s);
    return pcmk_rc_bad_input;
}

/*!
 * \internal
 * \brief Parse a time duration from an ISO 8601 duration specification
 *
 * \param[in] period_s  ISO 8601 duration specification (optionally followed by
 *                      whitespace, after which the rest of the string will be
 *                      ignored)
 *
 * \return New time object on success, or \c NULL (and set \c errno) otherwise
 * \note It is the caller's responsibility to free the result using
 *       \c crm_time_free().
 */
crm_time_t *
pcmk__time_parse_duration(const char *period_s)
{
    bool is_time = false;
    crm_time_t *diff = NULL;

    if (pcmk__str_empty(period_s)) {
        pcmk__err("No ISO 8601 time duration given");
        goto invalid;
    }
    if (period_s[0] != 'P') {
        pcmk__err("'%s' is not a valid ISO 8601 time duration because it does "
                  "not start with a 'P'",
                  period_s);
        goto invalid;
    }
    if ((period_s[1] == '\0') || isspace(period_s[1])) {
        pcmk__err("'%s' is not a valid ISO 8601 time duration because nothing "
                  "follows 'P'",
                  period_s);
        goto invalid;
    }

    diff = pcmk__assert_alloc(1, sizeof(crm_time_t));

    for (const char *current = period_s + 1;
         current[0] && (current[0] != '/') && !isspace(current[0]);
         ++current) {

        if (current[0] == 'T') {
            /* A 'T' separates year/month/day from hour/minute/seconds. We don't
             * require it strictly, but just use it to differentiate month from
             * minutes.
             */
            is_time = true;
            continue;
        }

        // current points to last character of current element on success
        if (parse_duration_element(&current, period_s, diff,
                                   is_time) != pcmk_rc_ok) {
            goto invalid;
        }
    }

    if (!crm_time_is_defined(diff)) {
        pcmk__err("'%s' is not a valid ISO 8601 time duration because no "
                  "amounts and units given",
                  period_s);
        goto invalid;
    }

    diff->duration = true;
    return diff;

invalid:
    /* @COMPAT Setting errno is required only for backward compatibility with
     * crm_time_parse_duration()
     */
    crm_time_free(diff);
    errno = EINVAL;
    return NULL;
}

/*!
 * \internal
 * \brief Set one time object to another if the other is earlier
 *
 * \param[in,out] target  Time object to set
 * \param[in]     source  Time object to use if earlier
 */
void
pcmk__set_time_if_earlier(crm_time_t *target, const crm_time_t *source)
{
    const int flags = crm_time_log_date
                      |crm_time_log_timeofday
                      |crm_time_log_with_timezone;

    if ((target == NULL)
        || (source == NULL)
        || (crm_time_is_defined(target)
            && (crm_time_compare(source, target) >= 0))) {

        return;
    }

    *target = *source;
    pcmk__time_log(LOG_TRACE, "source", source, flags);
    pcmk__time_log(LOG_TRACE, "target", target, flags);
}

crm_time_t *
pcmk_copy_time(const crm_time_t *source)
{
    crm_time_t *target = pcmk__assert_alloc(1, sizeof(crm_time_t));

    *target = *source;
    return target;
}

/*!
 * \internal
 * \brief Convert a \c time_t time to a \c crm_time_t time
 *
 * \param[in] source_sec  Time to convert (as seconds since epoch)
 *
 * \return Newly allocated \c crm_time_t object representing \p source_sec
 *
 * \note The caller is responsible for freeing the return value using
 *       \c crm_time_free().
 */
crm_time_t *
pcmk__copy_timet(time_t source_sec)
{
    const struct tm *source = localtime(&source_sec);
    crm_time_t *target = pcmk__assert_alloc(1, sizeof(crm_time_t));

    int h_offset = 0;
    int m_offset = 0;

    if (source->tm_year > 0) {
        // Years since 1900
        target->years = 1900;
        crm_time_add_years(target, source->tm_year);
    }

    if (source->tm_yday >= 0) {
        // Days since January 1 (0-365)
        target->days = 1 + source->tm_yday;
    }

    if (source->tm_hour >= 0) {
        target->seconds += SECONDS_IN_HOUR * source->tm_hour;
    }

    if (source->tm_min >= 0) {
        target->seconds += SECONDS_IN_MINUTE * source->tm_min;
    }

    if (source->tm_sec >= 0) {
        target->seconds += source->tm_sec;
    }

    // GMTOFF(source) == offset from UTC in seconds
    h_offset = GMTOFF(source) / SECONDS_IN_HOUR;
    m_offset = (GMTOFF(source) - (SECONDS_IN_HOUR * h_offset))
               / SECONDS_IN_MINUTE;
    pcmk__trace("Time offset is %lds (%.2d:%.2d)", GMTOFF(source), h_offset,
                m_offset);

    target->offset += SECONDS_IN_HOUR * h_offset;
    target->offset += SECONDS_IN_MINUTE * m_offset;

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
    utc = copy_time_to_utc(value);

    crm_time_add_years(answer, utc->years);
    crm_time_add_months(answer, utc->months);
    crm_time_add_days(answer, utc->days);
    crm_time_add_seconds(answer, utc->seconds);

    crm_time_free(utc);
    return answer;
}

/*!
 * \internal
 * \brief Return the XML attribute name corresponding to a time component
 *
 * \param[in] component  Component to check
 *
 * \return XML attribute name corresponding to \p component, or NULL if
 *         \p component is invalid
 */
const char *
pcmk__time_component_attr(enum pcmk__time_component component)
{
    switch (component) {
        case pcmk__time_years:
            return PCMK_XA_YEARS;

        case pcmk__time_months:
            return PCMK_XA_MONTHS;

        case pcmk__time_weeks:
            return PCMK_XA_WEEKS;

        case pcmk__time_days:
            return PCMK_XA_DAYS;

        case pcmk__time_hours:
            return PCMK_XA_HOURS;

        case pcmk__time_minutes:
            return PCMK_XA_MINUTES;

        case pcmk__time_seconds:
            return PCMK_XA_SECONDS;

        default:
            return NULL;
    }
}

typedef void (*component_fn_t)(crm_time_t *, int);

/*!
 * \internal
 * \brief Get the addition function corresponding to a time component
 * \param[in] component  Component to check
 *
 * \return Addition function corresponding to \p component, or NULL if
 *         \p component is invalid
 */
static component_fn_t
component_fn(enum pcmk__time_component component)
{
    switch (component) {
        case pcmk__time_years:
            return crm_time_add_years;

        case pcmk__time_months:
            return crm_time_add_months;

        case pcmk__time_weeks:
            return crm_time_add_weeks;

        case pcmk__time_days:
            return crm_time_add_days;

        case pcmk__time_hours:
            return crm_time_add_hours;

        case pcmk__time_minutes:
            return crm_time_add_minutes;

        case pcmk__time_seconds:
            return crm_time_add_seconds;

        default:
            return NULL;
    }

}

/*!
 * \internal
 * \brief Add the value of an XML attribute to a time object
 *
 * \param[in,out] t          Time object to add to
 * \param[in]     component  Component of \p t to add to
 * \param[in]     xml        XML with value to add
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__add_time_from_xml(crm_time_t *t, enum pcmk__time_component component,
                        const xmlNode *xml)
{
    long long value;
    const char *attr = pcmk__time_component_attr(component);
    component_fn_t add = component_fn(component);

    if ((t == NULL) || (attr == NULL) || (add == NULL)) {
        return EINVAL;
    }

    if (xml == NULL) {
        return pcmk_rc_ok;
    }

    if (pcmk__scan_ll(pcmk__xe_get(xml, attr), &value, 0LL) != pcmk_rc_ok) {
        return pcmk_rc_unpack_error;
    }

    if ((value < INT_MIN) || (value > INT_MAX)) {
        return ERANGE;
    }

    if (value != 0LL) {
        add(t, (int) value);
    }
    return pcmk_rc_ok;
}

static crm_time_t *
subtract_time(const crm_time_t *dt1, const crm_time_t *dt2, bool as_duration)
{
    crm_time_t *result = NULL;
    crm_time_t *utc = NULL;

    if ((dt1 == NULL) || (dt2 == NULL)) {
        errno = EINVAL;
        return NULL;
    }

    result = (as_duration? copy_time_to_utc(dt1) : pcmk_copy_time(dt1));
    result->duration = as_duration;

    utc = copy_time_to_utc(dt2);

    // Avoid overflow when negating INT_MIN in calculations below

    if (utc->years == INT_MIN) {
        crm_time_add_years(result, -1);
        utc->years++;
    }
    crm_time_add_years(result, -utc->years);

    if (utc->months == INT_MIN) {
        crm_time_add_months(result, -1);
        utc->months++;
    }
    crm_time_add_months(result, -utc->months);

    if (utc->days == INT_MIN) {
        crm_time_add_days(result, -1);
        utc->days++;
    }
    crm_time_add_days(result, -utc->days);

    if (utc->seconds == INT_MIN) {
        crm_time_add_seconds(result, -1);
        utc->seconds++;
    }
    crm_time_add_seconds(result, -utc->seconds);

    crm_time_free(utc);
    return result;
}

crm_time_t *
crm_time_subtract(const crm_time_t *dt, const crm_time_t *value)
{
    return subtract_time(dt, value, false);
}

#define do_cmp_field(l, r, field)					\
    if(rc == 0) {                                                       \
		if(l->field > r->field) {				\
			pcmk__trace("%s: %d > %d",			\
				    #field, l->field, r->field);	\
			rc = 1;                                         \
		} else if(l->field < r->field) {			\
			pcmk__trace("%s: %d < %d",			\
				    #field, l->field, r->field);	\
			rc = -1;					\
		}							\
    }

int
crm_time_compare(const crm_time_t *a, const crm_time_t *b)
{
    int rc = 0;
    crm_time_t *t1 = NULL;
    crm_time_t *t2 = NULL;

    if ((a == NULL) && (b == NULL)) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return 1;
    }

    t1 = copy_time_to_utc(a);
    t2 = copy_time_to_utc(b);

    do_cmp_field(t1, t2, years);
    do_cmp_field(t1, t2, days);
    do_cmp_field(t1, t2, seconds);

    crm_time_free(t1);
    crm_time_free(t2);
    return rc;
}

/*!
 * \brief Add a given number of seconds to a date/time or duration
 *
 * \param[in,out] dt     Date/time or duration to add seconds to
 * \param[in]     value  Number of seconds to add
 */
void
crm_time_add_seconds(crm_time_t *dt, int value)
{
    int days = value / SECONDS_IN_DAY;

    pcmk__assert(dt != NULL);

    pcmk__trace("Adding %d seconds (including %d whole day%s) to %d", value,
                days, pcmk__plural_s(days), dt->seconds);

    dt->seconds += value % SECONDS_IN_DAY;

    // Check whether the addition crossed a day boundary
    if (dt->seconds > SECONDS_IN_DAY) {
        ++days;
        dt->seconds -= SECONDS_IN_DAY;

    } else if (dt->seconds < 0) {
        --days;
        dt->seconds += SECONDS_IN_DAY;
    }

    crm_time_add_days(dt, days);
}

/*!
 * \brief Add days to a date/time
 *
 * \param[in,out] dt     Time to modify
 * \param[in]     value  Number of days to add (may be negative to subtract)
 */
void
crm_time_add_days(crm_time_t *dt, int value)
{
    pcmk__assert(dt != NULL);

    pcmk__trace("Adding %d days to %.4d-%.3d", value, dt->years, dt->days);

    if (value > 0) {
        while ((dt->days + (long long) value) > year_days(dt->years)) {
            if (dt->years == INT_MAX) {
                // Clip to latest we can handle
                dt->days = year_days(dt->years);
                return;
            }
            value -= year_days(dt->years);
            dt->years++;
        }
    } else if (value < 0) {
        const int min_days = dt->duration? 0 : 1;

        while ((dt->days + (long long) value) < min_days) {
            if (dt->years <= 1) {
                dt->days = 1; // Clip to earliest we can handle (no BCE)
                return;
            }
            dt->years--;
            value += year_days(dt->years);
        }
    }
    dt->days += value;
}

void
crm_time_add_months(crm_time_t *dt, int value)
{
    uint32_t year = 0;
    uint32_t month = 0;
    uint32_t day = 0;
    int days_in_month = 0;

    crm_time_get_gregorian(dt, &year, &month, &day);

    if (value > 0) {
        for (int i = value; i > 0; i--) {
            month++;
            if (month == 13) {
                month = 1;
                year++;
            }
        }
    } else {
        for (int i = value; i < 0; i++) {
            month--;
            if (month == 0) {
                month = 12;
                year--;
            }
        }
    }

    days_in_month = days_in_month_year(month, year);

    if (days_in_month < day) {
        // Preserve day-of-month unless the month doesn't have enough days
        day = days_in_month;
    }

    dt->years = year;
    dt->days = get_ordinal_days(year, month, day);
}

void
crm_time_add_minutes(crm_time_t *dt, int value)
{
    crm_time_add_seconds(dt, value * SECONDS_IN_MINUTE);
}

void
crm_time_add_hours(crm_time_t *dt, int value)
{
    crm_time_add_seconds(dt, value * SECONDS_IN_HOUR);
}

void
crm_time_add_weeks(crm_time_t *dt, int value)
{
    crm_time_add_days(dt, value * 7);
}

void
crm_time_add_years(crm_time_t *dt, int value)
{
    pcmk__assert(dt != NULL);

    if ((value > 0) && ((dt->years + (long long) value) > INT_MAX)) {
        dt->years = INT_MAX;

    } else if ((value < 0) && ((dt->years + (long long) value) < 1)) {
        dt->years = 1; // Clip to earliest we can handle (no BCE)

    } else {
        dt->years += value;
    }
}

static void
ha_get_tm_time(struct tm *target, const crm_time_t *source)
{
    *target = (struct tm) {
        .tm_year = source->years - 1900,

        /* source->days is day of year, but we assign it to tm_mday instead of
         * tm_yday. mktime() fixes it. See the mktime(3) man page for details.
         */
        .tm_mday = source->days,

        // mktime() converts this to hours/minutes/seconds appropriately
        .tm_sec = source->seconds,

        // Don't adjust DST here; let mktime() try to determine DST status
        .tm_isdst = -1,

#if defined(HAVE_STRUCT_TM_TM_GMTOFF)
        .tm_gmtoff = source->offset
#endif
    };
    mktime(target);
}

static char *
offset_text(int offset)
{
    uint32_t hours = 0;
    uint32_t minutes = 0;

    // If offset is out of range, default to NULL
    CRM_CHECK(QB_ABS(offset) <= SECONDS_IN_DAY, return NULL);

    seconds_to_hms(offset, &hours, &minutes, NULL);

    return pcmk__assert_asprintf("%c%02" PRIu32 ":%02" PRIu32,
                                 ((offset >= 0)? '+' : '-'), hours, minutes);
}

/*!
 * \internal
 * \brief Convert a <tt>struct tm</tt> to a \c GDateTime
 *
 * \param[in] tm      Time object to convert
 * \param[in] offset  Offset from UTC (in seconds)
 *
 * \return Newly allocated \c GDateTime object corresponding to \p tm, or
 *         \c NULL on error
 *
 * \note The caller is responsible for freeing the return value using
 *       \c g_date_time_unref().
 */
static GDateTime *
get_g_date_time(const struct tm *tm, int offset)
{
    // Accept an offset argument in case tm lacks a tm_gmtoff member
    char *offset_s = offset_text(offset);
    GTimeZone *tz = NULL;
    GDateTime *dt = NULL;

    // @COMPAT Starting in GLib 2.58, we can use g_time_zone_new_offset()
    tz = g_time_zone_new(offset_s);
    if (tz == NULL) {
        goto done;
    }

    dt = g_date_time_new(tz, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                         tm->tm_hour, tm->tm_min, tm->tm_sec);

done:
    free(offset_s);

    if (tz != NULL) {
        g_time_zone_unref(tz);
    }

    return dt;
}

/*!
 * \internal
 * \brief Expand a date/time format string, with support for fractional seconds
 *
 * \param[in] format  Date/time format string compatible with
 *                    \c g_date_time_format(), with additional support for
 *                    \c "%N" for fractional seconds
 * \param[in] dt      Time value to format (at seconds resolution)
 * \param[in] usec    Microseconds to add to \p dt when formatting
 *
 * \return Newly allocated string with formatted string, or \c NULL on error
 *
 * \note This function falls back to trying \c strftime() with a fixed-size
 *       buffer if \c g_date_time_format() fails. This fallback will be removed
 *       in a future release.
 */
char *
pcmk__time_format_hr(const char *format, const crm_time_t *dt, int usec)
{
    int scanned_pos = 0; // How many characters of format have been parsed
    int printed_pos = 0; // How many characters of format have been processed
    GString *buf = NULL;
    char *result = NULL;

    struct tm tm = { 0, };
    GDateTime *gdt = NULL;

    if (format == NULL) {
        return NULL;
    }

    buf = g_string_sized_new(128);

    ha_get_tm_time(&tm, dt);
    gdt = get_g_date_time(&tm, dt->offset);
    if (gdt == NULL) {
        goto done;
    }

    while (format[scanned_pos] != '\0') {
        int fmt_pos = 0;        // Index after last character to pass as-is
        int frac_digits = 0;    // %N specifier's width field value (if any)
        gchar *tmp_fmt_s = NULL;
        gchar *date_s = NULL;

        // Look for next format specifier
        const char *mark_s = strchr(&format[scanned_pos], '%');

        if (mark_s == NULL) {
            // No more specifiers, so pass remaining string to strftime() as-is
            scanned_pos = strlen(format);
            fmt_pos = scanned_pos;

        } else {
            fmt_pos = mark_s - format; // Index of %

            // Skip % and any width field
            scanned_pos = fmt_pos + 1;
            while (isdigit(format[scanned_pos])) {
                scanned_pos++;
            }

            switch (format[scanned_pos]) {
                case '\0': // Literal % and possibly digits at end of string
                    fmt_pos = scanned_pos; // Pass remaining string as-is
                    break;

                case 'N': // %[width]N
                    /* Fractional seconds. This was supposed to represent
                     * nanoseconds. However, we only store times at microsecond
                     * resolution, and the width field support makes this a
                     * general fractional component specifier rather than a
                     * nanoseconds specifier.
                     *
                     * Further, since we cap the width at 6 digits, a user
                     * cannot display times at greater than microsecond
                     * resolution.
                     *
                     * A leading zero in the width field is ignored, not treated
                     * as "use zero-padding." For example, "%03N" and "%3N"
                     * produce the same result.
                     */
                    scanned_pos++;

                    // Parse width field
                    frac_digits = atoi(&format[fmt_pos + 1]);
                    frac_digits = QB_MAX(frac_digits, 0);
                    frac_digits = QB_MIN(frac_digits, 6);
                    break;

                default: // Some other specifier
                    if (format[++scanned_pos] != '\0') { // More to parse
                        continue;
                    }
                    fmt_pos = scanned_pos; // Pass remaining string as-is
                    break;
            }
        }

        tmp_fmt_s = g_strndup(&format[printed_pos], fmt_pos - printed_pos);
        date_s = g_date_time_format(gdt, tmp_fmt_s);

        if (date_s == NULL) {
            char compat_date_s[1024] = { '\0' };
            size_t nbytes = 0;

            // @COMPAT Drop this fallback
            pcmk__warn("Could not format time using format string '%s' with "
                       "g_date_time_format(); trying strftime(). In a future "
                       "release, use of strftime() as a fallback will be "
                       "removed", format);

#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif  // HAVE_FORMAT_NONLITERAL
            nbytes = strftime(compat_date_s, sizeof(compat_date_s), tmp_fmt_s,
                              &tm);
#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic pop
#endif  // HAVE_FORMAT_NONLITERAL

            if (nbytes == 0) {
                // Truncation, empty string, or error; impossible to discern
                pcmk__err("Could not format time using format string '%s'",
                          format);

                // Ensure we return NULL
                g_string_truncate(buf, 0);
                g_free(tmp_fmt_s);
                goto done;
            }
            date_s = g_strdup(compat_date_s);
        }

        g_string_append(buf, date_s);
        g_free(date_s);
        g_free(tmp_fmt_s);

        printed_pos = scanned_pos;

        if (frac_digits != 0) {
            // Descending powers of 10 (10^5 down to 10^0)
            static const int powers[6] = { 1e5, 1e4, 1e3, 1e2, 1e1, 1e0 };

            // Sanity check to ensure array access is in bounds
            pcmk__assert((frac_digits > 0) && (frac_digits <= 6));

            /* Append fractional seconds at the requested resolution, truncated
             * toward zero. We're basically converting from microseconds to
             * another unit here. For example, suppose the width field
             * (frac_digits) is 3. This means "use millisecond resolution." Then
             * we need to divide our microseconds value by 10^3, which is
             * powers[3 - 1].
             *
             * If the width field is 6 (microsecond resolution), then we divide
             * our microseconds value by 10^0 == 1, which is powers[6 - 1].
             */
            g_string_append_printf(buf, "%0*d", frac_digits,
                                   usec / powers[frac_digits - 1]);
        }
    }

done:
    if (buf->len > 0) {
        result = pcmk__str_copy(buf->str);
    }
    g_string_free(buf, TRUE);

    if (gdt != NULL) {
        g_date_time_unref(gdt);
    }
    return result;
}

/*!
 * \internal
 * \brief Return a human-friendly string corresponding to an epoch time value
 *
 * \param[in]  source  Pointer to epoch time value (or \p NULL for current time)
 * \param[in]  flags   Group of \p crm_time_* flags controlling display format
 *                     (0 to use \p ctime() with newline removed)
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
    crm_time_t *dt = NULL;
    char *result = NULL;

    if (flags == 0) {
        return pcmk__str_copy(g_strchomp(ctime(&epoch_time)));
    }

    dt = pcmk__copy_timet(epoch_time);
    result = crm_time_as_string(dt, flags);

    crm_time_free(dt);
    return result;
}

/*!
 * \internal
 * \brief Return a human-friendly string corresponding to seconds-and-
 *        nanoseconds value
 *
 * Time is shown with microsecond resolution if \p crm_time_usecs is in \p
 * flags.
 *
 * \param[in]  ts     Time in seconds and nanoseconds (or \p NULL for current
 *                    time)
 * \param[in]  flags  Group of \p crm_time_* flags controlling display format
 *
 * \return String representation of \p ts on success (may be empty depending on
 *         \p flags; guaranteed not to be \p NULL)
 *
 * \note The caller is responsible for freeing the return value using \p free().
 */
char *
pcmk__timespec2str(const struct timespec *ts, uint32_t flags)
{
    struct timespec tmp_ts;
    crm_time_t *dt = NULL;
    char *result = NULL;

    if (ts == NULL) {
        qb_util_timespec_from_epoch_get(&tmp_ts);
        ts = &tmp_ts;
    }

    dt = pcmk__copy_timet(ts->tv_sec);
    result = time_as_string_common(dt, ts->tv_nsec / QB_TIME_NS_IN_USEC, flags);

    crm_time_free(dt);
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
 * \note The return value is a pointer to static memory that may be overwritten
 *       by later calls to this function.
 */
const char *
pcmk__readable_interval(unsigned int interval_ms)
{
#define MS_IN_S (1000)
#define MS_IN_M (MS_IN_S * SECONDS_IN_MINUTE)
#define MS_IN_H (MS_IN_M * MINUTES_IN_HOUR)
#define MS_IN_D (MS_IN_H * HOURS_IN_DAY)
#define MAXSTR sizeof("..d..h..m..s...ms")
    static char str[MAXSTR];
    GString *buf = NULL;

    if (interval_ms == 0) {
        return "0s";
    }

    buf = g_string_sized_new(128);

    if (interval_ms >= MS_IN_D) {
        g_string_append_printf(buf, "%ud", interval_ms / MS_IN_D);
        interval_ms -= (interval_ms / MS_IN_D) * MS_IN_D;
    }
    if (interval_ms >= MS_IN_H) {
        g_string_append_printf(buf, "%uh", interval_ms / MS_IN_H);
        interval_ms -= (interval_ms / MS_IN_H) * MS_IN_H;
    }
    if (interval_ms >= MS_IN_M) {
        g_string_append_printf(buf, "%um", interval_ms / MS_IN_M);
        interval_ms -= (interval_ms / MS_IN_M) * MS_IN_M;
    }

    // Ns, N.NNNs, or NNNms
    if (interval_ms >= MS_IN_S) {
        g_string_append_printf(buf, "%u", interval_ms / MS_IN_S);
        interval_ms -= (interval_ms / MS_IN_S) * MS_IN_S;

        if (interval_ms > 0) {
            g_string_append_printf(buf, ".%03u", interval_ms);
        }
        g_string_append_c(buf, 's');

    } else if (interval_ms > 0) {
        g_string_append_printf(buf, "%ums", interval_ms);
    }

    pcmk__assert(buf->len < sizeof(str));
    strncpy(str, buf->str, sizeof(str) - 1);
    g_string_free(buf, TRUE);
    return str;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/iso8601_compat.h>

bool
crm_time_leapyear(int year)
{
    return is_leap_year(year);
}

int
crm_time_days_in_month(int month, int year)
{
    return days_in_month_year(month, year);
}

int
crm_time_get_timezone(const crm_time_t *dt, uint32_t *h, uint32_t *m)
{
    seconds_to_hms(dt->seconds, h, m, NULL);
    return TRUE;
}

int
crm_time_weeks_in_year(int year)
{
    return weeks_in_year(year);
}

int
crm_time_january1_weekday(int year)
{
    return jan1_day_of_week(year);
}

void
crm_time_set(crm_time_t *target, const crm_time_t *source)
{
    const uint32_t flags = crm_time_log_date
                           |crm_time_log_timeofday
                           |crm_time_log_with_timezone;

    pcmk__trace("target=%p, source=%p", target, source);

    CRM_CHECK(target != NULL && source != NULL, return);

    target->years = source->years;
    target->days = source->days;
    target->months = source->months;    /* Only for durations */
    target->seconds = source->seconds;
    target->offset = source->offset;

    pcmk__time_log(LOG_TRACE, "source", source, flags);
    pcmk__time_log(LOG_TRACE, "target", target, flags);
}

bool
crm_time_check(const crm_time_t *dt)
{
    return valid_time(dt);
}

void
crm_time_set_timet(crm_time_t *target, const time_t *source_sec)
{
    crm_time_t *source = NULL;

    if (source_sec == NULL) {
        return;
    }

    source = pcmk__copy_timet(*source_sec);
    *target = *source;
    crm_time_free(source);
}

int
crm_time_get_isoweek(const crm_time_t *dt, uint32_t *y, uint32_t *w,
                     uint32_t *d)
{
    pcmk__assert((dt != NULL) && (y != NULL) && (w != NULL) && (d != NULL));

    CRM_CHECK(dt->days > 0, return FALSE);
    pcmk__time_get_ywd(dt, y, w, d);
    return TRUE;
}

void
crm_time_log_alias(int log_level, const char *file, const char *function,
                   int line, const char *prefix, const crm_time_t *date_time,
                   int flags)
{
    pcmk__time_log_as(file, function, line, pcmk__clip_log_level(log_level),
                      prefix, date_time, flags);
}

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

crm_time_period_t *
crm_time_parse_period(const char *period_str)
{
    const char *original = period_str;
    crm_time_period_t *period = NULL;

    if (pcmk__str_empty(period_str)) {
        pcmk__err("No ISO 8601 time period given");
        goto invalid;
    }

    tzset();
    period = pcmk__assert_alloc(1, sizeof(crm_time_period_t));

    if (period_str[0] == 'P') {
        period->diff = pcmk__time_parse_duration(period_str);
        if (period->diff == NULL) {
            goto invalid;
        }
    } else {
        period->start = parse_date(period_str);
        if (period->start == NULL) {
            goto invalid;
        }
    }

    period_str = strchr(original, '/');
    if (period_str != NULL) {
        ++period_str;
        if (period_str[0] == 'P') {
            if (period->diff != NULL) {
                pcmk__err("'%s' is not a valid ISO 8601 time period because it "
                          "has two durations",
                          original);
                goto invalid;
            }
            period->diff = pcmk__time_parse_duration(period_str);
            if (period->diff == NULL) {
                goto invalid;
            }
        } else {
            period->end = parse_date(period_str);
            if (period->end == NULL) {
                goto invalid;
            }
        }

    } else if (period->diff != NULL) {
        // Only duration given, assume start is now
        period->start = pcmk__copy_timet(time(NULL));

    } else {
        // Only start given
        pcmk__err("'%s' is not a valid ISO 8601 time period because it has no "
                  "duration or ending time",
                  original);
        goto invalid;
    }

    if (period->start == NULL) {
        period->start = crm_time_subtract(period->end, period->diff);

    } else if (period->end == NULL) {
        period->end = crm_time_add(period->start, period->diff);
    }

    if (!pcmk__time_valid_year(period->start->years)
        || !valid_time(period->start)) {

        pcmk__err("'%s' is not a valid ISO 8601 time period because the start "
                  "is invalid (must be between " BEGIN_VALID_RANGE_S " and "
                  END_VALID_RANGE_S ")", period_str);
        goto invalid;
    }

    if (!pcmk__time_valid_year(period->end->years)
        || !valid_time(period->end)) {

        pcmk__err("'%s' is not a valid ISO 8601 time period because the end is "
                  "invalid (must be between " BEGIN_VALID_RANGE_S " and "
                  END_VALID_RANGE_S ")", period_str);
        goto invalid;
    }

    return period;

invalid:
    errno = EINVAL;
    crm_time_free_period(period);
    return NULL;
}

crm_time_t *
crm_time_calculate_duration(const crm_time_t *dt, const crm_time_t *value)
{
    return subtract_time(dt, value, true);
}

crm_time_t *
crm_time_parse_duration(const char *period_s)
{
    return pcmk__time_parse_duration(period_s);
}

// LCOV_EXCL_STOP
// End deprecated API
