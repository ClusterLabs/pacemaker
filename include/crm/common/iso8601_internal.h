/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ISO8601_INTERNAL__H
#define PCMK__CRM_COMMON_ISO8601_INTERNAL__H

#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <crm/common/iso8601.h>

#ifdef __cplusplus
extern "C" {
#endif

void pcmk__time_get_ywd(const crm_time_t *dt, uint32_t *y, uint32_t *w,
                        uint32_t *d);
char *pcmk__time_format_hr(const char *format, const crm_time_t *dt, int usec);
char *pcmk__epoch2str(const time_t *source, uint32_t flags);
char *pcmk__timespec2str(const struct timespec *ts, uint32_t flags);
const char *pcmk__readable_interval(guint interval_ms);
crm_time_t *pcmk__copy_timet(time_t source_sec);

// A date/time or duration
struct crm_time_s {
    // Calendar year (date/time) or number of years (duration)
    int years;

    // Number of months (duration only)
    int months;

    // Ordinal day of year (date/time) or number of days (duration)
    int days;

    // Seconds of day (date/time) or number of seconds (duration)
    int seconds;

    // Seconds offset from UTC (date/time only)
    int offset;

    // True if duration
    bool duration;
};

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ISO8601_INTERNAL__H
