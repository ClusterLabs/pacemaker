/*
 * Copyright 2015-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__ISO8601_INTERNAL__H
#  define PCMK__ISO8601_INTERNAL__H

#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <crm/common/iso8601.h>

typedef struct pcmk__time_us pcmk__time_hr_t;

void pcmk__time_get_timezone(const crm_time_t *dt, int *hours, int *minutes);
pcmk__time_hr_t *pcmk__time_hr_convert(pcmk__time_hr_t *target,
                                       const crm_time_t *dt);
void pcmk__time_set_hr_dt(crm_time_t *target, const pcmk__time_hr_t *hr_dt);
pcmk__time_hr_t *pcmk__time_hr_now(time_t *epoch);
pcmk__time_hr_t *pcmk__time_hr_new(const char *date_time);
void pcmk__time_hr_free(pcmk__time_hr_t *hr_dt);
char *pcmk__time_format_hr(const char *format, const pcmk__time_hr_t *hr_dt);
char *pcmk__epoch2str(const time_t *source, uint32_t flags);
char *pcmk__timespec2str(const struct timespec *ts, uint32_t flags);
const char *pcmk__readable_interval(guint interval_ms);
crm_time_t *pcmk__copy_timet(time_t source);
void pcmk__time_set_timezone(crm_time_t *dt, int hours, int minutes);

struct pcmk__time_us {
    int years;
    int months;                 /* Only for durations */
    int days;
    int seconds;
    int offset;                 /* Seconds */
    bool duration;
    int useconds;
};

#endif
