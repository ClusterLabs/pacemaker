/*
 * Copyright 2015-2021 the Pacemaker project contributors
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

pcmk__time_hr_t *pcmk__time_hr_convert(pcmk__time_hr_t *target, crm_time_t *dt);
void pcmk__time_set_hr_dt(crm_time_t *target, pcmk__time_hr_t *hr_dt);
pcmk__time_hr_t *pcmk__time_timeval_hr_convert(pcmk__time_hr_t *target,
                                               struct timeval *tv);
pcmk__time_hr_t *pcmk__time_hr_new(const char *date_time);
void pcmk__time_hr_free(pcmk__time_hr_t *hr_dt);
char *pcmk__time_format_hr(const char *format, pcmk__time_hr_t *hr_dt);
const char *pcmk__epoch2str(time_t *when);
const char *pcmk__readable_interval(guint interval_ms);

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
