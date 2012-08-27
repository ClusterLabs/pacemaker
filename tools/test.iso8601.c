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

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/iso8601.h>
#include <unistd.h>

char command = 0;

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {"-spacer-",    0, 0, '-', "\nCommands:"},
    {"now",      0, 0, 'n', "\tDisplay the current date/time"},
    {"date",     1, 0, 'd', "Parse an ISO8601 date/time.  Eg. '2005-01-20 00:30:00 +01:00' or '2005-040'"},
    {"period",   1, 0, 'p', "Parse an ISO8601 date/time with interval/period (wth start time).  Eg. '2005-040/2005-043'"},
    {"duration", 1, 0, 'D', "Parse an ISO8601 date/time with duration (wth start time). Eg. '2005-040/P1M'"},
    {"expected", 1, 0, 'E', "Parse an ISO8601 date/time with duration (wth start time). Eg. '2005-040/P1M'"},

    {"-spacer-",0, 0, '-', "\nOutput Modifiers:"},
    {"seconds", 0, 0, 's', "\tShow result as a seconds since 0000-001 00:00:00Z"},
    {"epoch", 0, 0, 'S', "\tShow result as a seconds since EPOCH (1970-001 00:00:00Z)"},
    {"local",   0, 0, 'L', "\tShow result as a 'local' date/time"},
    {"ordinal", 0, 0, 'O', "\tShow result as an 'ordinal' date/time"},
    {"week",    0, 0, 'W', "\tShow result as an 'calendar week' date/time"},
    {"-spacer-",0, 0, '-', "\nFor more information on the ISO8601 standard, see: http://en.wikipedia.org/wiki/ISO_8601"},
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static void
log_time_period(int log_level, crm_time_period_t * dtp, int flags)
{
    char *start = crm_time_as_string(dtp->start, flags);
    char *end = crm_time_as_string(dtp->end, flags);
    if(log_level < LOG_CRIT) {
        printf("Period: %s to %s\n", start, end);
    } else {
        do_crm_log(log_level, "Period: %s to %s", start, end);
    }
    free(start);
    free(end);
}

int
main(int argc, char **argv)
{
    int rc = 0;
    int argerr = 0;
    int flag;
    int index = 0;
    int print_options = 0;
    crm_time_t *duration = NULL;
    crm_time_t *date_time = NULL;
    crm_time_period_t *interval = NULL;

    const char *period_s = NULL;
    const char *duration_s = NULL;
    const char *date_time_s = NULL;
    const char *expected_s = NULL;
    
    crm_log_cli_init("iso8601");
    crm_set_options(NULL, "command [output modifier] ", long_options,
                    "Display and parse ISO8601 dates and times");

    if (argc < 2) {
        argerr++;
    }

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
                crm_help(flag, 0);
                break;
            case 'n':
                date_time_s = "now";
                break;
            case 'd':
                date_time_s = optarg;
                break;
            case 'p':
                period_s = optarg;
                break;
            case 'D':
                duration_s = optarg;
                break;
            case 'E':
                expected_s = optarg;
                break;
            case 'S':
                print_options |= crm_time_epoch;
                break;
            case 's':
                print_options |= crm_time_seconds;
                break;
            case 'W':
                print_options |= crm_time_weeks;
                break;
            case 'O':
                print_options |= crm_time_ordinal;
                break;
            case 'L':
                print_options |= crm_time_log_with_timezone;
                break;
                break;
        }
    }

    if(safe_str_eq("now", date_time_s)) {
        date_time = crm_time_new(NULL);

        if (date_time == NULL) {
            fprintf(stderr, "Internal error: couldnt determin 'now' !\n");
            crm_help('?', 1);
        }
        crm_time_log(LOG_TRACE, "Current date/time", date_time, crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(-1, "Current date/time", date_time, print_options | crm_time_log_date | crm_time_log_timeofday);

    } else if(date_time_s) {
        date_time = crm_time_new(date_time_s);

        if (date_time == NULL) {
            fprintf(stderr, "Invalid date/time specified: %s\n", optarg);
            crm_help('?', 1);
        }
        crm_time_log(LOG_TRACE, "Date", date_time, crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(-1, "Date", date_time, print_options | crm_time_log_date | crm_time_log_timeofday);
    }

    if(duration_s) {
        duration = crm_time_parse_duration(duration_s);

        if (duration == NULL) {
            fprintf(stderr, "Invalid duration specified: %s\n", duration_s);
            crm_help('?', 1);
        }
        crm_time_log(LOG_TRACE, "Duration", duration, crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(-1, "Duration", duration, print_options | crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
    }

    if(period_s) {
        interval = crm_time_parse_period(period_s);

        if (interval == NULL) {
            fprintf(stderr, "Invalid interval specified: %s\n", optarg);
            crm_help('?', 1);
        }
        log_time_period(LOG_TRACE, interval, print_options | crm_time_log_date | crm_time_log_timeofday);
        log_time_period(-1, interval, print_options | crm_time_log_date | crm_time_log_timeofday);
    }

    if(date_time && duration) {
        crm_time_t *later = crm_time_add(date_time, duration);

        crm_time_log(LOG_TRACE, "Duration ends at", later, crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(-1, "Duration ends at", later, print_options | crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone);
        if(expected_s) {
            char *dt_s = crm_time_as_string(later, print_options | crm_time_log_date | crm_time_log_timeofday);
            if(safe_str_neq(expected_s, dt_s)) {
                rc = 1;
            }
            free(dt_s);
        }
        crm_time_free(later);

    } else if(date_time && expected_s) {
        char *dt_s = crm_time_as_string(date_time, print_options | crm_time_log_date | crm_time_log_timeofday);
        if(safe_str_neq(expected_s, dt_s)) {
            rc = 1;
        }
        free(dt_s);
    }

    /* if(date_time && interval) { */
    /* } */

    crm_time_free(date_time);
    crm_time_free(duration);
    if(interval) {
        crm_time_free(interval->start);
        crm_time_free(interval->end);
        crm_time_free(interval->diff);
        free(interval);
    }

    qb_log_fini();
    return rc;
}
