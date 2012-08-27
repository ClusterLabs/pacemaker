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

int
main(int argc, char **argv)
{
    int rc = 0;
    int argerr = 0;
    int flag;
    int index = 0;
    int print_options = 0;
    ha_time_t *duration = NULL;
    ha_time_t *date_time = NULL;
    ha_time_period_t *interval = NULL;

    char *period_s = NULL;
    char *duration_s = NULL;
    char *date_time_s = NULL;
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
                date_time_s = strdup("now");
                break;
            case 'd':
                date_time_s = strdup(optarg);
                break;
            case 'p':
                period_s = strdup(optarg);
                break;
            case 'D':
                duration_s = strdup(optarg);
                break;
            case 'E':
                expected_s = optarg;
                break;
            case 'S':
                print_options |= ha_date_epoch;
                break;
            case 's':
                print_options |= ha_date_seconds;
                break;
            case 'W':
                print_options |= ha_date_weeks;
                break;
            case 'O':
                print_options |= ha_date_ordinal;
                break;
            case 'L':
                print_options |= ha_log_local;
                break;
                break;
        }
    }

    if(safe_str_eq("now", date_time_s)) {
        date_time = new_ha_date(TRUE);

        if (date_time == NULL) {
            fprintf(stderr, "Internal error: couldnt determin 'now' !\n");
            crm_help('?', 1);
        }
        log_date(LOG_TRACE, "Current date/time", date_time, ha_date_ordinal | ha_log_date | ha_log_time);
        log_date(-1, "Current date/time", date_time, print_options | ha_log_date | ha_log_time);

    } else if(date_time_s) {
        date_time = parse_date(&date_time_s);

        if (date_time == NULL) {
            fprintf(stderr, "Invalid date/time specified: %s\n", optarg);
            crm_help('?', 1);
        }
        log_date(LOG_TRACE, "Date", date_time, ha_date_ordinal | ha_log_date | ha_log_time);
        log_date(-1, "Date", date_time, print_options | ha_log_date | ha_log_time);
    }

    if(duration_s) {
        duration = parse_time_duration(&duration_s);

        if (duration == NULL) {
            fprintf(stderr, "Invalid duration specified: %s\n", optarg);
            crm_help('?', 1);
        }
        log_date(LOG_TRACE, "Duration", duration, ha_date_ordinal | ha_log_date | ha_log_time);
        log_date(-1, "Duration", duration, print_options | ha_log_date | ha_log_time | ha_log_local);
    }

    if(period_s) {
        interval = parse_time_period(&period_s);

        if (interval == NULL) {
            fprintf(stderr, "Invalid interval specified: %s\n", optarg);
            crm_help('?', 1);
        }
        log_time_period(-1, interval, print_options | ha_log_date | ha_log_time);
    }

    if(date_time && duration) {
        ha_time_t *later = add_time(date_time, duration);

        log_date(LOG_TRACE, "Duration ends at", later, ha_date_ordinal | ha_log_date | ha_log_time);
        log_date(-1, "Duration ends at", later, print_options | ha_log_date | ha_log_time | ha_log_local);
        if(expected_s) {
            char *dt_s = date_to_string(later, print_options | ha_log_date | ha_log_time);
            if(safe_str_neq(expected_s, dt_s)) {
                rc = 1;
            }
            free(dt_s);
        }
        free_ha_date(later);

    } else if(date_time && expected_s) {
        char *dt_s = date_to_string(date_time, print_options | ha_log_date | ha_log_time);
        if(safe_str_neq(expected_s, dt_s)) {
            rc = 1;
        }
        free(dt_s);
    }

    /* if(date_time && interval) { */
    /* } */

    free_ha_date(date_time);
    free_ha_date(duration);
    if(interval) {
        free_ha_date(interval->start);
        free_ha_date(interval->end);
        free_ha_date(interval->diff);
        free(interval);
    }

    free(date_time_s);
    free(duration_s);
    free(period_s);

    qb_log_fini();
    return rc;
}
