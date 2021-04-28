/*
 * Copyright 2005-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/iso8601.h>
#include <crm/common/util.h>  /* CRM_ASSERT */
#include <unistd.h>

char command = 0;

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nCommands:", pcmk__option_default
    },
    {
        "now", no_argument, NULL, 'n',
        "\tDisplay the current date/time", pcmk__option_default
    },
    {
        "date", required_argument, NULL, 'd',
        "Parse an ISO 8601 date/time (for example, "
            "'2019-09-24 00:30:00 +01:00' or '2019-040')",
        pcmk__option_default
    },
    {
        "period", required_argument, NULL, 'p',
        "Parse an ISO 8601 period (interval) with start time (for example, "
            "'2005-040/2005-043')",
        pcmk__option_default
    },
    {
        "duration", required_argument, NULL, 'D',
        "Parse an ISO 8601 duration (for example, 'P1M')", pcmk__option_default
    },
    {
        "expected", required_argument, NULL, 'E',
        "Exit with error status if result does not match this text. "
            "Requires: -n or -d",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nOutput Modifiers:", pcmk__option_default
    },
    {
        "seconds", no_argument, NULL, 's',
        "\tShow result as a seconds since 0000-001 00:00:00Z",
        pcmk__option_default
    },
    {
        "epoch", no_argument, NULL, 'S',
        "\tShow result as a seconds since EPOCH (1970-001 00:00:00Z)",
        pcmk__option_default
    },
    {
        "local", no_argument, NULL, 'L',
        "\tShow result as a 'local' date/time", pcmk__option_default
    },
    {
        "ordinal", no_argument, NULL, 'O',
        "\tShow result as an 'ordinal' date/time", pcmk__option_default
    },
    {
        "week", no_argument, NULL, 'W',
        "\tShow result as an 'calendar week' date/time", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nFor more information on the ISO 8601 standard, see "
            "https://en.wikipedia.org/wiki/ISO_8601",
        pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

static void
log_time_period(int log_level, crm_time_period_t * dtp, int flags)
{
    char *start = crm_time_as_string(dtp->start, flags);
    char *end = crm_time_as_string(dtp->end, flags);

    CRM_ASSERT(start != NULL && end != NULL);
    do_crm_log(log_level, "Period: %s to %s", start, end);
    free(start);
    free(end);
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    int argerr = 0;
    int flag;
    int index = 0;
    int print_options = 0;
    crm_time_t *duration = NULL;
    crm_time_t *date_time = NULL;

    const char *period_s = NULL;
    const char *duration_s = NULL;
    const char *date_time_s = NULL;
    const char *expected_s = NULL;

    pcmk__cli_init_logging("iso8601", 0);
    pcmk__set_cli_options(NULL, "<command> [options] ", long_options,
                          "display and parse ISO 8601 dates and times");

    if (argc < 2) {
        argerr++;
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '?':
            case '$':
                pcmk__cli_help(flag, CRM_EX_OK);
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

    if (pcmk__str_eq("now", date_time_s, pcmk__str_casei)) {
        date_time = crm_time_new(NULL);

        if (date_time == NULL) {
            fprintf(stderr, "Internal error: couldn't determine 'now'!\n");
            crm_exit(CRM_EX_SOFTWARE);
        }
        crm_time_log(LOG_TRACE, "Current date/time", date_time,
                     crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(LOG_STDOUT, "Current date/time", date_time,
                     print_options | crm_time_log_date | crm_time_log_timeofday);

    } else if (date_time_s) {
        date_time = crm_time_new(date_time_s);

        if (date_time == NULL) {
            fprintf(stderr, "Invalid date/time specified: %s\n", date_time_s);
            crm_exit(CRM_EX_INVALID_PARAM);
        }
        crm_time_log(LOG_TRACE, "Date", date_time,
                     crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(LOG_STDOUT, "Date", date_time,
                     print_options | crm_time_log_date | crm_time_log_timeofday);
    }

    if (duration_s) {
        duration = crm_time_parse_duration(duration_s);

        if (duration == NULL) {
            fprintf(stderr, "Invalid duration specified: %s\n", duration_s);
            crm_exit(CRM_EX_INVALID_PARAM);
        }
        crm_time_log(LOG_TRACE, "Duration", duration, crm_time_log_duration);
        crm_time_log(LOG_STDOUT, "Duration", duration,
                     print_options | crm_time_log_duration);
    }

    if (period_s) {
        crm_time_period_t *period = crm_time_parse_period(period_s);

        if (period == NULL) {
            fprintf(stderr, "Invalid interval specified: %s\n", period_s);
            crm_exit(CRM_EX_INVALID_PARAM);
        }
        log_time_period(LOG_TRACE, period,
                        print_options | crm_time_log_date | crm_time_log_timeofday);
        log_time_period(LOG_STDOUT, period,
                        print_options | crm_time_log_date | crm_time_log_timeofday);
        crm_time_free_period(period);
    }

    if (date_time && duration) {
        crm_time_t *later = crm_time_add(date_time, duration);

        if (later == NULL) {
            fprintf(stderr, "Unable to calculate ending time of %s plus %s",
                    date_time_s, duration_s);
            crm_exit(CRM_EX_SOFTWARE);
        }
        crm_time_log(LOG_TRACE, "Duration ends at", later,
                     crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(LOG_STDOUT, "Duration ends at", later,
                     print_options | crm_time_log_date | crm_time_log_timeofday |
                     crm_time_log_with_timezone);
        if (expected_s) {
            char *dt_s = crm_time_as_string(later,
                                            print_options | crm_time_log_date |
                                            crm_time_log_timeofday);
            if (!pcmk__str_eq(expected_s, dt_s, pcmk__str_casei)) {
                exit_code = CRM_EX_ERROR;
            }
            free(dt_s);
        }
        crm_time_free(later);

    } else if (date_time && expected_s) {
        char *dt_s = crm_time_as_string(date_time,
                                        print_options | crm_time_log_date | crm_time_log_timeofday);

        if (!pcmk__str_eq(expected_s, dt_s, pcmk__str_casei)) {
            exit_code = CRM_EX_ERROR;
        }
        free(dt_s);
    }

    crm_time_free(date_time);
    crm_time_free(duration);
    crm_exit(exit_code);
}
