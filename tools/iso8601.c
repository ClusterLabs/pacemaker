/*
 * Copyright 2005-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/iso8601.h>
#include <crm/common/util.h>  /* CRM_ASSERT */
#include <unistd.h>

#define SUMMARY "Display and parse ISO 8601 dates and times"

struct {
    char *date_time_s;
    gchar *duration_s;
    gchar *expected_s;
    gchar *period_s;
    int print_options;
} options;

#define INDENT "                              "

static gboolean
date_now_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "--now", "-n", NULL)) {
        pcmk__str_update(&options.date_time_s, "now");
    } else if (pcmk__str_any_of(option_name, "--date", "-d", NULL)) {
        pcmk__str_update(&options.date_time_s, optarg);
    }

    return TRUE;
}

static gboolean
modifier_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "--seconds", "-s", NULL)) {
        options.print_options |= crm_time_seconds;
    } else if (pcmk__str_any_of(option_name, "--epoch", "-S", NULL)) {
        options.print_options |= crm_time_epoch;
    } else if (pcmk__str_any_of(option_name, "--local", "-L", NULL)) {
        options.print_options |= crm_time_log_with_timezone;
    } else if (pcmk__str_any_of(option_name, "--ordinal", "-O", NULL)) {
        options.print_options |= crm_time_ordinal;
    } else if (pcmk__str_any_of(option_name, "--week", "-W", NULL)) {
        options.print_options |= crm_time_weeks;
    }

    return TRUE;
}

static GOptionEntry command_entries[] = {
    { "now", 'n', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, date_now_cb,
      "Display the current date/time",
      NULL },

    { "date", 'd', 0, G_OPTION_ARG_CALLBACK, date_now_cb,
      "Parse an ISO 8601 date/time (for example,\n"
      INDENT "'2019-09-24 00:30:00 +01:00' or '2019-040')",
      "DATE" },

    { "period", 'p', 0, G_OPTION_ARG_STRING, &options.period_s,
      "Parse an ISO 8601 period (interval) with start time (for example,\n"
      INDENT "'2005-040/2005-043')",
      "PERIOD" },

    { "duration", 'D', 0, G_OPTION_ARG_STRING, &options.duration_s,
      "Parse an ISO 8601 duration (for example, 'P1M')",
      "DURATION" },

    { "expected", 'E', 0, G_OPTION_ARG_STRING, &options.expected_s,
      "Exit with error status if result does not match this text.\n"
      INDENT "Requires: -n or -d",
      "TEXT" },

    { NULL }
};

static GOptionEntry modifier_entries[] = {
    { "seconds", 's', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, modifier_cb,
      "Show result as a seconds since 0000-001 00:00:00Z",
      NULL },

    { "epoch", 'S', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, modifier_cb,
      "Show result as a seconds since EPOCH (1970-001 00:00:00Z)",
      NULL },

    { "local", 'L', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, modifier_cb,
      "Show result as a 'local' date/time",
      NULL },

    { "ordinal", 'O', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, modifier_cb,
      "Show result as an 'ordinal' date/time",
      NULL },

    { "week", 'W', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, modifier_cb,
      "Show result as an 'calendar week' date/time",
      NULL },

    { NULL }
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

static GOptionContext *
build_arg_context(pcmk__common_args_t *args) {
    GOptionContext *context = NULL;

    const char *description = "For more information on the ISO 8601 standard, see " \
                              "https://en.wikipedia.org/wiki/ISO_8601";

    context = pcmk__build_arg_context(args, NULL, NULL, NULL);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command options", command_entries);
    pcmk__add_arg_group(context, "modifiers", "Output modifiers:",
                        "Show output modifiers", modifier_entries);

    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    crm_time_t *duration = NULL;
    crm_time_t *date_time = NULL;

    GError *error = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    GOptionContext *context = build_arg_context(args);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "dpDE");

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("iso8601", args->verbosity);

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When iso8601 is converted to use formatted output, this can go. */
        pcmk__cli_help('v');
    }

    if (pcmk__str_eq("now", options.date_time_s, pcmk__str_casei)) {
        date_time = crm_time_new(NULL);

        if (date_time == NULL) {
            exit_code = CRM_EX_SOFTWARE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Internal error: couldn't determine 'now'!");
            goto done;
        }

        crm_time_log(LOG_TRACE, "Current date/time", date_time,
                     crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(LOG_STDOUT, "Current date/time", date_time,
                     options.print_options | crm_time_log_date | crm_time_log_timeofday);

    } else if (options.date_time_s) {
        date_time = crm_time_new(options.date_time_s);

        if (date_time == NULL) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid date/time specified: %s", options.date_time_s);
            goto done;
        }

        crm_time_log(LOG_TRACE, "Date", date_time,
                     crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(LOG_STDOUT, "Date", date_time,
                     options.print_options | crm_time_log_date | crm_time_log_timeofday);
    }

    if (options.duration_s) {
        duration = crm_time_parse_duration(options.duration_s);

        if (duration == NULL) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid duration specified: %s", options.duration_s);
            goto done;
        }

        crm_time_log(LOG_TRACE, "Duration", duration, crm_time_log_duration);
        crm_time_log(LOG_STDOUT, "Duration", duration,
                     options.print_options | crm_time_log_duration);
    }

    if (options.period_s) {
        crm_time_period_t *period = crm_time_parse_period(options.period_s);

        if (period == NULL) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid interval specified: %s", options.period_s);
            goto done;
        }

        log_time_period(LOG_TRACE, period,
                        options.print_options | crm_time_log_date | crm_time_log_timeofday);
        log_time_period(LOG_STDOUT, period,
                        options.print_options | crm_time_log_date | crm_time_log_timeofday);
        crm_time_free_period(period);
    }

    if (date_time && duration) {
        crm_time_t *later = crm_time_add(date_time, duration);

        if (later == NULL) {
            exit_code = CRM_EX_SOFTWARE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Unable to calculate ending time of %s plus %s",
                        options.date_time_s, options.duration_s);
            goto done;
        }

        crm_time_log(LOG_TRACE, "Duration ends at", later,
                     crm_time_ordinal | crm_time_log_date | crm_time_log_timeofday);
        crm_time_log(LOG_STDOUT, "Duration ends at", later,
                     options.print_options | crm_time_log_date | crm_time_log_timeofday |
                     crm_time_log_with_timezone);

        if (options.expected_s) {
            char *dt_s = crm_time_as_string(later,
                                            options.print_options | crm_time_log_date |
                                            crm_time_log_timeofday);
            if (!pcmk__str_eq(options.expected_s, dt_s, pcmk__str_casei)) {
                exit_code = CRM_EX_ERROR;
                goto done;
            }
            free(dt_s);
        }
        crm_time_free(later);

    } else if (date_time && options.expected_s) {
        char *dt_s = crm_time_as_string(date_time,
                                        options.print_options | crm_time_log_date | crm_time_log_timeofday);

        if (!pcmk__str_eq(options.expected_s, dt_s, pcmk__str_casei)) {
            exit_code = CRM_EX_ERROR;
            goto done;
        }
        free(dt_s);
    }

done:
    crm_time_free(date_time);
    crm_time_free(duration);

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    free(options.date_time_s);
    g_free(options.duration_s);
    g_free(options.expected_s);
    g_free(options.period_s);

    pcmk__output_and_clear_error(&error, NULL);
    crm_exit(exit_code);
}
