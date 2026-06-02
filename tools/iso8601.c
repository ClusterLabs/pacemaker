/*
 * Copyright 2005-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/crm.h>
#include <crm/common/iso8601.h>
#include <crm/common/util.h>
#include <unistd.h>

#define SUMMARY "DEPRECATED: This tool will be removed in a future release"

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

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
      INDENT "'2019-09-24 00:30:00+01:00' or '2019-040')",
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

PCMK__OUTPUT_ARGS("date", "const char *", "crm_time_t *", "int")
static int
date_default(pcmk__output_t *out, va_list args)
{
    const char *prefix = va_arg(args, const char *);
    crm_time_t *date = va_arg(args, crm_time_t *);
    int opts = va_arg(args, int);

    char *date_s = NULL;

    opts |= crm_time_log_date | crm_time_log_timeofday;
    date_s = crm_time_as_string(date, opts);

    out->info(out, "%s: %s", prefix, date_s);

    free(date_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("date", "const char *", "crm_time_t *", "int")
static int
date_xml(pcmk__output_t *out, va_list args)
{
    const char *prefix G_GNUC_UNUSED = va_arg(args, const char *);
    crm_time_t *date = va_arg(args, crm_time_t *);
    int opts = va_arg(args, int);

    char *date_s = NULL;

    opts |= crm_time_log_date | crm_time_log_timeofday;
    date_s = crm_time_as_string(date, opts);

    pcmk__output_create_xml_text_node(out, PCMK_XE_DATE, date_s);
    free(date_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("duration", "crm_time_t *", "int")
static int
duration_default(pcmk__output_t *out, va_list args)
{
    crm_time_t *time = va_arg(args, crm_time_t *);
    int opts = va_arg(args, int);

    char *date_s = crm_time_as_string(time, opts | crm_time_log_duration);

    out->info(out, "Duration: %s", date_s);

    free(date_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("duration", "crm_time_t *", "int")
static int
duration_xml(pcmk__output_t *out, va_list args)
{
    crm_time_t *time = va_arg(args, crm_time_t *);
    int opts = va_arg(args, int);

    char *date_s = crm_time_as_string(time, opts | crm_time_log_duration);

    pcmk__output_create_xml_text_node(out, PCMK_XE_DURATION, date_s);
    free(date_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("duration_ends", "crm_time_t *", "int")
static int
duration_ends_default(pcmk__output_t *out, va_list args)
{
    crm_time_t *time = va_arg(args, crm_time_t *);
    int opts = va_arg(args, int);

    char *date_s = NULL;

    opts |= crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone;
    date_s = crm_time_as_string(time, opts);

    out->info(out, "Duration ends at: %s", date_s);

    free(date_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("duration_ends", "crm_time_t *", "int")
static int
duration_ends_xml(pcmk__output_t *out, va_list args)
{
    crm_time_t *time = va_arg(args, crm_time_t *);
    int opts = va_arg(args, int);

    char *date_s = NULL;

    opts |= crm_time_log_date | crm_time_log_timeofday | crm_time_log_with_timezone;
    date_s = crm_time_as_string(time, opts);

    pcmk__output_create_xml_text_node(out, PCMK_XE_DURATION_ENDS, date_s);
    free(date_s);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("period", "crm_time_period_t *", "int")
static int
period_default(pcmk__output_t *out, va_list args)
{
    crm_time_period_t *period = va_arg(args, crm_time_period_t *);
    int opts = va_arg(args, int);

    char *start = NULL;
    char *end = NULL;

    opts |= crm_time_log_date | crm_time_log_timeofday;

    start = crm_time_as_string(period->start, opts);
    if (start == NULL) {
        return pcmk_rc_no_output;
    }

    end = crm_time_as_string(period->end, opts);
    if (end == NULL) {
        free(start);
        return pcmk_rc_no_output;
    }

    out->info(out, "Period: %s to %s", start, end);

    free(start);
    free(end);
    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("period", "crm_time_period_t *", "int")
static int
period_xml(pcmk__output_t *out, va_list args)
{
    crm_time_period_t *period = va_arg(args, crm_time_period_t *);
    int opts = va_arg(args, int);

    char *start = NULL;
    char *end = NULL;

    opts |= crm_time_log_date | crm_time_log_timeofday;

    start = crm_time_as_string(period->start, opts);
    if (start == NULL) {
        return pcmk_rc_no_output;
    }

    end = crm_time_as_string(period->end, opts);
    if (end == NULL) {
        free(start);
        return pcmk_rc_no_output;
    }

    pcmk__output_xml_create_parent(out, PCMK_XE_PERIOD);
    pcmk__output_create_xml_text_node(out, PCMK_XE_START, start);
    pcmk__output_create_xml_text_node(out, PCMK_XE_END, end);

    free(start);
    free(end);
    return pcmk_rc_ok;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;

    const char *description = "For more information on the ISO 8601 standard, see " \
                              "https://en.wikipedia.org/wiki/ISO_8601";

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command options", command_entries);
    pcmk__add_arg_group(context, "modifiers", "Output modifiers:",
                        "Show output modifiers", modifier_entries);

    return context;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "date", "default", date_default },
    { "date", "xml", date_xml },
    { "duration", "default", duration_default },
    { "duration", "xml", duration_xml },
    { "duration_ends", "default", duration_ends_default },
    { "duration_ends", "xml", duration_ends_xml },
    { "period", "default", period_default },
    { "period", "xml", period_xml },

    { NULL, NULL, NULL }
};

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;
    crm_time_t *duration = NULL;
    crm_time_t *date_time = NULL;

    GError *error = NULL;
    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    GOptionContext *context = build_arg_context(args, &output_group);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "dpDE");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("iso8601", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    pcmk__register_messages(out, fmt_functions);

    if (pcmk__str_eq("now", options.date_time_s, pcmk__str_casei)) {
        date_time = crm_time_new(NULL);

        if (date_time == NULL) {
            exit_code = CRM_EX_SOFTWARE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Internal error: couldn't determine 'now'!");
            goto done;
        }

        out->message(out, "date", "Current date/time", date_time,
                     options.print_options);

    } else if (options.date_time_s) {
        date_time = crm_time_new(options.date_time_s);

        if (date_time == NULL) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid date/time specified: %s", options.date_time_s);
            goto done;
        }

        out->message(out, "date", "Date", date_time, options.print_options);
    }

    if (options.duration_s) {
        duration = crm_time_parse_duration(options.duration_s);

        if (duration == NULL) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid duration specified: %s", options.duration_s);
            goto done;
        }

        out->message(out, "duration", duration, options.print_options);
    }

    if (options.period_s) {
        crm_time_period_t *period = crm_time_parse_period(options.period_s);

        if (period == NULL) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid interval specified: %s", options.period_s);
            goto done;
        }

        out->message(out, "period", period, options.print_options);
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

        out->message(out, "duration_ends", later, options.print_options);

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

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}
