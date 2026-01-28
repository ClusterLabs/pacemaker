/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/iso8601.h>
#include <crm/common/xml.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#include <sys/stat.h>

#define SUMMARY "evaluate rules from the Pacemaker configuration"

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

enum crm_rule_mode {
    crm_rule_mode_none,
    crm_rule_mode_check
};

struct {
    char *date;
    char *input_xml;
    enum crm_rule_mode mode;
    gchar **rules;
} options = {
    .mode = crm_rule_mode_none
};

static gboolean mode_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry mode_entries[] = {
    { "check", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, mode_cb,
      "Check whether a rule is in effect",
      NULL },

    { NULL }
};

static GOptionEntry data_entries[] = {
    { "xml-text", 'X', 0, G_OPTION_ARG_STRING, &options.input_xml,
      "Use argument for XML (or stdin if '-')",
      NULL },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "date", 'd', 0, G_OPTION_ARG_STRING, &options.date,
      "Whether the rule is in effect on a given date",
      NULL },
    { "rule", 'r', 0, G_OPTION_ARG_STRING_ARRAY, &options.rules,
      "The ID of the rule to check (may be specified multiple times)",
      NULL },

    { NULL }
};

static gboolean
mode_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (strcmp(option_name, "c")) {
        options.mode = crm_rule_mode_check;
    }

    return TRUE;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);

    pcmk__add_arg_group(context, "modes", "Modes (mutually exclusive):",
                        "Show modes of operation", mode_entries);
    pcmk__add_arg_group(context, "data", "Data:",
                        "Show data options", data_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    crm_time_t *rule_date = NULL;
    xmlNode *input = NULL;

    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    GError *error = NULL;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    GOptionContext *context = build_arg_context(args, &output_group);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "drX");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_rule", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pcmk__register_lib_messages(out);

    if (args->version) {
        out->version(out);
        goto done;
    }

    /* Check command line arguments before opening a connection to
     * the CIB manager or doing anything else important.
     */
    switch(options.mode) {
        case crm_rule_mode_check:
            if (options.rules == NULL) {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "--check requires use of --rule=");
                goto done;
            }

            break;

        default:
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "No mode operation given");
            goto done;
            break;
    }

    /* Set up some defaults. */
    rule_date = crm_time_new(options.date);
    if (rule_date == NULL) {
        if (options.date != NULL) {
            exit_code = CRM_EX_DATAERR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Invalid date specified: '%s'", options.date);

        } else {
            // Should never happen
            exit_code = CRM_EX_OSERR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "No --date given and can't determine current date");
        }
        goto done;
    }

    // Parse the input XML specified by the command-line options, if any
    if (pcmk__str_eq(options.input_xml, "-", pcmk__str_none)) {
        input = pcmk__xml_read(NULL);

        if (input == NULL) {
            exit_code = CRM_EX_DATAERR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Couldn't parse input from STDIN");
            goto done;
        }
    } else if (options.input_xml != NULL) {
        input = pcmk__xml_parse(options.input_xml);

        if (input == NULL) {
            exit_code = CRM_EX_DATAERR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Couldn't parse input string: %s", options.input_xml);
            goto done;
        }
    }

    /* Now do whichever operation mode was asked for.  There's only one at the
     * moment so this looks a little silly, but I expect there will be more
     * modes in the future.
     */
    switch(options.mode) {
        case crm_rule_mode_check:
            rc = pcmk__check_rules(out, input, rule_date,
                                   (const char *const *) options.rules);
            exit_code = pcmk_rc2exitc(rc);
            break;

        default:
            break;
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    crm_time_free(rule_date);
    pcmk__xml_free(input);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    return crm_exit(exit_code);
}
