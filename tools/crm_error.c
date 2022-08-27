/*
 * Copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/strings_internal.h>

#include <crm/crm.h>

#define SUMMARY "crm_error - display name or description of a Pacemaker error code"

struct {
    gboolean with_name;
    gboolean do_list;
    enum pcmk_result_type result_type; // How to interpret result codes
} options = {
    .result_type = pcmk_result_legacy,
};

static gboolean
result_type_cb(const gchar *option_name, const gchar *optarg, gpointer data,
               GError **error)
{
    if (pcmk__str_any_of(option_name, "--exit", "-X", NULL)) {
        options.result_type = pcmk_result_exitcode;
    } else if (pcmk__str_any_of(option_name, "--rc", "-r", NULL)) {
        options.result_type = pcmk_result_rc;
    }

    return TRUE;
}

static GOptionEntry entries[] = {
    { "name", 'n', 0, G_OPTION_ARG_NONE, &options.with_name,
      "Show error's name with its description (useful for looking for sources "
      "of the error in source code)",
       NULL },
    { "list", 'l', 0, G_OPTION_ARG_NONE, &options.do_list,
      "Show all known errors (enabled by default if no rc is specified)",
      NULL },
    { "exit", 'X', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, result_type_cb,
      "Interpret as exit code rather than legacy function return value",
      NULL },
    { "rc", 'r', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, result_type_cb,
      "Interpret as return code rather than legacy function return value",
      NULL },

    { NULL }
};

PCMK__OUTPUT_ARGS("result-code", "int", "char *", "char *");
static int
result_code_none(pcmk__output_t *out, va_list args)
{
    return pcmk_rc_no_output;
}

PCMK__OUTPUT_ARGS("result-code", "int", "char *", "char *");
static int
result_code_text(pcmk__output_t *out, va_list args)
{
    int code = va_arg(args, int);
    char *name = va_arg(args, char *);
    char *desc = va_arg(args, char *);

    static int code_width = 0;

    if (out->is_quiet(out)) {
        /* If out->is_quiet(), don't print the code. Print name and/or desc in a
         * compact format for text output, or print nothing at all for none-type
         * output.
         */
        if ((name != NULL) && (desc != NULL)) {
            pcmk__formatted_printf(out, "%s - %s\n", name, desc);

        } else if ((name != NULL) || (desc != NULL)) {
            pcmk__formatted_printf(out, "%s\n", ((name != NULL)? name : desc));
        }
        return pcmk_rc_ok;
    }

    /* Get length of longest (most negative) standard Pacemaker return code
     * This should be longer than all the values of any other type of return
     * code.
     */
    if (code_width == 0) {
        long long most_negative = pcmk_rc_error - (long long) pcmk__n_rc + 1;
        code_width = (int) snprintf(NULL, 0, "%lld", most_negative);
    }

    if ((name != NULL) && (desc != NULL)) {
        static int name_width = 0;

        if (name_width == 0) {
            // Get length of longest standard Pacemaker return code name
            for (int lpc = 0; lpc < pcmk__n_rc; lpc++) {
                int len = (int) strlen(pcmk_rc_name(pcmk_rc_error - lpc));
                name_width = QB_MAX(name_width, len);
            }
        }
        return out->info(out, "% *d: %-*s  %s", code_width, code, name_width,
                         name, desc);
    }

    if ((name != NULL) || (desc != NULL)) {
        return out->info(out, "% *d: %s", code_width, code,
                         ((name != NULL)? name : desc));
    }

    return out->info(out, "% *d", code_width, code);
}

PCMK__OUTPUT_ARGS("result-code", "int", "char *", "char *");
static int
result_code_xml(pcmk__output_t *out, va_list args)
{
    int code = va_arg(args, int);
    char *name = va_arg(args, char *);
    char *desc = va_arg(args, char *);

    char *code_str = pcmk__itoa(code);
    pcmk__output_create_xml_node(out, "result-code",
                                 "code", code_str,
                                 XML_ATTR_NAME, name,
                                 XML_ATTR_DESC, desc,
                                 NULL);
    free(code_str);
    return pcmk_rc_ok;
}

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static pcmk__message_entry_t fmt_functions[] = {
    { "result-code", "none", result_code_none },
    { "result-code", "text", result_code_text },
    { "result-code", "xml", result_code_xml },

    { NULL, NULL, NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group,
                                      "[-- <rc> [<rc>...]]");
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;
    const char *name = NULL;
    const char *desc = NULL;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_error", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (g_strv_length(processed_args) < 2) {
        // If no result codes were specified, list them all
        options.do_list = TRUE;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    pcmk__register_messages(out, fmt_functions);

    if (options.do_list) {
        int start = 0;
        int end = 0;
        int code = 0;

        pcmk__result_bounds(options.result_type, &start, &end);

        code = start;
        while (code <= end) {
            if (code == (pcmk_rc_error + 1)) {
                /* Values between here and pcmk_rc_ok are reserved for callers,
                 * so skip them
                 */
                code = pcmk_rc_ok;
                continue;
            }
            pcmk_result_get_strings(code, options.result_type, &name, &desc);

            if ((name == NULL)
                || pcmk__str_any_of(name, "Unknown", "CRM_EX_UNKNOWN", NULL)) {

                code++;
                continue;
            }
            out->message(out, "result-code", code,
                         (options.with_name? name : NULL), desc);
            code++;
        }

    } else {
        // For text output, print only "[name -] description" by default
        if (args->verbosity == 0) {
            out->quiet = true;
        }

        /* Skip #1 because that's the program name. */
        for (int lpc = 1; processed_args[lpc] != NULL; lpc++) {
            int code = 0;

            if (pcmk__str_eq(processed_args[lpc], "--", pcmk__str_none)) {
                continue;
            }
            pcmk__scan_min_int(processed_args[lpc], &code, INT_MIN);
            pcmk_result_get_strings(code, options.result_type, &name, &desc);
            out->message(out, "result-code", code,
                         (options.with_name? name : NULL), desc);
        }
    }

 done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    crm_exit(exit_code);
}
