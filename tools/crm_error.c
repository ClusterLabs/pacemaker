/*
 * Copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/strings_internal.h>

#include <crm/crm.h>

#define SUMMARY "crm_error - display name or description of a Pacemaker error code"

GError *error = NULL;

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

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, NULL, group, "[-- <rc> [<rc>...]]");
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    const char *name = NULL;
    const char *desc = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_error", args->verbosity);

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When crm_error is converted to use formatted output, this can go. */
        pcmk__cli_help('v', CRM_EX_OK);
    }

    if (g_strv_length(processed_args) < 2) {
        // If no result codes were specified, list them all
        options.do_list = TRUE;
    }

    if (options.do_list) {
        int start = 0;
        int end = 0;
        int code = 0;

        /* Get length of longest (most negative) standard Pacemaker return code
         * This should be longer than all the values of any other type of return
         * code.
         */
        long long most_negative = pcmk_rc_error - (long long) pcmk__n_rc + 1;
        int code_width = (int) snprintf(NULL, 0, "%lld", most_negative);
        int name_width = 0;

        if (options.with_name) {
            // Get length of longest standard Pacemaker return code name
            for (int lpc = 0; lpc < pcmk__n_rc; lpc++) {
                int len = (int) strlen(pcmk_rc_name(pcmk_rc_error - lpc));
                name_width = QB_MAX(name_width, len);
            }
        }

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

            if (options.with_name) {
                printf("% *d: %-*s  %s\n", code_width, code, name_width, name,
                       desc);
            } else {
                printf("% *d: %s\n", code_width, code, desc);
            }
            code++;
        }

    } else {
        int code = 0;

        /* Skip #1 because that's the program name. */
        for (int lpc = 1; processed_args[lpc] != NULL; lpc++) {
            if (pcmk__str_eq(processed_args[lpc], "--", pcmk__str_none)) {
                continue;
            }

            pcmk__scan_min_int(processed_args[lpc], &code, INT_MIN);
            pcmk_result_get_strings(code, options.result_type, &name, &desc);
            if (options.with_name) {
                printf("%s - %s\n", name, desc);
            } else {
                printf("%s\n", desc);
            }
        }
    }

 done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, NULL);
    return exit_code;
}
