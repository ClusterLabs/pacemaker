/*
 * Copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>

#include <crm/crm.h>

#include <pacemaker-internal.h>

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

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
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

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
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
        out->version(out);
        goto done;
    }

    pcmk__register_lib_messages(out);

    if (options.do_list) {
        uint32_t flags = pcmk_rc_disp_code|pcmk_rc_disp_desc;

        if (options.with_name) {
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "pcmk_rc_disp_flags",
                                       "pcmk__list_result_codes", flags,
                                       pcmk_rc_disp_name, "pcmk_rc_disp_name");
        }
        pcmk__list_result_codes(out, options.result_type, flags);

    } else {
        uint32_t flags = pcmk_rc_disp_desc;

        // For text output, print only "[name -] description" by default
        if (args->verbosity > 0) {
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "pcmk_rc_disp_flags",
                                       "pcmk__show_result_code", flags,
                                       pcmk_rc_disp_code, "pcmk_rc_disp_code");
        }

        if (options.with_name) {
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "pcmk_rc_disp_flags",
                                       "pcmk__show_result_code", flags,
                                       pcmk_rc_disp_name, "pcmk_rc_disp_name");
        }

        /* Skip #1 because that's the program name. */
        for (int lpc = 1; processed_args[lpc] != NULL; lpc++) {
            int code = 0;

            if (pcmk__str_eq(processed_args[lpc], "--", pcmk__str_none)) {
                continue;
            }
            pcmk__scan_min_int(processed_args[lpc], &code, INT_MIN);
            pcmk__show_result_code(out, code, options.result_type, flags);
        }
    }

 done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(exit_code);
}
