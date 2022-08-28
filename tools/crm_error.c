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

struct {
    gboolean as_exit_code;
    gboolean as_rc;
    gboolean with_name;
    gboolean do_list;
} options;

static GOptionEntry entries[] = {
    { "name", 'n', 0, G_OPTION_ARG_NONE, &options.with_name,
      "Show error's name with its description (useful for looking for sources "
      "of the error in source code)",
       NULL },
    { "list", 'l', 0, G_OPTION_ARG_NONE, &options.do_list,
      "Show all known errors",
      NULL },
    { "exit", 'X', 0, G_OPTION_ARG_NONE, &options.as_exit_code,
      "Interpret as exit code rather than legacy function return value",
      NULL },
    { "rc", 'r', 0, G_OPTION_ARG_NONE, &options.as_rc,
      "Interpret as return code rather than legacy function return value",
      NULL },

    { NULL }
};

static void
get_strings(int rc, const char **name, const char **str)
{
    if (options.as_exit_code) {
        *str = crm_exit_str((crm_exit_t) rc);
        *name = crm_exit_name(rc);
    } else if (options.as_rc) {
        *str = pcmk_rc_str(rc);
        *name = pcmk_rc_name(rc);
    } else {
        *str = pcmk_strerror(rc);
        *name = pcmk_errorname(rc);
    }
}


static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, NULL, group, "-- <rc> [...]");
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

    GError *error = NULL;

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

    if (options.do_list) {
        int start, end, width;

        // 256 is a hacky magic number that "should" be enough
        if (options.as_rc) {
            start = pcmk_rc_error - 256;
            end = PCMK_CUSTOM_OFFSET;
            width = 4;
        } else {
            start = 0;
            end = 256;
            width = 3;
        }

        for (rc = start; rc < end; rc++) {
            if (rc == (pcmk_rc_error + 1)) {
                // Values in between are reserved for callers, no use iterating
                rc = pcmk_rc_ok;
            }
            get_strings(rc, &name, &desc);
            if (pcmk__str_eq(name, "Unknown", pcmk__str_null_matches) || !strcmp(name, "CRM_EX_UNKNOWN")) {
                // Undefined
            } else if(options.with_name) {
                printf("% .*d: %-26s  %s\n", width, rc, name, desc);
            } else {
                printf("% .*d: %s\n", width, rc, desc);
            }
        }

    } else {
        if (g_strv_length(processed_args) < 2) {
            char *help = g_option_context_get_help(context, TRUE, NULL);
            fprintf(stderr, "%s", help);
            g_free(help);
            exit_code = CRM_EX_USAGE;
            goto done;
        }

        /* Skip #1 because that's the program name. */
        for (int lpc = 1; processed_args[lpc] != NULL; lpc++) {
            if (pcmk__str_eq(processed_args[lpc], "--", pcmk__str_none)) {
                continue;
            }

            pcmk__scan_min_int(processed_args[lpc], &rc, INT_MIN);
            get_strings(rc, &name, &desc);
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
