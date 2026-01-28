/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>             // atoi()

#include <glib.h>               // gboolean, GMainLoop, etc.
#include <libxml/tree.h>        // xmlNode

#include <pacemaker-internal.h>

#define SUMMARY "query and manage the Pacemaker controller"

static enum {
    cmd_none,
    cmd_health,
    cmd_whois_dc,
    cmd_list_nodes,
    cmd_pacemakerd_health,
} command = cmd_none;

struct {
    gboolean health;
    guint timeout;
    char *optarg;
    char *ipc_name;
    gboolean bash_export;
} options = {
    .timeout = 30000, // Default to 30 seconds
    .optarg = NULL,
    .ipc_name = NULL,
    .bash_export = FALSE
};

gboolean command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry command_options[] = {
    { "status", 'S', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the status of the specified node."
      "\n                             Result is state of node's internal finite state"
      "\n                             machine, which can be useful for debugging",
      "NODE"
    },
    { "pacemakerd", 'P', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the status of local pacemakerd."
      "\n                             Result is the state of the sub-daemons watched"
      "\n                             by pacemakerd.",
      NULL
    },
    { "dc_lookup", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the uname of the node co-ordinating the cluster."
      "\n                             This is an internal detail rarely useful to"
      "\n                             administrators except when deciding on which"
      "\n                             node to examine the logs.",
      NULL
    },
    { "nodes", 'N', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the uname of all member nodes [optionally filtered by type (comma-separated)]"
      "\n                             Types: all (default), cluster, guest, remote",
      "TYPE"
    },
    { "health", 'H', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.health,
      NULL,
      NULL
    },

    { NULL }
};

static GOptionEntry additional_options[] = {
    { "timeout", 't', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Time to wait before declaring the operation"
      "\n                             "
      "failed (default 30s; use 0 to disable timeout)",
      "DURATION"
    },
    { "bash-export", 'B', 0, G_OPTION_ARG_NONE, &options.bash_export,
      "Display nodes as shell commands of the form 'export uname=uuid'"
      "\n                             (valid with -N/--nodes)",
    },
    { "ipc-name", 'i', 0, G_OPTION_ARG_STRING, &options.ipc_name,
      "Name to use for ipc instead of 'crmadmin' (with -P/--pacemakerd).",
      "NAME"
    },

    { NULL }
};

gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error)
{
    if (!strcmp(option_name, "--status") || !strcmp(option_name, "-S")) {
        command = cmd_health;
        pcmk__trace("Option %c => %s", 'S', optarg);
    }

    if (!strcmp(option_name, "--pacemakerd") || !strcmp(option_name, "-P")) {
        command = cmd_pacemakerd_health;
    }

    if (!strcmp(option_name, "--dc_lookup") || !strcmp(option_name, "-D")) {
        command = cmd_whois_dc;
    }

    if (!strcmp(option_name, "--nodes") || !strcmp(option_name, "-N")) {
        command = cmd_list_nodes;
    }

    if (!strcmp(option_name, "--timeout") || !strcmp(option_name, "-t")) {
        return pcmk_parse_interval_spec(optarg, &options.timeout) == pcmk_rc_ok;
    }

    pcmk__str_update(&options.optarg, optarg);
    return TRUE;
}

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

#define DESC \
    "Notes:\n\n"                                                              \
    "DURATION in any command line option can be specified as an integer\n"    \
    "number of seconds, an integer plus units (ms, msec, us, usec, s, sec,\n" \
    "m, min, h, or hr), or an ISO 8601 period specification.\n\n"             \
    "Report bugs to " PCMK__BUG_URL


static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Display only the essential query information",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, DESC);

    /* Add the -q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "command", "Commands:",
                        "Show command options", command_options);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", additional_options);
    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    int rc;
    int argerr = 0;

    GError *error = NULL;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "itKNS");
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crmadmin", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pcmk__register_lib_messages(out);

    out->quiet = args->quiet;

    if (args->version) {
        out->version(out);
        goto done;
    }

    if (options.health) {
        out->err(out, "Cluster-wide health option not supported");
        ++argerr;
    }

    if (command == cmd_none) {
        out->err(out, "error: Must specify a command option");
        ++argerr;
    }

    if (argerr) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        out->err(out, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    switch (command) {
        case cmd_health:
            rc = pcmk__controller_status(out, options.optarg,
                                         (unsigned int) options.timeout);
            break;
        case cmd_pacemakerd_health:
            rc = pcmk__pacemakerd_status(out, options.ipc_name,
                                         (unsigned int) options.timeout, true,
                                         NULL);
            break;
        case cmd_list_nodes:
            rc = pcmk__list_nodes(out, options.optarg, options.bash_export);
            break;
        case cmd_whois_dc:
            rc = pcmk__designated_controller(out,
                                             (unsigned int) options.timeout);
            break;
        case cmd_none:
            rc = pcmk_rc_error;
            break;
    }

    if (rc != pcmk_rc_ok) {
        out->err(out, "error: Command failed: %s", pcmk_rc_str(rc));
        exit_code = pcmk_rc2exitc(rc);
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
    return crm_exit(exit_code);
}
