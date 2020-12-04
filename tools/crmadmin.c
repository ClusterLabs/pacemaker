/*
 * Copyright 2004-2020 the Pacemaker project contributors
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

#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>

#define SUMMARY "query and manage the Pacemaker controller"

static enum {
    cmd_none,
    cmd_shutdown,
    cmd_health,
    cmd_elect_dc,
    cmd_whois_dc,
    cmd_list_nodes,
    cmd_pacemakerd_health,
} command = cmd_none;

struct {
    gboolean health;
    gint timeout;
    char *dest_node;
    char *ipc_name;
    char *node_types;
    gboolean BASH_EXPORT;
} options = {
    .dest_node = NULL,
    .ipc_name = NULL,
    .node_types = NULL,
    .BASH_EXPORT = FALSE
};

gboolean command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry command_options[] = {
    { "status", 'S', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the status of the specified node."
      "\n                          Result is state of node's internal finite state"
      "\n                          machine, which can be useful for debugging",
      NULL
    },
    { "pacemakerd", 'P', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the status of local pacemakerd."
      "\n                          Result is the state of the sub-daemons watched"
      "\n                          by pacemakerd.",
      NULL
    },
    { "dc_lookup", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the uname of the node co-ordinating the cluster."
      "\n                          This is an internal detail rarely useful to"
      "\n                          administrators except when deciding on which"
      "\n                          node to examine the logs.",
      NULL
    },
    { "nodes", 'N', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the uname of all member nodes",
      NULL
    },
    { "election", 'E', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Start an election for the cluster co-ordinator",
      NULL
    },
    { "kill", 'K', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Stop controller (not rest of cluster stack) on specified node",
      NULL
    },
    { "health", 'H', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.health,
      NULL,
      NULL
    },

    { NULL }
};

static GOptionEntry additional_options[] = {
    { "timeout", 't', 0, G_OPTION_ARG_INT, &options.timeout,
      "Time (in milliseconds) to wait before declaring the"
      "\n                          operation failed",
      NULL
    },
    { "node-types", 'T', 0, G_OPTION_ARG_STRING, &options.node_types,
      "Node types to list (available options: all, member, pacemaker_remote,"
      "\n                          guest, remote) (valid with -N/--nodes)",
      NULL
    },
    { "bash-export", 'B', 0, G_OPTION_ARG_NONE, &options.BASH_EXPORT,
      "Display nodes as shell commands of the form 'export uname=uuid'"
      "\n                          (valid with -N/--nodes)",
    },
    { "ipc-name", 'i', 0, G_OPTION_ARG_STRING, &options.ipc_name,
      "Name to use for ipc instead of 'crmadmin' (with -P/--pacemakerd).",
      NULL
    },

    { NULL }
};

gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error)
{
    if (!strcmp(option_name, "--status") || !strcmp(option_name, "-S")) {
        command = cmd_health;
        crm_trace("Option %c => %s", 'S', optarg);
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

    if (!strcmp(option_name, "--election") || !strcmp(option_name, "-E")) {
        command = cmd_elect_dc;
    }

    if (!strcmp(option_name, "--kill") || !strcmp(option_name, "-K")) {
        command = cmd_shutdown;
        crm_trace("Option %c => %s", 'K', optarg);
    }

    if (optarg) {
        if (options.dest_node != NULL) {
            free(options.dest_node);
        }
        options.dest_node = strdup(optarg);
    }

    return TRUE;
}

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    const char *description = "Report bugs to users@clusterlabs.org";

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Display only the essential query information",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, description);

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
    pcmk__output_t *out = NULL;
    crm_exit_t exit_code = CRM_EX_OK;
    int rc;
    int argerr = 0;
    pcmk_ipc_api_t *controld_api = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);

    GError *error = NULL;
    GOptionContext *context = NULL;
    GOptionGroup *output_group = NULL;
    gchar **processed_args = NULL;

    context = build_arg_context(args, &output_group);
    pcmk__register_formats(output_group, formats);

    crm_log_cli_init("crmadmin");

    processed_args = pcmk__cmdline_preproc(argv, "itBDEHKNPS");

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        fprintf(stderr, "%s: %s\n", g_get_prgname(), error->message);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    for (int i = 0; i < args->verbosity; i++) {
        crm_bump_log_level(argc, argv);
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Error creating output format %s: %s\n",
                args->output_ty, pcmk_rc_str(rc));
        exit_code = CRM_EX_ERROR;
        goto done;
    }

    out->quiet = args->quiet;

    pcmk__register_lib_messages(out);

    if (!pcmk__force_args(context, &error, "%s --xml-simple-list --xml-substitute", g_get_prgname())) {
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (options.health) {
        out->err(out, "Cluster-wide health option not supported");
        ++argerr;
    }

    if (optind > argc) {
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
            rc = pcmk__controller_status(out, options.dest_node, options.timeout);
            break;
        case cmd_pacemakerd_health:
            rc = pcmk__pacemakerd_status(out, options.ipc_name, options.timeout);
            break;
        case cmd_list_nodes:
            rc = pcmk__list_nodes(out, options.node_types, options.BASH_EXPORT);
            break;
        case cmd_whois_dc:
            rc = pcmk__designated_controller(out, options.timeout);
            break;
        case cmd_shutdown:
            rc = pcmk__shutdown_controller(out, options.dest_node);
            break;
        case cmd_elect_dc:
            rc = pcmk__start_election(out);
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

    if (controld_api != NULL) {
        pcmk_ipc_api_t *capi = controld_api;
        controld_api = NULL; // Ensure we can't free this twice
        pcmk_free_ipc_api(capi);
    }

    g_strfreev(processed_args);
    g_clear_error(&error);
    pcmk__free_arg_context(context);
    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    return crm_exit(exit_code);

}
