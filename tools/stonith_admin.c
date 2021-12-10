/*
 * Copyright 2009-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/cib.h>
#include <crm/pengine/status.h>

#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#define SUMMARY "stonith_admin - Access the Pacemaker fencing API"

char action = 0;

struct {
    gboolean as_nodeid;
    gboolean broadcast;
    gboolean cleanup;
    gboolean installed;
    gboolean metadata;
    gboolean registered;
    gboolean validate_cfg;
    stonith_key_value_t *devices;
    stonith_key_value_t *params;
    int fence_level;
    int timeout ;
    int tolerance;
    int delay;
    char *agent;
    char *confirm_host;
    char *fence_host;
    char *history;
    char *last_fenced;
    char *query;
    char *reboot_host;
    char *register_dev;
    char *register_level;
    char *targets;
    char *terminate;
    char *unfence_host;
    char *unregister_dev;
    char *unregister_level;
} options = {
    .timeout = 120,
    .delay = 0
};

gboolean add_env_params(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean add_stonith_device(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean add_stonith_params(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean add_tolerance(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean set_tag(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

#define INDENT "                                    "

/* *INDENT-OFF* */
static GOptionEntry defn_entries[] = {
    { "register", 'R', 0, G_OPTION_ARG_STRING, &options.register_dev,
      "Register the named stonith device. Requires: --agent.\n"
      INDENT "Optional: --option, --env-option.",
      "DEVICE" },
    { "deregister", 'D', 0, G_OPTION_ARG_STRING, &options.unregister_dev,
      "De-register the named stonith device.",
      "DEVICE" },
    { "register-level", 'r', 0, G_OPTION_ARG_STRING, &options.register_level,
      "Register a stonith level for the named target,\n"
      INDENT "specified as one of NAME, @PATTERN, or ATTR=VALUE.\n"
      INDENT "Requires: --index and one or more --device entries.",
      "TARGET" },
    { "deregister-level", 'd', 0, G_OPTION_ARG_STRING, &options.unregister_level,
      "Unregister a stonith level for the named target,\n"
      INDENT "specified as for --register-level. Requires: --index",
      "TARGET" },

    { NULL }
};

static GOptionEntry query_entries[] = {
    { "list", 'l', 0, G_OPTION_ARG_STRING, &options.terminate,
      "List devices that can terminate the specified host.\n"
      INDENT "Optional: --timeout",
      "HOST" },
    { "list-registered", 'L', 0, G_OPTION_ARG_NONE, &options.registered,
      "List all registered devices. Optional: --timeout.",
      NULL },
    { "list-installed", 'I', 0, G_OPTION_ARG_NONE, &options.installed,
      "List all installed devices. Optional: --timeout.",
      NULL },
    { "list-targets", 's', 0, G_OPTION_ARG_STRING, &options.targets,
      "List the targets that can be fenced by the\n"
      INDENT "named device. Optional: --timeout.",
      "DEVICE" },
    { "metadata", 'M', 0, G_OPTION_ARG_NONE, &options.metadata,
      "Show agent metadata. Requires: --agent.\n"
      INDENT "Optional: --timeout.",
      NULL },
    { "query", 'Q', 0, G_OPTION_ARG_STRING, &options.query,
      "Check the named device's status. Optional: --timeout.",
      "DEVICE" },
    { "history", 'H', 0, G_OPTION_ARG_STRING, &options.history,
      "Show last successful fencing operation for named node\n"
      INDENT "(or '*' for all nodes). Optional: --timeout, --cleanup,\n"
      INDENT "--quiet (show only the operation's epoch timestamp),\n"
      INDENT "--verbose (show all recorded and pending operations),\n"
      INDENT "--broadcast (update history from all nodes available).",
      "NODE" },
    { "last", 'h', 0, G_OPTION_ARG_STRING, &options.last_fenced,
      "Indicate when the named node was last fenced.\n"
      INDENT "Optional: --as-node-id.",
      "NODE" },
    { "validate", 'K', 0, G_OPTION_ARG_NONE, &options.validate_cfg,
      "Validate a fence device configuration.\n"
      INDENT "Requires: --agent. Optional: --option, --env-option,\n"
      INDENT "--quiet (print no output, only return status).",
      NULL },

    { NULL }
};

static GOptionEntry fence_entries[] = {
    { "fence", 'F', 0, G_OPTION_ARG_STRING, &options.fence_host,
      "Fence named host. Optional: --timeout, --tolerance, --delay.",
      "HOST" },
    { "unfence", 'U', 0, G_OPTION_ARG_STRING, &options.unfence_host,
      "Unfence named host. Optional: --timeout, --tolerance, --delay.",
      "HOST" },
    { "reboot", 'B', 0, G_OPTION_ARG_STRING, &options.reboot_host,
      "Reboot named host. Optional: --timeout, --tolerance, --delay.",
      "HOST" },
    { "confirm", 'C', 0, G_OPTION_ARG_STRING, &options.confirm_host,
      "Tell cluster that named host is now safely down.",
      "HOST", },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "cleanup", 'c', 0, G_OPTION_ARG_NONE, &options.cleanup,
      "Cleanup wherever appropriate. Requires --history.",
      NULL },
    { "broadcast", 'b', 0, G_OPTION_ARG_NONE, &options.broadcast,
      "Broadcast wherever appropriate.",
      NULL },
    { "agent", 'a', 0, G_OPTION_ARG_STRING, &options.agent,
      "The agent to use (for example, fence_xvm;\n"
      INDENT "with --register, --metadata, --validate).",
      "AGENT" },
    { "option", 'o', 0, G_OPTION_ARG_CALLBACK, add_stonith_params,
      "Specify a device configuration parameter as NAME=VALUE\n"
      INDENT "(may be specified multiple times; with --register,\n"
      INDENT "--validate).",
      "PARAM" },
    { "env-option", 'e', 0, G_OPTION_ARG_CALLBACK, add_env_params,
      "Specify a device configuration parameter with the\n"
      INDENT "specified name, using the value of the\n"
      INDENT "environment variable of the same name prefixed with\n"
      INDENT "OCF_RESKEY_ (may be specified multiple times;\n"
      INDENT "with --register, --validate).",
      "PARAM" },
    { "tag", 'T', 0, G_OPTION_ARG_CALLBACK, set_tag,
      "Identify fencing operations in logs with the specified\n"
      INDENT "tag; useful when multiple entities might invoke\n"
      INDENT "stonith_admin (used with most commands).",
      "TAG" },
    { "device", 'v', 0, G_OPTION_ARG_CALLBACK, add_stonith_device,
      "Device ID (with --register-level, device to associate with\n"
      INDENT "a given host and level; may be specified multiple times)"
#if SUPPORT_CIBSECRETS
      "\n" INDENT "(with --validate, name to use to load CIB secrets)"
#endif
      ".",
      "DEVICE" },
    { "index", 'i', 0, G_OPTION_ARG_INT, &options.fence_level,
      "The stonith level (1-9) (with --register-level,\n"
      INDENT "--deregister-level).",
      "LEVEL" },
    { "timeout", 't', 0, G_OPTION_ARG_INT, &options.timeout,
      "Operation timeout in seconds (default 120;\n"
      INDENT "used with most commands).",
      "SECONDS" },
    { "delay", 'y', 0, G_OPTION_ARG_INT, &options.delay,
      "Apply a fencing delay in seconds. Any static/random delays from\n"
      INDENT "pcmk_delay_base/max will be added, otherwise all\n"
      INDENT "disabled with the value -1\n"
      INDENT "(default 0; with --fence, --reboot, --unfence).",
      "SECONDS" },
    { "as-node-id", 'n', 0, G_OPTION_ARG_NONE, &options.as_nodeid,
      "(Advanced) The supplied node is the corosync node ID\n"
      INDENT "(with --last).",
      NULL },
    { "tolerance", 0, 0, G_OPTION_ARG_CALLBACK, add_tolerance,
      "(Advanced) Do nothing if an equivalent --fence request\n"
      INDENT "succeeded less than this many seconds earlier\n"
      INDENT "(with --fence, --unfence, --reboot).",
      "SECONDS" },

    { NULL }
};
/* *INDENT-ON* */

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_HTML,
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static const int st_opts = st_opt_sync_call | st_opt_allow_suicide;

static char *name = NULL;

gboolean
add_env_params(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    char *key = crm_strdup_printf("OCF_RESKEY_%s", optarg);
    const char *env = getenv(key);
    gboolean retval = TRUE;

    if (env == NULL) {
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "Invalid option: -e %s", optarg);
        retval = FALSE;
    } else {
        crm_info("Got: '%s'='%s'", optarg, env);
        options.params = stonith_key_value_add(options.params, optarg, env);
    }

    free(key);
    return retval;
}

gboolean
add_stonith_device(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.devices = stonith_key_value_add(options.devices, NULL, optarg);
    return TRUE;
}

gboolean
add_tolerance(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.tolerance = crm_get_msec(optarg) / 1000;
    return TRUE;
}

gboolean
add_stonith_params(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    char *name = NULL;
    char *value = NULL;
    int rc = 0;
    gboolean retval = TRUE;

    crm_info("Scanning: -o %s", optarg);

    rc = pcmk__scan_nvpair(optarg, &name, &value);

    if (rc != 2) {
        rc = pcmk_legacy2rc(rc);
        g_set_error(error, PCMK__RC_ERROR, rc, "Invalid option: -o %s: %s", optarg, pcmk_rc_str(rc));
        retval = FALSE;
    } else {
        crm_info("Got: '%s'='%s'", name, value);
        options.params = stonith_key_value_add(options.params, name, value);
    }

    free(name);
    free(value);
    return retval;
}

gboolean
set_tag(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    free(name);
    name = crm_strdup_printf("%s.%s", crm_system_name, optarg);
    return TRUE;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Be less descriptive in output.",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), html, xml", group, NULL);

    /* Add the -q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "definition", "Device Definition Commands:",
                        "Show device definition help", defn_entries);
    pcmk__add_arg_group(context, "queries", "Queries:",
                        "Show query help", query_entries);
    pcmk__add_arg_group(context, "fence", "Fencing Commands:",
                        "Show fence help", fence_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = 0;
    crm_exit_t exit_code = CRM_EX_OK;
    bool no_connect = false;
    bool required_agent = false;

    char *target = NULL;
    const char *device = NULL;
    stonith_t *st = NULL;

    GError *error = NULL;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "adehilorstvyBCDFHQRTU");
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("stonith_admin", args->verbosity);

    name = strdup(crm_system_name);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    stonith__register_messages(out);

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (options.validate_cfg) {
        required_agent = true;
        no_connect = true;
        action = 'K';
    }

    if (options.installed) {
        no_connect = true;
        action = 'I';
    }

    if (options.registered) {
        action = 'L';
    }

    if (options.register_dev != NULL) {
        required_agent = true;
        action = 'R';
        device = options.register_dev;
    }

    if (options.query != NULL) {
        action = 'Q';
        device = options.query;
    }

    if (options.unregister_dev != NULL) {
        action = 'D';
        device = options.unregister_dev;
    }

    if (options.targets != NULL) {
        action = 's';
        device = options.targets;
    }

    if (options.terminate != NULL) {
        action = 'L';
        target = options.terminate;
    }

    if (options.metadata) {
        no_connect = true;
        required_agent = true;
        action = 'M';
    }

    if (options.reboot_host != NULL) {
        no_connect = true;
        action = 'B';
        target = options.reboot_host;
        crm_log_args(argc, argv);
    }

    if (options.fence_host != NULL) {
        no_connect = true;
        action = 'F';
        target = options.fence_host;
        crm_log_args(argc, argv);
    }

    if (options.unfence_host != NULL) {
        no_connect = true;
        action = 'U';
        target = options.unfence_host;
        crm_log_args(argc, argv);
    }

    if (options.confirm_host != NULL) {
        action = 'C';
        target = options.confirm_host;
        crm_log_args(argc, argv);
    }

    if (options.last_fenced != NULL) {
        action = 'h';
        target = options.last_fenced;
    }

    if (options.history != NULL) {
        action = 'H';
        target = options.history;
    }

    if (options.register_level != NULL) {
        action = 'r';
        target = options.register_level;
    }

    if (options.unregister_level != NULL) {
        action = 'd';
        target = options.unregister_level;
    }

    if (action == 0) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        out->err(out, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (required_agent && options.agent == NULL) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        out->err(out, "Please specify an agent to query using -a,--agent [value]");
        out->err(out, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    out->quiet = args->quiet;

    st = stonith_api_new();
    if (st == NULL) {
        rc = -ENOMEM;
    } else if (!no_connect) {
        rc = st->cmds->connect(st, name, NULL);
    }
    if (rc < 0) {
        out->err(out, "Could not connect to fencer: %s", pcmk_strerror(rc));
        exit_code = CRM_EX_DISCONNECT;
        goto done;
    }

    switch (action) {
        case 'I':
            rc = pcmk__fence_installed(out, st, options.timeout*1000);
            if (rc != pcmk_rc_ok) {
                out->err(out, "Failed to list installed devices: %s", pcmk_strerror(rc));
            }

            break;

        case 'L':
            rc = pcmk__fence_registered(out, st, target, options.timeout*1000);
            if (rc != pcmk_rc_ok) {
                out->err(out, "Failed to list registered devices: %s", pcmk_strerror(rc));
            }

            break;

        case 'Q':
            rc = st->cmds->monitor(st, st_opts, device, options.timeout);
            if (rc != pcmk_rc_ok) {
                rc = st->cmds->list(st, st_opts, device, NULL, options.timeout);
            }
            rc = pcmk_legacy2rc(rc);
            break;

        case 's':
            rc = pcmk__fence_list_targets(out, st, device, options.timeout*1000);
            if (rc != pcmk_rc_ok) {
                out->err(out, "Couldn't list targets: %s", pcmk_strerror(rc));
            }

            break;

        case 'R':
            rc = st->cmds->register_device(st, st_opts, device, NULL, options.agent,
                                           options.params);
            rc = pcmk_legacy2rc(rc);
            break;

        case 'D':
            rc = st->cmds->remove_device(st, st_opts, device);
            rc = pcmk_legacy2rc(rc);
            break;

        case 'd':
            rc = pcmk__fence_unregister_level(st, target, options.fence_level);
            break;

        case 'r':
            rc = pcmk__fence_register_level(st, target, options.fence_level, options.devices);
            break;

        case 'M':
            rc = pcmk__fence_metadata(out, st, options.agent, options.timeout*1000);
            if (rc != pcmk_rc_ok) {
                out->err(out, "Can't get fence agent meta-data: %s", pcmk_strerror(rc));
            }

            break;

        case 'C':
            rc = st->cmds->confirm(st, st_opts, target);
            rc = pcmk_legacy2rc(rc);
            break;

        case 'B':
            rc = pcmk__request_fencing(st, target, "reboot", name,
                                       options.timeout * 1000,
                                       options.tolerance * 1000,
                                       options.delay, NULL);
            break;

        case 'F':
            rc = pcmk__request_fencing(st, target, "off", name,
                                       options.timeout * 1000,
                                       options.tolerance * 1000,
                                       options.delay, NULL);
            break;

        case 'U':
            rc = pcmk__request_fencing(st, target, "on", name,
                                       options.timeout * 1000,
                                       options.tolerance * 1000,
                                       options.delay, NULL);
            break;

        case 'h':
            rc = pcmk__fence_last(out, target, options.as_nodeid);
            break;

        case 'H':
            rc = pcmk__fence_history(out, st, target, options.timeout*1000, args->verbosity,
                                     options.broadcast, options.cleanup);
            break;

        case 'K':
            device = options.devices ? options.devices->key : NULL;
            rc = pcmk__fence_validate(out, st, options.agent, device, options.params,
                                        options.timeout*1000);
            break;
    }

    crm_info("Command returned: %s (%d)", pcmk_rc_str(rc), rc);
    exit_code = pcmk_rc2exitc(rc);

  done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    free(name);
    stonith_key_value_freeall(options.params, 1, 1);

    if (st != NULL) {
        st->cmds->disconnect(st);
        stonith_api_delete(st);
    }

    return exit_code;
}
