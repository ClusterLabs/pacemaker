/*
 * Copyright 2009-2019 the Pacemaker project contributors
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
#include <crm/common/mainloop.h>
#include <crm/common/output.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/cib.h>
#include <crm/pengine/status.h>

#include <crm/common/xml.h>

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
    int verbose;
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
    .timeout = 120
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
      "Fence named host. Optional: --timeout, --tolerance.",
      "HOST" },
    { "unfence", 'U', 0, G_OPTION_ARG_STRING, &options.unfence_host,
      "Unfence named host. Optional: --timeout, --tolerance.",
      "HOST" },
    { "reboot", 'B', 0, G_OPTION_ARG_STRING, &options.reboot_host,
      "Reboot named host. Optional: --timeout, --tolerance.",
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
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static int st_opts = st_opt_sync_call | st_opt_allow_suicide;

static GMainLoop *mainloop = NULL;
struct {
    stonith_t *st;
    const char *target;
    const char *action;
    char *name;
    int timeout;
    int tolerance;
    int rc;
} async_fence_data;

gboolean
add_env_params(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    char *key = crm_concat("OCF_RESKEY", optarg, '_');
    const char *env = getenv(key);
    gboolean retval = TRUE;

    if (env == NULL) {
        crm_err("Invalid option: -e %s", optarg);
        g_set_error(error, G_OPTION_ERROR, CRM_EX_INVALID_PARAM, "Invalid option: -e %s", optarg);
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

    rc = pcmk_scan_nvpair(optarg, &name, &value);

    if (rc != 2) {
        crm_err("Invalid option: -o %s: %s", optarg, pcmk_strerror(rc));
        g_set_error(error, G_OPTION_ERROR, rc, "Invalid option: -o %s: %s", optarg, pcmk_strerror(rc));
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
    free(async_fence_data.name);
    async_fence_data.name = crm_strdup_printf("%s.%s", crm_system_name, optarg);
    return TRUE;
}

static void
notify_callback(stonith_t * st, stonith_event_t * e)
{
    if (e->result != pcmk_ok) {
        return;
    }

    if (safe_str_eq(async_fence_data.target, e->target) &&
        safe_str_eq(async_fence_data.action, e->action)) {

        async_fence_data.rc = e->result;
        g_main_loop_quit(mainloop);
    }
}

static void
fence_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    async_fence_data.rc = data->rc;

    g_main_loop_quit(mainloop);
}

static gboolean
async_fence_helper(gpointer user_data)
{
    stonith_t *st = async_fence_data.st;
    int call_id = 0;
    int rc = stonith_api_connect_retry(st, async_fence_data.name, 10);

    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not connect to fencer: %s\n", pcmk_strerror(rc));
        g_main_loop_quit(mainloop);
        return TRUE;
    }

    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, notify_callback);

    call_id = st->cmds->fence(st,
                              st_opt_allow_suicide,
                              async_fence_data.target,
                              async_fence_data.action,
                              async_fence_data.timeout, async_fence_data.tolerance);

    if (call_id < 0) {
        g_main_loop_quit(mainloop);
        return TRUE;
    }

    st->cmds->register_callback(st,
                                call_id,
                                async_fence_data.timeout,
                                st_opt_timeout_updates, NULL, "callback", fence_callback);

    return TRUE;
}

static int
mainloop_fencing(stonith_t * st, const char *target, const char *action, int timeout, int tolerance)
{
    crm_trigger_t *trig;

    async_fence_data.st = st;
    async_fence_data.target = target;
    async_fence_data.action = action;
    async_fence_data.timeout = timeout;
    async_fence_data.tolerance = tolerance;
    async_fence_data.rc = -1;

    trig = mainloop_add_trigger(G_PRIORITY_HIGH, async_fence_helper, NULL);
    mainloop_set_trigger(trig);

    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);

    return async_fence_data.rc;
}

static int
handle_level(stonith_t *st, char *target, int fence_level,
             stonith_key_value_t *devices, bool added)
{
    char *node = NULL;
    char *pattern = NULL;
    char *name = NULL;
    char *value = NULL;

    if (target == NULL) {
        // Not really possible, but makes static analysis happy
        return -EINVAL;
    }

    /* Determine if targeting by attribute, node name pattern or node name */
    value = strchr(target, '=');
    if (value != NULL)  {
        name = target;
        *value++ = '\0';
    } else if (*target == '@') {
        pattern = target + 1;
    } else {
        node = target;
    }

    /* Register or unregister level as appropriate */
    if (added) {
        return st->cmds->register_level_full(st, st_opts, node, pattern,
                                             name, value, fence_level,
                                             devices);
    }
    return st->cmds->remove_level_full(st, st_opts, node, pattern,
                                       name, value, fence_level);
}

static int
handle_history(stonith_t *st, const char *target, int timeout, int quiet,
             int verbose, int cleanup, int broadcast, pcmk__output_t *out)
{
    stonith_history_t *history = NULL, *hp, *latest = NULL;
    int rc = 0;

    if (!quiet) {
        if (cleanup) {
            out->info(out, "cleaning up fencing-history%s%s",
                      target ? " for node " : "", target ? target : "");
        }
        if (broadcast) {
            out->info(out, "gather fencing-history from all nodes");
        }
    }

    rc = st->cmds->history(st, st_opts | (cleanup?st_opt_cleanup:0) |
                           (broadcast?st_opt_broadcast:0),
                           (safe_str_eq(target, "*")? NULL : target),
                           &history, timeout);

    out->begin_list(out, "Fencing history", "event", "events");

    for (hp = history; hp; hp = hp->next) {
        if (hp->state == st_done) {
            latest = hp;
        }

        if (quiet || !verbose) {
            continue;
        }

        out->message(out, "stonith-event", hp, 1);
    }

    if (latest) {
        if (quiet && out->supports_quiet) {
            out->info(out, "%lld", (long long) latest->completed);
        } else if (!verbose) { // already printed if verbose
            out->message(out, "stonith-event", latest, 0);
        }
    }

    out->end_list(out);

    stonith_history_free(history);
    return rc;
}

static int
validate(stonith_t *st, const char *agent, const char *id,
         stonith_key_value_t *params, int timeout, int quiet,
         pcmk__output_t *out)
{
    int rc = 1;
    char *output = NULL;
    char *error_output = NULL;

    rc = st->cmds->validate(st, st_opt_sync_call, id, NULL, agent, params,
                            timeout, &output, &error_output);

    if (quiet) {
        return rc;
    }

    out->message(out, "validate", agent, id, output, error_output, rc); 
    return rc;
}

static void
show_last_fenced(pcmk__output_t *out, const char *target)
{
    time_t when = 0;

    if (target == NULL) {
        // Not really possible, but makes static analysis happy
        return;
    }
    if (options.as_nodeid) {
        uint32_t nodeid = atol(target);
        when = stonith_api_time(nodeid, NULL, FALSE);
    } else {
        when = stonith_api_time(0, target, FALSE);
    }
    out->message(out, "last-fenced", target, when);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args) {
    GOptionContext *context = NULL;
    GOptionGroup *defn_group, *query_group, *fence_group, *addl_group;
    GOptionGroup *main_group;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Be less descriptive in output.",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), html, xml");

    /* Add the -q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    main_group = g_option_context_get_main_group(context);
    g_option_group_add_entries(main_group, extra_prog_entries);

    defn_group = g_option_group_new("definition", "Device Definition Commands:",
                                    "Show device definition help", NULL, NULL);
    g_option_group_add_entries(defn_group, defn_entries);
    g_option_context_add_group(context, defn_group);

    query_group = g_option_group_new("queries", "Queries:", "Show query help", NULL, NULL);
    g_option_group_add_entries(query_group, query_entries);
    g_option_context_add_group(context, query_group);

    fence_group = g_option_group_new("fence", "Fencing Commands:", "Show fence help", NULL, NULL);
    g_option_group_add_entries(fence_group, fence_entries);
    g_option_context_add_group(context, fence_group);

    addl_group = g_option_group_new("additional", "Additional Options:", "Show additional options", NULL, NULL);
    g_option_group_add_entries(addl_group, addl_entries);
    g_option_context_add_group(context, addl_group);

    return context;
}

int
main(int argc, char **argv)
{
    int rc = 0;
    bool no_connect = false;
    bool required_agent = false;

    char *target = NULL;
    char *lists = NULL;
    const char *device = NULL;

    crm_exit_t exit_code = CRM_EX_OK;
    stonith_t *st = NULL;
    stonith_key_value_t *dIter = NULL;

    pcmk__output_t *out = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);

    GError *error = NULL;
    GOptionContext *context = NULL;
    gchar **processed_args = NULL;

    context = build_arg_context(args);
    pcmk__register_formats(context, formats);

    crm_log_cli_init("stonith_admin");

    async_fence_data.name = strdup(crm_system_name);

    processed_args = pcmk__cmdline_preproc(argc, argv, "adehilorstvBCDFHQRTU");

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        fprintf(stderr, "%s: %s\n", g_get_prgname(), error->message);
    }

    for (int i = 0; i < options.verbose; i++) {
        crm_bump_log_level(argc, argv);
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != 0) {
        fprintf(stderr, "Error creating output format %s: %s\n", args->output_ty, pcmk_strerror(rc));
        exit_code = CRM_EX_ERROR;
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

    if (optind > argc || action == 0) {
        out->err(out, "%s", g_option_context_get_help(context, TRUE, NULL));
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (required_agent && options.agent == NULL) {
        out->err(out, "Please specify an agent to query using -a,--agent [value]");
        out->err(out, "%s", g_option_context_get_help(context, TRUE, NULL));
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    st = stonith_api_new();
    if (st == NULL) {
        rc = -ENOMEM;
    } else if (!no_connect) {
        rc = st->cmds->connect(st, async_fence_data.name, NULL);
    }
    if (rc < 0) {
        out->err(out, "Could not connect to fencer: %s", pcmk_strerror(rc));
        exit_code = CRM_EX_DISCONNECT;
        goto done;
    }

    switch (action) {
        case 'I':
            rc = st->cmds->list_agents(st, st_opt_sync_call, NULL, &options.devices, options.timeout);
            if (rc < 0) {
                out->err(out, "Failed to list installed devices: %s", pcmk_strerror(rc));
                break;
            }

            out->begin_list(out, "Installed fence devices", "fence device", "fence devices");
            for (dIter = options.devices; dIter; dIter = dIter->next) {
                out->list_item(out, "device", dIter->value);
            }

            out->end_list(out);
            rc = 0;

            stonith_key_value_freeall(options.devices, 1, 1);
            break;

        case 'L':
            rc = st->cmds->query(st, st_opts, target, &options.devices, options.timeout);
            if (rc < 0) {
                out->err(out, "Failed to list registered devices: %s", pcmk_strerror(rc));
                break;
            }

            out->begin_list(out, "Registered fence devices", "fence device", "fence devices");
            for (dIter = options.devices; dIter; dIter = dIter->next) {
                out->list_item(out, "device", dIter->value);
            }

            out->end_list(out);
            rc = 0;

            stonith_key_value_freeall(options.devices, 1, 1);
            break;

        case 'Q':
            rc = st->cmds->monitor(st, st_opts, device, options.timeout);
            if (rc < 0) {
                rc = st->cmds->list(st, st_opts, device, NULL, options.timeout);
            }
            break;
        case 's':
            rc = st->cmds->list(st, st_opts, device, &lists, options.timeout);
            if (rc == 0) {
                GList *targets = stonith__parse_targets(lists);

                out->begin_list(out, "Fence targets", "fence target", "fence targets");
                while (targets != NULL) {
                    out->list_item(out, NULL, (const char *) targets->data);
                    targets = targets->next;
                }
                out->end_list(out);
                free(lists);

            } else if (rc != 0) {
                out->err(out, "List command returned error. rc : %d", rc);
            }
            break;
        case 'R':
            rc = st->cmds->register_device(st, st_opts, device, NULL, options.agent,
                                           options.params);
            break;
        case 'D':
            rc = st->cmds->remove_device(st, st_opts, device);
            break;
        case 'd':
        case 'r':
            rc = handle_level(st, target, options.fence_level, options.devices, action == 'r');
            break;
        case 'M':
            {
                char *buffer = NULL;

                rc = st->cmds->metadata(st, st_opt_sync_call, options.agent, NULL,
                                        &buffer, options.timeout);
                if (rc == pcmk_ok) {
                    out->output_xml(out, "metadata", buffer);
                }
                free(buffer);
            }
            break;
        case 'C':
            rc = st->cmds->confirm(st, st_opts, target);
            break;
        case 'B':
            rc = mainloop_fencing(st, target, "reboot", options.timeout, options.tolerance);
            break;
        case 'F':
            rc = mainloop_fencing(st, target, "off", options.timeout, options.tolerance);
            break;
        case 'U':
            rc = mainloop_fencing(st, target, "on", options.timeout, options.tolerance);
            break;
        case 'h':
            show_last_fenced(out, target);
            break;
        case 'H':
            rc = handle_history(st, target, options.timeout, args->quiet,
                                options.verbose, options.cleanup,
                                options.broadcast, out);
            break;
        case 'K':
            device = (options.devices ? options.devices->key : NULL);
            rc = validate(st, options.agent, device, options.params,
                          options.timeout, args->quiet, out);
            break;
    }

    crm_info("Command returned: %s (%d)", pcmk_strerror(rc), rc);
    exit_code = crm_errno2exit(rc);

  done:
    g_strfreev(processed_args);
    g_option_context_free(context);
    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    free(async_fence_data.name);
    stonith_key_value_freeall(options.params, 1, 1);

    if (st != NULL) {
        st->cmds->disconnect(st);
        stonith_api_delete(st);
    }

    return exit_code;
}
