/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/xml.h>

#include <pacemaker-internal.h>

#define SUMMARY "query and update Pacemaker node attributes"

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

GError *error = NULL;
bool printed_values = false;

struct {
    char command;
    gchar *attr_dampen;
    gchar *attr_name;
    gchar *attr_pattern;
    gchar *attr_node;
    gchar *attr_set;
    char *attr_value;
    uint32_t attr_options;
    gboolean query_all;
    gboolean quiet;
} options = {
    .attr_options = pcmk__node_attr_none,
    .command = 'Q',
};

static gboolean
command_cb (const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.attr_value, optarg);

    if (pcmk__str_any_of(option_name, "--update-both", "-B", NULL)) {
        options.command = 'B';
    } else if (pcmk__str_any_of(option_name, "--delete", "-D", NULL)) {
        options.command = 'D';
    } else if (pcmk__str_any_of(option_name, "--query", "-Q", NULL)) {
        options.command = 'Q';
    } else if (pcmk__str_any_of(option_name, "--refresh", "-R", NULL)) {
        options.command = 'R';
    } else if (pcmk__str_any_of(option_name, "--update", "-U", "-v", NULL)) {
        options.command = 'U';
    } else if (pcmk__str_any_of(option_name, "--update-delay", "-Y", NULL)) {
        options.command = 'Y';
    }

    return TRUE;
}

static gboolean
private_cb (const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__set_node_attr_flags(options.attr_options, pcmk__node_attr_private);
    return TRUE;
}

static gboolean
section_cb (const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (pcmk__str_any_of(optarg, PCMK_XE_NODES, "forever", NULL)) {
        pcmk__set_node_attr_flags(options.attr_options, pcmk__node_attr_perm);
    } else if (pcmk__str_any_of(optarg, PCMK_XE_STATUS, PCMK_VALUE_REBOOT,
                                NULL)) {
        pcmk__clear_node_attr_flags(options.attr_options, pcmk__node_attr_perm);
    } else {
        g_set_error(err, PCMK__EXITC_ERROR, CRM_EX_USAGE, "Unknown value for --lifetime: %s",
                    optarg);
        return FALSE;
    }

    return TRUE;
}

static gboolean
attr_set_type_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-z", "--utilization", NULL)) {
        pcmk__set_node_attr_flags(options.attr_options, pcmk__node_attr_utilization);
    }

    return TRUE;
}

static gboolean
wait_cb (const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (pcmk__str_eq(optarg, "no", pcmk__str_none)) {
        pcmk__clear_node_attr_flags(options.attr_options, pcmk__node_attr_sync_local | pcmk__node_attr_sync_cluster);
        return TRUE;
    } else if (pcmk__str_eq(optarg, PCMK__VALUE_LOCAL, pcmk__str_none)) {
        pcmk__clear_node_attr_flags(options.attr_options, pcmk__node_attr_sync_local | pcmk__node_attr_sync_cluster);
        pcmk__set_node_attr_flags(options.attr_options, pcmk__node_attr_sync_local);
        return TRUE;
    } else if (pcmk__str_eq(optarg, PCMK__VALUE_CLUSTER, pcmk__str_none)) {
        pcmk__clear_node_attr_flags(options.attr_options, pcmk__node_attr_sync_local | pcmk__node_attr_sync_cluster);
        pcmk__set_node_attr_flags(options.attr_options, pcmk__node_attr_sync_cluster);
        return TRUE;
    } else {
        g_set_error(err, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "--wait= must be one of 'no', 'local', 'cluster'");
        return FALSE;
    }
}

#define INDENT "                              "

static GOptionEntry required_entries[] = {
    { "name", 'n', 0, G_OPTION_ARG_STRING, &options.attr_name,
      "The attribute's name",
      "NAME" },

    { "pattern", 'P', 0, G_OPTION_ARG_STRING, &options.attr_pattern,
      "Operate on all attributes matching this pattern\n"
      INDENT "(with -B, -D, -U, or -Y)",
      "PATTERN"
    },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "update", 'U', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Update attribute's value. Required: -n/--name or -P/--pattern.\n"
      INDENT "Optional: -d/--delay (if specified, the delay will be used if\n"
      INDENT "the attribute needs to be created, but ignored if the\n"
      INDENT "attribute already exists), -s/--set, -p/--private, -W/--wait,\n"
      INDENT "-z/--utilization.",
      "VALUE" },

    { "update-both", 'B', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Update attribute's value and time to wait (dampening) in the\n"
      INDENT "attribute manager. If this changes the value or dampening,\n"
      INDENT "the attribute will also be written to the cluster configuration,\n"
      INDENT "so be aware that repeatedly changing the dampening reduces its\n"
      INDENT "effectiveness.\n"
      INDENT "Requires -d/--delay",
      "VALUE" },

    { "update-delay", 'Y', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Update attribute's dampening in the attribute manager. If this\n"
      INDENT "changes the dampening, the attribute will also be written\n"
      INDENT "to the cluster configuration, so be aware that repeatedly\n"
      INDENT "changing the dampening reduces its effectiveness.\n"
      INDENT "Requires -d/--delay",
      NULL },

    { "query", 'Q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Query the attribute's value from the attribute manager. By default\n"
      INDENT "this will query the value of the attribute on the local node.\n"
      INDENT "Use -N/--node for the value on a given node, or -A/--all for the\n"
      INDENT "value on all nodes.",
      NULL },

    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Unset attribute from the attribute manager. At the moment, there is no\n"
      INDENT "way to remove an attribute. This option will instead set its\n"
      INDENT "value to the empty string.",
      NULL },

    { "refresh", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Force the attribute manager to resend all current\n"
      INDENT "values to the CIB",
      NULL },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "delay", 'd', 0, G_OPTION_ARG_STRING, &options.attr_dampen,
      "The time to wait (dampening) in seconds for further changes\n"
      INDENT "before sending to the CIB",
      "SECONDS" },

    { "set", 's', 0, G_OPTION_ARG_STRING, &options.attr_set,
      "(Advanced) The attribute set in which to place the value",
      "SET" },

    { "node", 'N', 0, G_OPTION_ARG_STRING, &options.attr_node,
      "Use the named node for setting and querying the attribute (instead\n"
      INDENT "of the local one)",
      "NODE" },

    { "all", 'A', 0, G_OPTION_ARG_NONE, &options.query_all,
      "Show values of the attribute for all nodes (query only)",
      NULL },

    { "lifetime", 'l', 0, G_OPTION_ARG_CALLBACK, section_cb,
      "(Not yet implemented) Lifetime of the node attribute (silently\n"
      INDENT "ignored by cluster)",
      "SECTION" },

    { "private", 'p', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, private_cb,
      "If this creates a new attribute, never write the attribute to CIB",
      NULL },

    { "wait", 'W', 0, G_OPTION_ARG_CALLBACK, wait_cb,
      "Wait for some event to occur before returning.  Values are 'no' (wait\n"
      INDENT "only for the attribute daemon to acknowledge the request),\n"
      INDENT "'local' (wait until the change has propagated to where a local\n"
      INDENT "query will return the request value, or the value set by a\n"
      INDENT "later request), or 'cluster' (wait until the change has propagated\n"
      INDENT "to where a query anywhere on the cluster will return the requested\n"
      INDENT "value, or the value set by a later request).  Default is 'no'.",
      "UNTIL" },

    { "utilization", 'z', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, attr_set_type_cb,
      "When creating a new attribute, create it as a node utilization attribute\n"
      INDENT "instead of an instance attribute.  If the attribute already exists,\n"
      INDENT "its existing type (utilization vs. instance) will be used regardless.\n"
      INDENT "(with -B, -U, -Y)",
      NULL },

    { NULL }
};

static GOptionEntry deprecated_entries[] = {
    { "quiet", 'q', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.quiet,
      NULL,
      NULL },

    { "update", 'v', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, command_cb,
      NULL,
      NULL },

    { "section", 'S', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, section_cb,
      NULL,
      NULL },

    { NULL }
};

static int send_attrd_query(pcmk__output_t *out, const char *attr_name, const char *attr_node,
                    gboolean query_all);
static int send_attrd_update(char command, const char *attr_node, const char *attr_name,
                             const char *attr_value, const char *attr_set,
                             const char *attr_dampen, uint32_t attr_options);

static bool
pattern_used_correctly(void)
{
    /* --pattern can only be used with:
     * -B (update-both), -D (delete), -U (update), or -Y (update-delay)
     */
    return options.command == 'B' || options.command == 'D' || options.command == 'U' || options.command == 'Y';
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);

    pcmk__add_arg_group(context, "required", "Required Arguments:",
                        "Show required arguments", required_entries);
    pcmk__add_arg_group(context, "command", "Command:",
                        "Show command options (mutually exclusive)", command_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    pcmk__add_arg_group(context, "deprecated", "Deprecated Options:",
                        "Show deprecated options", deprecated_entries);

    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    GOptionContext *context = build_arg_context(args, &output_group);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "dlnsvBNUS");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("attrd_updater", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    if (options.attr_pattern) {
        if (options.attr_name) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error: --name and --pattern cannot be used at the same time");
            goto done;
        }

        if (!pattern_used_correctly()) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error: pattern can only be used with delete or update");
            goto done;
        }

        g_free(options.attr_name);
        options.attr_name = options.attr_pattern;
        options.attr_options |= pcmk__node_attr_pattern;
    }

    if (options.command != 'R' && options.attr_name == NULL) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Command requires --name or --pattern argument");
        goto done;
    } else if ((options.command == 'B'|| options.command == 'Y') && options.attr_dampen == NULL) {
        out->info(out, "Warning: '%c' command given without required --delay", options.command);
    }

    pcmk__register_lib_messages(out);

    if (options.command == 'Q') {
        int rc = send_attrd_query(out, options.attr_name, options.attr_node, options.query_all);
        exit_code = pcmk_rc2exitc(rc);
    } else {
        /* @TODO We don't know whether the specified node is a Pacemaker Remote
         * node or not, so we can't set pcmk__node_attr_remote when appropriate.
         * However, it's not a big problem, because the attribute manager will
         * learn and remember a node's "remoteness".
         */
        int rc = send_attrd_update(options.command, options.attr_node,
                                   options.attr_name, options.attr_value,
                                   options.attr_set, options.attr_dampen,
                                   options.attr_options);
        exit_code = pcmk_rc2exitc(rc);
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    g_free(options.attr_dampen);
    g_free(options.attr_name);
    g_free(options.attr_node);
    g_free(options.attr_set);
    free(options.attr_value);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

/*!
 * \brief Print the attribute values in an attribute manager XML query reply
 *
 * \param[in,out] out    Output object
 * \param[in]     reply  List of attribute name/value pairs
 *
 * \return true if any values were printed
 */
static void
print_attrd_values(pcmk__output_t *out, const GList *reply)
{
    for (const GList *iter = reply; iter != NULL; iter = iter->next) {
        const pcmk__attrd_query_pair_t *pair = iter->data;

        out->message(out, "attribute", NULL, NULL, pair->name, pair->value,
                     pair->node, false, false);
        printed_values = true;
    }
}

static void
attrd_event_cb(pcmk_ipc_api_t *attrd_api, enum pcmk_ipc_event event_type,
               crm_exit_t status, void *event_data, void *user_data)
{
    pcmk__output_t *out = (pcmk__output_t *) user_data;
    pcmk__attrd_api_reply_t *reply = event_data;

    if (event_type != pcmk_ipc_event_reply || status != CRM_EX_OK) {
        return;
    }

    /* Print the values from the reply. */
    if (reply->reply_type == pcmk__attrd_reply_query) {
        print_attrd_values(out, reply->data.pairs);
    }
}

/*!
 * \brief Submit a query to the attribute manager and print reply
 *
 * \param[in,out] out  Output object
 * \param[in]     attr_name  Name of attribute to be affected by request
 * \param[in]     attr_node  Name of host to query for (or NULL for localhost)
 * \param[in]     query_all  If TRUE, ignore attr_node and query all nodes
 *
 * \return Standard Pacemaker return code
 */
static int
send_attrd_query(pcmk__output_t *out, const char *attr_name,
                 const char *attr_node, gboolean query_all)
{
    uint32_t options = pcmk__node_attr_none;
    pcmk_ipc_api_t *attrd_api = NULL;
    int rc = pcmk_rc_ok;

    // Create attrd IPC object
    rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to attrd: %s", pcmk_rc_str(rc));
        return ENOTCONN;
    }

    pcmk_register_ipc_callback(attrd_api, attrd_event_cb, out);

    // Connect to attrd (without main loop)
    rc = pcmk__connect_ipc(attrd_api, pcmk_ipc_dispatch_sync, 5);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to %s: %s",
                    pcmk_ipc_name(attrd_api, true), pcmk_rc_str(rc));
        pcmk_free_ipc_api(attrd_api);
        return rc;
    }

    /* Decide which node(s) to query */
    if (query_all == TRUE) {
        options |= pcmk__node_attr_query_all;
    }

    rc = pcmk__attrd_api_query(attrd_api, attr_node, attr_name, options);

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not query value of %s: %s (%d)",
                    attr_name, pcmk_rc_str(rc), rc);
    } else if (!printed_values) {
        rc = pcmk_rc_schema_validation;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not query value of %s: attribute does not exist", attr_name);
    }

    pcmk_disconnect_ipc(attrd_api);
    pcmk_free_ipc_api(attrd_api);

    return rc;
}

static int
send_attrd_update(char command, const char *attr_node, const char *attr_name,
                  const char *attr_value, const char *attr_set,
                  const char *attr_dampen, uint32_t attr_options)
{
    int rc = pcmk_rc_ok;

    switch (command) {
        case 'B':
            rc = pcmk__attrd_api_update(NULL, attr_node, attr_name, attr_value,
                                        attr_dampen, attr_set, NULL,
                                        attr_options | pcmk__node_attr_value | pcmk__node_attr_delay);
            break;

        case 'D':
            rc = pcmk__attrd_api_delete(NULL, attr_node, attr_name, attr_options);
            break;

        case 'R':
            rc = pcmk__attrd_api_refresh(NULL, attr_node);
            break;

        case 'U':
            rc = pcmk__attrd_api_update(NULL, attr_node, attr_name, attr_value,
                                        attr_dampen, attr_set, NULL,
                                        attr_options | pcmk__node_attr_value);
            break;

        case 'Y':
            rc = pcmk__attrd_api_update(NULL, attr_node, attr_name, NULL,
                                        attr_dampen, attr_set, NULL,
                                        attr_options | pcmk__node_attr_delay);
            break;
    }

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not update %s=%s: %s (%d)",
                    attr_name, attr_value, pcmk_rc_str(rc), rc);
    }

    return rc;
}
