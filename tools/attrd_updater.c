/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml_internal.h>

#include <crm/common/attrd_internal.h>

#include <pcmki/pcmki_output.h>

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
    gchar *attr_node;
    gchar *attr_set;
    char *attr_value;
    int attr_options;
    gboolean query_all;
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
    if (pcmk__str_any_of(optarg, "nodes", "forever", NULL)) {
        pcmk__set_node_attr_flags(options.attr_options, pcmk__node_attr_perm);
    } else if (pcmk__str_any_of(optarg, "status", "reboot", NULL)) {
        pcmk__clear_node_attr_flags(options.attr_options, pcmk__node_attr_perm);
    } else {
        g_set_error(err, PCMK__EXITC_ERROR, CRM_EX_USAGE, "Unknown value for --lifetime: %s",
                    optarg);
        return FALSE;
    }

    return TRUE;
}

#define INDENT "                              "

static GOptionEntry required_entries[] = {
    { "name", 'n', 0, G_OPTION_ARG_STRING, &options.attr_name,
      "The attribute's name",
      "NAME" },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "update", 'U', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Update attribute's value in pacemaker-attrd. If this causes the value\n"
      INDENT "to change, it will also be updated in the cluster configuration.",
      "VALUE" },

    { "update-both", 'B', 0, G_OPTION_ARG_CALLBACK, command_cb,
      "Update attribute's value and time to wait (dampening) in\n"
      INDENT "pacemaker-attrd. If this causes the value or dampening to change,\n"
      INDENT "the attribute will also be written to the cluster configuration,\n"
      INDENT "so be aware that repeatedly changing the dampening reduces its\n"
      INDENT "effectiveness.",
      "VALUE" },

    { "update-delay", 'Y', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Update attribute's dampening in pacemaker-attrd (requires\n"
      INDENT "-d/--delay). If this causes the dampening to change, the\n"
      INDENT "attribute will also be written to the cluster configuration, so\n"
      INDENT "be aware that repeatedly changing the dampening reduces its\n"
      INDENT "effectiveness.",
      NULL },

    { "query", 'Q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Query the attribute's value from pacemaker-attrd",
      NULL },

    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Unset attribute from pacemaker-attrd. At the moment, there is no way\n"
      INDENT "to remove an attribute. This option will instead set its value\n"
      INDENT "to the empty string.",
      NULL },

    { "refresh", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Force the pacemaker-attrd daemon to resend all current\n"
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
      "Set the attribute for the named node (instead of the local one)",
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

    { NULL }
};

static GOptionEntry deprecated_entries[] = {
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

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (options.command != 'R' && options.attr_name == NULL) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Command requires --name argument");
        goto done;
    }

    pcmk__register_lib_messages(out);

    if (options.command == 'Q') {
        int rc = send_attrd_query(out, options.attr_name, options.attr_node, options.query_all);
        exit_code = pcmk_rc2exitc(rc);
    } else {
        /* @TODO We don't know whether the specified node is a Pacemaker Remote
         * node or not, so we can't set pcmk__node_attr_remote when appropriate.
         * However, it's not a big problem, because pacemaker-attrd will learn
         * and remember a node's "remoteness".
         */
        const char *target = pcmk__node_attr_target(options.attr_node);

        int rc = send_attrd_update(options.command,
                                   target == NULL ? options.attr_node : target,
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

    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    crm_exit(exit_code);
}

/*!
 * \brief Print the attribute values in a pacemaker-attrd XML query reply
 *
 * \param[in] reply     List of attribute name/value pairs
 * \param[in] attr_name Name of attribute that was queried
 *
 * \return true if any values were printed
 */
static void
print_attrd_values(pcmk__output_t *out, GList *reply)
{
    for (GList *iter = reply; iter != NULL; iter = iter->next) {
        pcmk__attrd_query_pair_t *pair = (pcmk__attrd_query_pair_t *) iter->data;

        out->message(out, "attribute", NULL, NULL, pair->name, pair->value,
                     pair->node);
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
 * \brief Submit a query to pacemaker-attrd and print reply
 *
 * \param[in] attr_name  Name of attribute to be affected by request
 * \param[in] attr_node  Name of host to query for (or NULL for localhost)
 * \param[in] query_all  If TRUE, ignore attr_node and query all nodes instead
 *
 * \return Standard Pacemaker return code
 */
static int
send_attrd_query(pcmk__output_t *out, const char *attr_name, const char *attr_node, gboolean query_all)
{
    pcmk_ipc_api_t *attrd_api = NULL;
    int rc = pcmk_rc_ok;

    // Create attrd IPC object
    rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to attrd: %s\n",
                pcmk_rc_str(rc));
        return ENOTCONN;
    }

    pcmk_register_ipc_callback(attrd_api, attrd_event_cb, out);

    // Connect to attrd (without main loop)
    rc = pcmk_connect_ipc(attrd_api, pcmk_ipc_dispatch_sync);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to attrd: %s\n",
                pcmk_rc_str(rc));
        pcmk_free_ipc_api(attrd_api);
        return rc;
    }

    /* Decide which node(s) to query */
    if (query_all == TRUE) {
        attr_node = NULL;
    } else {
        const char *target = pcmk__node_attr_target(attr_node);
        if (target != NULL) {
            attr_node = target;
        }
    }

    rc = pcmk__attrd_api_query(attrd_api, attr_node, attr_name, 0);

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not query value of %s: %s (%d)",
                    attr_name, pcmk_strerror(rc), rc);
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
    pcmk_ipc_api_t *attrd_api = NULL;
    int rc = pcmk_rc_ok;
    xmlNode *reply = NULL;
    const char *target = NULL;

    // Create attrd IPC object
    rc = pcmk_new_ipc_api(&attrd_api, pcmk_ipc_attrd);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to attrd: %s\n",
                pcmk_rc_str(rc));
        return ENOTCONN;
    }

    pcmk_register_ipc_callback(attrd_api, attrd_event_cb, &reply);

    // Connect to attrd (without main loop)
    rc = pcmk_connect_ipc(attrd_api, pcmk_ipc_dispatch_sync);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to attrd: %s\n",
                pcmk_rc_str(rc));
        pcmk_free_ipc_api(attrd_api);
        return rc;
    }

    target = pcmk__node_attr_target(attr_node);
    if (target != NULL) {
        attr_node = target;
    }

    switch (command) {
        case 'B':
            rc = pcmk__attrd_api_update(attrd_api, attr_node, attr_name,
                                        attr_value, attr_dampen, attr_set, NULL,
                                        attr_options | pcmk__node_attr_value | pcmk__node_attr_delay);
            break;

        case 'D':
            rc = pcmk__attrd_api_delete(attrd_api, attr_node, attr_name,
                                        attr_options);
            break;

        case 'R':
            rc = pcmk__attrd_api_refresh(attrd_api, attr_node);
            break;

        case 'U':
            rc = pcmk__attrd_api_update(attrd_api, attr_node, attr_name,
                                        attr_value, NULL, attr_set, NULL,
                                        attr_options | pcmk__node_attr_value);
            break;

        case 'Y':
            rc = pcmk__attrd_api_update(attrd_api, attr_node, attr_name,
                                        NULL, attr_dampen, attr_set, NULL,
                                        attr_options | pcmk__node_attr_delay);
            break;
    }

    pcmk_disconnect_ipc(attrd_api);
    pcmk_free_ipc_api(attrd_api);

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not update %s=%s: %s (%d)",
                    attr_name, attr_value, pcmk_rc_str(rc), rc);
    }

    return rc;
}
