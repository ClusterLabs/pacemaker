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
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/common/ipc.h>

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

struct {
    char command;
    gchar *attr_dampen;
    gchar *attr_name;
    gchar *attr_node;
    gchar *attr_section;
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

    { "lifetime", 'l', 0, G_OPTION_ARG_STRING, &options.attr_section,
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

    { "section", 'S', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.attr_section,
      NULL,
      NULL },

    { NULL }
};

static int do_query(pcmk__output_t *out, const char *attr_name, const char *attr_node,
                    gboolean query_all);
static int do_update(char command, const char *attr_node, const char *attr_name,
                     const char *attr_value, const char *attr_section,
                     const char *attr_set, const char *attr_dampen, int attr_options);

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
        int rc = do_query(out, options.attr_name, options.attr_node, options.query_all);
        exit_code = pcmk_rc2exitc(rc);
    } else {
        /* @TODO We don't know whether the specified node is a Pacemaker Remote
         * node or not, so we can't set pcmk__node_attr_remote when appropriate.
         * However, it's not a big problem, because pacemaker-attrd will learn
         * and remember a node's "remoteness".
         */
        const char *target = pcmk__node_attr_target(options.attr_node);

        exit_code = pcmk_rc2exitc(do_update(options.command,
                                            target == NULL ? options.attr_node : target,
                                            options.attr_name, options.attr_value,
                                            options.attr_section, options.attr_set,
                                            options.attr_dampen, options.attr_options));
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    g_free(options.attr_dampen);
    g_free(options.attr_name);
    g_free(options.attr_node);
    g_free(options.attr_section);
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
 * \internal
 * \brief Submit a query request to pacemaker-attrd and wait for reply
 *
 * \param[in] name    Name of attribute to query
 * \param[in] host    Query applies to this host only (or all hosts if NULL)
 * \param[out] reply  On success, will be set to new XML tree with reply
 *
 * \return Standard Pacemaker return code
 * \note On success, caller is responsible for freeing result via free_xml(*reply)
 */
static int
send_attrd_query(const char *name, const char *host, xmlNode **reply)
{
    int rc = pcmk_rc_ok;
    crm_ipc_t *ipc;
    xmlNode *query;

    /* Build the query XML */
    query = create_xml_node(NULL, __func__);
    if (query == NULL) {
        return ENOMEM;
    }
    crm_xml_add(query, F_TYPE, T_ATTRD);
    crm_xml_add(query, F_ORIG, crm_system_name);
    crm_xml_add(query, PCMK__XA_ATTR_NODE_NAME, host);
    crm_xml_add(query, PCMK__XA_TASK, PCMK__ATTRD_CMD_QUERY);
    crm_xml_add(query, PCMK__XA_ATTR_NAME, name);

    /* Connect to pacemaker-attrd, send query XML and get reply */
    crm_debug("Sending query for value of %s on %s", name, (host? host : "all nodes"));
    ipc = crm_ipc_new(T_ATTRD, 0);
    if (!crm_ipc_connect(ipc)) {
        crm_perror(LOG_ERR, "Connection to cluster attribute manager failed");
        rc = ENOTCONN;
    } else {
        rc = crm_ipc_send(ipc, query, crm_ipc_client_response, 0, reply);
        if (rc > 0) {
            rc = pcmk_rc_ok;
        }
        crm_ipc_close(ipc);
    }
    crm_ipc_destroy(ipc);

    free_xml(query);
    return(rc);
}

/*!
 * \brief Validate pacemaker-attrd's XML reply to an query
 *
 * param[in] reply      Root of reply XML tree to validate
 * param[in] attr_name  Name of attribute that was queried
 *
 * \return Standard Pacemaker return code
 * \note A return value of ENXIO means the requested attribute does not exist
 */
static int
validate_attrd_reply(xmlNode *reply, const char *attr_name)
{
    int rc = pcmk_rc_ok;
    const char *reply_attr;

    if (reply == NULL) {
        rc = pcmk_rc_schema_validation;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not query value of %s: reply did not contain valid XML",
                    attr_name);
        return rc;
    }
    crm_log_xml_trace(reply, "Reply");

    reply_attr = crm_element_value(reply, PCMK__XA_ATTR_NAME);
    if (reply_attr == NULL) {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not query value of %s: attribute does not exist",
                    attr_name);
        return rc;
    }

    if (!pcmk__str_eq(crm_element_value(reply, F_TYPE), T_ATTRD, pcmk__str_casei)
        || (crm_element_value(reply, PCMK__XA_ATTR_VERSION) == NULL)
        || strcmp(reply_attr, attr_name)) {
            rc = pcmk_rc_schema_validation;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not query value of %s: reply did not contain expected identification",
                        attr_name);
            return rc;
    }

    return pcmk_rc_ok;
}

/*!
 * \brief Print the attribute values in a pacemaker-attrd XML query reply
 *
 * \param[in] reply     Root of XML tree with query reply
 * \param[in] attr_name Name of attribute that was queried
 *
 * \return true if any values were printed
 */
static bool
print_attrd_values(pcmk__output_t *out, xmlNode *reply, const char *attr_name)
{
    xmlNode *child;
    const char *reply_host, *reply_value;
    bool have_values = false;

    /* Iterate through reply's XML tags (a node tag for each host-value pair) */
    for (child = pcmk__xml_first_child(reply); child != NULL;
         child = pcmk__xml_next(child)) {

        if (!pcmk__str_eq((const char *)child->name, XML_CIB_TAG_NODE,
                          pcmk__str_casei)) {
            crm_warn("Ignoring unexpected %s tag in query reply", child->name);
        } else {
            reply_host = crm_element_value(child, PCMK__XA_ATTR_NODE_NAME);
            reply_value = crm_element_value(child, PCMK__XA_ATTR_VALUE);

            if (reply_host == NULL) {
                crm_warn("Ignoring %s tag without %s attribute in query reply",
                         XML_CIB_TAG_NODE, PCMK__XA_ATTR_NODE_NAME);
            } else {
                out->message(out, "attribute", NULL, NULL, attr_name, reply_value, reply_host);
                have_values = true;
            }
        }
    }

    return have_values;
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
do_query(pcmk__output_t *out, const char *attr_name, const char *attr_node, gboolean query_all)
{
    xmlNode *reply = NULL;
    int rc = pcmk_rc_ok;

    /* Decide which node(s) to query */
    if (query_all == TRUE) {
        attr_node = NULL;
    } else {
        const char *target = pcmk__node_attr_target(attr_node);
        if (target != NULL) {
            attr_node = target;
        }
    }

    /* Build and send pacemaker-attrd request, and get XML reply */
    rc = send_attrd_query(attr_name, attr_node, &reply);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not query value of %s: %s (%d)",
                    attr_name, pcmk_strerror(rc), rc);
        return rc;
    }

    /* Validate the XML reply */
    rc = validate_attrd_reply(reply, attr_name);
    if (rc != pcmk_rc_ok) {
        if (reply != NULL) {
            free_xml(reply);
        }
        return rc;
    }

    /* Print the values from the reply */
    if (!print_attrd_values(out, reply, attr_name)) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not query value of %s: reply had attribute name but no host values",
                    attr_name);
        free_xml(reply);
        return pcmk_rc_schema_validation;
    }

    return pcmk_rc_ok;
}

static int
do_update(char command, const char *attr_node, const char *attr_name,
          const char *attr_value, const char *attr_section,
          const char *attr_set, const char *attr_dampen, int attr_options)
{
    int rc = pcmk__node_attr_request(NULL, command, attr_node, attr_name,
                                     attr_value, attr_section, attr_set,
                                     attr_dampen, NULL, attr_options);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not update %s=%s: %s (%d)",
                    attr_name, attr_value, pcmk_rc_str(rc), rc);
    }
    return rc;
}
