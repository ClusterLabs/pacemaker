/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>

#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/util.h>
#include <crm/cluster.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/attrd_internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/output_internal.h>
#include <sys/utsname.h>

#include <pacemaker-internal.h>

#define SUMMARY "crm_attribute - query and update Pacemaker cluster options and node attributes"

GError *error = NULL;
crm_exit_t exit_code = CRM_EX_OK;
uint64_t cib_opts = cib_sync_call;

PCMK__OUTPUT_ARGS("attribute", "const char *", "const char *", "const char *",
                  "const char *", "const char *")
static int
attribute_text(pcmk__output_t *out, va_list args)
{
    const char *scope = va_arg(args, const char *);
    const char *instance = va_arg(args, const char *);
    const char *name = va_arg(args, const char *);
    const char *value = va_arg(args, const char *);
    const char *host G_GNUC_UNUSED = va_arg(args, const char *);

    if (out->quiet) {
        if (value != NULL) {
            pcmk__formatted_printf(out, "%s\n", value);
        }
    } else {
        out->info(out, "%s%s %s%s %s%s value=%s",
                  scope ? "scope=" : "", scope ? scope : "",
                  instance ? "id=" : "", instance ? instance : "",
                  name ? "name=" : "", name ? name : "",
                  value ? value : "(null)");
    }

    return pcmk_rc_ok;
}

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static pcmk__message_entry_t fmt_functions[] = {
    { "attribute", "text", attribute_text },

    { NULL, NULL, NULL }
};

struct {
    char command;
    gchar *attr_default;
    gchar *attr_id;
    gchar *attr_name;
    gchar *attr_pattern;
    char *attr_value;
    char *dest_node;
    gchar *dest_uname;
    gboolean inhibit;
    gchar *set_name;
    char *set_type;
    gchar *type;
    gboolean promotion_score;
} options = {
    .command = 'G',
    .promotion_score = FALSE
};

#define INDENT "                               "

static gboolean
delete_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'D';
    pcmk__str_update(&options.attr_value, NULL);
    return TRUE;
}

static gboolean
promotion_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    char *score_name = NULL;

    options.promotion_score = TRUE;

    if (options.attr_name) {
        g_free(options.attr_name);
    }

    score_name = pcmk_promotion_score_name(optarg);
    if (score_name != NULL) {
        options.attr_name = g_strdup(score_name);
        free(score_name);
    } else {
        options.attr_name = NULL;
    }

    return TRUE;
}

static gboolean
update_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'u';
    pcmk__str_update(&options.attr_value, optarg);
    return TRUE;
}

static gboolean
utilization_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.type) {
        g_free(options.type);
    }

    options.type = g_strdup(XML_CIB_TAG_NODES);
    pcmk__str_update(&options.set_type, XML_TAG_UTILIZATION);
    return TRUE;
}

static gboolean
value_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'G';
    pcmk__str_update(&options.attr_value, NULL);
    return TRUE;
}

static GOptionEntry selecting_entries[] = {
    { "id", 'i', 0, G_OPTION_ARG_STRING, &options.attr_id,
      "(Advanced) Operate on instance of specified attribute with this\n"
      INDENT "XML ID",
      "XML_ID"
    },

    { "name", 'n', 0, G_OPTION_ARG_STRING, &options.attr_name,
      "Operate on attribute or option with this name.  For queries, this\n"
      INDENT "is optional, in which case all matching attributes will be\n"
      INDENT "returned.",
      "NAME"
    },

    { "pattern", 'P', 0, G_OPTION_ARG_STRING, &options.attr_pattern,
      "Operate on all attributes matching this pattern\n"
      INDENT "(with -G, or with -v/-D and -l reboot)",
      "PATTERN"
    },

    { "promotion", 'p', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, promotion_cb,
      "Operate on node attribute used as promotion score for specified\n"
      INDENT "resource, or resource given in OCF_RESOURCE_INSTANCE environment\n"
      INDENT "variable if none is specified; this also defaults -l/--lifetime\n"
      INDENT "to reboot (normally invoked from an OCF resource agent)",
      "RESOURCE"
    },

    { "set-name", 's', 0, G_OPTION_ARG_STRING, &options.set_name,
      "(Advanced) Operate on instance of specified attribute that is\n"
      INDENT "within set with this XML ID",
      "NAME"
    },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, delete_cb,
      "Delete the attribute/option",
      NULL
    },

    { "query", 'G', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, value_cb,
      "Query the current value of the attribute/option.\n"
      INDENT "See also: -n, -P",
      NULL
    },

    { "update", 'v', 0, G_OPTION_ARG_CALLBACK, update_cb,
      "Update the value of the attribute/option",
      "VALUE"
    },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "default", 'd', 0, G_OPTION_ARG_STRING, &options.attr_default,
      "(Advanced) Default value to display if none is found in configuration",
      "VALUE"
    },

    { "lifetime", 'l', 0, G_OPTION_ARG_STRING, &options.type,
      "Lifetime of the node attribute.\n"
      INDENT "Valid values: reboot, forever",
      "LIFETIME"
    },

    { "node", 'N', 0, G_OPTION_ARG_STRING, &options.dest_uname,
      "Set a node attribute for named node (instead of a cluster option).\n"
      INDENT "See also: -l",
      "NODE"
    },

    { "type", 't', 0, G_OPTION_ARG_STRING, &options.type,
      "Which part of the configuration to update/delete/query the option in.\n"
      INDENT "Valid values: crm_config, rsc_defaults, op_defaults, tickets",
      "SECTION"
    },

    { "utilization", 'z', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, utilization_cb,
      "Set an utilization attribute for the node.",
      NULL
    },

    { "inhibit-policy-engine", '!', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.inhibit,
      NULL, NULL
    },

    { NULL }
};

static GOptionEntry deprecated_entries[] = {
    { "attr-id", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.attr_id,
      NULL, NULL
    },

    { "attr-name", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.attr_name,
      NULL, NULL
    },

    { "attr-value", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, update_cb,
      NULL, NULL
    },

    { "delete-attr", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, delete_cb,
      NULL, NULL
    },

    { "get-value", 0, G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, value_cb,
      NULL, NULL
    },

    { "node-uname", 'U', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.dest_uname,
      NULL, NULL
    },

    { NULL }
};

static void
get_node_name_from_local(void)
{
    char *hostname = pcmk_hostname();

    g_free(options.dest_uname);

    /* This silliness is so that dest_uname is always a glib-managed
     * string so we know how to free it later.  pcmk_hostname returns
     * a newly allocated string via strdup.
     */
    options.dest_uname = g_strdup(hostname);
    free(hostname);
}

static int
send_attrd_update(char command, const char *attr_node, const char *attr_name,
                  const char *attr_value, const char *attr_set,
                  const char *attr_dampen, uint32_t attr_options)
{
    int rc = pcmk_rc_ok;
    uint32_t opts = attr_options;

    if (options.attr_pattern) {
        opts |= pcmk__node_attr_pattern;
    }

    switch (command) {
        case 'D':
            rc = pcmk__attrd_api_delete(NULL, attr_node, attr_name, opts);
            break;

        case 'u':
            rc = pcmk__attrd_api_update(NULL, attr_node, attr_name,
                                        attr_value, NULL, attr_set, NULL,
                                        opts | pcmk__node_attr_value);
            break;
    }

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not update %s=%s: %s (%d)",
                    attr_name, attr_value, pcmk_rc_str(rc), rc);
    }

    return rc;
}

struct delete_data_s {
    pcmk__output_t *out;
    cib_t *cib;
};

static int
delete_attr_on_node(xmlNode *child, void *userdata)
{
    struct delete_data_s *dd = (struct delete_data_s *) userdata;

    const char *attr_name = crm_element_value(child, XML_NVPAIR_ATTR_NAME);
    int rc = pcmk_rc_ok;

    if (!pcmk__str_eq(attr_name, options.attr_pattern, pcmk__str_regex)) {
        return pcmk_rc_ok;
    }

    rc = cib__delete_node_attr(dd->out, dd->cib, cib_opts, options.type,
                               options.dest_node, options.set_type,
                               options.set_name, options.attr_id,
                               attr_name, options.attr_value, NULL);

    if (rc == ENXIO) {
        rc = pcmk_rc_ok;
    }

    return rc;
}

static int
command_delete(pcmk__output_t *out, cib_t *cib)
{
    int rc = pcmk_rc_ok;

    xmlNode *result = NULL;
    bool use_pattern = options.attr_pattern != NULL;

    /* See the comment in command_query regarding xpath and regular expressions. */
    if (use_pattern) {
        struct delete_data_s dd = { out, cib };

        rc = cib__get_node_attrs(out, cib, options.type, options.dest_node,
                                 options.set_type, options.set_name, NULL, NULL,
                                 NULL, &result);

        if (rc != pcmk_rc_ok) {
            goto done_deleting;
        }

        rc = pcmk__xe_foreach_child(result, NULL, delete_attr_on_node, &dd);

        if (rc != pcmk_rc_ok) {
            goto done_deleting;
        }

    } else {
        rc = cib__delete_node_attr(out, cib, cib_opts, options.type, options.dest_node,
                                   options.set_type, options.set_name, options.attr_id,
                                   options.attr_name, options.attr_value, NULL);
    }

done_deleting:
    free_xml(result);

    if (rc == ENXIO) {
        /* Nothing to delete...
         * which means it's not there...
         * which is what the admin wanted
         */
        rc = pcmk_rc_ok;
    }

    return rc;
}

struct update_data_s {
    pcmk__output_t *out;
    cib_t *cib;
    int is_remote_node;
};

static int
update_attr_on_node(xmlNode *child, void *userdata)
{
    struct update_data_s *ud = (struct update_data_s *) userdata;

    const char *attr_name = crm_element_value(child, XML_NVPAIR_ATTR_NAME);

    if (!pcmk__str_eq(attr_name, options.attr_pattern, pcmk__str_regex)) {
        return pcmk_rc_ok;
    }

    return cib__update_node_attr(ud->out, ud->cib, cib_opts, options.type,
                                 options.dest_node, options.set_type,
                                 options.set_name, options.attr_id,
                                 attr_name, options.attr_value, NULL,
                                 ud->is_remote_node ? "remote" : NULL);
}

static int
command_update(pcmk__output_t *out, cib_t *cib, int is_remote_node)
{
    int rc = pcmk_rc_ok;

    xmlNode *result = NULL;
    bool use_pattern = options.attr_pattern != NULL;

    CRM_LOG_ASSERT(options.type != NULL);
    CRM_LOG_ASSERT(options.attr_name != NULL);
    CRM_LOG_ASSERT(options.attr_value != NULL);

    /* See the comment in command_query regarding xpath and regular expressions. */
    if (use_pattern) {
        struct update_data_s ud = { out, cib, is_remote_node };

        rc = cib__get_node_attrs(out, cib, options.type, options.dest_node,
                                 options.set_type, options.set_name, NULL, NULL,
                                 NULL, &result);

        if (rc != pcmk_rc_ok) {
            goto done_updating;
        }

        rc = pcmk__xe_foreach_child(result, NULL, update_attr_on_node, &ud);

        if (rc != pcmk_rc_ok) {
            goto done_updating;
        }

    } else {
        rc = cib__update_node_attr(out, cib, cib_opts, options.type,
                                   options.dest_node, options.set_type,
                                   options.set_name, options.attr_id,
                                   options.attr_name, options.attr_value,
                                   NULL, is_remote_node ? "remote" : NULL);
    }

done_updating:
    free_xml(result);
    return rc;
}

struct output_data_s {
    pcmk__output_t *out;
    bool use_pattern;
    bool did_output;
};

static int
output_one_attribute(xmlNode *node, void *userdata)
{
    struct output_data_s *od = (struct output_data_s *) userdata;

    const char *name = crm_element_value(node, XML_NVPAIR_ATTR_NAME);
    const char *value = crm_element_value(node, XML_NVPAIR_ATTR_VALUE);
    const char *host = crm_element_value(node, PCMK__XA_ATTR_NODE_NAME);

    const char *type = options.type;
    const char *attr_id = options.attr_id;

    if (od->use_pattern && !pcmk__str_eq(name, options.attr_pattern, pcmk__str_regex)) {
        return pcmk_rc_ok;
    }

    od->out->message(od->out, "attribute", type, attr_id, name, value, host);
    od->did_output = true;
    crm_info("Read %s='%s' %s%s",
             pcmk__s(name, "<null>"), pcmk__s(value, ""),
             options.set_name ? "in " : "", options.set_name ? options.set_name : "");

    return pcmk_rc_ok;
}

static int
command_query(pcmk__output_t *out, cib_t *cib)
{
    int rc = pcmk_rc_ok;

    xmlNode *result = NULL;
    bool use_pattern = options.attr_pattern != NULL;

    /* libxml2 doesn't support regular expressions in xpath queries (which is how
     * cib__get_node_attrs -> find_attr finds attributes).  So instead, we'll just
     * find all the attributes for a given node here by passing NULL for attr_id
     * and attr_name, and then later see if they match the given pattern.
     */
    if (use_pattern) {
        rc = cib__get_node_attrs(out, cib, options.type, options.dest_node,
                                 options.set_type, options.set_name, NULL,
                                 NULL, NULL, &result);
    } else {
        rc = cib__get_node_attrs(out, cib, options.type, options.dest_node,
                                 options.set_type, options.set_name, options.attr_id,
                                 options.attr_name, NULL, &result);
    }

    if (rc == ENXIO && options.attr_default) {
        /* Make static analysis happy */
        const char *type = options.type;
        const char *attr_id = options.attr_id;
        const char *attr_name = options.attr_name;
        const char *attr_default = options.attr_default;
        const char *dest_uname = options.dest_uname;

        out->message(out, "attribute", type, attr_id, attr_name, attr_default,
                     dest_uname);
        rc = pcmk_rc_ok;

    } else if (rc != pcmk_rc_ok) {
        // Don't do anything.

    } else if (xml_has_children(result)) {
        struct output_data_s od = { out, use_pattern, false };

        pcmk__xe_foreach_child(result, NULL, output_one_attribute, &od);

        if (!od.did_output) {
            rc = ENXIO;
        }

    } else {
        struct output_data_s od = { out, use_pattern, false };
        output_one_attribute(result, &od);
    }

    free_xml(result);
    return rc;
}

static void
set_type(void)
{
    if (options.type == NULL) {
        if (options.promotion_score) {
            // Updating a promotion score node attribute
            options.type = g_strdup(XML_CIB_TAG_STATUS);

        } else if (options.dest_uname != NULL) {
            // Updating some other node attribute
            options.type = g_strdup(XML_CIB_TAG_NODES);

        } else {
            // Updating cluster options
            options.type = g_strdup(XML_CIB_TAG_CRMCONFIG);
        }

    } else if (pcmk__str_eq(options.type, "reboot", pcmk__str_casei)) {
        options.type = g_strdup(XML_CIB_TAG_STATUS);

    } else if (pcmk__str_eq(options.type, "forever", pcmk__str_casei)) {
        options.type = g_strdup(XML_CIB_TAG_NODES);
    }
}

static bool
use_attrd(void)
{
    /* Only go through the attribute manager for transient attributes, and
     * then only if we're not using a file as the CIB.
     */
    return pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei) &&
           getenv("CIB_file") == NULL && getenv("CIB_shadow") == NULL;
}

static bool
try_ipc_update(void)
{
    return use_attrd() && (options.command == 'D' || options.command == 'u');
}

static bool
pattern_used_correctly(void)
{
    /* --pattern can only be used with:
     * -G (query), or
     * -v (update) or -D (delete), with till-reboot
     */
    return options.command == 'G' ||
           ((options.command == 'u' || options.command == 'D') &&
            pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei));
}

static bool
delete_used_correctly(void)
{
    return options.command != 'D' || options.attr_name != NULL || options.attr_pattern != NULL;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Print only the value on stdout",
          NULL },

        { "quiet", 'Q', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &(args->quiet),
          NULL, NULL
        },

        { NULL }
    };

    const char *description = "Examples:\n\n"
                              "Add new node attribute called 'location' with the value of 'office' for host 'myhost':\n\n"
                              "\tcrm_attribute --node myhost --name location --update office\n\n"
                              "Query the value of the 'location' node attribute for host 'myhost':\n\n"
                              "\tcrm_attribute --node myhost --name location --query\n\n"
                              "Change the value of the 'location' node attribute for host 'myhost':\n\n"
                              "\tcrm_attribute --node myhost --name location --update backoffice\n\n"
                              "Delete the 'location' node attribute for host 'myhost':\n\n"
                              "\tcrm_attribute --node myhost --name location --delete\n\n"
                              "Query the value of the 'cluster-delay' cluster option:\n\n"
                              "\tcrm_attribute --type crm_config --name cluster-delay --query\n\n"
                              "Query value of the 'cluster-delay' cluster option and print only the value:\n\n"
                              "\tcrm_attribute --type crm_config --name cluster-delay --query --quiet\n\n";

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, extra_prog_entries);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "selections", "Selecting attributes:",
                        "Show selecting options", selecting_entries);
    pcmk__add_arg_group(context, "command", "Commands:",
                        "Show command options", command_entries);
    pcmk__add_arg_group(context, "additional", "Additional options:",
                        "Show additional options", addl_entries);
    pcmk__add_arg_group(context, "deprecated", "Deprecated Options:",
                        "Show deprecated options", deprecated_entries);

    return context;
}

int
main(int argc, char **argv)
{
    cib_t *the_cib = NULL;
    int is_remote_node = 0;
    int attrd_opts = pcmk__node_attr_none;

    int rc = pcmk_rc_ok;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "NPUdilnpstv");
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_attribute", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pcmk__register_lib_messages(out);
    pcmk__register_messages(out, fmt_functions);

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    out->quiet = args->quiet;

    if (options.promotion_score && options.attr_name == NULL) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "-p/--promotion must be called from an OCF resource agent "
                    "or with a resource ID specified");
        goto done;
    }

    if (options.inhibit) {
        crm_warn("Inhibiting notifications for this update");
        cib__set_call_options(cib_opts, crm_system_name, cib_inhibit_notify);
    }

    the_cib = cib_new();
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to the CIB: %s", pcmk_rc_str(rc));
        goto done;
    }

    set_type();

    // Use default node if not given (except for cluster options and tickets)
    if (!pcmk__strcase_any_of(options.type, XML_CIB_TAG_CRMCONFIG, XML_CIB_TAG_TICKETS,
                              NULL)) {
        /* If we are being called from a resource agent via the cluster,
         * the correct local node name will be passed as an environment
         * variable. Otherwise, we have to ask the cluster.
         */
        const char *target = pcmk__node_attr_target(options.dest_uname);

        if (target != NULL) {
            g_free(options.dest_uname);
            options.dest_uname = g_strdup(target);
        } else if (getenv("CIB_file") != NULL && options.dest_uname == NULL) {
            get_node_name_from_local();
        }

        if (options.dest_uname == NULL) {
            char *node_name = NULL;

            rc = pcmk__query_node_name(out, 0, &node_name, 0);

            if (rc != pcmk_rc_ok) {
                exit_code = pcmk_rc2exitc(rc);
                free(node_name);
                goto done;
            }
            options.dest_uname = g_strdup(node_name);
            free(node_name);
        }

        rc = query_node_uuid(the_cib, options.dest_uname, &options.dest_node, &is_remote_node);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not map name=%s to a UUID", options.dest_uname);
            goto done;
        }
    }

    if (!delete_used_correctly()) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error: must specify attribute name or pattern to delete");
        goto done;
    }

    if (options.attr_pattern) {
        if (!pattern_used_correctly()) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error: pattern can only be used with query, or with "
                        "till-reboot update or delete");
            goto done;
        }

        g_free(options.attr_name);
        options.attr_name = options.attr_pattern;
    }

    if (is_remote_node) {
        attrd_opts = pcmk__node_attr_remote;
    }

    if (try_ipc_update() &&
        (send_attrd_update(options.command, options.dest_uname, options.attr_name,
                           options.attr_value, options.set_name, NULL, attrd_opts) == pcmk_rc_ok)) {
        crm_info("Update %s=%s sent via pacemaker-attrd",
                 options.attr_name, ((options.command == 'D')? "<none>" : options.attr_value));

    } else if (options.command == 'D') {
        rc = command_delete(out, the_cib);

    } else if (options.command == 'u') {
        rc = command_update(out, the_cib, is_remote_node);

    } else {
        rc = command_query(out, the_cib);
    }

    if (rc == ENOTUNIQ) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Please choose from one of the matches below and supply the 'id' with --attr-id");

    } else if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error performing operation: %s", pcmk_strerror(rc));
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    free(options.attr_default);
    g_free(options.attr_id);
    g_free(options.attr_name);
    free(options.attr_value);
    free(options.dest_node);
    g_free(options.dest_uname);
    g_free(options.set_name);
    free(options.set_type);
    g_free(options.type);

    cib__clean_up_connection(&the_cib);

    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    return crm_exit(exit_code);
}
