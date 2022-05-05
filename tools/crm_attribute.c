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

#include <pcmki/pcmki_output.h>

#define SUMMARY "crm_attribute - query and update Pacemaker cluster options and node attributes"

GError *error = NULL;
crm_exit_t exit_code = CRM_EX_OK;
uint64_t cib_opts = cib_sync_call;

PCMK__OUTPUT_ARGS("attribute", "char *", "char *", "char *", "char *")
static int
attribute_text(pcmk__output_t *out, va_list args)
{
    char *scope = va_arg(args, char *);
    char *instance = va_arg(args, char *);
    char *name = va_arg(args, char *);
    char *value = va_arg(args, char *);
    char *host G_GNUC_UNUSED = va_arg(args, char *);

    if (out->quiet) {
        pcmk__formatted_printf(out, "%s\n", value);
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
    options.command = 'v';
    pcmk__str_update(&options.attr_value, optarg);
    return TRUE;
}

static gboolean
utilization_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.type) {
        g_free(options.type);
    }

    options.type = g_strdup(XML_CIB_TAG_NODES);
    pcmk__str_update(&options.attr_value, XML_TAG_UTILIZATION);
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
controller_event_cb(pcmk_ipc_api_t *controld_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    pcmk_controld_api_reply_t *reply = event_data;

    if (event_type != pcmk_ipc_event_reply) {
        return;
    }

    if (status != CRM_EX_OK) {
        exit_code = status;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bad reply from controller: %s", crm_exit_str(exit_code));
        return;
    }

    if (reply->reply_type != pcmk_controld_reply_info) {
        exit_code = CRM_EX_PROTOCOL;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Unknown reply type %d from controller", reply->reply_type);
        return;
    }

    if (reply->data.node_info.uname == NULL) {
        exit_code = CRM_EX_NOHOST;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Node is not known to cluster");
    }

    exit_code = CRM_EX_OK;
    pcmk__str_update(&options.dest_uname, reply->data.node_info.uname);
}

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
get_node_name_from_controller(void)
{
    int rc = pcmk_rc_ok;
    pcmk_ipc_api_t *controld_api = NULL;

    rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
    if (controld_api == NULL) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not connect to controller: %s",
                    pcmk_rc_str(rc));
        return rc;
    }

    pcmk_register_ipc_callback(controld_api, controller_event_cb, NULL);

    rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_sync);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not connect to controller: %s",
                    pcmk_rc_str(rc));
        pcmk_free_ipc_api(controld_api);
        return rc;
    }

    rc = pcmk_controld_api_node_info(controld_api, 0);

    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not ping controller: %s",
                    pcmk_rc_str(rc));
    }

    /* This is a synchronous call, so we have already received and processed
     * the reply, which means controller_event_cb has been called.  If
     * exit_code was set, return some generic error here.  The caller can
     * then check for that and fail with exit_code.
     */
    if (exit_code != CRM_EX_OK) {
        rc = pcmk_rc_error;
    }

    pcmk_disconnect_ipc(controld_api);
    pcmk_free_ipc_api(controld_api);

    return rc;
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
        case 'v':
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
    bool try_attrd = true;
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

    // Use default CIB location if not given
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
            rc = get_node_name_from_controller();

            if (rc == pcmk_rc_error) {
                /* The callback failed with some error condition that is stored in
                 * exit_code.
                 */
                goto done;
            } else if (rc != pcmk_rc_ok) {
                /* get_node_name_from_controller failed in some other way.  Convert
                 * the return code to an exit code.
                 */
                exit_code = pcmk_rc2exitc(rc);
                goto done;
            }
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

    if ((options.command == 'D') && (options.attr_name == NULL) && (options.attr_pattern == NULL)) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error: must specify attribute name or pattern to delete");
        goto done;
    }

    if (options.attr_pattern) {
        if (options.command != 'G' &&
            (((options.command != 'v') && (options.command != 'D'))
             || !pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei))) {

            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error: pattern can only be used with query, or with "
                        "till-reboot update or delete");
            goto done;
        }

        g_free(options.attr_name);
        options.attr_name = options.attr_pattern;
    }

    // Only go through attribute manager for transient attributes
    try_attrd = pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei);

    // Don't try to contact attribute manager if we're using a file as CIB
    if (getenv("CIB_file") || getenv("CIB_shadow")) {
        try_attrd = false;
    }

    if (is_remote_node) {
        attrd_opts = pcmk__node_attr_remote;
    }
    if (((options.command == 'v') || (options.command == 'D') || (options.command == 'u'))
        && try_attrd
        && (send_attrd_update(options.command, options.dest_uname, options.attr_name,
                              options.attr_value, options.set_name, NULL, attrd_opts) == pcmk_rc_ok)) {
        crm_info("Update %s=%s sent via pacemaker-attrd",
                 options.attr_name, ((options.command == 'D')? "<none>" : options.attr_value));

    } else if (options.command == 'D') {
        rc = cib__delete_node_attr(out, the_cib, cib_opts, options.type, options.dest_node,
                                   options.set_type, options.set_name, options.attr_id,
                                   options.attr_name, options.attr_value, NULL);

        if (rc == ENXIO) {
            /* Nothing to delete...
             * which means it's not there...
             * which is what the admin wanted
             */
            rc = pcmk_rc_ok;
        }

    } else if (options.command == 'v') {
        CRM_LOG_ASSERT(options.type != NULL);
        CRM_LOG_ASSERT(options.attr_name != NULL);
        CRM_LOG_ASSERT(options.attr_value != NULL);

        rc = cib__update_node_attr(out, the_cib, cib_opts, options.type, options.dest_node,
                                   options.set_type, options.set_name, options.attr_id,
                                   options.attr_name, options.attr_value, NULL,
                                   is_remote_node ? "remote" : NULL);

    } else {                    /* query */

        xmlNode *result = NULL;
        bool use_pattern = options.attr_pattern != NULL;

        /* libxml2 doesn't support regular expressions in xpath queries (which is how
         * cib__get_node_attrs -> find_attr finds attributes).  So instead, we'll just
         * find all the attributes for a given node here by passing NULL for attr_id
         * and attr_name, and then later see if they match the given pattern.
         */
        if (use_pattern) {
            rc = cib__get_node_attrs(out, the_cib, options.type, options.dest_node,
                                     options.set_type, options.set_name, NULL,
                                     NULL, NULL, &result);
        } else {
            rc = cib__get_node_attrs(out, the_cib, options.type, options.dest_node,
                                     options.set_type, options.set_name, options.attr_id,
                                     options.attr_name, NULL, &result);
        }

        if (rc == ENXIO && options.attr_default) {
            out->message(out, "attribute", options.type, options.attr_id,
                         options.attr_name, options.attr_default);
            free_xml(result);
            rc = pcmk_rc_ok;

        } else if (rc != pcmk_rc_ok) {
            // Don't do anything and fall through to the error checking after this block.
            free_xml(result);

        } else if (xml_has_children(result)) {
            xmlNode *child = NULL;

            for (child = pcmk__xml_first_child(result); child != NULL;
                 child = pcmk__xml_next(child)) {
                const char *name = crm_element_value(child, XML_NVPAIR_ATTR_NAME);
                const char *value = crm_element_value(child, XML_NVPAIR_ATTR_VALUE);

                if (use_pattern && !pcmk__str_eq(name, options.attr_pattern, pcmk__str_regex)) {
                    continue;
                }

                out->message(out, "attribute", options.type, options.attr_id,
                             name, value);
                crm_info("Read %s=%s %s%s",
                         crm_str(name), crm_str(value),
                         options.set_name ? "in " : "", options.set_name ? options.set_name : "");
            }

            free_xml(result);

        } else {
            const char *name = crm_element_value(result, XML_NVPAIR_ATTR_NAME);
            const char *value = crm_element_value(result, XML_NVPAIR_ATTR_VALUE);

            if (!use_pattern || pcmk__str_eq(name, options.attr_pattern, pcmk__str_regex)) {
                out->message(out, "attribute", options.type, options.attr_id,
                             name, value);
                crm_info("Read %s=%s %s%s",
                         crm_str(name), crm_str(value),
                         options.set_name ? "in " : "", options.set_name ? options.set_name : "");
            }

            free_xml(result);
        }

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
