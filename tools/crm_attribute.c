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
#include <sys/utsname.h>

#define SUMMARY "crm_attribute - query and update Pacemaker cluster options and node attributes"

crm_exit_t exit_code = CRM_EX_OK;
uint64_t cib_opts = cib_sync_call;

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

gboolean BE_QUIET = FALSE;

#define INDENT "                              "

static gboolean
delete_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'D';

    if (options.attr_value) {
        free(options.attr_value);
    }

    options.attr_value = NULL;
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

    if (options.attr_value) {
        free(options.attr_value);
    }

    options.attr_value = strdup(optarg);
    return TRUE;
}

static gboolean
utilization_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.type) {
        g_free(options.type);
    }

    options.type = g_strdup(XML_CIB_TAG_NODES);

    if (options.set_type) {
        free(options.set_type);
    }

    options.set_type = strdup(XML_TAG_UTILIZATION);
    return TRUE;
}

static gboolean
value_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'G';

    if (options.attr_value) {
        free(options.attr_value);
    }

    options.attr_value = NULL;
    return TRUE;
}

static GOptionEntry selecting_entries[] = {
    { "id", 'i', 0, G_OPTION_ARG_STRING, &options.attr_id,
      "(Advanced) Operate on instance of specified attribute with this\n"
      INDENT "XML ID",
      "XML_ID"
    },

    { "name", 'n', 0, G_OPTION_ARG_STRING, &options.attr_name,
      "Operate on attribute or option with this name",
      "NAME"
    },

    { "pattern", 'P', 0, G_OPTION_ARG_STRING, &options.attr_pattern,
      "Operate on all attributes matching this pattern\n"
      INDENT "(with -v/-D and -l reboot)",
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
      "Query the current value of the attribute/option",
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

    context = pcmk__build_arg_context(args, NULL, group, NULL);
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

    int rc = pcmk_ok;
    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "NPUdilnpstv");
    GOptionContext *context = build_arg_context(args, &output_group);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_attribute", 0);

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When crm_attribute is converted to use formatted output, this can go. */
        pcmk__cli_help('v', CRM_EX_OK);
    }

    if (options.promotion_score && options.attr_name == NULL) {
        fprintf(stderr, "-p/--promotion must be called from an "
                        " OCF resource agent or with a resource ID "
                        " specified\n\n");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.inhibit) {
        crm_warn("Inhibiting notifications for this update");
        cib__set_call_options(cib_opts, crm_system_name, cib_inhibit_notify);
    }

    if (args->quiet) {
        BE_QUIET = TRUE;
    }

    the_cib = cib_new();
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);

    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not connect to the CIB: %s\n",
                pcmk_strerror(rc));
        exit_code = crm_errno2exit(rc);
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
        }

        if (options.dest_uname == NULL) {
            options.dest_uname = g_strdup(get_local_node_name());
        }

        rc = query_node_uuid(the_cib, options.dest_uname, &options.dest_node, &is_remote_node);
        if (pcmk_ok != rc) {
            fprintf(stderr, "Could not map name=%s to a UUID\n", options.dest_uname);
            exit_code = crm_errno2exit(rc);
            goto done;
        }
    }

    if ((options.command == 'D') && (options.attr_name == NULL) && (options.attr_pattern == NULL)) {
        fprintf(stderr, "Error: must specify attribute name or pattern to delete\n");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.attr_pattern) {
        if (((options.command != 'v') && (options.command != 'D'))
            || !pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei)) {

            fprintf(stderr, "Error: pattern can only be used with till-reboot update or delete\n");
            exit_code = CRM_EX_USAGE;
            goto done;
        }
        options.command = 'u';
        g_free(options.attr_name);
        options.attr_name = options.attr_pattern;
    }

    // Only go through attribute manager for transient attributes
    try_attrd = pcmk__str_eq(options.type, XML_CIB_TAG_STATUS, pcmk__str_casei);

    // Don't try to contact attribute manager if we're using a file as CIB
    if (getenv("CIB_file") || getenv("CIB_shadow")) {
        try_attrd = FALSE;
    }

    if (is_remote_node) {
        attrd_opts = pcmk__node_attr_remote;
    }
    if (((options.command == 'v') || (options.command == 'D') || (options.command == 'u')) && try_attrd
        && (pcmk__node_attr_request(NULL, options.command, options.dest_uname, options.attr_name,
                                    options.attr_value, options.type, options.set_name, NULL, NULL,
                                    attrd_opts) == pcmk_rc_ok)) {
        crm_info("Update %s=%s sent via pacemaker-attrd",
                 options.attr_name, ((options.command == 'D')? "<none>" : options.attr_value));

    } else if (options.command == 'D') {
        rc = delete_attr_delegate(the_cib, cib_opts, options.type, options.dest_node, options.set_type, options.set_name,
                                  options.attr_id, options.attr_name, options.attr_value, TRUE, NULL);

        if (rc == -ENXIO) {
            /* Nothing to delete...
             * which means it's not there...
             * which is what the admin wanted
             */
            rc = pcmk_ok;
        }

    } else if (options.command == 'v') {
        CRM_LOG_ASSERT(options.type != NULL);
        CRM_LOG_ASSERT(options.attr_name != NULL);
        CRM_LOG_ASSERT(options.attr_value != NULL);

        rc = update_attr_delegate(the_cib, cib_opts, options.type, options.dest_node, options.set_type, options.set_name,
                                  options.attr_id, options.attr_name, options.attr_value, TRUE, NULL, is_remote_node ? "remote" : NULL);

    } else {                    /* query */

        char *read_value = NULL;

        rc = read_attr_delegate(the_cib, options.type, options.dest_node, options.set_type, options.set_name,
                                options.attr_id, options.attr_name, &read_value, TRUE, NULL);

        if (rc == -ENXIO && options.attr_default) {
            read_value = strdup(options.attr_default);
            rc = pcmk_ok;
        }

        crm_info("Read %s=%s %s%s",
                 options.attr_name, crm_str(read_value), options.set_name ? "in " : "", options.set_name ? options.set_name : "");

        if (rc == -ENOTUNIQ) {
            // Multiple matches (already displayed) are not error for queries
            rc = pcmk_ok;

        } else if (BE_QUIET == FALSE) {
            fprintf(stdout, "%s%s %s%s %s%s value=%s\n",
                    options.type ? "scope=" : "", options.type ? options.type : "",
                    options.attr_id ? "id=" : "", options.attr_id ? options.attr_id : "",
                    options.attr_name ? "name=" : "", options.attr_name ? options.attr_name : "",
                    read_value ? read_value : "(null)");

        } else if (read_value != NULL) {
            fprintf(stdout, "%s\n", read_value);
        }
        free(read_value);
    }

    if (rc == -ENOTUNIQ) {
        printf("Please choose from one of the matches above and supply the 'id' with --attr-id\n");
        exit_code = crm_errno2exit(rc);

    } else if (rc != pcmk_ok) {
        fprintf(stderr, "Error performing operation: %s\n", pcmk_strerror(rc));
        exit_code = crm_errno2exit(rc);
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

    pcmk__output_and_clear_error(error, NULL);
    return crm_exit(exit_code);
}
