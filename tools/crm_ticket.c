/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/common/xml.h>
#include <crm/common/ipc.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>

#include <pacemaker-internal.h>

GError *error = NULL;

#define SUMMARY "Perform tasks related to cluster tickets\n\n" \
                "Allows ticket attributes to be queried, modified and deleted."

struct {
    gchar *attr_default;
    gchar *attr_id;
    char *attr_name;
    char *attr_value;
    gboolean force;
    char *get_attr_name;
    gboolean quiet;
    gchar *set_name;
    char ticket_cmd;
    gchar *ticket_id;
    gchar *xml_file;
} options = {
    .ticket_cmd = 'S'
};

GList *attr_delete;
GHashTable *attr_set;
bool modified = false;
int cib_options = cib_sync_call;
static pcmk__output_t *out = NULL;

#define INDENT "                               "

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static gboolean
attr_value_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.attr_value, optarg);

    if (!options.attr_name || !options.attr_value) {
        return TRUE;
    }

    pcmk__insert_dup(attr_set, options.attr_name, options.attr_value);
    g_clear_pointer(&options.attr_name, free);
    g_clear_pointer(&options.attr_value, free);

    modified = true;

    return TRUE;
}

static gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (pcmk__str_any_of(option_name, "--info", "-l", NULL)) {
        options.ticket_cmd = 'l';
    } else if (pcmk__str_any_of(option_name, "--details", "-L", NULL)) {
        options.ticket_cmd = 'L';
    } else if (pcmk__str_any_of(option_name, "--raw", "-w", NULL)) {
        options.ticket_cmd = 'w';
    } else if (pcmk__str_any_of(option_name, "--query-xml", "-q", NULL)) {
        options.ticket_cmd = 'q';
    } else if (pcmk__str_any_of(option_name, "--constraints", "-c", NULL)) {
        options.ticket_cmd = 'c';
    } else if (pcmk__str_any_of(option_name, "--cleanup", "-C", NULL)) {
        options.ticket_cmd = 'C';
    }

    return TRUE;
}

static gboolean
delete_attr_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    attr_delete = g_list_append(attr_delete, strdup(optarg));
    modified = true;
    return TRUE;
}

static gboolean
get_attr_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.get_attr_name, optarg);
    options.ticket_cmd = 'G';
    return TRUE;
}

static gboolean
grant_standby_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    if (pcmk__str_any_of(option_name, "--grant", "-g", NULL)) {
        pcmk__insert_dup(attr_set, PCMK__XA_GRANTED, PCMK_VALUE_TRUE);
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--revoke", "-r", NULL)) {
        pcmk__insert_dup(attr_set, PCMK__XA_GRANTED, PCMK_VALUE_FALSE);
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--standby", "-s", NULL)) {
        pcmk__insert_dup(attr_set, PCMK_XA_STANDBY, PCMK_VALUE_TRUE);
        modified = true;
    } else if (pcmk__str_any_of(option_name, "--activate", "-a", NULL)) {
        pcmk__insert_dup(attr_set, PCMK_XA_STANDBY, PCMK_VALUE_FALSE);
        modified = true;
    }

    return TRUE;
}

static gboolean
set_attr_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **err) {
    pcmk__str_update(&options.attr_name, optarg);

    if (!options.attr_name || !options.attr_value) {
        return TRUE;
    }

    pcmk__insert_dup(attr_set, options.attr_name, options.attr_value);
    g_clear_pointer(&options.attr_name, free);
    g_clear_pointer(&options.attr_value, free);

    modified = true;

    return TRUE;
}

static GOptionEntry query_entries[] = {
    { "info", 'l', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the information of ticket(s)",
      NULL },

    { "details", 'L', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the details of ticket(s)",
      NULL },

    { "raw", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the IDs of ticket(s)",
      NULL },

    { "query-xml", 'q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Query the XML of ticket(s)",
      NULL },

    { "constraints", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the " PCMK_XE_RSC_TICKET " constraints that apply to ticket(s)",
      NULL },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "grant", 'g', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Grant a ticket to this cluster site",
      NULL },

    { "revoke", 'r', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Revoke a ticket from this cluster site",
      NULL },

    { "standby", 's', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Tell this cluster site this ticket is standby",
      NULL },

    { "activate", 'a', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, grant_standby_cb,
      "Tell this cluster site this ticket is active",
      NULL },

    { NULL }
};

static GOptionEntry advanced_entries[] = {
    { "get-attr", 'G', 0, G_OPTION_ARG_CALLBACK, get_attr_cb,
      "Display the named attribute for a ticket",
      "ATTRIBUTE" },

    { "set-attr", 'S', 0, G_OPTION_ARG_CALLBACK, set_attr_cb,
      "Set the named attribute for a ticket",
      "ATTRIBUTE" },

    { "delete-attr", 'D', 0, G_OPTION_ARG_CALLBACK, delete_attr_cb,
      "Delete the named attribute for a ticket",
      "ATTRIBUTE" },

    { "cleanup", 'C', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Delete all state of a ticket at this cluster site",
      NULL },

    { NULL}
};

static GOptionEntry addl_entries[] = {
    { "attr-value", 'v', 0, G_OPTION_ARG_CALLBACK, attr_value_cb,
      "Attribute value to use with -S",
      "VALUE" },

    { "default", 'd', 0, G_OPTION_ARG_STRING, &options.attr_default,
      "(Advanced) Default attribute value to display if none is found\n"
      INDENT "(for use with -G)",
      "VALUE" },

    { "force", 'f', 0, G_OPTION_ARG_NONE, &options.force,
      "(Advanced) Force the action to be performed",
      NULL },

    { "ticket", 't', 0, G_OPTION_ARG_STRING, &options.ticket_id,
      "Ticket ID",
      "ID" },

    { "xml-file", 'x', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.xml_file,
      NULL,
      NULL },

    { NULL }
};

static GOptionEntry deprecated_entries[] = {
    { "set-name", 'n', 0, G_OPTION_ARG_STRING, &options.set_name,
      "(Advanced) ID of the " PCMK_XE_INSTANCE_ATTRIBUTES " object to change",
      "ID" },

    { "nvpair", 'i', 0, G_OPTION_ARG_STRING, &options.attr_id,
      "(Advanced) ID of the nvpair object to change/delete",
      "ID" },

    { "quiet", 'Q', 0, G_OPTION_ARG_NONE, &options.quiet,
      "Print only the value on stdout",
      NULL },

    { NULL }
};

static void
ticket_grant_warning(gchar *ticket_id)
{
    out->err(out, "This command cannot help you verify whether '%s' has "
                  "been already granted elsewhere.\n"
                  "If you really want to grant '%s' to this site now, and "
                  "you know what you are doing,\n"
                  "please specify --force.",
                  ticket_id, ticket_id);
}

static void
ticket_revoke_warning(gchar *ticket_id)
{
    out->err(out, "Revoking '%s' can trigger the specified '" PCMK_XA_LOSS_POLICY
              "'(s) relating to '%s'.\n\n"
              "You can check that with:\n"
              "crm_ticket --ticket %s --constraints\n\n"
              "Otherwise before revoking '%s', you may want to make '%s'"
              "standby with:\n"
              "crm_ticket --ticket %s --standby\n\n"
              "If you really want to revoke '%s' from this site now, and "
              "you know what you are doing,\n"
              "please specify --force.",
              ticket_id, ticket_id, ticket_id, ticket_id, ticket_id,
              ticket_id, ticket_id);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;

    const char *description = "Examples:\n\n"
                              "Display the info of tickets:\n\n"
                              "\tcrm_ticket --info\n\n"
                              "Display the detailed info of tickets:\n\n"
                              "\tcrm_ticket --details\n\n"
                              "Display the XML of 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --query-xml\n\n"
                              "Display the " PCMK_XE_RSC_TICKET " constraints that apply to 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --constraints\n\n"
                              "Grant 'ticketA' to this cluster site:\n\n"
                              "\tcrm_ticket --ticket ticketA --grant\n\n"
                              "Revoke 'ticketA' from this cluster site:\n\n"
                              "\tcrm_ticket --ticket ticketA --revoke\n\n"
                              "Make 'ticketA' standby (the cluster site will treat a granted\n"
                              "'ticketA' as 'standby', and the dependent resources will be\n"
                              "stopped or demoted gracefully without triggering loss-policies):\n\n"
                              "\tcrm_ticket --ticket ticketA --standby\n\n"
                              "Activate 'ticketA' from being standby:\n\n"
                              "\tcrm_ticket --ticket ticketA --activate\n\n"
                              "Get the value of the 'granted' attribute for 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --get-attr granted\n\n"
                              "Set the value of the 'standby' attribute for 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --set-attr standby --attr-value true\n\n"
                              "Delete the 'granted' attribute for 'ticketA':\n\n"
                              "\tcrm_ticket --ticket ticketA --delete-attr granted\n\n"
                              "Erase the operation history of 'ticketA' at this cluster site,\n"
                              "causing the cluster site to 'forget' the existing ticket state:\n\n"
                              "\tcrm_ticket --ticket ticketA --cleanup\n\n";

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "queries", "Queries:",
                        "Show queries", query_entries);
    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command options", command_entries);
    pcmk__add_arg_group(context, "advanced", "Advanced Options:",
                        "Show advanced options", advanced_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    pcmk__add_arg_group(context, "deprecated", "Deprecated Options:",
                        "Show deprecated options", deprecated_entries);

    return context;
}

int
main(int argc, char **argv)
{
    pcmk_scheduler_t *scheduler = NULL;
    xmlNode *cib_xml_copy = NULL;

    cib_t *cib_conn = NULL;
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = NULL;
    GOptionContext *context = NULL;
    gchar **processed_args = NULL;

    attr_set = pcmk__strkey_table(free, free);
    attr_delete = NULL;

    args = pcmk__new_common_args(SUMMARY);
    context = build_arg_context(args, &output_group);
    processed_args = pcmk__cmdline_preproc(argv, "dintvxCDGS");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_ticket", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    if (args->version) {
        out->version(out);
        goto done;
    }

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        rc = errno;
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not allocate scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }
    pcmk__set_scheduler_flags(scheduler, pcmk__sched_no_counts);

    rc = cib__create_signon(&cib_conn);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Could not connect to the CIB: %s",
                    pcmk_rc_str(rc));
        goto done;
    }

    if (options.xml_file != NULL) {
        cib_xml_copy = pcmk__xml_read(options.xml_file);

    } else {
        rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy,
                                   cib_sync_call);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Could not get local CIB: %s",
                        pcmk_rc_str(rc));
            goto done;
        }
    }

    rc = pcmk__update_configured_schema(&cib_xml_copy, false);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not update local CIB to latest schema version");
        goto done;
    }

    scheduler->input = cib_xml_copy;
    scheduler->priv->now = crm_time_new(NULL);

    cluster_status(scheduler);

    /* For recording the tickets that are referenced in PCMK_XE_RSC_TICKET
     * constraints but have never been granted yet.
     */
    pcmk__unpack_constraints(scheduler);

    if (options.ticket_cmd == 'l' || options.ticket_cmd == 'L' || options.ticket_cmd == 'w') {
        bool raw = false;
        bool details = false;

        if (options.ticket_cmd == 'L') {
            details = true;
        } else if (options.ticket_cmd == 'w') {
            raw = true;
        }

        rc = pcmk__ticket_info(out, scheduler, options.ticket_id, details, raw);
        exit_code = pcmk_rc2exitc(rc);

        if (rc == ENXIO) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "No such ticket '%s'", options.ticket_id);
        } else if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not get ticket info: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'q') {
        rc = pcmk__ticket_state(out, cib_conn, options.ticket_id);

        if (rc != pcmk_rc_ok && rc != pcmk_rc_duplicate_id) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not query ticket XML: %s", pcmk_rc_str(rc));
        } else {
            exit_code = CRM_EX_OK;
        }

    } else if (options.ticket_cmd == 'c') {
        rc = pcmk__ticket_constraints(out, cib_conn, options.ticket_id);
        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not show ticket constraints: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'G') {
        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_NOSUCH;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        rc = pcmk__ticket_get_attr(out, scheduler, options.ticket_id,
                                   options.get_attr_name, options.attr_default);
        exit_code = pcmk_rc2exitc(rc);

    } else if (options.ticket_cmd == 'C') {
        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        rc = pcmk__ticket_delete(out, cib_conn, scheduler, options.ticket_id,
                                 options.force);
        exit_code = pcmk_rc2exitc(rc);

        switch (rc) {
            case ENXIO:
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "No such ticket '%s'", options.ticket_id);
                break;

            case EACCES:
                ticket_revoke_warning(options.ticket_id);
                break;

            case pcmk_rc_ok:
            case pcmk_rc_duplicate_id:
                break;

            default:
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Could not clean up ticket: %s", pcmk_rc_str(rc));
                break;
        }

    } else if (modified) {
        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        if (options.attr_value
            && (pcmk__str_empty(options.attr_name))) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply attribute name with -S for -v %s", options.attr_value);
            goto done;
        }

        if (options.attr_name
            && (pcmk__str_empty(options.attr_value))) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply attribute value with -v for -S %s", options.attr_value);
            goto done;
        }

        if (attr_delete != NULL) {
            rc = pcmk__ticket_remove_attr(out, cib_conn, scheduler, options.ticket_id,
                                          attr_delete, options.force);

            if (rc == EACCES) {
                ticket_revoke_warning(options.ticket_id);
                exit_code = CRM_EX_UNSAFE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Ticket modification not allowed without --force");
                goto done;
            }
        } else {
            rc = pcmk__ticket_set_attr(out, cib_conn, scheduler, options.ticket_id,
                                       attr_set, options.force);

            if (rc == EACCES) {
                const char *value = NULL;

                value = g_hash_table_lookup(attr_set, PCMK__XA_GRANTED);
                if (pcmk__is_true(value)) {
                    ticket_grant_warning(options.ticket_id);
                } else {
                    ticket_revoke_warning(options.ticket_id);
                }

                exit_code = CRM_EX_UNSAFE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Ticket modification not allowed without --force");
                goto done;
            }
        }

        exit_code = pcmk_rc2exitc(rc);

        if (rc != pcmk_rc_ok && error == NULL) {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not modify ticket: %s", pcmk_rc_str(rc));
        }

    } else if (options.ticket_cmd == 'S') {
        /* Correct usage was handled in the "if (modified)" block above, so
         * this is just for reporting usage errors
         */

        if (pcmk__str_empty(options.attr_name)) {
            // We only get here if ticket_cmd was left as default
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Must supply a command");
            goto done;
        }

        if (options.ticket_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply ticket ID with -t");
            goto done;
        }

        if (pcmk__str_empty(options.attr_value)) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Must supply value with -v for -S %s", options.attr_name);
            goto done;
        }

    } else {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Unknown command: %c", options.ticket_cmd);
    }

 done:
    if (attr_set) {
        g_hash_table_destroy(attr_set);
    }
    attr_set = NULL;

    if (attr_delete) {
        g_list_free_full(attr_delete, free);
    }
    attr_delete = NULL;

    g_clear_pointer(&scheduler, pcmk_free_scheduler);

    cib__clean_up_connection(&cib_conn);

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    g_free(options.attr_default);
    g_free(options.attr_id);
    free(options.attr_name);
    free(options.attr_value);
    free(options.get_attr_name);
    g_free(options.set_name);
    g_free(options.ticket_id);
    g_free(options.xml_file);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}
