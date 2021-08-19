/*
 * Copyright 2009-2021 the Pacemaker project contributors
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
#include <time.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <dirent.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>

#define SUMMARY "crm_simulate - simulate a Pacemaker cluster's response to events"

struct {
    char *dot_file;
    char *graph_file;
    gchar *input_file;
    guint modified;
    pcmk_injections_t *injections;
    unsigned int flags;
    gchar *output_file;
    long long repeat;
    gboolean store;
    gchar *test_dir;
    char *use_date;
    char *xml_file;
} options = {
    .flags = pcmk_sim_show_pending,
    .repeat = 1
};

unsigned int section_opts = 0;
cib_t *global_cib = NULL;
char *temp_shadow = NULL;
extern gboolean bringing_nodes_online;
crm_exit_t exit_code = CRM_EX_OK;

#define INDENT "                                   "

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static gboolean
all_actions_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_all_actions;
    return TRUE;
}

static gboolean
attrs_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    section_opts |= pcmk_section_attributes;
    return TRUE;
}

static gboolean
failcounts_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    section_opts |= pcmk_section_failcounts | pcmk_section_failures;
    return TRUE;
}

static gboolean
in_place_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.store = TRUE;
    options.flags |= pcmk_sim_process | pcmk_sim_simulate;
    return TRUE;
}

static gboolean
live_check_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.xml_file) {
        free(options.xml_file);
    }

    options.xml_file = NULL;
    return TRUE;
}

static gboolean
node_down_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->node_down = g_list_append(options.injections->node_down, g_strdup(optarg));
    return TRUE;
}

static gboolean
node_fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->node_fail = g_list_append(options.injections->node_fail, g_strdup(optarg));
    return TRUE;
}

static gboolean
node_up_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    bringing_nodes_online = TRUE;
    options.injections->node_up = g_list_append(options.injections->node_up, g_strdup(optarg));
    return TRUE;
}

static gboolean
op_fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process | pcmk_sim_simulate;
    options.injections->op_fail = g_list_append(options.injections->op_fail, g_strdup(optarg));
    return TRUE;
}

static gboolean
op_inject_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->op_inject = g_list_append(options.injections->op_inject, g_strdup(optarg));
    return TRUE;
}

static gboolean
pending_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_show_pending;
    return TRUE;
}

static gboolean
process_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process;
    return TRUE;
}

static gboolean
quorum_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.injections->quorum) {
        free(options.injections->quorum);
    }

    options.modified++;
    options.injections->quorum = strdup(optarg);
    return TRUE;
}

static gboolean
save_dotfile_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.dot_file) {
        free(options.dot_file);
    }

    options.flags |= pcmk_sim_process;
    options.dot_file = strdup(optarg);
    return TRUE;
}

static gboolean
save_graph_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.graph_file) {
        free(options.graph_file);
    }

    options.flags |= pcmk_sim_process;
    options.graph_file = strdup(optarg);
    return TRUE;
}

static gboolean
show_scores_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process | pcmk_sim_show_scores;
    return TRUE;
}

static gboolean
simulate_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process | pcmk_sim_simulate;
    return TRUE;
}

static gboolean
ticket_activate_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->ticket_activate = g_list_append(options.injections->ticket_activate, g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_grant_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->ticket_grant = g_list_append(options.injections->ticket_grant, g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_revoke_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->ticket_revoke = g_list_append(options.injections->ticket_revoke, g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_standby_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.injections->ticket_standby = g_list_append(options.injections->ticket_standby, g_strdup(optarg));
    return TRUE;
}

static gboolean
utilization_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process | pcmk_sim_show_utilization;
    return TRUE;
}

static gboolean
watchdog_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.injections->watchdog) {
        free(options.injections->watchdog);
    }

    options.modified++;
    options.injections->watchdog = strdup(optarg);
    return TRUE;
}

static gboolean
xml_file_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.xml_file) {
        free(options.xml_file);
    }

    options.xml_file = strdup(optarg);
    return TRUE;
}

static gboolean
xml_pipe_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.xml_file) {
        free(options.xml_file);
    }

    options.xml_file = strdup("-");
    return TRUE;
}

static GOptionEntry operation_entries[] = {
    { "run", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, process_cb,
      "Process the supplied input and show what actions the cluster will take in response",
      NULL },
    { "simulate", 'S', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, simulate_cb,
      "Like --run, but also simulate taking those actions and show the resulting new status",
      NULL },
    { "in-place", 'X', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, in_place_cb,
      "Like --simulate, but also store the results back to the input file",
      NULL },
    { "show-attrs", 'A', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, attrs_cb,
      "Show node attributes",
      NULL },
    { "show-failcounts", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, failcounts_cb,
      "Show resource fail counts",
      NULL },
    { "show-scores", 's', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, show_scores_cb,
      "Show allocation scores",
      NULL },
    { "show-utilization", 'U', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, utilization_cb,
      "Show utilization information",
      NULL },
    { "profile", 'P', 0, G_OPTION_ARG_FILENAME, &options.test_dir,
      "Process all the XML files in the named directory to create profiling data",
      "DIR" },
    { "repeat", 'N', 0, G_OPTION_ARG_INT, &options.repeat,
      "With --profile, repeat each test N times and print timings",
      "N" },
    /* Deprecated */
    { "pending", 'j', G_OPTION_FLAG_NO_ARG|G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, pending_cb,
      "Display pending state if 'record-pending' is enabled",
      NULL },

    { NULL }
};

static GOptionEntry synthetic_entries[] = {
    { "node-up", 'u', 0, G_OPTION_ARG_CALLBACK, node_up_cb,
      "Simulate bringing a node online",
      "NODE" },
    { "node-down", 'd', 0, G_OPTION_ARG_CALLBACK, node_down_cb,
      "Simulate taking a node offline",
      "NODE" },
    { "node-fail", 'f', 0, G_OPTION_ARG_CALLBACK, node_fail_cb,
      "Simulate a node failing",
      "NODE" },
    { "op-inject", 'i', 0, G_OPTION_ARG_CALLBACK, op_inject_cb,
      "Generate a failure for the cluster to react to in the simulation.\n"
      INDENT "See `Operation Specification` help for more information.",
      "OPSPEC" },
    { "op-fail", 'F', 0, G_OPTION_ARG_CALLBACK, op_fail_cb,
      "If the specified task occurs during the simulation, have it fail with return code ${rc}.\n"
      INDENT "The transition will normally stop at the failed action.\n"
      INDENT "Save the result with --save-output and re-run with --xml-file.\n"
      INDENT "See `Operation Specification` help for more information.",
      "OPSPEC" },
    { "set-datetime", 't', 0, G_OPTION_ARG_STRING, &options.use_date,
      "Set date/time (ISO 8601 format, see https://en.wikipedia.org/wiki/ISO_8601)",
      "DATETIME" },
    { "quorum", 'q', 0, G_OPTION_ARG_CALLBACK, quorum_cb,
      "Set to '1' (or 'true') to indicate cluster has quorum",
      "QUORUM" },
    { "watchdog", 'w', 0, G_OPTION_ARG_CALLBACK, watchdog_cb,
      "Set to '1' (or 'true') to indicate cluster has an active watchdog device",
      "DEVICE" },
    { "ticket-grant", 'g', 0, G_OPTION_ARG_CALLBACK, ticket_grant_cb,
      "Simulate granting a ticket",
      "TICKET" },
    { "ticket-revoke", 'r', 0, G_OPTION_ARG_CALLBACK, ticket_revoke_cb,
      "Simulate revoking a ticket",
      "TICKET" },
    { "ticket-standby", 'b', 0, G_OPTION_ARG_CALLBACK, ticket_standby_cb,
      "Simulate making a ticket standby",
      "TICKET" },
    { "ticket-activate", 'e', 0, G_OPTION_ARG_CALLBACK, ticket_activate_cb,
      "Simulate activating a ticket",
      "TICKET" },

    { NULL }
};

static GOptionEntry artifact_entries[] = {
    { "save-input", 'I', 0, G_OPTION_ARG_FILENAME, &options.input_file,
      "Save the input configuration to the named file",
      "FILE" },
    { "save-output", 'O', 0, G_OPTION_ARG_FILENAME, &options.output_file,
      "Save the output configuration to the named file",
      "FILE" },
    { "save-graph", 'G', 0, G_OPTION_ARG_CALLBACK, save_graph_cb,
      "Save the transition graph (XML format) to the named file",
      "FILE" },
    { "save-dotfile", 'D', 0, G_OPTION_ARG_CALLBACK, save_dotfile_cb,
      "Save the transition graph (DOT format) to the named file",
      "FILE" },
    { "all-actions", 'a', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, all_actions_cb,
      "Display all possible actions in DOT graph (even if not part of transition)",
      NULL },

    { NULL }
};

static GOptionEntry source_entries[] = {
    { "live-check", 'L', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, live_check_cb,
      "Connect to CIB manager and use the current CIB contents as input",
      NULL },
    { "xml-file", 'x', 0, G_OPTION_ARG_CALLBACK, xml_file_cb,
      "Retrieve XML from the named file",
      "FILE" },
    { "xml-pipe", 'p', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, xml_pipe_cb,
      "Retrieve XML from stdin",
      NULL },

    { NULL }
};

static void
print_cluster_status(pe_working_set_t * data_set, unsigned int show_opts,
                     unsigned int section_opts, const char *title, bool print_spacer)
{
    pcmk__output_t *out = data_set->priv;
    GList *all = NULL;

    section_opts |= pcmk_section_nodes | pcmk_section_resources;

    all = g_list_prepend(all, (gpointer) "*");

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "%s", title);
    out->message(out, "cluster-status", data_set, 0, NULL, FALSE,
                 section_opts, show_opts | pcmk_show_inactive_rscs,
                 NULL, all, all);
    out->end_list(out);

    g_list_free(all);
}

static void
print_transition_summary(pe_working_set_t *data_set, bool print_spacer)
{
    pcmk__output_t *out = data_set->priv;

    PCMK__OUTPUT_SPACER_IF(out, print_spacer);
    out->begin_list(out, NULL, NULL, "Transition Summary");
    LogNodeActions(data_set);
    g_list_foreach(data_set->resources, (GFunc) LogActions, data_set);
    out->end_list(out);
}

static int
setup_input(const char *input, const char *output, GError **error)
{
    int rc = pcmk_rc_ok;
    xmlNode *cib_object = NULL;
    char *local_output = NULL;

    if (input == NULL) {
        /* Use live CIB */
        rc = cib__signon_query(NULL, &cib_object);
        if (rc != pcmk_rc_ok) {
            g_set_error(error, PCMK__RC_ERROR, rc,
                        "CIB query failed: %s", pcmk_rc_str(rc));
            return rc;
        }

    } else if (pcmk__str_eq(input, "-", pcmk__str_casei)) {
        cib_object = filename2xml(NULL);

    } else {
        cib_object = filename2xml(input);
    }

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        return pcmk_rc_transform_failed;
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        return pcmk_rc_schema_validation;
    }

    if (output == NULL) {
        char *pid = pcmk__getpid_s();

        local_output = get_shadow_file(pid);
        temp_shadow = strdup(local_output);
        output = local_output;
        free(pid);
    }

    rc = write_xml_file(cib_object, output, FALSE);
    free_xml(cib_object);
    cib_object = NULL;

    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_CANTCREAT,
                    "Could not create '%s': %s", output, pcmk_rc_str(rc));
        return rc;
    } else {
        setenv("CIB_file", output, 1);
        free(local_output);
        return pcmk_rc_ok;
    }
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'Q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Display only essential output",
          NULL },

        { NULL }
    };

    const char *description = "Operation Specification:\n\n"
                              "The OPSPEC in any command line option is of the form\n"
                              "${resource}_${task}_${interval_in_ms}@${node}=${rc}\n"
                              "(memcached_monitor_20000@bart.example.com=7, for example).\n"
                              "${rc} is an OCF return code.  For more information on these\n"
                              "return codes, refer to https://clusterlabs.org/pacemaker/doc/2.1/Pacemaker_Administration/html/agents.html#ocf-return-codes\n\n"
                              "Examples:\n\n"
                              "Pretend a recurring monitor action found memcached stopped on node\n"
                              "fred.example.com and, during recovery, that the memcached stop\n"
                              "action failed:\n\n"
                              "\tcrm_simulate -LS --op-inject memcached:0_monitor_20000@bart.example.com=7 "
                              "--op-fail memcached:0_stop_0@fred.example.com=1 --save-output /tmp/memcached-test.xml\n\n"
                              "Now see what the reaction to the stop failed would be:\n\n"
                              "\tcrm_simulate -S --xml-file /tmp/memcached-test.xml\n\n";

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, extra_prog_entries);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "operations", "Operations:",
                        "Show operations options", operation_entries);
    pcmk__add_arg_group(context, "synthetic", "Synthetic Cluster Events:",
                        "Show synthetic cluster event options", synthetic_entries);
    pcmk__add_arg_group(context, "artifact", "Artifact Options:",
                        "Show artifact options", artifact_entries);
    pcmk__add_arg_group(context, "source", "Data Source:",
                        "Show data source options", source_entries);

    return context;
}

static void
reset(pe_working_set_t *data_set, xmlNodePtr input, pcmk__output_t *out)
{
    data_set->input = input;
    data_set->priv = out;
    pcmk__set_effective_date(data_set, true, options.use_date);
    if(options.xml_file) {
        pe__set_working_set_flags(data_set, pe_flag_sanitized);
    }
    if (pcmk_is_set(options.flags, pcmk_sim_show_scores)) {
        pe__set_working_set_flags(data_set, pe_flag_show_scores);
    }
    if (pcmk_is_set(options.flags, pcmk_sim_show_utilization)) {
        pe__set_working_set_flags(data_set, pe_flag_show_utilization);
    }
}

int
main(int argc, char **argv)
{
    int printed = pcmk_rc_no_output;
    int rc = pcmk_rc_ok;
    pe_working_set_t *data_set = NULL;
    pcmk__output_t *out = NULL;
    xmlNode *input = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "bdefgiqrtuwxDFGINOP");
    GOptionContext *context = build_arg_context(args, &output_group);

    options.injections = calloc(1, sizeof(pcmk_injections_t));
    if (options.injections == NULL) {
        rc = ENOMEM;
        goto done;
    }

    /* This must come before g_option_context_parse_strv. */
    options.xml_file = strdup("-");

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_simulate", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Error creating output format %s: %s\n",
                args->output_ty, pcmk_rc_str(rc));
        exit_code = CRM_EX_ERROR;
        goto done;
    }

    if (pcmk__str_eq(args->output_ty, "text", pcmk__str_null_matches) &&
        !pcmk_is_set(options.flags, pcmk_sim_show_scores) &&
        !pcmk_is_set(options.flags, pcmk_sim_show_utilization)) {
        pcmk__force_args(context, &error, "%s --text-fancy", g_get_prgname());
    } else if (pcmk__str_eq(args->output_ty, "xml", pcmk__str_none)) {
        pcmk__force_args(context, &error, "%s --xml-simple-list --xml-substitute", g_get_prgname());
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    out->quiet = args->quiet;

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (args->verbosity > 0) {
#ifdef PCMK__COMPAT_2_0
        /* Redirect stderr to stdout so we can grep the output */
        close(STDERR_FILENO);
        dup2(STDOUT_FILENO, STDERR_FILENO);
#endif
    }

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        rc = ENOMEM;
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not allocate working set");
        goto done;
    }

    if (pcmk_is_set(options.flags, pcmk_sim_show_scores)) {
        pe__set_working_set_flags(data_set, pe_flag_show_scores);
    }
    if (pcmk_is_set(options.flags, pcmk_sim_show_utilization)) {
        pe__set_working_set_flags(data_set, pe_flag_show_utilization);
    }
    pe__set_working_set_flags(data_set, pe_flag_no_compat);

    if (options.test_dir != NULL) {
        data_set->priv = out;
        pcmk__profile_dir(options.test_dir, options.repeat, data_set, options.use_date);
        rc = pcmk_rc_ok;
        goto done;
    }

    rc = setup_input(options.xml_file, options.store ? options.xml_file : options.output_file, &error);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = cib__signon_query(&global_cib, &input);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "CIB query failed: %s", pcmk_rc_str(rc));
        goto done;
    }

    reset(data_set, input, out);
    cluster_status(data_set);

    if (!out->is_quiet(out)) {
        if (pcmk_is_set(data_set->flags, pe_flag_maintenance_mode)) {
            printed = out->message(out, "maint-mode", data_set->flags);
        }

        if (data_set->disabled_resources || data_set->blocked_resources) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            printed = out->info(out, "%d of %d resource instances DISABLED and %d BLOCKED "
                                "from further action due to failure",
                                data_set->disabled_resources, data_set->ninstances,
                                data_set->blocked_resources);
        }

        /* Most formatted output headers use caps for each word, but this one
         * only has the first word capitalized for compatibility with pcs.
         */
        print_cluster_status(data_set, pcmk_is_set(options.flags, pcmk_sim_show_pending) ? pcmk_show_pending : 0,
                             section_opts, "Current cluster status", printed == pcmk_rc_ok);
        printed = pcmk_rc_ok;
    }

    if (options.modified) {
        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        modify_configuration(data_set, global_cib, options.injections);
        printed = pcmk_rc_ok;

        rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call);
        if (rc != pcmk_rc_ok) {
            rc = pcmk_legacy2rc(rc);
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not get modified CIB: %s", pcmk_rc_str(rc));
            goto done;
        }

        cleanup_calculations(data_set);
        reset(data_set, input, out);
        cluster_status(data_set);
    }

    if (options.input_file != NULL) {
        rc = write_xml_file(input, options.input_file, FALSE);
        if (rc < 0) {
            rc = pcmk_legacy2rc(rc);
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not create '%s': %s", options.input_file, pcmk_rc_str(rc));
            goto done;
        }
    }

    if (pcmk_any_flags_set(options.flags, pcmk_sim_process | pcmk_sim_simulate)) {
        crm_time_t *local_date = NULL;
        pcmk__output_t *logger_out = NULL;

        if (pcmk_all_flags_set(data_set->flags, pe_flag_show_scores|pe_flag_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Allocation Scores and Utilization Information");
            printed = pcmk_rc_ok;
        } else if (pcmk_is_set(data_set->flags, pe_flag_show_scores)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Allocation Scores");
            printed = pcmk_rc_ok;
        } else if (pcmk_is_set(data_set->flags, pe_flag_show_utilization)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Utilization Information");
            printed = pcmk_rc_ok;
        } else {
            logger_out = pcmk__new_logger();
            if (logger_out == NULL) {
                goto done;
            }

            data_set->priv = logger_out;
        }

        pcmk__schedule_actions(data_set, input, local_date);

        if (logger_out == NULL) {
            out->end_list(out);
        } else {
            logger_out->finish(logger_out, CRM_EX_OK, true, NULL);
            pcmk__output_free(logger_out);
            data_set->priv = out;
        }

        input = NULL;           /* Don't try and free it twice */

        if (options.graph_file != NULL) {
            write_xml_file(data_set->graph, options.graph_file, FALSE);
        }

        if (options.dot_file != NULL) {
            rc = pcmk__write_sim_dotfile(data_set, options.dot_file,
                                         pcmk_is_set(options.flags, pcmk_sim_all_actions),
                                         args->verbosity > 0);
            if (rc != pcmk_rc_ok) {
                g_set_error(&error, PCMK__RC_ERROR, rc,
                            "Could not open %s for writing: %s", options.dot_file,
                            pcmk_rc_str(rc));
                goto done;
            }
        }

        if (!out->is_quiet(out)) {
            print_transition_summary(data_set, printed == pcmk_rc_ok);
        }
    }

    rc = pcmk_rc_ok;

    if (pcmk_is_set(options.flags, pcmk_sim_simulate)) {
        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        if (run_simulation(data_set, global_cib, options.injections->op_fail) != pcmk_rc_ok) {
            rc = pcmk_rc_error;
        }

        if (!out->is_quiet(out)) {
            pcmk__set_effective_date(data_set, true, options.use_date);

            if (pcmk_is_set(options.flags, pcmk_sim_show_scores)) {
                pe__set_working_set_flags(data_set, pe_flag_show_scores);
            }
            if (pcmk_is_set(options.flags, pcmk_sim_show_utilization)) {
                pe__set_working_set_flags(data_set, pe_flag_show_utilization);
            }

            cluster_status(data_set);
            print_cluster_status(data_set, 0, section_opts, "Revised Cluster Status", true);
        }
    }

  done:
    pcmk__output_and_clear_error(error, NULL);

    /* There sure is a lot to free in options. */
    free(options.dot_file);
    free(options.graph_file);
    g_free(options.input_file);
    g_free(options.output_file);
    g_free(options.test_dir);
    free(options.use_date);
    free(options.xml_file);

    pcmk_free_injections(options.injections);
    pcmk__free_arg_context(context);
    g_strfreev(processed_args);

    if (data_set) {
        pe_free_working_set(data_set);
    }

    if (global_cib) {
        global_cib->cmds->signoff(global_cib);
        cib_delete(global_cib);
    }

    fflush(stderr);

    if (temp_shadow) {
        unlink(temp_shadow);
        free(temp_shadow);
    }

    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
    }

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    crm_exit(exit_code);
}
