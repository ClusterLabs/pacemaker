/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdint.h>                         // uint32_t
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
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>

#define SUMMARY "crm_simulate - simulate a Pacemaker cluster's response to events"

struct {
    char *dot_file;
    char *graph_file;
    gchar *input_file;
    pcmk_injections_t *injections;
    uint32_t flags;
    gchar *output_file;
    gint repeat;
    gboolean store;
    gchar *test_dir;
    char *use_date;
    char *xml_file;
} options = {
    .flags = pcmk_sim_show_pending | pcmk_sim_sanitized,
    .repeat = 1
};

uint32_t section_opts = 0;
char *temp_shadow = NULL;
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
    options.flags &= ~pcmk_sim_sanitized;
    return TRUE;
}

static gboolean
node_down_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.injections->node_down = g_list_append(options.injections->node_down, g_strdup(optarg));
    return TRUE;
}

static gboolean
node_fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.injections->node_fail = g_list_append(options.injections->node_fail, g_strdup(optarg));
    return TRUE;
}

static gboolean
node_up_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    pcmk__simulate_node_config = true;
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
    pcmk__str_update(&options.injections->quorum, optarg);
    return TRUE;
}

static gboolean
save_dotfile_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process;
    pcmk__str_update(&options.dot_file, optarg);
    return TRUE;
}

static gboolean
save_graph_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.flags |= pcmk_sim_process;
    pcmk__str_update(&options.graph_file, optarg);
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
    options.injections->ticket_activate = g_list_append(options.injections->ticket_activate, g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_grant_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.injections->ticket_grant = g_list_append(options.injections->ticket_grant, g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_revoke_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.injections->ticket_revoke = g_list_append(options.injections->ticket_revoke, g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_standby_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
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
    pcmk__str_update(&options.injections->watchdog, optarg);
    return TRUE;
}

static gboolean
xml_file_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    pcmk__str_update(&options.xml_file, optarg);
    options.flags |= pcmk_sim_sanitized;
    return TRUE;
}

static gboolean
xml_pipe_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    pcmk__str_update(&options.xml_file, "-");
    options.flags |= pcmk_sim_sanitized;
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
      "Display pending state if '" PCMK_META_RECORD_PENDING "' is enabled",
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

static int
setup_input(pcmk__output_t *out, const char *input, const char *output,
            GError **error)
{
    int rc = pcmk_rc_ok;
    xmlNode *cib_object = NULL;
    char *local_output = NULL;

    if (input == NULL) {
        /* Use live CIB */
        rc = cib__signon_query(out, NULL, &cib_object);
        if (rc != pcmk_rc_ok) {
            // cib__signon_query() outputs any relevant error
            return rc;
        }

    } else if (pcmk__str_eq(input, "-", pcmk__str_casei)) {
        cib_object = pcmk__xml_read(NULL);

    } else {
        cib_object = pcmk__xml_read(input);
    }

    if (cib_object == NULL) {
        rc = pcmk_rc_bad_input;
        g_set_error(error, PCMK__EXITC_ERROR, pcmk_rc2exitc(rc),
                    "Could not read input XML: %s", pcmk_rc_str(rc));
        return rc;
    }

    if (pcmk_find_cib_element(cib_object, PCMK_XE_STATUS) == NULL) {
        pcmk__xe_create(cib_object, PCMK_XE_STATUS);
    }

    rc = pcmk__update_configured_schema(&cib_object, false);
    if (rc != pcmk_rc_ok) {
        pcmk__xml_free(cib_object);
        return rc;
    }

    if (!pcmk__validate_xml(cib_object, NULL, NULL, NULL)) {
        pcmk__xml_free(cib_object);
        return pcmk_rc_schema_validation;
    }

    if (output == NULL) {
        char *pid = pcmk__getpid_s();

        local_output = get_shadow_file(pid);
        temp_shadow = strdup(local_output);
        output = local_output;
        free(pid);
    }

    rc = pcmk__xml_write_file(cib_object, output, false);
    if (rc != pcmk_rc_ok) {
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_CANTCREAT,
                    "Could not create '%s': %s", output, pcmk_rc_str(rc));
    } else {
        setenv("CIB_file", output, 1);
    }

    pcmk__xml_free(cib_object);
    free(local_output);
    return rc;
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

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;

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

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Error creating output format %s: %s\n",
                args->output_ty, pcmk_rc_str(rc));
        exit_code = CRM_EX_ERROR;
        goto done;
    }

    if (pcmk__str_eq(args->output_ty, "text", pcmk__str_null_matches)
        && !(pcmk__is_set(options.flags, pcmk_sim_show_scores)
             && args->quiet)) {
        pcmk__output_text_set_fancy(out, true);
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    out->quiet = args->quiet;

    if (args->version) {
        out->version(out);
        goto done;
    }

    if (args->verbosity > 0) {
        options.flags |= pcmk_sim_verbose;
    }

    if (options.test_dir != NULL) {
        rc = pcmk__profile_dir(out, options.flags, options.test_dir,
                               (unsigned int) QB_MAX(options.repeat, 0),
                               options.use_date);
        goto done;
    }

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        rc = ENOMEM;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not allocate scheduler data");
        goto done;
    }

    rc = setup_input(out, options.xml_file,
                     options.store? options.xml_file : options.output_file,
                     &error);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__simulate(scheduler, out, options.injections, options.flags,
                        section_opts, options.use_date, options.input_file,
                        options.graph_file, options.dot_file);

  done:
    pcmk__output_and_clear_error(&error, NULL);

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

    pcmk_free_scheduler(scheduler);

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

    pcmk__unregister_formats();
    crm_exit(exit_code);
}
