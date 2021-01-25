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
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/output.h>
#include <crm/common/util.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#define SUMMARY "crm_simulate - simulate a Pacemaker cluster's response to events"

struct {
    gboolean all_actions;
    char *dot_file;
    char *graph_file;
    gchar *input_file;
    guint modified;
    GList *node_up;
    GList *node_down;
    GList *node_fail;
    GList *op_fail;
    GList *op_inject;
    gchar *output_file;
    gboolean print_pending;
    gboolean process;
    char *quorum;
    long long repeat;
    gboolean show_attrs;
    gboolean show_failcounts;
    gboolean show_scores;
    gboolean show_utilization;
    gboolean simulate;
    gboolean store;
    gchar *test_dir;
    GList *ticket_grant;
    GList *ticket_revoke;
    GList *ticket_standby;
    GList *ticket_activate;
    char *use_date;
    char *watchdog;
    char *xml_file;
} options = {
    .print_pending = TRUE,
    .repeat = 1
};

cib_t *global_cib = NULL;
bool action_numbers = FALSE;
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
in_place_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.store = TRUE;
    options.process = TRUE;
    options.simulate = TRUE;
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
    options.node_down = g_list_append(options.node_down, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
node_fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.node_fail = g_list_append(options.node_fail, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
node_up_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    bringing_nodes_online = TRUE;
    options.node_up = g_list_append(options.node_up, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
op_fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.process = TRUE;
    options.simulate = TRUE;
    options.op_fail = g_list_append(options.op_fail, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
op_inject_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.op_inject = g_list_append(options.op_inject, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
quorum_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.quorum) {
        free(options.quorum);
    }

    options.modified++;
    options.quorum = strdup(optarg);
    return TRUE;
}

static gboolean
save_dotfile_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.dot_file) {
        free(options.dot_file);
    }

    options.process = TRUE;
    options.dot_file = strdup(optarg);
    return TRUE;
}

static gboolean
save_graph_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.graph_file) {
        free(options.graph_file);
    }

    options.process = TRUE;
    options.graph_file = strdup(optarg);
    return TRUE;
}

static gboolean
show_scores_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.process = TRUE;
    options.show_scores = TRUE;
    return TRUE;
}

static gboolean
simulate_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.process = TRUE;
    options.simulate = TRUE;
    return TRUE;
}

static gboolean
ticket_activate_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.ticket_activate = g_list_append(options.ticket_activate, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_grant_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.ticket_grant = g_list_append(options.ticket_grant, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_revoke_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.ticket_revoke = g_list_append(options.ticket_revoke, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
ticket_standby_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.modified++;
    options.ticket_standby = g_list_append(options.ticket_standby, (gchar *) g_strdup(optarg));
    return TRUE;
}

static gboolean
utilization_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.process = TRUE;
    options.show_utilization = TRUE;
    return TRUE;
}

static gboolean
watchdog_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.watchdog) {
        free(options.watchdog);
    }

    options.modified++;
    options.watchdog = strdup(optarg);
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
    { "run", 'R', 0, G_OPTION_ARG_NONE, &options.process,
      "Process the supplied input and show what actions the cluster will take in response",
      NULL },
    { "simulate", 'S', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, simulate_cb,
      "Like --run, but also simulate taking those actions and show the resulting new status",
      NULL },
    { "in-place", 'X', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, in_place_cb,
      "Like --simulate, but also store the results back to the input file",
      NULL },
    { "show-attrs", 'A', 0, G_OPTION_ARG_NONE, &options.show_attrs,
      "Show node attributes",
      NULL },
    { "show-failcounts", 'c', 0, G_OPTION_ARG_NONE, &options.show_failcounts,
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
    { "pending", 'j', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.print_pending,
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
    { "all-actions", 'a', 0, G_OPTION_ARG_NONE, &options.all_actions,
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
get_date(pe_working_set_t *data_set, bool print_original, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    time_t original_date = 0;

    crm_element_value_epoch(data_set->input, "execution-date", &original_date);

    if (use_date) {
        data_set->now = crm_time_new(use_date);
        out->info(out, "Setting effective cluster time: %s", use_date);
        crm_time_log(LOG_NOTICE, "Pretending 'now' is", data_set->now,
                     crm_time_log_date | crm_time_log_timeofday);


    } else if (original_date) {

        data_set->now = crm_time_new(NULL);
        crm_time_set_timet(data_set->now, &original_date);

        if (print_original) {
            char *when = crm_time_as_string(data_set->now,
                            crm_time_log_date|crm_time_log_timeofday);

            out->info(out, "Using the original execution date of: %s", when);
            free(when);
        }
    }
}

static void
print_cluster_status(pe_working_set_t * data_set, unsigned int show_opts)
{
    pcmk__output_t *out = data_set->priv;
    int rc = pcmk_rc_no_output;
    GList *all = NULL;

    all = g_list_prepend(all, (gpointer) "*");

    rc = out->message(out, "node-list", data_set->nodes, all, all, show_opts, FALSE);
    rc = out->message(out, "resource-list", data_set, show_opts | pcmk_show_inactive_rscs,
                      FALSE, all, all, rc == pcmk_rc_ok);

    if (options.show_attrs) {
        rc = out->message(out, "node-attribute-list", data_set,
                          0, rc == pcmk_rc_ok, all, all);
    }

    if (options.show_failcounts) {
        rc = out->message(out, "node-summary", data_set, all, all,
                          0, show_opts, rc == pcmk_rc_ok);

        out->message(out, "failed-action-list", data_set, all, all,
                     0, rc == pcmk_rc_ok);
    }

    g_list_free(all);
}

static char *
create_action_name(pe_action_t *action)
{
    char *action_name = NULL;
    const char *prefix = "";
    const char *action_host = NULL;
    const char *clone_name = NULL;
    const char *task = action->task;

    if (action->node) {
        action_host = action->node->details->uname;
    } else if (!pcmk_is_set(action->flags, pe_action_pseudo)) {
        action_host = "<none>";
    }

    if (pcmk__str_eq(action->task, RSC_CANCEL, pcmk__str_casei)) {
        prefix = "Cancel ";
        task = action->cancel_task;
    }

    if (action->rsc && action->rsc->clone_name) {
        clone_name = action->rsc->clone_name;
    }

    if (clone_name) {
        char *key = NULL;
        guint interval_ms = 0;

        if (pcmk__guint_from_hash(action->meta,
                                  XML_LRM_ATTR_INTERVAL_MS, 0,
                                  &interval_ms) != pcmk_rc_ok) {
            interval_ms = 0;
        }

        if (pcmk__strcase_any_of(action->task, RSC_NOTIFY, RSC_NOTIFIED, NULL)) {
            const char *n_type = g_hash_table_lookup(action->meta, "notify_key_type");
            const char *n_task = g_hash_table_lookup(action->meta, "notify_key_operation");

            CRM_ASSERT(n_type != NULL);
            CRM_ASSERT(n_task != NULL);
            key = pcmk__notify_key(clone_name, n_type, n_task);

        } else {
            key = pcmk__op_key(clone_name, task, interval_ms);
        }

        if (action_host) {
            action_name = crm_strdup_printf("%s%s %s", prefix, key, action_host);
        } else {
            action_name = crm_strdup_printf("%s%s", prefix, key);
        }
        free(key);

    } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {
        const char *op = g_hash_table_lookup(action->meta, "stonith_action");

        action_name = crm_strdup_printf("%s%s '%s' %s", prefix, action->task, op, action_host);

    } else if (action->rsc && action_host) {
        action_name = crm_strdup_printf("%s%s %s", prefix, action->uuid, action_host);

    } else if (action_host) {
        action_name = crm_strdup_printf("%s%s %s", prefix, action->task, action_host);

    } else {
        action_name = crm_strdup_printf("%s", action->uuid);
    }

    if (action_numbers) { // i.e. verbose
        char *with_id = crm_strdup_printf("%s (%d)", action_name, action->id);

        free(action_name);
        action_name = with_id;
    }
    return action_name;
}

static bool
create_dotfile(pe_working_set_t * data_set, const char *dot_file, gboolean all_actions,
               GError **error)
{
    GList *gIter = NULL;
    FILE *dot_strm = fopen(dot_file, "w");

    if (dot_strm == NULL) {
        g_set_error(error, PCMK__RC_ERROR, errno,
                    "Could not open %s for writing: %s", dot_file,
                    pcmk_rc_str(errno));
        return false;
    }

    fprintf(dot_strm, " digraph \"g\" {\n");
    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;
        const char *style = "dashed";
        const char *font = "black";
        const char *color = "black";
        char *action_name = create_action_name(action);

        crm_trace("Action %d: %s %s %p", action->id, action_name, action->uuid, action);

        if (pcmk_is_set(action->flags, pe_action_pseudo)) {
            font = "orange";
        }

        if (pcmk_is_set(action->flags, pe_action_dumped)) {
            style = "bold";
            color = "green";

        } else if ((action->rsc != NULL)
                   && !pcmk_is_set(action->rsc->flags, pe_rsc_managed)) {
            color = "red";
            font = "purple";
            if (all_actions == FALSE) {
                goto do_not_write;
            }

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            color = "blue";
            if (all_actions == FALSE) {
                goto do_not_write;
            }

        } else {
            color = "red";
            CRM_CHECK(!pcmk_is_set(action->flags, pe_action_runnable), ;);
        }

        pe__set_action_flags(action, pe_action_dumped);
        crm_trace("\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]",
                action_name, style, color, font);
        fprintf(dot_strm, "\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]\n",
                action_name, style, color, font);
  do_not_write:
        free(action_name);
    }

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        GList *gIter2 = NULL;

        for (gIter2 = action->actions_before; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_action_wrapper_t *before = (pe_action_wrapper_t *) gIter2->data;

            char *before_name = NULL;
            char *after_name = NULL;
            const char *style = "dashed";
            gboolean optional = TRUE;

            if (before->state == pe_link_dumped) {
                optional = FALSE;
                style = "bold";
            } else if (pcmk_is_set(action->flags, pe_action_pseudo)
                       && (before->type & pe_order_stonith_stop)) {
                continue;
            } else if (before->type == pe_order_none) {
                continue;
            } else if (pcmk_is_set(before->action->flags, pe_action_dumped)
                       && pcmk_is_set(action->flags, pe_action_dumped)
                       && before->type != pe_order_load) {
                optional = FALSE;
            }

            if (all_actions || optional == FALSE) {
                before_name = create_action_name(before->action);
                after_name = create_action_name(action);
                crm_trace("\"%s\" -> \"%s\" [ style = %s]",
                        before_name, after_name, style);
                fprintf(dot_strm, "\"%s\" -> \"%s\" [ style = %s]\n",
                        before_name, after_name, style);
                free(before_name);
                free(after_name);
            }
        }
    }

    fprintf(dot_strm, "}\n");
    fflush(dot_strm);
    fclose(dot_strm);
    return true;
}

static int
setup_input(const char *input, const char *output, GError **error)
{
    int rc = pcmk_rc_ok;
    cib_t *cib_conn = NULL;
    xmlNode *cib_object = NULL;
    char *local_output = NULL;

    if (input == NULL) {
        /* Use live CIB */
        cib_conn = cib_new();
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
        rc = pcmk_legacy2rc(rc);

        if (rc == pcmk_rc_ok) {
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_scope_local | cib_sync_call);
        }

        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
        cib_conn = NULL;

        if (rc != pcmk_rc_ok) {
            rc = pcmk_legacy2rc(rc);
            g_set_error(error, PCMK__RC_ERROR, rc,
                        "Live CIB query failed: %s (%d)", pcmk_rc_str(rc), rc);
            return rc;

        } else if (cib_object == NULL) {
            g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_NOINPUT,
                        "Live CIB query failed: empty result");
            return pcmk_rc_no_input;
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

static void
profile_one(const char *xml_file, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    xmlNode *cib_object = NULL;
    clock_t start = 0;
    clock_t end;

    cib_object = filename2xml(xml_file);
    start = clock();

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }


    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        return;
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        return;
    }

    for (int i = 0; i < repeat; ++i) {
        xmlNode *input = (repeat == 1)? cib_object : copy_xml(cib_object);

        data_set->input = input;
        get_date(data_set, false, use_date);
        pcmk__schedule_actions(data_set, input, NULL);
        pe_reset_working_set(data_set);
    }

    end = clock();
    out->message(out, "profile", xml_file, start, end);
}

#ifndef FILENAME_MAX
#  define FILENAME_MAX 512
#endif

static void
profile_all(const char *dir, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    struct dirent **namelist;

    int file_num = scandir(dir, &namelist, 0, alphasort);

    if (file_num > 0) {
        struct stat prop;
        char buffer[FILENAME_MAX];

        out->begin_list(out, NULL, NULL, "Timings");

        while (file_num--) {
            if ('.' == namelist[file_num]->d_name[0]) {
                free(namelist[file_num]);
                continue;

            } else if (!pcmk__ends_with_ext(namelist[file_num]->d_name,
                                            ".xml")) {
                free(namelist[file_num]);
                continue;
            }
            snprintf(buffer, sizeof(buffer), "%s/%s", dir, namelist[file_num]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                profile_one(buffer, repeat, data_set, use_date);
            }
            free(namelist[file_num]);
        }
        free(namelist);

        out->end_list(out);
    }
}

PCMK__OUTPUT_ARGS("profile", "const char *", "clock_t", "clock_t")
static int
profile_default(pcmk__output_t *out, va_list args) {
    const char *xml_file = va_arg(args, const char *);
    clock_t start = va_arg(args, clock_t);
    clock_t end = va_arg(args, clock_t);

    out->list_item(out, NULL, "Testing %s ... %.2f secs", xml_file,
                   (end - start) / (float) CLOCKS_PER_SEC);

    return pcmk_rc_ok;
}

PCMK__OUTPUT_ARGS("profile", "const char *", "clock_t", "clock_t")
static int
profile_xml(pcmk__output_t *out, va_list args) {
    const char *xml_file = va_arg(args, const char *);
    clock_t start = va_arg(args, clock_t);
    clock_t end = va_arg(args, clock_t);

    char *duration = pcmk__ftoa((end - start) / (float) CLOCKS_PER_SEC);

    pcmk__output_create_xml_node(out, "timing",
                                 "file", xml_file,
                                 "duration", duration,
                                 NULL);

    free(duration);
    return pcmk_rc_ok;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "profile", "default", profile_default, },
    { "profile", "xml", profile_xml },

    { NULL }
};

static void
crm_simulate_register_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
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
        !options.show_scores && !options.show_utilization) {
        pcmk__force_args(context, &error, "%s --text-fancy", g_get_prgname());
    } else if (pcmk__str_eq(args->output_ty, "xml", pcmk__str_none)) {
        pcmk__force_args(context, &error, "%s --xml-simple-list --xml-substitute", g_get_prgname());
    }

    crm_simulate_register_messages(out);
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
        action_numbers = TRUE;
    }

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        rc = ENOMEM;
        g_set_error(&error, PCMK__RC_ERROR, rc, "Could not allocate working set");
        goto done;
    }

    if (options.show_scores) {
        pe__set_working_set_flags(data_set, pe_flag_show_scores);
    }
    if (options.show_utilization) {
        pe__set_working_set_flags(data_set, pe_flag_show_utilization);
    }
    pe__set_working_set_flags(data_set, pe_flag_no_compat);

    if (options.test_dir != NULL) {
        data_set->priv = out;
        profile_all(options.test_dir, options.repeat, data_set, options.use_date);
        rc = pcmk_rc_ok;
        goto done;
    }

    rc = setup_input(options.xml_file, options.store ? options.xml_file : options.output_file, &error);
    if (rc != pcmk_rc_ok) {
        goto done;
    }

    global_cib = cib_new();
    rc = global_cib->cmds->signon(global_cib, crm_system_name, cib_command);
    if (rc != pcmk_rc_ok) {
        rc = pcmk_legacy2rc(rc);
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to the CIB: %s", pcmk_rc_str(rc));
        goto done;
    }

    rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call | cib_scope_local);
    if (rc != pcmk_rc_ok) {
        rc = pcmk_legacy2rc(rc);
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not get local CIB: %s", pcmk_rc_str(rc));
        goto done;
    }

    data_set->input = input;
    data_set->priv = out;
    get_date(data_set, true, options.use_date);
    if(options.xml_file) {
        pe__set_working_set_flags(data_set, pe_flag_sanitized);
    }
    if (options.show_scores) {
        pe__set_working_set_flags(data_set, pe_flag_show_scores);
    }
    if (options.show_utilization) {
        pe__set_working_set_flags(data_set, pe_flag_show_utilization);
    }
    cluster_status(data_set);

    if (!out->is_quiet(out)) {
        unsigned int show_opts = options.print_pending ? pcmk_show_pending : 0;

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

        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        /* Most formatted output headers use caps for each word, but this one
         * only has the first word capitalized for compatibility with pcs.
         */
        out->begin_list(out, NULL, NULL, "Current cluster status");
        print_cluster_status(data_set, show_opts);
        out->end_list(out);
        printed = pcmk_rc_ok;
    }

    if (options.modified) {
        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        modify_configuration(data_set, global_cib, options.quorum, options.watchdog, options.node_up,
                             options.node_down, options.node_fail, options.op_inject,
                             options.ticket_grant, options.ticket_revoke, options.ticket_standby,
                             options.ticket_activate);
        printed = pcmk_rc_ok;

        rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call);
        if (rc != pcmk_rc_ok) {
            rc = pcmk_legacy2rc(rc);
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not get modified CIB: %s", pcmk_rc_str(rc));
            goto done;
        }

        cleanup_calculations(data_set);
        data_set->input = input;
        data_set->priv = out;
        get_date(data_set, true, options.use_date);

        if(options.xml_file) {
            pe__set_working_set_flags(data_set, pe_flag_sanitized);
        }
        if (options.show_scores) {
            pe__set_working_set_flags(data_set, pe_flag_show_scores);
        }
        if (options.show_utilization) {
            pe__set_working_set_flags(data_set, pe_flag_show_utilization);
        }
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

    if (options.process || options.simulate) {
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
            if (!create_dotfile(data_set, options.dot_file, options.all_actions, &error)) {
                goto done;
            }
        }

        if (!out->is_quiet(out)) {
            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Transition Summary");

            LogNodeActions(data_set);
            g_list_foreach(data_set->resources, (GFunc) LogActions, data_set);
            out->end_list(out);
            printed = pcmk_rc_ok;
        }
    }

    rc = pcmk_rc_ok;

    if (options.simulate) {
        PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
        if (run_simulation(data_set, global_cib, options.op_fail) != pcmk_rc_ok) {
            rc = pcmk_rc_error;
        }

        printed = pcmk_rc_ok;

        if (!out->is_quiet(out)) {
            get_date(data_set, true, options.use_date);

            PCMK__OUTPUT_SPACER_IF(out, printed == pcmk_rc_ok);
            out->begin_list(out, NULL, NULL, "Revised Cluster Status");

            if (options.show_scores) {
                pe__set_working_set_flags(data_set, pe_flag_show_scores);
            }
            if (options.show_utilization) {
                pe__set_working_set_flags(data_set, pe_flag_show_utilization);
            }

            cluster_status(data_set);
            print_cluster_status(data_set, 0);

            out->end_list(out);
        }
    }

  done:
    pcmk__output_and_clear_error(error, NULL);

    /* There sure is a lot to free in options. */
    free(options.dot_file);
    free(options.graph_file);
    g_free(options.input_file);
    g_list_free_full(options.node_up, g_free);
    g_list_free_full(options.node_down, g_free);
    g_list_free_full(options.node_fail, g_free);
    g_list_free_full(options.op_fail, g_free);
    g_list_free_full(options.op_inject, g_free);
    g_free(options.output_file);
    free(options.quorum);
    g_free(options.test_dir);
    g_list_free_full(options.ticket_grant, g_free);
    g_list_free_full(options.ticket_revoke, g_free);
    g_list_free_full(options.ticket_standby, g_free);
    g_list_free_full(options.ticket_activate, g_free);
    free(options.use_date);
    free(options.watchdog);
    free(options.xml_file);

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
