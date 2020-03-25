/*
 * Copyright 2009-2020 the Pacemaker project contributors
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
#include <crm/common/util.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

/* show_scores and show_utilization can't be added to this struct.  They
 * actually come from include/pcmki/pcmki_scheduler.h where they are
 * defined as extern.
 */
struct {
    gboolean all_actions;
    char *dot_file;
    char *graph_file;
    gchar *input_file;
    guint modified;
    GListPtr node_up;
    GListPtr node_down;
    GListPtr node_fail;
    GListPtr op_fail;
    GListPtr op_inject;
    gchar *output_file;
    gboolean print_pending;
    gboolean process;
    char *quorum;
    long long repeat;
    gboolean simulate;
    gboolean store;
    gchar *test_dir;
    GListPtr ticket_grant;
    GListPtr ticket_revoke;
    GListPtr ticket_standby;
    GListPtr ticket_activate;
    char *use_date;
    char *watchdog;
    char *xml_file;
} options = {
    .print_pending = TRUE,
    .repeat = 1
};

cib_t *global_cib = NULL;
bool action_numbers = FALSE;
gboolean quiet = FALSE;
char *temp_shadow = NULL;
extern gboolean bringing_nodes_online;

#define quiet_log(fmt, args...) do {		\
	if(quiet == FALSE) {			\
	    printf(fmt , ##args);		\
	}					\
    } while(0)

static void
get_date(pe_working_set_t *data_set, bool print_original, char *use_date)
{
    time_t original_date = 0;

    crm_element_value_epoch(data_set->input, "execution-date", &original_date);

    if (use_date) {
        data_set->now = crm_time_new(use_date);
        quiet_log(" + Setting effective cluster time: %s", use_date);
        crm_time_log(LOG_NOTICE, "Pretending 'now' is", data_set->now,
                     crm_time_log_date | crm_time_log_timeofday);


    } else if (original_date) {

        data_set->now = crm_time_new(NULL);
        crm_time_set_timet(data_set->now, &original_date);

        if (print_original) {
            char *when = crm_time_as_string(data_set->now,
                            crm_time_log_date|crm_time_log_timeofday);

            printf("Using the original execution date of: %s\n", when);
            free(when);
        }
    }
}

static void
print_cluster_status(pe_working_set_t * data_set, long options)
{
    char *online_nodes = NULL;
    char *online_remote_nodes = NULL;
    char *online_guest_nodes = NULL;
    char *offline_nodes = NULL;
    char *offline_remote_nodes = NULL;

    GListPtr gIter = NULL;

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;
        const char *node_mode = NULL;
        char *node_name = NULL;

        if (pe__is_guest_node(node)) {
            node_name = crm_strdup_printf("%s:%s", node->details->uname, node->details->remote_rsc->container->id);
        } else {
            node_name = crm_strdup_printf("%s", node->details->uname);
        }

        if (node->details->unclean) {
            if (node->details->online && node->details->unclean) {
                node_mode = "UNCLEAN (online)";

            } else if (node->details->pending) {
                node_mode = "UNCLEAN (pending)";

            } else {
                node_mode = "UNCLEAN (offline)";
            }

        } else if (node->details->pending) {
            node_mode = "pending";

        } else if (node->details->standby_onfail && node->details->online) {
            node_mode = "standby (on-fail)";

        } else if (node->details->standby) {
            if (node->details->online) {
                node_mode = "standby";
            } else {
                node_mode = "OFFLINE (standby)";
            }

        } else if (node->details->maintenance) {
            if (node->details->online) {
                node_mode = "maintenance";
            } else {
                node_mode = "OFFLINE (maintenance)";
            }

        } else if (node->details->online) {
            if (pe__is_guest_node(node)) {
                online_guest_nodes = pcmk__add_word(online_guest_nodes,
                                                    node_name);
            } else if (pe__is_remote_node(node)) {
                online_remote_nodes = pcmk__add_word(online_remote_nodes,
                                                     node_name);
            } else {
                online_nodes = pcmk__add_word(online_nodes, node_name);
            }
            free(node_name);
            continue;

        } else {
            if (pe__is_remote_node(node)) {
                offline_remote_nodes = pcmk__add_word(offline_remote_nodes,
                                                      node_name);
            } else if (pe__is_guest_node(node)) {
                /* ignore offline container nodes */
            } else {
                offline_nodes = pcmk__add_word(offline_nodes, node_name);
            }
            free(node_name);
            continue;
        }

        if (pe__is_guest_node(node)) {
            printf("GuestNode %s: %s\n", node_name, node_mode);
        } else if (pe__is_remote_node(node)) {
            printf("RemoteNode %s: %s\n", node_name, node_mode);
        } else if (safe_str_eq(node->details->uname, node->details->id)) {
            printf("Node %s: %s\n", node_name, node_mode);
        } else {
            printf("Node %s (%s): %s\n", node_name, node->details->id, node_mode);
        }

        free(node_name);
    }

    if (online_nodes) {
        printf("Online: [%s ]\n", online_nodes);
        free(online_nodes);
    }
    if (offline_nodes) {
        printf("OFFLINE: [%s ]\n", offline_nodes);
        free(offline_nodes);
    }
    if (online_remote_nodes) {
        printf("RemoteOnline: [%s ]\n", online_remote_nodes);
        free(online_remote_nodes);
    }
    if (offline_remote_nodes) {
        printf("RemoteOFFLINE: [%s ]\n", offline_remote_nodes);
        free(offline_remote_nodes);
    }
    if (online_guest_nodes) {
        printf("GuestOnline: [%s ]\n", online_guest_nodes);
        free(online_guest_nodes);
    }

    fprintf(stdout, "\n");
    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        if (is_set(rsc->flags, pe_rsc_orphan)
            && rsc->role == RSC_ROLE_STOPPED) {
            continue;
        }
        rsc->fns->print(rsc, NULL, pe_print_printf | options, stdout);
    }
    fprintf(stdout, "\n");
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
    } else if (is_not_set(action->flags, pe_action_pseudo)) {
        action_host = "<none>";
    }

    if (safe_str_eq(action->task, RSC_CANCEL)) {
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

        if (safe_str_eq(action->task, RSC_NOTIFY)
            || safe_str_eq(action->task, RSC_NOTIFIED)) {
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

    } else if (safe_str_eq(action->task, CRM_OP_FENCE)) {
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

static void
create_dotfile(pe_working_set_t * data_set, const char *dot_file, gboolean all_actions)
{
    GListPtr gIter = NULL;
    FILE *dot_strm = fopen(dot_file, "w");

    if (dot_strm == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for writing", dot_file);
        return;
    }

    fprintf(dot_strm, " digraph \"g\" {\n");
    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;
        const char *style = "dashed";
        const char *font = "black";
        const char *color = "black";
        char *action_name = create_action_name(action);

        crm_trace("Action %d: %s %s %p", action->id, action_name, action->uuid, action);

        if (is_set(action->flags, pe_action_pseudo)) {
            font = "orange";
        }

        if (is_set(action->flags, pe_action_dumped)) {
            style = "bold";
            color = "green";

        } else if (action->rsc != NULL && is_not_set(action->rsc->flags, pe_rsc_managed)) {
            color = "red";
            font = "purple";
            if (all_actions == FALSE) {
                goto do_not_write;
            }

        } else if (is_set(action->flags, pe_action_optional)) {
            color = "blue";
            if (all_actions == FALSE) {
                goto do_not_write;
            }

        } else {
            color = "red";
            CRM_CHECK(is_set(action->flags, pe_action_runnable) == FALSE,;
                );
        }

        set_bit(action->flags, pe_action_dumped);
        crm_trace("\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]",
                action_name, style, color, font);
        fprintf(dot_strm, "\"%s\" [ style=%s color=\"%s\" fontcolor=\"%s\"]\n",
                action_name, style, color, font);
  do_not_write:
        free(action_name);
    }

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        GListPtr gIter2 = NULL;

        for (gIter2 = action->actions_before; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_action_wrapper_t *before = (pe_action_wrapper_t *) gIter2->data;

            char *before_name = NULL;
            char *after_name = NULL;
            const char *style = "dashed";
            gboolean optional = TRUE;

            if (before->state == pe_link_dumped) {
                optional = FALSE;
                style = "bold";
            } else if (is_set(action->flags, pe_action_pseudo)
                       && (before->type & pe_order_stonith_stop)) {
                continue;
            } else if (before->type == pe_order_none) {
                continue;
            } else if (is_set(before->action->flags, pe_action_dumped)
                       && is_set(action->flags, pe_action_dumped)
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
}

static void
setup_input(const char *input, const char *output)
{
    int rc = pcmk_ok;
    cib_t *cib_conn = NULL;
    xmlNode *cib_object = NULL;
    char *local_output = NULL;

    if (input == NULL) {
        /* Use live CIB */
        cib_conn = cib_new();
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);

        if (rc == pcmk_ok) {
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_object, cib_scope_local | cib_sync_call);
        }

        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
        cib_conn = NULL;

        if (rc != pcmk_ok) {
            fprintf(stderr, "Live CIB query failed: %s (%d)\n", pcmk_strerror(rc), rc);
            crm_exit(crm_errno2exit(rc));

        } else if (cib_object == NULL) {
            fprintf(stderr, "Live CIB query failed: empty result\n");
            crm_exit(CRM_EX_NOINPUT);
        }

    } else if (safe_str_eq(input, "-")) {
        cib_object = filename2xml(NULL);

    } else {
        cib_object = filename2xml(input);
    }

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        crm_exit(CRM_EX_CONFIG);
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        crm_exit(CRM_EX_CONFIG);
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
        fprintf(stderr, "Could not create '%s': %s\n",
                output, pcmk_strerror(rc));
        crm_exit(CRM_EX_CANTCREAT);
    }
    setenv("CIB_file", output, 1);
    free(local_output);
}


static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "quiet", no_argument, NULL, 'Q',
        "\tDisplay only essential output", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nOperations:", pcmk__option_default
    },
    {
        "run", no_argument, NULL, 'R',
        "\tDetermine cluster's response to the given configuration and status",
        pcmk__option_default
    },
    {
        "simulate", no_argument, NULL, 'S',
        "Simulate transition's execution and display resulting cluster status",
        pcmk__option_default
    },
    {
        "in-place", no_argument, NULL, 'X',
        "Simulate transition's execution and store result back to input file",
        pcmk__option_default
    },
    {
        "show-scores", no_argument, NULL, 's',
        "Show allocation scores", pcmk__option_default
    },
    {
        "show-utilization", no_argument, NULL, 'U',
        "Show utilization information", pcmk__option_default
    },
    {
        "profile", required_argument, NULL, 'P',
        "Run all tests in the named directory to create profiling data",
        pcmk__option_default
    },
    {
        "repeat", required_argument, NULL, 'N',
        "With --profile, repeat each test N times and print timings",
        pcmk__option_default
    },
    {
        "pending", no_argument, NULL, 'j',
        "\tDisplay pending state if 'record-pending' is enabled",
        pcmk__option_hidden
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nSynthetic Cluster Events:", pcmk__option_default
    },
    {
        "node-up", required_argument, NULL, 'u',
        "\tBring a node online", pcmk__option_default
    },
    {
        "node-down", required_argument, NULL, 'd',
        "\tTake a node offline", pcmk__option_default
    },
    {
        "node-fail", required_argument, NULL, 'f',
        "\tMark a node as failed", pcmk__option_default
    },
    {
        "op-inject", required_argument, NULL, 'i',
        "\tGenerate a failure for the cluster to react to in the simulation",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\tValue is of the form "
            "${resource}_${task}_${interval_in_ms}@${node}=${rc}.",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\t(for example, memcached_monitor_20000@bart.example.com=7)",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\tFor more information on OCF return codes, refer to: "
            "https://clusterlabs.org/pacemaker/doc/en-US/Pacemaker/"
            "2.0/html/Pacemaker_Administration/s-ocf-return-codes.html",
        pcmk__option_default
    },
    {
        "op-fail", required_argument, NULL, 'F',
        "\tIf the specified task occurs during the simulation, have it fail "
            "with return code ${rc}",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\tValue is of the form "
            "${resource}_${task}_${interval_in_ms}@${node}=${rc}.",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\t(for example, memcached_stop_0@bart.example.com=1)\n",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\t\tThe transition will normally stop at the failed action. Save "
            "the result with --save-output and re-run with --xml-file",
        pcmk__option_default
    },
    {   "set-datetime", required_argument, NULL, 't',
        "Set date/time (ISO 8601 format, see "
            "https://en.wikipedia.org/wiki/ISO_8601)",
        pcmk__option_default
    },
    {
        "quorum", required_argument, NULL, 'q',
        "\tSpecify a value for quorum", pcmk__option_default
    },
    {
        "watchdog", required_argument, NULL, 'w',
        "\tAssume a watchdog device is active", pcmk__option_default
    },
    {
        "ticket-grant", required_argument, NULL, 'g',
        "Grant a ticket", pcmk__option_default
    },
    {
        "ticket-revoke", required_argument, NULL, 'r',
        "Revoke a ticket", pcmk__option_default
    },
    {
        "ticket-standby", required_argument, NULL, 'b',
        "Make a ticket standby", pcmk__option_default
    },
    {
        "ticket-activate", required_argument, NULL, 'e',
        "Activate a ticket", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nOutput Options:", pcmk__option_default
    },
    {
        "save-input", required_argument, NULL, 'I',
        "\tSave the input configuration to the named file", pcmk__option_default
    },
    {
        "save-output", required_argument, NULL, 'O',
        "Save the output configuration to the named file", pcmk__option_default
    },
    {
        "save-graph", required_argument, NULL, 'G',
        "\tSave the transition graph (XML format) to the named file",
        pcmk__option_default
    },
    {
        "save-dotfile", required_argument, NULL, 'D',
        "Save the transition graph (DOT format) to the named file",
        pcmk__option_default
    },
    {
        "all-actions", no_argument, NULL, 'a',
        "\tDisplay all possible actions in DOT graph (even if not part "
            "of transition)",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nData Source:", pcmk__option_default
    },
    {
        "live-check", no_argument, NULL, 'L',
        "\tConnect to CIB mamager and use the current CIB contents as input",
        pcmk__option_default
    },
    {
        "xml-file", required_argument, NULL, 'x',
        "\tRetrieve XML from the named file", pcmk__option_default
    },
    {
        "xml-pipe", no_argument, NULL, 'p',
        "\tRetrieve XML from stdin", pcmk__option_default
    },

    {
        "-spacer-", no_argument, NULL, '-',
        "\nExamples:\n", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Pretend a recurring monitor action found memcached stopped on node "
            "fred.example.com and, during recovery, that the memcached stop "
            "action failed",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_simulate -LS --op-inject "
            "memcached:0_monitor_20000@bart.example.com=7 "
            "--op-fail memcached:0_stop_0@fred.example.com=1 "
            "--save-output /tmp/memcached-test.xml",
        pcmk__option_example
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Now see what the reaction to the stop failure would be",
        pcmk__option_paragraph
    },
    {
        "-spacer-", no_argument, NULL, '-',
        " crm_simulate -S --xml-file /tmp/memcached-test.xml",
        pcmk__option_example
    },
    { 0, 0, 0, 0 }
};

static void
profile_one(const char *xml_file, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    xmlNode *cib_object = NULL;
    clock_t start = 0;

    printf("* Testing %s ...", xml_file);
    fflush(stdout);

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
    printf(" %.2f secs\n", (clock() - start) / (float) CLOCKS_PER_SEC);
}

#ifndef FILENAME_MAX
#  define FILENAME_MAX 512
#endif

static void
profile_all(const char *dir, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    struct dirent **namelist;

    int file_num = scandir(dir, &namelist, 0, alphasort);

    if (file_num > 0) {
        struct stat prop;
        char buffer[FILENAME_MAX];

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
    }
}

int
main(int argc, char **argv)
{
    int rc = pcmk_ok;

    gboolean have_stdout = FALSE;

    pe_working_set_t *data_set = NULL;

    const char *repeat_s = NULL;

    int flag = 0;
    int index = 0;
    int argerr = 0;

    xmlNode *input = NULL;

    options.xml_file = strdup("-");

    crm_log_cli_init("crm_simulate");
    pcmk__set_cli_options(NULL, "<data source> <operation> [options]",
                          long_options,
                          "simulate a Pacemaker cluster's response to events");

    if (argc < 2) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                if (have_stdout == FALSE) {
                    /* Redirect stderr to stdout so we can grep the output */
                    have_stdout = TRUE;
                    close(STDERR_FILENO);
                    dup2(STDOUT_FILENO, STDERR_FILENO);
                }

                crm_bump_log_level(argc, argv);
                action_numbers = TRUE;
                break;
            case '?':
            case '$':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'p':
                if (options.xml_file) {
                    free(options.xml_file);
                }

                options.xml_file = strdup("-");
                break;
            case 'Q':
                quiet = TRUE;
                break;
            case 'L':
                if (options.xml_file) {
                    free(options.xml_file);
                }

                options.xml_file = NULL;
                break;
            case 'x':
                if (options.xml_file) {
                    free(options.xml_file);
                }

                options.xml_file = strdup(optarg);
                break;
            case 'u':
                options.modified++;
                bringing_nodes_online = TRUE;
                options.node_up = g_list_append(options.node_up, optarg);
                break;
            case 'd':
                options.modified++;
                options.node_down = g_list_append(options.node_down, optarg);
                break;
            case 'f':
                options.modified++;
                options.node_fail = g_list_append(options.node_fail, optarg);
                break;
            case 't':
                if (options.use_date) {
                    free(options.use_date);
                }

                options.use_date = strdup(optarg);
                break;
            case 'i':
                options.modified++;
                options.op_inject = g_list_append(options.op_inject, optarg);
                break;
            case 'F':
                options.process = TRUE;
                options.simulate = TRUE;
                options.op_fail = g_list_append(options.op_fail, optarg);
                break;
            case 'w':
                if (options.watchdog) {
                    free(options.watchdog);
                }

                options.modified++;
                options.watchdog = strdup(optarg);
                break;
            case 'q':
                if (options.quorum) {
                    free(options.quorum);
                }

                options.modified++;
                options.quorum = strdup(optarg);
                break;
            case 'g':
                options.modified++;
                options.ticket_grant = g_list_append(options.ticket_grant, optarg);
                break;
            case 'r':
                options.modified++;
                options.ticket_revoke = g_list_append(options.ticket_revoke, optarg);
                break;
            case 'b':
                options.modified++;
                options.ticket_standby = g_list_append(options.ticket_standby, optarg);
                break;
            case 'e':
                options.modified++;
                options.ticket_activate = g_list_append(options.ticket_activate, optarg);
                break;
            case 'a':
                options.all_actions = TRUE;
                break;
            case 's':
                options.process = TRUE;
                show_scores = TRUE;
                break;
            case 'U':
                options.process = TRUE;
                show_utilization = TRUE;
                break;
            case 'j':
                options.print_pending = TRUE;
                break;
            case 'S':
                options.process = TRUE;
                options.simulate = TRUE;
                break;
            case 'X':
                options.store = TRUE;
                options.process = TRUE;
                options.simulate = TRUE;
                break;
            case 'R':
                options.process = TRUE;
                break;
            case 'D':
                if (options.dot_file) {
                    free(options.dot_file);
                }

                options.process = TRUE;
                options.dot_file = strdup(optarg);
                break;
            case 'G':
                if (options.graph_file) {
                    free(options.graph_file);
                }

                options.process = TRUE;
                options.graph_file = strdup(optarg);
                break;
            case 'I':
                options.input_file = optarg;
                break;
            case 'O':
                options.output_file = optarg;
                break;
            case 'P':
                options.test_dir = optarg;
                break;
            case 'N':
                repeat_s = optarg;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        crm_perror(LOG_ERR, "Could not allocate working set");
        rc = -ENOMEM;
        goto done;
    }
    set_bit(data_set->flags, pe_flag_no_compat);

    if (options.test_dir != NULL) {
        if (repeat_s != NULL) {
            options.repeat = crm_parse_ll(repeat_s, NULL);
            if (errno || (options.repeat < 1)) {
                fprintf(stderr, "--repeat must be positive integer, not '%s' -- using 1",
                        repeat_s);
                options.repeat = 1;
            }
        }
        profile_all(options.test_dir, options.repeat, data_set, options.use_date);
        return CRM_EX_OK;
    }

    setup_input(options.xml_file, options.store ? options.xml_file : options.output_file);

    global_cib = cib_new();
    rc = global_cib->cmds->signon(global_cib, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not connect to the CIB: %s\n",
                pcmk_strerror(rc));
        goto done;
    }

    rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call | cib_scope_local);
    if (rc != pcmk_ok) {
        fprintf(stderr, "Could not get local CIB: %s\n", pcmk_strerror(rc));
        goto done;
    }

    data_set->input = input;
    get_date(data_set, true, options.use_date);
    if(options.xml_file) {
        set_bit(data_set->flags, pe_flag_sanitized);
    }
    set_bit(data_set->flags, pe_flag_stdout);
    cluster_status(data_set);

    if (quiet == FALSE) {
        int opts = options.print_pending ? pe_print_pending : 0;

        if (is_set(data_set->flags, pe_flag_maintenance_mode)) {
            quiet_log("\n              *** Resource management is DISABLED ***");
            quiet_log("\n  The cluster will not attempt to start, stop or recover services");
            quiet_log("\n");
        }

        if (data_set->disabled_resources || data_set->blocked_resources) {
            quiet_log("%d of %d resource instances DISABLED and %d BLOCKED "
                      "from further action due to failure\n",
                      data_set->disabled_resources, data_set->ninstances,
                      data_set->blocked_resources);
        }

        quiet_log("\nCurrent cluster status:\n");
        print_cluster_status(data_set, opts);
    }

    if (options.modified) {
        quiet_log("Performing requested modifications\n");
        modify_configuration(data_set, global_cib, options.quorum, options.watchdog, options.node_up,
                             options.node_down, options.node_fail, options.op_inject,
                             options.ticket_grant, options.ticket_revoke, options.ticket_standby,
                             options.ticket_activate);

        rc = global_cib->cmds->query(global_cib, NULL, &input, cib_sync_call);
        if (rc != pcmk_ok) {
            fprintf(stderr, "Could not get modified CIB: %s\n", pcmk_strerror(rc));
            goto done;
        }

        cleanup_calculations(data_set);
        data_set->input = input;
        get_date(data_set, true, options.use_date);

        if(options.xml_file) {
            set_bit(data_set->flags, pe_flag_sanitized);
        }
        set_bit(data_set->flags, pe_flag_stdout);
        cluster_status(data_set);
    }

    if (options.input_file != NULL) {
        rc = write_xml_file(input, options.input_file, FALSE);
        if (rc < 0) {
            fprintf(stderr, "Could not create '%s': %s\n",
                    options.input_file, pcmk_strerror(rc));
            goto done;
        }
    }

    if (options.process || options.simulate) {
        crm_time_t *local_date = NULL;

        if (show_scores && show_utilization) {
            printf("Allocation scores and utilization information:\n");
        } else if (show_scores) {
            fprintf(stdout, "Allocation scores:\n");
        } else if (show_utilization) {
            printf("Utilization information:\n");
        }

        pcmk__schedule_actions(data_set, input, local_date);
        input = NULL;           /* Don't try and free it twice */

        if (options.graph_file != NULL) {
            write_xml_file(data_set->graph, options.graph_file, FALSE);
        }

        if (options.dot_file != NULL) {
            create_dotfile(data_set, options.dot_file, options.all_actions);
        }

        if (quiet == FALSE) {
            GListPtr gIter = NULL;

            quiet_log("%sTransition Summary:\n", show_scores || show_utilization
                      || options.modified ? "\n" : "");
            fflush(stdout);

            LogNodeActions(data_set, TRUE);
            for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
                pe_resource_t *rsc = (pe_resource_t *) gIter->data;

                LogActions(rsc, data_set, TRUE);
            }
        }
    }

    rc = pcmk_ok;

    if (options.simulate) {
        if (run_simulation(data_set, global_cib, options.op_fail, quiet) != pcmk_ok) {
            rc = pcmk_err_generic;
        }
        if(quiet == FALSE) {
            get_date(data_set, true, options.use_date);

            quiet_log("\nRevised cluster status:\n");
            set_bit(data_set->flags, pe_flag_stdout);
            cluster_status(data_set);
            print_cluster_status(data_set, 0);
        }
    }

  done:
    pe_free_working_set(data_set);
    global_cib->cmds->signoff(global_cib);
    cib_delete(global_cib);

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

    fflush(stderr);

    if (temp_shadow) {
        unlink(temp_shadow);
        free(temp_shadow);
    }
    crm_exit(crm_errno2exit(rc));
}
