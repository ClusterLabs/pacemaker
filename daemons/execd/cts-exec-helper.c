/*
 * Copyright 2012-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/lrmd.h>

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        NULL, pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\t\tPrint out logs and events to screen", pcmk__option_default
    },
    {
        "quiet", no_argument, NULL, 'Q',
        "\t\tSuppress all output to screen", pcmk__option_default
    },
    {
        "tls", no_argument, NULL, 'S',
        "\t\tUse TLS backend for local connection", pcmk__option_default
    },
    {
        "listen", required_argument, NULL, 'l',
        "\tListen for a specific event string", pcmk__option_default
    },
    {
        "api-call", required_argument, NULL, 'c',
        "\tDirectly relates to executor API functions", pcmk__option_default
    },
    {
        "no-wait", no_argument, NULL, 'w',
        "\tMake api call and do not wait for result", pcmk__option_default
    },
    {
        "is-running", no_argument, NULL, 'R',
        "\tDetermine if a resource is registered and running",
        pcmk__option_default
    },
    {
        "notify-orig", no_argument, NULL, 'n',
        "\tOnly notify this client the results of an API action",
        pcmk__option_default
    },
    {
        "notify-changes", no_argument, NULL, 'o',
        "\tOnly notify client changes to recurring operations",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nParameters for api-call option", pcmk__option_default
    },
    {
        "action", required_argument, NULL, 'a',
        NULL, pcmk__option_default
    },
    {
        "rsc-id", required_argument, NULL, 'r',
        NULL, pcmk__option_default
    },
    {
        "cancel-call-id", required_argument, NULL, 'x',
        NULL, pcmk__option_default
    },
    {
        "provider", required_argument, NULL, 'P',
        NULL, pcmk__option_default
    },
    {
        "class", required_argument, NULL, 'C',
        NULL, pcmk__option_default
    },
    {
        "type", required_argument, NULL, 'T',
        NULL, pcmk__option_default
    },
    {
        "interval", required_argument, NULL, 'i',
        NULL, pcmk__option_default
    },
    {
        "timeout", required_argument, NULL, 't',
        NULL, pcmk__option_default
    },
    {
        "start-delay", required_argument, NULL, 's',
        NULL, pcmk__option_default
    },
    {
        "param-key", required_argument, NULL, 'k',
        NULL, pcmk__option_default
    },
    {
        "param-val", required_argument, NULL, 'v',
        NULL, pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        NULL, pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

static int exec_call_id = 0;
static int exec_call_opts = 0;
static gboolean start_test(gpointer user_data);
static void try_connect(void);

static struct {
    int verbose;
    int quiet;
    guint interval_ms;
    int timeout;
    int start_delay;
    int cancel_call_id;
    int no_wait;
    int is_running;
    int no_connect;
    const char *api_call;
    const char *rsc_id;
    const char *provider;
    const char *class;
    const char *type;
    const char *action;
    const char *listen;
    lrmd_key_value_t *params;
} options;

static GMainLoop *mainloop = NULL;
static lrmd_t *lrmd_conn = NULL;

static char event_buf_v0[1024];

static void
test_exit(crm_exit_t exit_code)
{
    lrmd_api_delete(lrmd_conn);
    crm_exit(exit_code);
}

#define print_result(result) \
    if (!options.quiet) {    \
        result;              \
    }                        \

#define report_event(event)                                             \
    snprintf(event_buf_v0, sizeof(event_buf_v0), "NEW_EVENT event_type:%s rsc_id:%s action:%s rc:%s op_status:%s", \
             lrmd_event_type2str(event->type),                          \
             event->rsc_id,                                             \
             event->op_type ? event->op_type : "none",                  \
             services_ocf_exitcode_str(event->rc),                      \
             pcmk_exec_status_str(event->op_status));                   \
    crm_info("%s", event_buf_v0);

static void
test_shutdown(int nsig)
{
    lrmd_api_delete(lrmd_conn);
    lrmd_conn = NULL;
}

static void
read_events(lrmd_event_data_t * event)
{
    report_event(event);
    if (options.listen) {
        if (pcmk__str_eq(options.listen, event_buf_v0, pcmk__str_casei)) {
            print_result(printf("LISTEN EVENT SUCCESSFUL\n"));
            test_exit(CRM_EX_OK);
        }
    }

    if (exec_call_id && (event->call_id == exec_call_id)) {
        if (event->op_status == 0 && event->rc == 0) {
            print_result(printf("API-CALL SUCCESSFUL for 'exec'\n"));
        } else {
            print_result(printf("API-CALL FAILURE for 'exec', rc:%d lrmd_op_status:%s\n",
                                event->rc,
                                pcmk_exec_status_str(event->op_status)));
            test_exit(CRM_EX_ERROR);
        }

        if (!options.listen) {
            test_exit(CRM_EX_OK);
        }
    }
}

static gboolean
timeout_err(gpointer data)
{
    print_result(printf("LISTEN EVENT FAILURE - timeout occurred, never found.\n"));
    test_exit(CRM_EX_TIMEOUT);
    return FALSE;
}

static void
connection_events(lrmd_event_data_t * event)
{
    int rc = event->connection_rc;

    if (event->type != lrmd_event_connect) {
        /* ignore */
        return;
    }

    if (!rc) {
        crm_info("Executor client connection established");
        start_test(NULL);
        return;
    } else {
        sleep(1);
        try_connect();
        crm_notice("Executor client connection failed");
    }
}

static void
try_connect(void)
{
    int tries = 10;
    static int num_tries = 0;
    int rc = 0;

    lrmd_conn->cmds->set_callback(lrmd_conn, connection_events);
    for (; num_tries < tries; num_tries++) {
        rc = lrmd_conn->cmds->connect_async(lrmd_conn, crm_system_name, 3000);

        if (!rc) {
            return;             /* we'll hear back in async callback */
        }
        sleep(1);
    }

    print_result(printf("API CONNECTION FAILURE\n"));
    test_exit(CRM_EX_ERROR);
}

static gboolean
start_test(gpointer user_data)
{
    int rc = 0;

    if (!options.no_connect) {
        if (!lrmd_conn->cmds->is_connected(lrmd_conn)) {
            try_connect();
            /* async connect -- this function will get called back into */
            return 0;
        }
    }
    lrmd_conn->cmds->set_callback(lrmd_conn, read_events);

    if (options.timeout) {
        g_timeout_add(options.timeout, timeout_err, NULL);
    }

    if (!options.api_call) {
        return 0;
    }

    if (pcmk__str_eq(options.api_call, "exec", pcmk__str_casei)) {
        rc = lrmd_conn->cmds->exec(lrmd_conn,
                                   options.rsc_id,
                                   options.action,
                                   NULL,
                                   options.interval_ms,
                                   options.timeout,
                                   options.start_delay, exec_call_opts, options.params);

        if (rc > 0) {
            exec_call_id = rc;
            print_result(printf("API-CALL 'exec' action pending, waiting on response\n"));
        }

    } else if (pcmk__str_eq(options.api_call, "register_rsc", pcmk__str_casei)) {
        rc = lrmd_conn->cmds->register_rsc(lrmd_conn,
                                           options.rsc_id,
                                           options.class, options.provider, options.type, 0);
    } else if (pcmk__str_eq(options.api_call, "get_rsc_info", pcmk__str_casei)) {
        lrmd_rsc_info_t *rsc_info;

        rsc_info = lrmd_conn->cmds->get_rsc_info(lrmd_conn, options.rsc_id, 0);

        if (rsc_info) {
            print_result(printf("RSC_INFO: id:%s class:%s provider:%s type:%s\n",
                                rsc_info->id, rsc_info->standard,
                                rsc_info->provider ? rsc_info->provider : "<none>",
                                rsc_info->type));
            lrmd_free_rsc_info(rsc_info);
            rc = pcmk_ok;
        } else {
            rc = -1;
        }
    } else if (pcmk__str_eq(options.api_call, "unregister_rsc", pcmk__str_casei)) {
        rc = lrmd_conn->cmds->unregister_rsc(lrmd_conn, options.rsc_id, 0);
    } else if (pcmk__str_eq(options.api_call, "cancel", pcmk__str_casei)) {
        rc = lrmd_conn->cmds->cancel(lrmd_conn, options.rsc_id, options.action,
                                     options.interval_ms);
    } else if (pcmk__str_eq(options.api_call, "metadata", pcmk__str_casei)) {
        char *output = NULL;

        rc = lrmd_conn->cmds->get_metadata(lrmd_conn,
                                           options.class,
                                           options.provider, options.type, &output, 0);
        if (rc == pcmk_ok) {
            print_result(printf("%s", output));
            free(output);
        }
    } else if (pcmk__str_eq(options.api_call, "list_agents", pcmk__str_casei)) {
        lrmd_list_t *list = NULL;
        lrmd_list_t *iter = NULL;

        rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, options.class, options.provider);

        if (rc > 0) {
            print_result(printf("%d agents found\n", rc));
            for (iter = list; iter != NULL; iter = iter->next) {
                print_result(printf("%s\n", iter->val));
            }
            lrmd_list_freeall(list);
            rc = 0;
        } else {
            print_result(printf("API_CALL FAILURE - no agents found\n"));
            rc = -1;
        }
    } else if (pcmk__str_eq(options.api_call, "list_ocf_providers", pcmk__str_casei)) {
        lrmd_list_t *list = NULL;
        lrmd_list_t *iter = NULL;

        rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, options.type, &list);

        if (rc > 0) {
            print_result(printf("%d providers found\n", rc));
            for (iter = list; iter != NULL; iter = iter->next) {
                print_result(printf("%s\n", iter->val));
            }
            lrmd_list_freeall(list);
            rc = 0;
        } else {
            print_result(printf("API_CALL FAILURE - no providers found\n"));
            rc = -1;
        }

    } else if (pcmk__str_eq(options.api_call, "list_standards", pcmk__str_casei)) {
        lrmd_list_t *list = NULL;
        lrmd_list_t *iter = NULL;

        rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);

        if (rc > 0) {
            print_result(printf("%d standards found\n", rc));
            for (iter = list; iter != NULL; iter = iter->next) {
                print_result(printf("%s\n", iter->val));
            }
            lrmd_list_freeall(list);
            rc = 0;
        } else {
            print_result(printf("API_CALL FAILURE - no providers found\n"));
            rc = -1;
        }

    } else if (pcmk__str_eq(options.api_call, "get_recurring_ops", pcmk__str_casei)) {
        GList *op_list = NULL;
        GList *op_item = NULL;
        rc = lrmd_conn->cmds->get_recurring_ops(lrmd_conn, options.rsc_id, 0, 0,
                                                &op_list);

        for (op_item = op_list; op_item != NULL; op_item = op_item->next) {
            lrmd_op_info_t *op_info = op_item->data;

            print_result(printf("RECURRING_OP: %s_%s_%s timeout=%sms\n",
                                op_info->rsc_id, op_info->action,
                                op_info->interval_ms_s, op_info->timeout_ms_s));
            lrmd_free_op_info(op_info);
        }
        g_list_free(op_list);

    } else if (options.api_call) {
        print_result(printf("API-CALL FAILURE unknown action '%s'\n", options.action));
        test_exit(CRM_EX_ERROR);
    }

    if (rc < 0) {
        print_result(printf("API-CALL FAILURE for '%s' api_rc:%d\n", options.api_call, rc));
        test_exit(CRM_EX_ERROR);
    }

    if (options.api_call && rc == pcmk_ok) {
        print_result(printf("API-CALL SUCCESSFUL for '%s'\n", options.api_call));
        if (!options.listen) {
            test_exit(CRM_EX_OK);
        }
    }

    if (options.no_wait) {
        /* just make the call and exit regardless of anything else. */
        test_exit(CRM_EX_OK);
    }

    return 0;
}

static int
generate_params(void)
{
    int rc = 0;
    pe_working_set_t *data_set = NULL;
    xmlNode *cib_xml_copy = NULL;
    pe_resource_t *rsc = NULL;
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTableIter iter;

    if (options.params) {
        return 0;
    }

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        crm_crit("Could not allocate working set");
        return -ENOMEM;
    }
    pe__set_working_set_flags(data_set, pe_flag_no_counts|pe_flag_no_compat);

    rc = cib__signon_query(NULL, &cib_xml_copy);

    if (rc != pcmk_rc_ok) {
        crm_err("CIB query failed: %s", pcmk_rc_str(rc));
        goto param_gen_bail;
    }

    if (cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
        crm_err("Error updating cib configuration");
        rc = -1;
        goto param_gen_bail;
    }

    data_set->input = cib_xml_copy;
    data_set->now = crm_time_new(NULL);

    cluster_status(data_set);
    if (options.rsc_id) {
        rsc = pe_find_resource_with_flags(data_set->resources, options.rsc_id,
                                          pe_find_renamed|pe_find_any);
    }

    if (!rsc) {
        crm_err("Resource does not exist in config");
        rc = -1;
        goto param_gen_bail;
    }

    params = pe_rsc_params(rsc, NULL, data_set);
    meta = pcmk__strkey_table(free, free);

    get_meta_attributes(meta, rsc, NULL, data_set);

    if (params != NULL) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            options.params = lrmd_key_value_add(options.params, key, value);
        }
    }

    if (meta) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, meta);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            char *crm_name = crm_meta_name(key);

            options.params = lrmd_key_value_add(options.params, crm_name, value);
            free(crm_name);
        }
        g_hash_table_destroy(meta);
    }

  param_gen_bail:
    pe_free_working_set(data_set);
    return rc;
}

int
main(int argc, char **argv)
{
    GError *error = NULL;
    crm_exit_t exit_code = CRM_EX_OK;

    int option_index = 0;
    int argerr = 0;
    int flag;
    char *key = NULL;
    char *val = NULL;
    gboolean use_tls = FALSE;
    crm_trigger_t *trig;

    pcmk__cli_init_logging("cts-exec-helper", 0);
    pcmk__set_cli_options(NULL, "<mode> [options]", long_options,
                          "inject commands into the Pacemaker executor, "
                          "and watch for events");

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'V':
                ++options.verbose;
                crm_bump_log_level(argc, argv);
                break;
            case 'Q':
                options.quiet = 1;
                options.verbose = 0;
                break;
            case 'l':
                options.listen = optarg;
                break;
            case 'w':
                options.no_wait = 1;
                break;
            case 'R':
                options.is_running = 1;
                break;
            case 'n':
                exec_call_opts = lrmd_opt_notify_orig_only;
                break;
            case 'o':
                exec_call_opts = lrmd_opt_notify_changes_only;
                break;
            case 'c':
                options.api_call = optarg;
                break;
            case 'a':
                options.action = optarg;
                break;
            case 'r':
                options.rsc_id = optarg;
                break;
            case 'x':
                if(optarg) {
                    options.cancel_call_id = atoi(optarg);
                }
                break;
            case 'P':
                options.provider = optarg;
                break;
            case 'C':
                options.class = optarg;
                break;
            case 'T':
                options.type = optarg;
                break;
            case 'i':
                if(optarg) {
                    options.interval_ms = crm_parse_interval_spec(optarg);
                }
                break;
            case 't':
                if(optarg) {
                    options.timeout = atoi(optarg);
                }
                break;
            case 's':
                if(optarg) {
                    options.start_delay = atoi(optarg);
                }
                break;
            case 'k':
                key = optarg;
                if (key && val) {
                    options.params = lrmd_key_value_add(options.params, key, val);
                    key = val = NULL;
                }
                break;
            case 'v':
                val = optarg;
                if (key && val) {
                    options.params = lrmd_key_value_add(options.params, key, val);
                    key = val = NULL;
                }
                break;
            case 'S':
                use_tls = TRUE;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }
    if (optind > argc) {
        ++argerr;
    }

    if (!options.listen && pcmk__strcase_any_of(options.api_call, "metadata", "list_agents",
                                                "list_standards", "list_ocf_providers", NULL)) {
        options.no_connect = 1;
    }

    crm_log_init(NULL, LOG_INFO, TRUE, (options.verbose? TRUE : FALSE),
                 argc, argv, FALSE);

    if (options.is_running) {
        if (!options.timeout) {
            options.timeout = 30000;
        }
        options.interval_ms = 0;
        if (!options.rsc_id) {
            exit_code = CRM_EX_ERROR;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "rsc-id must be given when is-running is used");
            goto done;
        }

        if (generate_params()) {
            exit_code = CRM_EX_ERROR;
            print_result(printf
                         ("Failed to retrieve rsc parameters from cib, can not determine if rsc is running.\n"));
            goto done;
        }
        options.api_call = "exec";
        options.action = "monitor";
        exec_call_opts = lrmd_opt_notify_orig_only;
    }

    /* if we can't perform an api_call or listen for events, 
     * there is nothing to do */
    if (!options.api_call && !options.listen) {
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Nothing to be done.  Please specify 'api-call' and/or 'listen'");
        goto done;
    }

    if (use_tls) {
        lrmd_conn = lrmd_remote_api_new(NULL, "localhost", 0);
    } else {
        lrmd_conn = lrmd_api_new();
    }
    trig = mainloop_add_trigger(G_PRIORITY_HIGH, start_test, NULL);
    mainloop_set_trigger(trig);
    mainloop_add_signal(SIGTERM, test_shutdown);

    crm_info("Starting");
    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);

done:
    pcmk__output_and_clear_error(error, NULL);
    test_exit(CRM_EX_OK);
}
