/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdbool.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/lrmd.h>

#define SUMMARY "cts-exec-helper - inject commands into the Pacemaker executor and watch for events"

static int exec_call_id = 0;
static gboolean start_test(gpointer user_data);
static void try_connect(void);

static char *key = NULL;
static char *val = NULL;

static struct {
    int verbose;
    int quiet;
    guint interval_ms;
    int timeout;
    int start_delay;
    int cancel_call_id;
    gboolean no_wait;
    gboolean is_running;
    gboolean no_connect;
    int exec_call_opts;
    const char *api_call;
    const char *rsc_id;
    const char *provider;
    const char *class;
    const char *type;
    const char *action;
    const char *listen;
    gboolean use_tls;
    lrmd_key_value_t *params;
} options;

static gboolean
interval_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    return pcmk_parse_interval_spec(optarg,
                                    &options.interval_ms) == pcmk_rc_ok;
}

static gboolean
notify_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "--notify-orig", "-n", NULL)) {
        options.exec_call_opts = lrmd_opt_notify_orig_only;
    } else if (pcmk__str_any_of(option_name, "--notify-changes", "-o", NULL)) {
        options.exec_call_opts = lrmd_opt_notify_changes_only;
    }

    return TRUE;
}

static gboolean
param_key_val_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "--param-key", "-k", NULL)) {
        pcmk__str_update(&key, optarg);
    } else if (pcmk__str_any_of(option_name, "--param-val", "-v", NULL)) {
        pcmk__str_update(&val, optarg);
    }

    if (key != NULL && val != NULL) {
        options.params = lrmd_key_value_add(options.params, key, val);
        g_clear_pointer(&key, free);
        g_clear_pointer(&val, free);
    }

    return TRUE;
}

static GOptionEntry basic_entries[] = {
    { "api-call", 'c', 0, G_OPTION_ARG_STRING, &options.api_call,
      "Directly relates to executor API functions",
      NULL },

    { "is-running", 'R', 0, G_OPTION_ARG_NONE, &options.is_running,
      "Determine if a resource is registered and running",
      NULL },

    { "listen", 'l', 0, G_OPTION_ARG_STRING, &options.listen,
      "Listen for a specific event string",
      NULL },

    { "no-wait", 'w', 0, G_OPTION_ARG_NONE, &options.no_wait,
      "Make api call and do not wait for result",
      NULL },

    { "notify-changes", 'o', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, notify_cb,
      "Only notify client changes to recurring operations",
      NULL },

    { "notify-orig", 'n', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, notify_cb,
      "Only notify this client of the results of an API action",
      NULL },

    { "tls", 'S', 0, G_OPTION_ARG_NONE, &options.use_tls,
      "Use TLS backend for local connection",
      NULL },

    { NULL }
};

static GOptionEntry api_call_entries[] = {
    { "action", 'a', 0, G_OPTION_ARG_STRING, &options.action,
      NULL, NULL },

    { "cancel-call-id", 'x', 0, G_OPTION_ARG_INT, &options.cancel_call_id,
      NULL, NULL },

    { "class", 'C', 0, G_OPTION_ARG_STRING, &options.class,
      NULL, NULL },

    { "interval", 'i', 0, G_OPTION_ARG_CALLBACK, interval_cb,
      NULL, NULL },

    { "param-key", 'k', 0, G_OPTION_ARG_CALLBACK, param_key_val_cb,
      NULL, NULL },

    { "param-val", 'v', 0, G_OPTION_ARG_CALLBACK, param_key_val_cb,
      NULL, NULL },

    { "provider", 'P', 0, G_OPTION_ARG_STRING, &options.provider,
      NULL, NULL },

    { "rsc-id", 'r', 0, G_OPTION_ARG_STRING, &options.rsc_id,
      NULL, NULL },

    { "start-delay", 's', 0, G_OPTION_ARG_INT, &options.start_delay,
      NULL, NULL },

    { "timeout", 't', 0, G_OPTION_ARG_INT, &options.timeout,
      NULL, NULL },

    { "type", 'T', 0, G_OPTION_ARG_STRING, &options.type,
      NULL, NULL },

    { NULL }
};

static GMainLoop *mainloop = NULL;
static lrmd_t *lrmd_conn = NULL;

static crm_exit_t
test_exit(crm_exit_t exit_code)
{
    lrmd_api_delete(lrmd_conn);
    return crm_exit(exit_code);
}

#define print_result(fmt, args...)  \
    if (!options.quiet) {           \
        printf(fmt "\n", ##args);   \
    }

static void
test_shutdown(int nsig)
{
    lrmd_api_delete(lrmd_conn);
    lrmd_conn = NULL;
}

static void
read_events(lrmd_event_data_t * event)
{
    char buf[1024] = { '\0', };

    pcmk__assert(snprintf(buf, sizeof(buf),
                          "NEW_EVENT event_type:%s rsc_id:%s action:%s rc:%s "
                          "op_status:%s",
                          lrmd_event_type2str(event->type), event->rsc_id,
                          pcmk__s(event->op_type, "none"),
                          crm_exit_str((crm_exit_t) event->rc),
                          pcmk_exec_status_str(event->op_status)) >= 0);
    pcmk__info("%s", buf);

    if (options.listen && pcmk__str_eq(options.listen, buf, pcmk__str_casei)) {
        print_result("LISTEN EVENT SUCCESSFUL");
        test_exit(CRM_EX_OK);
    }

    if (exec_call_id && (event->call_id == exec_call_id)) {
        if (event->op_status == 0 && event->rc == 0) {
            print_result("API-CALL SUCCESSFUL for 'exec'");
        } else {
            print_result("API-CALL FAILURE for 'exec', rc:%d lrmd_op_status:%s",
                         event->rc, pcmk_exec_status_str(event->op_status));
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
    print_result("LISTEN EVENT FAILURE - timeout occurred, never found");
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
        pcmk__info("Executor client connection established");
        start_test(NULL);
        return;
    } else {
        sleep(1);
        try_connect();
        pcmk__notice("Executor client connection failed");
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

    print_result("API CONNECTION FAILURE");
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
        pcmk__create_timer(options.timeout, timeout_err, NULL);
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
                                   options.start_delay,
                                   options.exec_call_opts,
                                   options.params);

        if (rc > 0) {
            exec_call_id = rc;
            print_result("API-CALL 'exec' action pending, waiting on response");
        }

    } else if (pcmk__str_eq(options.api_call, "register_rsc", pcmk__str_casei)) {
        rc = lrmd_conn->cmds->register_rsc(lrmd_conn,
                                           options.rsc_id,
                                           options.class, options.provider, options.type, 0);
    } else if (pcmk__str_eq(options.api_call, "get_rsc_info", pcmk__str_casei)) {
        lrmd_rsc_info_t *rsc_info;

        rsc_info = lrmd_conn->cmds->get_rsc_info(lrmd_conn, options.rsc_id, 0);

        if (rsc_info) {
            print_result("RSC_INFO: id:%s class:%s provider:%s type:%s",
                         rsc_info->id, rsc_info->standard,
                         (rsc_info->provider? rsc_info->provider : "<none>"),
                         rsc_info->type);
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
            print_result("%s", output);
            free(output);
        }
    } else if (pcmk__str_eq(options.api_call, "list_agents", pcmk__str_casei)) {
        lrmd_list_t *list = NULL;
        lrmd_list_t *iter = NULL;

        rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, options.class, options.provider);

        if (rc > 0) {
            print_result("%d agents found", rc);
            for (iter = list; iter != NULL; iter = iter->next) {
                print_result("%s", iter->val);
            }
            lrmd_list_freeall(list);
            rc = 0;
        } else {
            print_result("API_CALL FAILURE - no agents found");
            rc = -1;
        }
    } else if (pcmk__str_eq(options.api_call, "list_ocf_providers", pcmk__str_casei)) {
        lrmd_list_t *list = NULL;
        lrmd_list_t *iter = NULL;

        rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, options.type, &list);

        if (rc > 0) {
            print_result("%d providers found", rc);
            for (iter = list; iter != NULL; iter = iter->next) {
                print_result("%s", iter->val);
            }
            lrmd_list_freeall(list);
            rc = 0;
        } else {
            print_result("API_CALL FAILURE - no providers found");
            rc = -1;
        }

    } else if (pcmk__str_eq(options.api_call, "list_standards", pcmk__str_casei)) {
        lrmd_list_t *list = NULL;
        lrmd_list_t *iter = NULL;

        rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);

        if (rc > 0) {
            print_result("%d standards found", rc);
            for (iter = list; iter != NULL; iter = iter->next) {
                print_result("%s", iter->val);
            }
            lrmd_list_freeall(list);
            rc = 0;
        } else {
            print_result("API_CALL FAILURE - no providers found");
            rc = -1;
        }

    } else if (pcmk__str_eq(options.api_call, "get_recurring_ops", pcmk__str_casei)) {
        GList *op_list = NULL;
        GList *op_item = NULL;
        rc = lrmd_conn->cmds->get_recurring_ops(lrmd_conn, options.rsc_id, 0, 0,
                                                &op_list);

        for (op_item = op_list; op_item != NULL; op_item = op_item->next) {
            lrmd_op_info_t *op_info = op_item->data;

            print_result("RECURRING_OP: %s_%s_%s timeout=%sms",
                         op_info->rsc_id, op_info->action,
                         op_info->interval_ms_s, op_info->timeout_ms_s);
            lrmd_free_op_info(op_info);
        }
        g_list_free(op_list);

    } else if (options.api_call) {
        print_result("API-CALL FAILURE unknown action '%s'", options.action);
        test_exit(CRM_EX_ERROR);
    }

    if (rc < 0) {
        print_result("API-CALL FAILURE for '%s' api_rc:%d",
                     options.api_call, rc);
        test_exit(CRM_EX_ERROR);
    }

    if (options.api_call && rc == pcmk_ok) {
        print_result("API-CALL SUCCESSFUL for '%s'", options.api_call);
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

/*!
 * \internal
 * \brief Generate resource parameters from CIB if none explicitly given
 *
 * \return Standard Pacemaker return code
 */
static int
generate_params(void)
{
    int rc = pcmk_rc_ok;
    pcmk_scheduler_t *scheduler = NULL;
    xmlNode *cib_xml_copy = NULL;
    pcmk_resource_t *rsc = NULL;
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTableIter iter;
    char *key = NULL;
    char *value = NULL;

    if (options.params != NULL) {
        return pcmk_rc_ok; // User specified parameters explicitly
    }

    // Retrieve and update CIB
    rc = cib__signon_query(NULL, NULL, &cib_xml_copy);
    if (rc != pcmk_rc_ok) {
        return rc;
    }
    rc = pcmk__update_configured_schema(&cib_xml_copy, false);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    // Calculate cluster status
    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        pcmk__crit("Could not allocate scheduler data");
        return ENOMEM;
    }
    pcmk__set_scheduler_flags(scheduler, pcmk__sched_no_counts);
    scheduler->input = cib_xml_copy;
    scheduler->priv->now = crm_time_new(NULL);
    cluster_status(scheduler);

    // Find resource in CIB
    rsc = pe_find_resource_with_flags(scheduler->priv->resources,
                                      options.rsc_id,
                                      pcmk_rsc_match_history
                                      |pcmk_rsc_match_basename);
    if (rsc == NULL) {
        pcmk__err("Resource does not exist in config");
        pcmk_free_scheduler(scheduler);
        return EINVAL;
    }

    // Add resource instance parameters to options.params
    params = pe_rsc_params(rsc, NULL, scheduler);
    if (params != NULL) {
        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key,
                                      (gpointer *) &value)) {
            options.params = lrmd_key_value_add(options.params, key, value);
        }
    }

    // Add resource meta-attributes to options.params
    meta = pcmk__strkey_table(free, free);
    get_meta_attributes(meta, rsc, NULL, scheduler);
    g_hash_table_iter_init(&iter, meta);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key,
                                  (gpointer *) &value)) {
        char *crm_name = crm_meta_name(key);

        options.params = lrmd_key_value_add(options.params, crm_name, value);
        free(crm_name);
    }
    g_hash_table_destroy(meta);

    pcmk_free_scheduler(scheduler);
    return rc;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, NULL, group, NULL);

    pcmk__add_main_args(context, basic_entries);
    pcmk__add_arg_group(context, "api-call", "API Call Options:",
                        "Parameters for api-call option", api_call_entries);

    return context;
}

int
main(int argc, char **argv)
{
    GError *error = NULL;
    crm_exit_t exit_code = CRM_EX_OK;
    crm_trigger_t *trig = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    /* Typically we'd pass all the single character options that take an argument
     * as the second parameter here (and there's a bunch of those in this tool).
     * However, we control how this program is called so we can just not call it
     * in a way where the preprocessing ever matters.
     */
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, NULL);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    /* We have to use crm_log_init here to set up the logging because there's
     * different handling for daemons vs. command line programs, and
     * pcmk__cli_init_logging is set up to only handle the latter.
     */
    crm_log_init(NULL, LOG_INFO, TRUE, (args->verbosity? TRUE : FALSE), argc,
                 argv, FALSE);

    for (int i = 0; i < args->verbosity; i++) {
        crm_bump_log_level(argc, argv);
    }

    if (!options.listen && pcmk__strcase_any_of(options.api_call, "metadata", "list_agents",
                                                "list_standards", "list_ocf_providers", NULL)) {
        options.no_connect = TRUE;
    }

    if (options.is_running) {
        int rc = pcmk_rc_ok;

        if (options.rsc_id == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "--is-running requires --rsc-id");
            goto done;
        }

        options.interval_ms = 0;
        if (options.timeout == 0) {
            options.timeout = 30000;
        }

        rc = generate_params();
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Can not determine resource status: "
                        "unable to get parameters from CIB");
            goto done;
        }
        options.api_call = "exec";
        options.action = PCMK_ACTION_MONITOR;
        options.exec_call_opts = lrmd_opt_notify_orig_only;
    }

    if (!options.api_call && !options.listen) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Must specify at least one of --api-call, --listen, "
                    "or --is-running");
        goto done;
    }

    if (options.use_tls) {
        lrmd_conn = lrmd_remote_api_new(NULL, "localhost", 0);
    } else {
        lrmd_conn = lrmd_api_new();
    }
    trig = mainloop_add_trigger(G_PRIORITY_HIGH, start_test, NULL);
    mainloop_set_trigger(trig);
    mainloop_add_signal(SIGTERM, test_shutdown);

    pcmk__info("Starting");
    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    free(key);
    free(val);

    pcmk__output_and_clear_error(&error, NULL);
    return test_exit(exit_code);
}
