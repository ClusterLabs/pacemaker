/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
	{"help",             0, 0, '?'},
	{"verbose",          0, 0, 'V', "\t\tPrint out logs and events to screen"},
	{"quiet",            0, 0, 'Q', "\t\tSuppress all output to screen"},
	/* just incase we have to add data to events,
	 * we don't want break a billion regression tests. Instead
	 * we'll create different versions */
	{"listen",           1, 0, 'l', "\tListen for a specific event string"},
	{"event-ver",        1, 0, 'e', "\tVersion of event to listen to"},
	{"api-call",         1, 0, 'c', "\tDirectly relates to lrmd api functions"},
	{"no-wait",          0, 0, 'w', "\tMake api call and do not wait for result."},
	{"is-running",       0, 0, 'R', "\tDetermine if a resource is registered and running."},
	{"-spacer-",         1, 0, '-', "\nParameters for api-call option"},
	{"action",           1, 0, 'a'},
	{"rsc-id",           1, 0, 'r'},
	{"cancel-call-id",   1, 0, 'x'},
	{"provider",         1, 0, 'P'},
	{"class",            1, 0, 'C'},
	{"type",             1, 0, 'T'},
	{"interval",         1, 0, 'i'},
	{"timeout",          1, 0, 't'},
	{"start-delay",      1, 0, 's'},
	{"param-key",        1, 0, 'k'},
	{"param-val",        1, 0, 'v'},

	{"-spacer-",         1, 0, '-'},
	{0, 0, 0, 0}
};
/* *INDENT-ON* */

cib_t *cib_conn = NULL;
static int exec_call_id = 0;
static int exec_call_opts = 0;
extern void cleanup_alloc_calculations(pe_working_set_t * data_set);

static struct {
    int verbose;
    int quiet;
    int print;
    int interval;
    int timeout;
    int start_delay;
    int cancel_call_id;
    int event_version;
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

GMainLoop *mainloop = NULL;
lrmd_t *lrmd_conn = NULL;

static char event_buf_v0[1024];

#define print_result(result) \
	if (!options.quiet) { \
		result; \
	} \

#define report_event(event)	\
	snprintf(event_buf_v0, sizeof(event_buf_v0), "NEW_EVENT event_type:%s rsc_id:%s action:%s rc:%s op_status:%s", \
		lrmd_event_type2str(event->type),	\
		event->rsc_id,	\
		event->op_type ? event->op_type : "none",	\
		lrmd_event_rc2str(event->rc),	\
		services_lrm_status_str(event->op_status));	\
	crm_info("%s", event_buf_v0);;

static void
test_shutdown(int nsig)
{
    lrmd_api_delete(lrmd_conn);
}

static void
read_events(lrmd_event_data_t * event)
{
    report_event(event);
    if (options.listen) {
        if (safe_str_eq(options.listen, event_buf_v0)) {
            print_result(printf("LISTEN EVENT SUCCESSFUL\n"));
            exit(0);
        }
    }

    if (exec_call_id && (event->call_id == exec_call_id)) {
        if (event->op_status == 0 && event->rc == 0) {
            print_result(printf("API-CALL SUCCESSFUL for 'exec'\n"));
        } else {
            print_result(printf("API-CALL FAILURE for 'exec', rc:%d lrmd_op_status:%s\n",
                                event->rc, services_lrm_status_str(event->op_status)));
            exit(-1);
        }

        if (!options.listen) {
            exit(0);
        }
    }
}

static gboolean
timeout_err(gpointer data)
{
    print_result(printf("LISTEN EVENT FAILURE - timeout occurred, never found.\n"));
    exit(-1);

    return FALSE;
}

static void
try_connect(void)
{
    int tries = 10;
    int i = 0;
    int rc = 0;

    for (i = 0; i < tries; i++) {
        rc = lrmd_conn->cmds->connect(lrmd_conn, "lrmd", NULL);

        if (!rc) {
            crm_info("lrmd client connection established");
            return;
        } else {
            crm_info("lrmd client connection failed");
        }
        sleep(1);
    }

    print_result(printf("API CONNECTION FAILURE\n"));
    exit(-1);
}

static gboolean
start_test(gpointer user_data)
{
    int rc = 0;

    if (!options.no_connect) {
        try_connect();
    }
    lrmd_conn->cmds->set_callback(lrmd_conn, read_events);

    if (options.timeout) {
        g_timeout_add(options.timeout, timeout_err, NULL);
    }

    if (!options.api_call) {
        return 0;
    }

    if (safe_str_eq(options.api_call, "exec")) {
        rc = lrmd_conn->cmds->exec(lrmd_conn,
                                   options.rsc_id,
                                   options.action,
                                   NULL,
                                   options.interval,
                                   options.timeout,
                                   options.start_delay, exec_call_opts, options.params);

        if (rc > 0) {
            exec_call_id = rc;
            print_result(printf("API-CALL 'exec' action pending, waiting on response\n"));
        }

    } else if (safe_str_eq(options.api_call, "register_rsc")) {
        rc = lrmd_conn->cmds->register_rsc(lrmd_conn,
                                           options.rsc_id,
                                           options.class, options.provider, options.type, 0);
    } else if (safe_str_eq(options.api_call, "get_rsc_info")) {
        lrmd_rsc_info_t *rsc_info;

        rsc_info = lrmd_conn->cmds->get_rsc_info(lrmd_conn, options.rsc_id, 0);

        if (rsc_info) {
            print_result(printf("RSC_INFO: id:%s class:%s provider:%s type:%s\n",
                                rsc_info->id, rsc_info->class,
                                rsc_info->provider ? rsc_info->provider : "<none>",
                                rsc_info->type));
            lrmd_free_rsc_info(rsc_info);
            rc = lrmd_ok;
        } else {
            rc = -1;
        }
    } else if (safe_str_eq(options.api_call, "unregister_rsc")) {
        rc = lrmd_conn->cmds->unregister_rsc(lrmd_conn, options.rsc_id, 0);
    } else if (safe_str_eq(options.api_call, "cancel")) {
        rc = lrmd_conn->cmds->cancel(lrmd_conn, options.rsc_id, options.action, options.interval);
    } else if (safe_str_eq(options.api_call, "metadata")) {
        char *output = NULL;

        rc = lrmd_conn->cmds->get_metadata(lrmd_conn,
                                           options.class,
                                           options.provider, options.type, &output, 0);
        if (rc == lrmd_ok) {
            print_result(printf("%s", output));
            free(output);
        }
    } else if (safe_str_eq(options.api_call, "list_agents")) {
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
    } else if (safe_str_eq(options.api_call, "list_ocf_providers")) {
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
    } else if (options.api_call) {
        print_result(printf("API-CALL FAILURE unknown action '%s'\n", options.action));
        exit(-1);
    }

    if (rc < 0) {
        print_result(printf("API-CALL FAILURE for '%s' api_rc:%d\n", options.api_call, rc));
        exit(-1);
    }

    if (options.api_call && rc == lrmd_ok) {
        print_result(printf("API-CALL SUCCESSFUL for '%s'\n", options.api_call));
        if (!options.listen) {
            exit(0);
        }
    }

    if (options.no_wait) {
        /* just make the call and exit regardless of anything else. */
        exit(0);
    }

    return 0;
}

static resource_t *
find_rsc_or_clone(const char *rsc, pe_working_set_t * data_set)
{
    resource_t *the_rsc = pe_find_resource(data_set->resources, rsc);

    if (the_rsc == NULL) {
        char *as_clone = crm_concat(rsc, "0", ':');

        the_rsc = pe_find_resource(data_set->resources, as_clone);
        free(as_clone);
    }
    return the_rsc;
}

static int
generate_params(void)
{
    int rc = 0;
    pe_working_set_t data_set;
    xmlNode *cib_xml_copy = NULL;
    resource_t *rsc = NULL;
    GHashTable *params = NULL;
    GHashTable *meta = NULL;
    GHashTableIter iter;

    if (options.params) {
        return 0;
    }

    set_working_set_defaults(&data_set);

    cib_conn = cib_new();
    rc = cib_conn->cmds->signon(cib_conn, "lrmd_test", cib_query);
    if (rc != cib_ok) {
        crm_err("Error signing on to the CIB service: %s\n", cib_error2string(rc));
        rc = -1;
        goto param_gen_bail;
    }

    cib_xml_copy = get_cib_copy(cib_conn);

    if (!cib_xml_copy) {
        crm_err("Error retrieving cib copy.");
        rc = -1;
        goto param_gen_bail;
    }

    if (cli_config_update(&cib_xml_copy, NULL, FALSE) == FALSE) {
        crm_err("Error updating cib configuration");
        rc = -1;
        goto param_gen_bail;
    }

    data_set.input = cib_xml_copy;
    data_set.now = new_ha_date(TRUE);

    cluster_status(&data_set);
    if (options.rsc_id) {
        rsc = find_rsc_or_clone(options.rsc_id, &data_set);
    }

    if (!rsc) {
        crm_err("Resource does not exist in config");
        rc = -1;
        goto param_gen_bail;
    }

    params = g_hash_table_new_full(crm_str_hash,
                                   g_str_equal, g_hash_destroy_str, g_hash_destroy_str);
    meta = g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    get_rsc_attributes(params, rsc, NULL, &data_set);
    get_meta_attributes(meta, rsc, NULL, &data_set);

    if (params) {
        char *key = NULL;
        char *value = NULL;

        g_hash_table_iter_init(&iter, params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            options.params = lrmd_key_value_add(options.params, key, value);
        }
        g_hash_table_destroy(params);
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

    cleanup_alloc_calculations(&data_set);
    return rc;
}

int
main(int argc, char **argv)
{
    int option_index = 0;
    int argerr = 0;
    int flag;
    char *key = NULL;
    char *val = NULL;
    crm_trigger_t *trig;

    crm_set_options(NULL, "mode [options]", long_options,
                    "Inject commands into the lrmd and watch for events\n");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'V':
                options.verbose = 1;
                break;
            case 'Q':
                options.quiet = 1;
                options.verbose = 0;
                break;
            case 'e':
                options.event_version = atoi(optarg);
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
                options.cancel_call_id = atoi(optarg);
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
                options.interval = atoi(optarg);
                break;
            case 't':
                options.timeout = atoi(optarg);
                break;
            case 's':
                options.start_delay = atoi(optarg);
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
            default:
                ++argerr;
                break;
        }
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }
    if (optind > argc) {
        ++argerr;
    }

    if (!options.listen &&
        (safe_str_eq(options.api_call, "metadata") ||
         safe_str_eq(options.api_call, "list_agents") ||
         safe_str_eq(options.api_call, "list_ocf_providers"))) {
        options.no_connect = 1;
    }

    crm_log_init("lrmd_ctest", LOG_INFO, TRUE, options.verbose ? TRUE : FALSE, argc, argv, FALSE);

    if (options.is_running) {
        if (!options.timeout) {
            options.timeout = 30000;
        }
        options.interval = 0;
        if (!options.rsc_id) {
            crm_err("rsc-id must be given when is-running is used");
            exit(-1);
        }

        if (generate_params()) {
            print_result(printf
                         ("Failed to retrieve rsc parameters from cib, can not determine if rsc is running.\n"));
            exit(-1);
        }
        options.api_call = "exec";
        options.action = "monitor";
        exec_call_opts = lrmd_opt_notify_orig_only;
    }

    /* if we can't perform an api_call or listen for events, 
     * there is nothing to do */
    if (!options.api_call && !options.listen) {
        crm_err("Nothing to be done.  Please specify 'api-call' and/or 'listen'");
        return 0;
    }

    lrmd_conn = lrmd_api_new();
    trig = mainloop_add_trigger(G_PRIORITY_HIGH, start_test, NULL);
    mainloop_set_trigger(trig);
    mainloop_add_signal(SIGTERM, test_shutdown);

    crm_info("Starting");
    mainloop = g_main_new(FALSE);
    g_main_run(mainloop);
    lrmd_api_delete(lrmd_conn);

    if (cib_conn != NULL) {
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
    }

    return 0;
}
