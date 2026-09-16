/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EINVAL, ENODATA, ENODEV
#include <poll.h>                   // POLLIN, poll, pollfd
#include <signal.h>                 // SIGTERM
#include <stdbool.h>                // bool, false, true
#include <stdint.h>                 // uint32_t
#include <stdlib.h>                 // NULL, free
#include <syslog.h>                 // LOG_INFO
#include <time.h>                   // time, time_t

#include <glib.h>

#include <crm/common/actions.h>     // PCMK_ACTION_OFF, PCMK_ACTION_ON
#include <crm/common/agents.h>      // PCMK_FENCING_HOST_MAP
#include <crm/common/logging.h>     // crm_bump_log_level, crm_log_init
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/results.h>     // CRM_EX_*, pcmk_rc_*, crm_exit, pcmk_strerror
#include <crm/crm.h>                // crm_system_name
#include <crm/fencing/internal.h>   // stonith__key_value_add, stonith__key_value_freeall
#include <crm/stonith-ng.h>         // stonith_s, stonith_key_value_t

#define SUMMARY "cts-fence-helper - inject commands into the Pacemaker fencer and watch for events"

static crm_trigger_t *trig = NULL;
static int mainloop_iter = 0;
static pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

typedef void (*mainloop_test_iteration_cb) (int check_event);

#define MAINLOOP_DEFAULT_TIMEOUT 2

static enum test_modes {
    test_standard = 0,  // test using a specific developer environment
    test_api_sanity,    // sanity-test stonith client API using fence_dummy
    test_api_mainloop,  // sanity-test mainloop code with async responses
} mode = test_standard;

static gboolean
mode_cb(const char *option_name, const char *optarg, void *data, GError **error)
{
    if (pcmk__str_any_of(option_name, "--mainloop_api_test", "-m", NULL)) {
        mode = test_api_mainloop;
    } else if (pcmk__str_any_of(option_name, "--api_test", "-t", NULL)) {
        mode = test_api_sanity;
    }

    return TRUE;
}

static GOptionEntry entries[] = {
    { "mainloop_api_test", 'm', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, mode_cb,
      NULL, NULL,
    },

    { "api_test", 't', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, mode_cb,
      NULL, NULL,
    },

    { NULL }
};

static stonith_t *st = NULL;
static struct pollfd pollfd;
static const int st_opts = st_opt_sync_call;
static int expected_notifications = 0;

static void
mainloop_test_done(const char *origin, bool pass)
{
    if (!pass) {
        pcmk__err("FAILURE - %s (%d: %s)", origin, result.exit_status,
                  pcmk_exec_status_str(result.execution_status));
        crm_exit(CRM_EX_ERROR);
    }

    pcmk__info("SUCCESS - %s", origin);
    mainloop_iter++;
    mainloop_set_trigger(trig);
    result.execution_status = PCMK_EXEC_DONE;
    result.exit_status = CRM_EX_OK;
}

static void
dispatch_helper(int timeout)
{
    int rc;

    pcmk__debug("Looking for notification");
    pollfd.events = POLLIN;
    while (true) {
        rc = poll(&pollfd, 1, timeout); /* wait 10 minutes, -1 forever */
        if (rc > 0) {
            if (stonith__api_dispatch(st) != pcmk_rc_ok) {
                break;
            }
        } else {
            break;
        }
    }
}

static void
st_callback(stonith_t * st, stonith_event_t * e)
{
    char *desc = NULL;

    if (st->state == stonith_disconnected) {
        crm_exit(CRM_EX_DISCONNECT);
    }

    desc = stonith__event_description(e);
    pcmk__notice("%s", desc);
    free(desc);

    if (expected_notifications != 0) {
        expected_notifications--;
    }
}

static void
st_global_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    pcmk__notice("Call %d exited %d: %s (%s)", data->call_id,
                 stonith__exit_status(data), stonith__execution_status(data),
                 pcmk__s(stonith__exit_reason(data), "unspecified reason"));
}

#define single_test(cmd, str, num_notifications, expected_rc)               \
    do {                                                                    \
        int rc = cmd;                                                       \
                                                                            \
        expected_notifications = 0;                                         \
                                                                            \
        if (num_notifications != 0) {                                       \
            expected_notifications = num_notifications;                     \
            dispatch_helper(500);                                           \
        }                                                                   \
                                                                            \
        if (rc != expected_rc) {                                            \
            pcmk__err("FAILURE - expected rc %d != %d(%s) for cmd - %s",    \
                      expected_rc, rc, pcmk_strerror(rc), str);             \
            crm_exit(CRM_EX_ERROR);                                         \
        }                                                                   \
                                                                            \
        if (expected_notifications != 0) {                                  \
            /* @TODO Make this message's logic more clear */                \
            pcmk__err("FAILURE - expected %d notifications, got only %d "   \
                      "for cmd - %s",                                       \
                      num_notifications,                                    \
                      (num_notifications - expected_notifications), str);   \
            crm_exit(CRM_EX_ERROR);                                         \
        }                                                                   \
                                                                            \
        pcmk__debug("SUCCESS - %s: %d", str, rc);                           \
    } while (0)

static void
run_fence_failure_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "false_1_node1=1,2 false_1_node2=3,4");
    params = stonith__key_value_add(params, "mode", "fail");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id1", "stonith-ng", "fence_dummy", params),
                "Register device1 for failure test", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2", PCMK_ACTION_OFF,
                                3, 0),
                "Fence failure results off", 1, -ENODATA);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2",
                                PCMK_ACTION_REBOOT, 3, 0),
                "Fence failure results reboot", 1, -ENODATA);

    single_test(st->cmds->remove_device(st, st_opts, "test-id1"),
                "Remove device1 for failure test", 1, 0);

    stonith__key_value_freeall(params, true, true);
}

static void
run_fence_failure_rollover_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "false_1_node1=1,2 false_1_node2=3,4");
    params = stonith__key_value_add(params, "mode", "fail");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id1", "stonith-ng", "fence_dummy", params),
                "Register device1 for rollover test", 1, 0);
    stonith__key_value_freeall(params, true, true);
    params = NULL;
    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "false_1_node1=1,2 false_1_node2=3,4");
    params = stonith__key_value_add(params, "mode", "pass");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id2", "stonith-ng", "fence_dummy", params),
                "Register device2 for rollover test", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2", PCMK_ACTION_OFF,
                                3, 0),
                "Fence rollover results off", 1, 0);

    /* Expect -ENODEV because fence_dummy requires 'on' to be executed on target */
    single_test(st->cmds->fence(st, st_opts, "false_1_node2", PCMK_ACTION_ON, 3,
                                0),
                "Fence rollover results on", 1, -ENODEV);

    single_test(st->cmds->remove_device(st, st_opts, "test-id1"),
                "Remove device1 for rollover tests", 1, 0);

    single_test(st->cmds->remove_device(st, st_opts, "test-id2"),
                "Remove device2 for rollover tests", 1, 0);

    stonith__key_value_freeall(params, true, true);
}

static void
run_standard_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "false_1_node1=1,2 false_1_node2=3,4");
    params = stonith__key_value_add(params, "mode", "pass");
    params = stonith__key_value_add(params, "mock_dynamic_hosts",
                                    "false_1_node1 false_1_node2");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_dummy", params),
                "Register", 1, 0);
    stonith__key_value_freeall(params, true, true);
    params = NULL;

    single_test(st->cmds->list(st, st_opts, "test-id", NULL, 1),
                PCMK_ACTION_LIST, 0, 0);

    single_test(st->cmds->monitor(st, st_opts, "test-id", 1), "Monitor", 0, 0);

    single_test(st->cmds->status(st, st_opts, "test-id", "false_1_node2", 1),
                "Status false_1_node2", 0, 0);

    single_test(st->cmds->status(st, st_opts, "test-id", "false_1_node1", 1),
                "Status false_1_node1", 0, 0);

    single_test(st->cmds->fence(st, st_opts, "unknown-host", PCMK_ACTION_OFF,
                                1, 0),
                "Fence unknown-host (expected failure)", 0, -ENODEV);

    single_test(st->cmds->fence(st, st_opts, "false_1_node1", PCMK_ACTION_OFF,
                                1, 0),
                "Fence false_1_node1", 1, 0);

    /* Expect -ENODEV because fence_dummy requires 'on' to be executed on target */
    single_test(st->cmds->fence(st, st_opts, "false_1_node1", PCMK_ACTION_ON, 1,
                                0),
                "Unfence false_1_node1", 1, -ENODEV);

    /* Confirm that an invalid level index is rejected */
    single_test(st->cmds->register_level(st, st_opts, "node1", 999, params),
                "Attempt to register an invalid level index", 0, -EINVAL);

    single_test(st->cmds->remove_device(st, st_opts, "test-id"), "Remove test-id", 1, 0);

    stonith__key_value_freeall(params, true, true);
}

static void
sanity_tests(void)
{
    int rc = 0;

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    if (rc != pcmk_ok) {
        stonith__api_free(st);
        crm_exit(CRM_EX_DISCONNECT);
    }
    st->cmds->register_notification(st, PCMK__VALUE_ST_NOTIFY_DISCONNECT,
                                    st_callback);
    st->cmds->register_notification(st, PCMK__VALUE_ST_NOTIFY_FENCE,
                                    st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_ADD, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_DEL, st_callback);
    st->cmds->register_callback(st, 0, 120, st_opt_timeout_updates, NULL, "st_global_callback",
                                st_global_callback);

    pcmk__info("Starting API Sanity Tests");
    run_standard_test();
    run_fence_failure_test();
    run_fence_failure_rollover_test();
    pcmk__info("Sanity Tests Passed");
}

static void
standard_dev_test(void)
{
    int rc = 0;
    char *tmp = NULL;
    stonith_key_value_t *params = NULL;

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    if (rc != pcmk_ok) {
        stonith__api_free(st);
        crm_exit(CRM_EX_DISCONNECT);
    }

    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "some-host=pcmk-7 true_1_node1=3,4");

    rc = st->cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_xvm", params);
    pcmk__debug("Register: %d", rc);

    rc = st->cmds->list(st, st_opts, "test-id", &tmp, 10);
    pcmk__debug("List: %d output: %s", rc, tmp ? tmp : "<none>");

    rc = st->cmds->monitor(st, st_opts, "test-id", 10);
    pcmk__debug("Monitor: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node2", 10);
    pcmk__debug("Status false_1_node2: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    pcmk__debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "unknown-host", PCMK_ACTION_OFF, 60, 0);
    pcmk__debug("Fence unknown-host: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    pcmk__debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "false_1_node1", PCMK_ACTION_OFF, 60, 0);
    pcmk__debug("Fence false_1_node1: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    pcmk__debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "false_1_node1", PCMK_ACTION_ON, 10, 0);
    pcmk__debug("Unfence false_1_node1: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    pcmk__debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "some-host", PCMK_ACTION_OFF, 10, 0);
    pcmk__debug("Fence alias: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "some-host", 10);
    pcmk__debug("Status alias: %d", rc);

    rc = st->cmds->fence(st, st_opts, "false_1_node1", PCMK_ACTION_ON, 10, 0);
    pcmk__debug("Unfence false_1_node1: %d", rc);

    rc = st->cmds->remove_device(st, st_opts, "test-id");
    pcmk__debug("Remove test-id: %d", rc);

    stonith__key_value_freeall(params, true, true);
}

static void
 iterate_mainloop_tests(gboolean event_ready);

static void
mainloop_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    pcmk__set_result(&result, stonith__exit_status(data),
                     stonith__execution_status(data),
                     stonith__exit_reason(data));
    iterate_mainloop_tests(TRUE);
}

static int
register_callback_helper(int callid)
{
    return st->cmds->register_callback(st,
                                       callid,
                                       MAINLOOP_DEFAULT_TIMEOUT,
                                       st_opt_timeout_updates, NULL, "callback", mainloop_callback);
}

static void
test_async_fence_pass(int check_event)
{
    int rc = 0;

    if (check_event != 0) {
        mainloop_test_done(__func__, (result.exit_status == CRM_EX_OK));
        return;
    }

    rc = st->cmds->fence(st, 0, "true_1_node1", PCMK_ACTION_OFF,
                         MAINLOOP_DEFAULT_TIMEOUT, 0);
    if (rc < 0) {
        pcmk__err("fence failed with rc %d", rc);
        mainloop_test_done(__func__, false);
    }
    register_callback_helper(rc);
    /* wait for event */
}

#define CUSTOM_TIMEOUT_ADDITION 10
static void
test_async_fence_custom_timeout(int check_event)
{
    int rc = 0;
    static time_t begin = 0;

    if (check_event != 0) {
        uint32_t diff = (time(NULL) - begin);

        if (result.execution_status != PCMK_EXEC_TIMEOUT) {
            mainloop_test_done(__func__, false);
        } else if (diff < CUSTOM_TIMEOUT_ADDITION + MAINLOOP_DEFAULT_TIMEOUT) {
            pcmk__err("Custom timeout test failed, callback expiration should "
                      "be updated to %d, actual timeout was %d",
                      (CUSTOM_TIMEOUT_ADDITION + MAINLOOP_DEFAULT_TIMEOUT),
                      diff);
            mainloop_test_done(__func__, false);
        } else {
            mainloop_test_done(__func__, true);
        }
        return;
    }
    begin = time(NULL);

    rc = st->cmds->fence(st, 0, "custom_timeout_node1", PCMK_ACTION_OFF,
                         MAINLOOP_DEFAULT_TIMEOUT, 0);
    if (rc < 0) {
        pcmk__err("fence failed with rc %d", rc);
        mainloop_test_done(__func__, false);
    }
    register_callback_helper(rc);
    /* wait for event */
}

static void
test_async_fence_timeout(int check_event)
{
    int rc = 0;

    if (check_event != 0) {
        mainloop_test_done(__func__,
                           (result.execution_status == PCMK_EXEC_NO_FENCE_DEVICE));
        return;
    }

    rc = st->cmds->fence(st, 0, "false_1_node2", PCMK_ACTION_OFF,
                         MAINLOOP_DEFAULT_TIMEOUT, 0);
    if (rc < 0) {
        pcmk__err("fence failed with rc %d", rc);
        mainloop_test_done(__func__, false);
    }
    register_callback_helper(rc);
    /* wait for event */
}

static void
test_async_monitor(int check_event)
{
    int rc = 0;

    if (check_event != 0) {
        mainloop_test_done(__func__, (result.exit_status == CRM_EX_OK));
        return;
    }

    rc = st->cmds->monitor(st, 0, "false_1", MAINLOOP_DEFAULT_TIMEOUT);
    if (rc < 0) {
        pcmk__err("monitor failed with rc %d", rc);
        mainloop_test_done(__func__, false);
    }

    register_callback_helper(rc);
    /* wait for event */
}

static void
test_register_async_devices(int check_event)
{
    char *off_timeout_s = pcmk__itoa(MAINLOOP_DEFAULT_TIMEOUT
                                     + CUSTOM_TIMEOUT_ADDITION);
    stonith_key_value_t *params = NULL;

    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "false_1_node1=1,2");
    params = stonith__key_value_add(params, "mode", "fail");
    st->cmds->register_device(st, st_opts, "false_1", "stonith-ng", "fence_dummy", params);
    stonith__key_value_freeall(params, true, true);

    params = NULL;
    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "true_1_node1=1,2");
    params = stonith__key_value_add(params, "mode", "pass");
    st->cmds->register_device(st, st_opts, "true_1", "stonith-ng", "fence_dummy", params);
    stonith__key_value_freeall(params, true, true);

    params = NULL;
    params = stonith__key_value_add(params, PCMK_FENCING_HOST_MAP,
                                    "custom_timeout_node1=1,2");
    params = stonith__key_value_add(params, "mode", "fail");
    params = stonith__key_value_add(params, "delay", "1000");
    params = stonith__key_value_add(params, "pcmk_off_timeout", off_timeout_s);
    st->cmds->register_device(st, st_opts, "false_custom_timeout", "stonith-ng", "fence_dummy",
                              params);
    stonith__key_value_freeall(params, true, true);

    free(off_timeout_s);
    mainloop_test_done(__func__, true);
}

static void
try_mainloop_connect(int check_event)
{
    int rc = stonith__api_connect_retry(st, crm_system_name, 10);

    if (rc == pcmk_rc_ok) {
        mainloop_test_done(__func__, true);
        return;
    }
    pcmk__err("API CONNECTION FAILURE");
    mainloop_test_done(__func__, false);
}

static void
iterate_mainloop_tests(gboolean event_ready)
{
    static mainloop_test_iteration_cb callbacks[] = {
        try_mainloop_connect,
        test_register_async_devices,
        test_async_monitor,
        test_async_fence_pass,
        test_async_fence_timeout,
        test_async_fence_custom_timeout,
    };

    if (mainloop_iter == (sizeof(callbacks) / sizeof(mainloop_test_iteration_cb))) {
        /* all tests ran, everything passed */
        pcmk__info("ALL MAINLOOP TESTS PASSED!");
        crm_exit(CRM_EX_OK);
    }

    callbacks[mainloop_iter] (event_ready);
}

static gboolean
trigger_iterate_mainloop_tests(void *user_data)
{
    iterate_mainloop_tests(FALSE);
    return TRUE;
}

static void
test_shutdown(int nsig)
{
    int rc = 0;

    if (st != NULL) {
        rc = st->cmds->disconnect(st);
        pcmk__info("Disconnect: %d", rc);

        pcmk__debug("Destroy");
        stonith__api_free(st);
    }

    if (rc != 0) {
        crm_exit(CRM_EX_ERROR);
    }
}

static void
mainloop_tests(void)
{
    GMainLoop *mainloop = NULL;

    trig = mainloop_add_trigger(G_PRIORITY_HIGH, trigger_iterate_mainloop_tests, NULL);
    mainloop_set_trigger(trig);
    mainloop_add_signal(SIGTERM, test_shutdown);

    pcmk__info("Starting");
    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, NULL, group, NULL);
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    GError *error = NULL;
    crm_exit_t exit_code = CRM_EX_OK;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
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
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    for (int i = 0; i < args->verbosity; i++) {
        crm_bump_log_level(argc, argv);
    }

    st = stonith__api_new();

    switch (mode) {
        case test_standard:
            standard_dev_test();
            break;
        case test_api_sanity:
            sanity_tests();
            break;
        case test_api_mainloop:
            mainloop_tests();
            break;
    }

    test_shutdown(0);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, NULL);
    crm_exit(exit_code);
}
