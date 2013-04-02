/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <crm/common/mainloop.h>

GMainLoop *mainloop = NULL;
crm_trigger_t *trig = NULL;
int mainloop_iter = 0;
int callback_rc = 0;
typedef void (*mainloop_test_iteration_cb) (int check_event);

#define MAINLOOP_DEFAULT_TIMEOUT 2

#define mainloop_test_done(pass) \
    if (pass) { \
        crm_info("SUCCESS - %s", __PRETTY_FUNCTION__); \
        mainloop_iter++;   \
        mainloop_set_trigger(trig);  \
    } else { \
        crm_err("FAILURE = %s async_callback %d", __PRETTY_FUNCTION__, callback_rc); \
        crm_exit(-1); \
    } \
    callback_rc = 0; \


/* *INDENT-OFF* */
enum test_modes {
    /* class dev test using a very specific environment */
    test_standard = 0,
    /* watch notifications only */
    test_passive,
    /* sanity test stonith client api using fence_true and fence_false */
    test_api_sanity,
    /* sanity test mainloop code with async respones. */
    test_api_mainloop,
};

static struct crm_option long_options[] = {
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},
    {"passive",     0, 0, 'p'},
    {"api_test",    0, 0, 't'},
    {"mainloop_api_test",    0, 0, 'm'},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

stonith_t *st = NULL;
struct pollfd pollfd;
int st_opts = st_opt_sync_call;
int expected_notifications = 0;
int verbose = 0;

static void
dispatch_helper(int timeout)
{
    int rc;

    crm_debug("Looking for notification");
    pollfd.events = POLLIN;
    while (true) {
        rc = poll(&pollfd, 1, timeout); /* wait 10 minutes, -1 forever */
        if (rc > 0) {
            if (!stonith_dispatch(st)) {
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
    if (st->state == stonith_disconnected) {
        crm_exit(1);
    }

    crm_notice("Operation %s requested by %s %s for peer %s.  %s reported: %s (ref=%s)",
               e->operation, e->origin, e->result == pcmk_ok ? "completed" : "failed",
               e->target, e->executioner ? e->executioner : "<none>",
               pcmk_strerror(e->result), e->id);

    if (expected_notifications) {
        expected_notifications--;
    }
}

static void
st_global_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    crm_notice("Call id %d completed with rc %d", data->call_id, data->rc);
}

static void
passive_test(void)
{
    int rc = 0;

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    crm_debug("Connect: %d", rc);

    st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT, st_callback);
    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_ADD, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_DEL, st_callback);
    st->cmds->register_callback(st, 0, 120, st_opt_timeout_updates, NULL, "st_global_callback",
                                st_global_callback);

    dispatch_helper(600 * 1000);
}

#define single_test(cmd, str, num_notifications, expected_rc) \
{ \
    int rc = 0; \
    rc = cmd; \
    expected_notifications = 0;  \
    if (num_notifications) { \
        expected_notifications = num_notifications; \
        dispatch_helper(500);  \
    } \
    if (rc != expected_rc) { \
        crm_err("FAILURE - expected rc %d != %d(%s) for cmd - %s\n", expected_rc, rc, pcmk_strerror(rc), str); \
        crm_exit(-1); \
    } else if (expected_notifications) { \
        crm_err("FAILURE - expected %d notifications, got only %d for cmd - %s\n", \
            num_notifications, num_notifications - expected_notifications, str); \
        crm_exit(-1); \
    } else { \
        if (verbose) {                   \
            crm_info("SUCCESS - %s: %d", str, rc);    \
        } else {   \
            crm_debug("SUCCESS - %s: %d", str, rc);    \
        }                          \
    } \
}\

static void
run_fence_failure_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith_key_value_add(params, "pcmk_host_map", "false_1_node1=1,2 false_1_node2=3,4");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id1", "stonith-ng", "fence_false", params),
                "Register device1 for failure test", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2", "off", 3, 0),
                "Fence failure results off", 1, -62);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2", "reboot", 3, 0),
                "Fence failure results reboot", 1, -62);

    single_test(st->cmds->remove_device(st, st_opts, "test-id1"),
                "Remove device1 for failure test", 1, 0);

    stonith_key_value_freeall(params, 1, 1);
}

static void
run_fence_failure_rollover_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith_key_value_add(params, "pcmk_host_map", "false_1_node1=1,2 false_1_node2=3,4");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id1", "stonith-ng", "fence_false", params),
                "Register device1 for rollover test", 1, 0);

    single_test(st->
                cmds->register_device(st, st_opts, "test-id2", "stonith-ng", "fence_true", params),
                "Register device2 for rollover test", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2", "off", 3, 0),
                "Fence rollover results off", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "false_1_node2", "on", 3, 0),
                "Fence rollover results on", 1, 0);

    single_test(st->cmds->remove_device(st, st_opts, "test-id1"),
                "Remove device1 for rollover tests", 1, 0);

    single_test(st->cmds->remove_device(st, st_opts, "test-id2"),
                "Remove device2 for rollover tests", 1, 0);

    stonith_key_value_freeall(params, 1, 1);
}

static void
run_standard_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith_key_value_add(params, "pcmk_host_map", "false_1_node1=1,2 false_1_node2=3,4");

    single_test(st->
                cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_true", params),
                "Register", 1, 0);

    single_test(st->cmds->list(st, st_opts, "test-id", NULL, 1), "list", 1, 0);

    single_test(st->cmds->monitor(st, st_opts, "test-id", 1), "Monitor", 1, 0);

    single_test(st->cmds->status(st, st_opts, "test-id", "false_1_node2", 1),
                "Status false_1_node2", 1, 0);

    single_test(st->cmds->status(st, st_opts, "test-id", "false_1_node1", 1),
                "Status false_1_node1", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "unknown-host", "off", 1, 0),
                "Fence unknown-host (expected failure)", 0, -19);

    single_test(st->cmds->fence(st, st_opts, "false_1_node1", "off", 1, 0),
                "Fence false_1_node1", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "false_1_node1", "on", 1, 0),
                "Unfence false_1_node1", 1, 0);

    single_test(st->cmds->remove_device(st, st_opts, "test-id"), "Remove test-id", 1, 0);

    stonith_key_value_freeall(params, 1, 1);
}

static void
sanity_tests(void)
{
    int rc = 0;

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    crm_debug("Connect: %d", rc);

    st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT, st_callback);
    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_ADD, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_DEL, st_callback);
    st->cmds->register_callback(st, 0, 120, st_opt_timeout_updates, NULL, "st_global_callback",
                                st_global_callback);

    crm_info("Starting API Sanity Tests");
    run_standard_test();
    run_fence_failure_test();
    run_fence_failure_rollover_test();
    crm_info("Sanity Tests Passed");
}

static void
standard_dev_test(void)
{
    int rc = 0;
    char *tmp = NULL;
    stonith_key_value_t *params = NULL;

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    crm_debug("Connect: %d", rc);

    params = stonith_key_value_add(params, "pcmk_host_map", "some-host=pcmk-7 true_1_node1=3,4");

    rc = st->cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_xvm", params);
    crm_debug("Register: %d", rc);

    rc = st->cmds->list(st, st_opts, "test-id", &tmp, 10);
    crm_debug("List: %d output: %s\n", rc, tmp ? tmp : "<none>");

    rc = st->cmds->monitor(st, st_opts, "test-id", 10);
    crm_debug("Monitor: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node2", 10);
    crm_debug("Status false_1_node2: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    crm_debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "unknown-host", "off", 60, 0);
    crm_debug("Fence unknown-host: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    crm_debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "false_1_node1", "off", 60, 0);
    crm_debug("Fence false_1_node1: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    crm_debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "false_1_node1", "on", 10, 0);
    crm_debug("Unfence false_1_node1: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "false_1_node1", 10);
    crm_debug("Status false_1_node1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "some-host", "off", 10, 0);
    crm_debug("Fence alias: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "some-host", 10);
    crm_debug("Status alias: %d", rc);

    rc = st->cmds->fence(st, st_opts, "false_1_node1", "on", 10, 0);
    crm_debug("Unfence false_1_node1: %d", rc);

    rc = st->cmds->remove_device(st, st_opts, "test-id");
    crm_debug("Remove test-id: %d", rc);

    stonith_key_value_freeall(params, 1, 1);
}

static void
 iterate_mainloop_tests(gboolean event_ready);

static void
mainloop_callback(stonith_t * stonith, stonith_callback_data_t * data)
{
    callback_rc = data->rc;
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

    if (check_event) {
        if (callback_rc != 0) {
            mainloop_test_done(FALSE);
        } else {
            mainloop_test_done(TRUE);
        }
        return;
    }

    rc = st->cmds->fence(st, 0, "true_1_node1", "off", MAINLOOP_DEFAULT_TIMEOUT, 0);
    if (rc < 0) {
        crm_err("fence failed with rc %d", rc);
        mainloop_test_done(FALSE);
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

    if (check_event) {
        uint32_t diff = (time(NULL) - begin);

        if (callback_rc != -ETIME) {
            mainloop_test_done(FALSE);
        } else if (diff < CUSTOM_TIMEOUT_ADDITION + MAINLOOP_DEFAULT_TIMEOUT) {
            crm_err
                ("Custom timeout test failed, callback expiration should be updated to %d, actual timeout was %d",
                 CUSTOM_TIMEOUT_ADDITION + MAINLOOP_DEFAULT_TIMEOUT, diff);
            mainloop_test_done(FALSE);
        } else {
            mainloop_test_done(TRUE);
        }
        return;
    }
    begin = time(NULL);

    rc = st->cmds->fence(st, 0, "custom_timeout_node1", "off", MAINLOOP_DEFAULT_TIMEOUT, 0);
    if (rc < 0) {
        crm_err("fence failed with rc %d", rc);
        mainloop_test_done(FALSE);
    }
    register_callback_helper(rc);
    /* wait for event */
}

static void
test_async_fence_timeout(int check_event)
{
    int rc = 0;

    if (check_event) {
        if (callback_rc != -EHOSTUNREACH) {
            mainloop_test_done(FALSE);
        } else {
            mainloop_test_done(TRUE);
        }
        return;
    }

    rc = st->cmds->fence(st, 0, "false_1_node2", "off", MAINLOOP_DEFAULT_TIMEOUT, 0);
    if (rc < 0) {
        crm_err("fence failed with rc %d", rc);
        mainloop_test_done(FALSE);
    }
    register_callback_helper(rc);
    /* wait for event */
}

static void
test_async_monitor(int check_event)
{
    int rc = 0;

    if (check_event) {
        if (callback_rc) {
            mainloop_test_done(FALSE);
        } else {
            mainloop_test_done(TRUE);
        }
        return;
    }

    rc = st->cmds->monitor(st, 0, "false_1", MAINLOOP_DEFAULT_TIMEOUT);
    if (rc < 0) {
        crm_err("monitor failed with rc %d", rc);
        mainloop_test_done(FALSE);
    }

    register_callback_helper(rc);
    /* wait for event */
}

static void
test_register_async_devices(int check_event)
{
    char buf[16] = { 0, };
    stonith_key_value_t *params = NULL;

    params = stonith_key_value_add(params, "pcmk_host_map", "false_1_node1=1,2");
    st->cmds->register_device(st, st_opts, "false_1", "stonith-ng", "fence_false", params);
    stonith_key_value_freeall(params, 1, 1);

    params = NULL;
    params = stonith_key_value_add(params, "pcmk_host_map", "true_1_node1=1,2");
    st->cmds->register_device(st, st_opts, "true_1", "stonith-ng", "fence_true", params);
    stonith_key_value_freeall(params, 1, 1);

    params = NULL;
    params = stonith_key_value_add(params, "pcmk_host_map", "custom_timeout_node1=1,2");
    snprintf(buf, sizeof(buf) - 1, "%d", MAINLOOP_DEFAULT_TIMEOUT + CUSTOM_TIMEOUT_ADDITION);
    params = stonith_key_value_add(params, "pcmk_off_timeout", buf);
    st->cmds->register_device(st, st_opts, "false_custom_timeout", "stonith-ng", "fence_false",
                              params);
    stonith_key_value_freeall(params, 1, 1);

    mainloop_test_done(TRUE);
}

static void
try_mainloop_connect(int check_event)
{
    int tries = 10;
    int i = 0;
    int rc = 0;

    for (i = 0; i < tries; i++) {
        rc = st->cmds->connect(st, crm_system_name, NULL);

        if (!rc) {
            crm_info("stonith client connection established");
            mainloop_test_done(TRUE);
            return;
        } else {
            crm_info("stonith client connection failed");
        }
        sleep(1);
    }

    crm_err("API CONNECTION FAILURE\n");
    mainloop_test_done(FALSE);
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
        crm_info("ALL MAINLOOP TESTS PASSED!");
        crm_exit(0);
    }

    callbacks[mainloop_iter] (event_ready);
}

static gboolean
trigger_iterate_mainloop_tests(gpointer user_data)
{
    iterate_mainloop_tests(FALSE);
    return TRUE;
}

static void
test_shutdown(int nsig)
{
    int rc = 0;

    if (st) {
        rc = st->cmds->disconnect(st);
        crm_info("Disconnect: %d", rc);

        crm_debug("Destroy");
        stonith_api_delete(st);
    }

    if (rc) {
        crm_exit(-1);
    }
}

static void
mainloop_tests(void)
{
    trig = mainloop_add_trigger(G_PRIORITY_HIGH, trigger_iterate_mainloop_tests, NULL);
    mainloop_set_trigger(trig);
    mainloop_add_signal(SIGTERM, test_shutdown);

    crm_info("Starting");
    mainloop = g_main_new(FALSE);
    g_main_run(mainloop);
}

int
main(int argc, char **argv)
{
    int argerr = 0;
    int flag;
    int option_index = 0;

    enum test_modes mode = test_standard;

    crm_set_options(NULL, "mode [options]", long_options,
                    "Provides a summary of cluster's current state."
                    "\n\nOutputs varying levels of detail in a number of different formats.\n");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1) {
            break;
        }

        switch (flag) {
            case 'V':
                verbose = 1;
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'p':
                mode = test_passive;
                break;
            case 't':
                mode = test_api_sanity;
                break;
            case 'm':
                mode = test_api_mainloop;
                break;
            default:
                ++argerr;
                break;
        }
    }

    crm_log_init("stonith-test", LOG_INFO, TRUE, verbose ? TRUE : FALSE, argc, argv, FALSE);

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    crm_debug("Create");
    st = stonith_api_new();

    switch (mode) {
        case test_standard:
            standard_dev_test();
            break;
        case test_passive:
            passive_test();
            break;
        case test_api_sanity:
            sanity_tests();
            break;
        case test_api_mainloop:
            mainloop_tests();
            break;
    }

    test_shutdown(0);
    return 0;
}
