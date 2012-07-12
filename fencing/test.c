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

/* *INDENT-OFF* */
enum test_modes {
    /* class dev test using a very specific environment */
    test_standard = 0,
    /* watch notifications only */
    test_passive,
    /* sanity test stonith client api using fence_true and fence_false */
    test_api_sanity,
};

static struct crm_option long_options[] = {
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},
    {"passive",     0, 0, 'p'},
    {"api_test",    0, 0, 't'},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

stonith_t *st = NULL;
struct pollfd pollfd;
int st_opts = st_opt_sync_call;
int expected_notifications = 0;
int verbose = 0;

static void dispatch_helper(int timeout)
{
    int rc;
    crm_debug("Looking for notification");
    pollfd.events = POLLIN;
    while(true) {
        rc = poll( &pollfd, 1, timeout);    /* wait 10 minutes, -1 forever */
        if (rc > 0 ) {
           stonith_dispatch( st );
        } else {
            break;
        }
    }
}

static void st_callback(stonith_t *st, stonith_event_t *e)
{
    if(st->state == stonith_disconnected) {
        exit(1);
    }

    crm_notice("Operation %s requested by %s %s for peer %s.  %s reported: %s (ref=%s)",
               e->operation, e->origin, e->result == pcmk_ok?"completed":"failed",
               e->target, e->executioner ? e->executioner : "<none>",
               pcmk_strerror(e->result), e->id);

    if (expected_notifications) {
        expected_notifications--;
    }
}

static  void
st_global_callback(stonith_t * stonith, const xmlNode * msg, int call_id, int rc,
                   xmlNode * output, void *userdata)
{
    crm_log_xml_notice((xmlNode*)msg, "Event");
}

static void
passive_test(void)
{
    st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT, st_callback);
    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_ADD, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_DEL, st_callback);
    st->cmds->register_callback(st, 0, 120, FALSE, NULL, "st_global_callback", st_global_callback);

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
        printf("FAILURE - expected rc %d != %d(%s) for cmd - %s\n", expected_rc, rc, pcmk_strerror(rc), str); \
        exit(-1); \
    } else if (expected_notifications) { \
        printf("FAILURE - expected %d notifications, got only %d for cmd - %s\n", \
            num_notifications, num_notifications - expected_notifications, str); \
        exit(-1); \
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

    params = stonith_key_value_add(params, "pcmk_host_map", "pcmk-1=1,2 pcmk-2=3,4");

    single_test(st->cmds->register_device(st, st_opts, "test-id1", "stonith-ng", "fence_false", params),
        "Register device1 for failure test", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "pcmk-2", "off", 3),
        "Fence failure results off", 1, -62);

    single_test(st->cmds->fence(st, st_opts, "pcmk-2", "reboot", 3),
        "Fence failure results reboot", 1, -62);

    single_test(st->cmds->remove_device(st, st_opts, "test-id1"),
        "Remove device1 for failure test", 1, 0);

    stonith_key_value_freeall(params, 1, 1);
}

static void
run_fence_failure_rollover_test(void)
{
    stonith_key_value_t *params = NULL;

    params = stonith_key_value_add(params, "pcmk_host_map", "pcmk-1=1,2 pcmk-2=3,4");

    single_test(st->cmds->register_device(st, st_opts, "test-id1", "stonith-ng", "fence_false", params),
        "Register device1 for rollover test", 1, 0);

    single_test(st->cmds->register_device(st, st_opts, "test-id2", "stonith-ng", "fence_true", params),
        "Register device2 for rollover test", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "pcmk-2", "off", 3),
        "Fence rollover results off", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "pcmk-2", "on", 3),
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

    params = stonith_key_value_add(params, "pcmk_host_map", "pcmk-1=1,2 pcmk-2=3,4");

    single_test(st->cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_true", params),
        "Register", 1, 0);

    single_test(st->cmds->list(st, st_opts, "test-id", NULL, 1),
        "list", 1, 0);

    single_test(st->cmds->monitor(st, st_opts, "test-id", 1),
        "Monitor", 1, 0);

    single_test(st->cmds->status(st, st_opts, "test-id", "pcmk-2", 1),
        "Status pcmk-2", 1, 0);

    single_test(st->cmds->status(st, st_opts, "test-id", "pcmk-1", 1),
        "Status pcmk-1", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "unknown-host", "off", 1),
        "Fence unknown-host (expected failure)", 0, -113);

    single_test(st->cmds->fence(st, st_opts, "pcmk-1", "off", 1),
        "Fence pcmk-1", 1, 0);

    single_test(st->cmds->fence(st, st_opts, "pcmk-1", "on", 1),
        "Unfence pcmk-1", 1, 0);

    single_test(st->cmds->remove_device(st, st_opts, "test-id"),
        "Remove test-id", 1, 0);

    stonith_key_value_freeall(params, 1, 1);
}

static void
sanity_tests(void)
{
    st->cmds->register_notification(st, T_STONITH_NOTIFY_DISCONNECT, st_callback);
    st->cmds->register_notification(st, T_STONITH_NOTIFY_FENCE, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_ADD, st_callback);
    st->cmds->register_notification(st, STONITH_OP_DEVICE_DEL, st_callback);
    st->cmds->register_callback(st, 0, 120, FALSE, NULL, "st_global_callback", st_global_callback);

    printf("--- Running API sanity test ---\n");

    printf("\nRunning Standard Tests\n");
    run_standard_test();

    printf("\nRunning Fencing Failure Tests\n");
    run_fence_failure_test();

    printf("\nRunning Fencing Device Rollover Tests\n");
    run_fence_failure_rollover_test();

    printf("\n--- Sanity Tests Passed ---\n");
}

static void
standard_dev_test(void)
{
    int rc = 0;
    char *tmp = NULL;
    stonith_key_value_t *params = NULL;

    params = stonith_key_value_add(params, "pcmk_host_map", "some-host=pcmk-7 pcmk-3=3,4");

    rc = st->cmds->register_device(st, st_opts, "test-id", "stonith-ng", "fence_xvm", params);
    crm_debug("Register: %d", rc);

    rc = st->cmds->list(st, st_opts, "test-id", &tmp, 10);
    crm_debug("List: %d output: %s\n", rc, tmp ? tmp : "<none>");

    rc = st->cmds->monitor(st, st_opts, "test-id", 10);
    crm_debug("Monitor: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "pcmk-2", 10);
    crm_debug("Status pcmk-2: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "pcmk-1", 10);
    crm_debug("Status pcmk-1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "unknown-host", "off", 60);
    crm_debug("Fence unknown-host: %d", rc);

    rc = st->cmds->status(st, st_opts,  "test-id", "pcmk-1", 10);
    crm_debug("Status pcmk-1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "pcmk-1", "off", 60);
    crm_debug("Fence pcmk-1: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "pcmk-1", 10);
    crm_debug("Status pcmk-1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "pcmk-1", "on", 10);
    crm_debug("Unfence pcmk-1: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "pcmk-1", 10);
    crm_debug("Status pcmk-1: %d", rc);

    rc = st->cmds->fence(st, st_opts, "some-host", "off", 10);
    crm_debug("Fence alias: %d", rc);

    rc = st->cmds->status(st, st_opts, "test-id", "some-host", 10);
    crm_debug("Status alias: %d", rc);

    rc = st->cmds->fence(st, st_opts, "pcmk-1", "on", 10);
    crm_debug("Unfence pcmk-1: %d", rc);

    rc = st->cmds->remove_device(st, st_opts, "test-id");
    crm_debug("Remove test-id: %d", rc);

    stonith_key_value_freeall(params, 1, 1);
}

int
main(int argc, char ** argv)
{
    int argerr = 0;
    int flag;
    int option_index = 0;
    int rc = 0;

    enum test_modes mode = test_standard;

    crm_set_options(NULL, "mode [options]", long_options,
            "Provides a summary of cluster's current state."
            "\n\nOutputs varying levels of detail in a number of different formats.\n");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1) {
            break;
        }

        switch(flag) {
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

    rc = st->cmds->connect(st, crm_system_name, &pollfd.fd);
    crm_debug("Connect: %d", rc);

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
    }

    rc = st->cmds->disconnect(st);
    crm_debug("Disconnect: %d", rc);

    crm_debug("Destroy");
    stonith_api_delete(st);

    return rc;
}
