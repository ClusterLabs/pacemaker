/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

static void
basic(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_true(parse_op_key("Fencing_monitor_60000", &rsc, &ty, &ms));
    assert_string_equal(rsc, "Fencing");
    assert_string_equal(ty, "monitor");
    assert_int_equal(ms, 60000);
    free(rsc);
    free(ty);
}

static void
colon_in_rsc(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_true(parse_op_key("ClusterIP:0_start_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "ClusterIP:0");
    assert_string_equal(ty, "start");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);

    assert_true(parse_op_key("imagestoreclone:1_post_notify_stop_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "imagestoreclone:1");
    assert_string_equal(ty, "post_notify_stop");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);
}

static void
dashes_in_rsc(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_true(parse_op_key("httpd-bundle-0_monitor_30000", &rsc, &ty, &ms));
    assert_string_equal(rsc, "httpd-bundle-0");
    assert_string_equal(ty, "monitor");
    assert_int_equal(ms, 30000);
    free(rsc);
    free(ty);

    assert_true(parse_op_key("httpd-bundle-ip-192.168.122.132_start_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "httpd-bundle-ip-192.168.122.132");
    assert_string_equal(ty, "start");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);
}

static void
migrate_to_from(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_true(parse_op_key("vm_migrate_from_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "vm");
    assert_string_equal(ty, "migrate_from");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);

    assert_true(parse_op_key("vm_migrate_to_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "vm");
    assert_string_equal(ty, "migrate_to");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);

    assert_true(parse_op_key("vm_idcc_devel_migrate_to_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "vm_idcc_devel");
    assert_string_equal(ty, "migrate_to");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);
}

static void
pre_post(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_true(parse_op_key("rsc_drbd_7788:1_post_notify_start_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "rsc_drbd_7788:1");
    assert_string_equal(ty, "post_notify_start");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);

    assert_true(parse_op_key("rabbitmq-bundle-clone_pre_notify_stop_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "rabbitmq-bundle-clone");
    assert_string_equal(ty, "pre_notify_stop");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);

    assert_true(parse_op_key("post_notify_start_0", &rsc, &ty, &ms));
    assert_string_equal(rsc, "post_notify");
    assert_string_equal(ty, "start");
    assert_int_equal(ms, 0);
    free(rsc);
    free(ty);
}

static void
skip_rsc(void **state)
{
    char *ty = NULL;
    guint ms = 0;

    assert_true(parse_op_key("Fencing_monitor_60000", NULL, &ty, &ms));
    assert_string_equal(ty, "monitor");
    assert_int_equal(ms, 60000);
    free(ty);
}

static void
skip_ty(void **state)
{
    char *rsc = NULL;
    guint ms = 0;

    assert_true(parse_op_key("Fencing_monitor_60000", &rsc, NULL, &ms));
    assert_string_equal(rsc, "Fencing");
    assert_int_equal(ms, 60000);
    free(rsc);
}

static void
skip_ms(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;

    assert_true(parse_op_key("Fencing_monitor_60000", &rsc, &ty, NULL));
    assert_string_equal(rsc, "Fencing");
    assert_string_equal(ty, "monitor");
    free(rsc);
    free(ty);
}

static void
empty_input(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_false(parse_op_key("", &rsc, &ty, &ms));
    assert_null(rsc);
    assert_null(ty);
    assert_int_equal(ms, 0);

    assert_false(parse_op_key(NULL, &rsc, &ty, &ms));
    assert_null(rsc);
    assert_null(ty);
    assert_int_equal(ms, 0);
}

static void
malformed_input(void **state)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    assert_false(parse_op_key("httpd-bundle-0", &rsc, &ty, &ms));
    assert_null(rsc);
    assert_null(ty);
    assert_int_equal(ms, 0);

    assert_false(parse_op_key("httpd-bundle-0_monitor", &rsc, &ty, &ms));
    assert_null(rsc);
    assert_null(ty);
    assert_int_equal(ms, 0);

    assert_false(parse_op_key("httpd-bundle-0_30000", &rsc, &ty, &ms));
    assert_null(rsc);
    assert_null(ty);
    assert_int_equal(ms, 0);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(basic),
        cmocka_unit_test(colon_in_rsc),
        cmocka_unit_test(dashes_in_rsc),
        cmocka_unit_test(migrate_to_from),
        cmocka_unit_test(pre_post),

        cmocka_unit_test(skip_rsc),
        cmocka_unit_test(skip_ty),
        cmocka_unit_test(skip_ms),

        cmocka_unit_test(empty_input),
        cmocka_unit_test(malformed_input),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
