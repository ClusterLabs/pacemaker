/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <glib.h>

static void
basic(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("Fencing_monitor_60000", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "Fencing");
    g_assert_cmpstr(ty, ==, "monitor");
    g_assert_cmpint(ms, ==, 60000);
    free(rsc);
    free(ty);
}

static void
colon_in_rsc(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("ClusterIP:0_start_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "ClusterIP:0");
    g_assert_cmpstr(ty, ==, "start");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);

    g_assert_true(parse_op_key("imagestoreclone:1_post_notify_stop_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "imagestoreclone:1");
    g_assert_cmpstr(ty, ==, "post_notify_stop");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);
}

static void
dashes_in_rsc(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("httpd-bundle-0_monitor_30000", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "httpd-bundle-0");
    g_assert_cmpstr(ty, ==, "monitor");
    g_assert_cmpint(ms, ==, 30000);
    free(rsc);
    free(ty);

    g_assert_true(parse_op_key("httpd-bundle-ip-192.168.122.132_start_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "httpd-bundle-ip-192.168.122.132");
    g_assert_cmpstr(ty, ==, "start");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);
}

static void
migrate_to_from(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("vm_migrate_from_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "vm");
    g_assert_cmpstr(ty, ==, "migrate_from");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);

    g_assert_true(parse_op_key("vm_migrate_to_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "vm");
    g_assert_cmpstr(ty, ==, "migrate_to");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);

    g_assert_true(parse_op_key("vm_idcc_devel_migrate_to_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "vm_idcc_devel");
    g_assert_cmpstr(ty, ==, "migrate_to");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);
}

static void
pre_post(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("rsc_drbd_7788:1_post_notify_start_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "rsc_drbd_7788:1");
    g_assert_cmpstr(ty, ==, "post_notify_start");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);

    g_assert_true(parse_op_key("rabbitmq-bundle-clone_pre_notify_stop_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "rabbitmq-bundle-clone");
    g_assert_cmpstr(ty, ==, "pre_notify_stop");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);

    g_assert_true(parse_op_key("post_notify_start_0", &rsc, &ty, &ms));
    g_assert_cmpstr(rsc, ==, "post_notify");
    g_assert_cmpstr(ty, ==, "start");
    g_assert_cmpint(ms, ==, 0);
    free(rsc);
    free(ty);
}

static void
skip_rsc(void)
{
    char *ty = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("Fencing_monitor_60000", NULL, &ty, &ms));
    g_assert_cmpstr(ty, ==, "monitor");
    g_assert_cmpint(ms, ==, 60000);
    free(ty);
}

static void
skip_ty(void)
{
    char *rsc = NULL;
    guint ms = 0;

    g_assert_true(parse_op_key("Fencing_monitor_60000", &rsc, NULL, &ms));
    g_assert_cmpstr(rsc, ==, "Fencing");
    g_assert_cmpint(ms, ==, 60000);
    free(rsc);
}

static void
skip_ms(void)
{
    char *rsc = NULL;
    char *ty = NULL;

    g_assert_true(parse_op_key("Fencing_monitor_60000", &rsc, &ty, NULL));
    g_assert_cmpstr(rsc, ==, "Fencing");
    g_assert_cmpstr(ty, ==, "monitor");
    free(rsc);
    free(ty);
}

static void
empty_input(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_false(parse_op_key("", &rsc, &ty, &ms));
    g_assert_null(rsc);
    g_assert_null(ty);
    g_assert_cmpint(ms, ==, 0);

    g_assert_false(parse_op_key(NULL, &rsc, &ty, &ms));
    g_assert_null(rsc);
    g_assert_null(ty);
    g_assert_cmpint(ms, ==, 0);
}

static void
malformed_input(void)
{
    char *rsc = NULL;
    char *ty = NULL;
    guint ms = 0;

    g_assert_false(parse_op_key("httpd-bundle-0", &rsc, &ty, &ms));
    g_assert_null(rsc);
    g_assert_null(ty);
    g_assert_cmpint(ms, ==, 0);

    g_assert_false(parse_op_key("httpd-bundle-0_monitor", &rsc, &ty, &ms));
    g_assert_null(rsc);
    g_assert_null(ty);
    g_assert_cmpint(ms, ==, 0);

    g_assert_false(parse_op_key("httpd-bundle-0_30000", &rsc, &ty, &ms));
    g_assert_null(rsc);
    g_assert_null(ty);
    g_assert_cmpint(ms, ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/utils/parse_op_key/basic", basic);
    g_test_add_func("/common/utils/parse_op_key/colon_in_rsc", colon_in_rsc);
    g_test_add_func("/common/utils/parse_op_key/dashes_in_rsc", dashes_in_rsc);
    g_test_add_func("/common/utils/parse_op_key/migrate_to_from", migrate_to_from);
    g_test_add_func("/common/utils/parse_op_key/pre_post", pre_post);

    g_test_add_func("/common/utils/parse_op_key/skip_rsc", skip_rsc);
    g_test_add_func("/common/utils/parse_op_key/skip_ty", skip_ty);
    g_test_add_func("/common/utils/parse_op_key/skip_ms", skip_ms);

    g_test_add_func("/common/utils/parse_op_key/empty_input", empty_input);
    g_test_add_func("/common/utils/parse_op_key/malformed_input", malformed_input);

    return g_test_run();
}
