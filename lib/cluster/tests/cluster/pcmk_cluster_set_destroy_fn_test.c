/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>                           // gpointer

#include <crm/cluster.h>                    // pcmk_cluster_t, etc.
#include <crm/common/unittest_internal.h>

static void
destroy_fn1(gpointer arg)
{
    return;
}

static void
destroy_fn2(gpointer arg)
{
    return;
}

static void
null_cluster(void **state)
{
    assert_int_equal(pcmk_cluster_set_destroy_fn(NULL, NULL), EINVAL);
    assert_int_equal(pcmk_cluster_set_destroy_fn(NULL, destroy_fn1), EINVAL);
}

static void
null_fn(void **state)
{
    pcmk_cluster_t cluster = {
        .destroy = NULL,
    };

    assert_int_equal(pcmk_cluster_set_destroy_fn(&cluster, NULL), pcmk_rc_ok);
    assert_ptr_equal(cluster.destroy, NULL);

    cluster.destroy = destroy_fn1;
    assert_int_equal(pcmk_cluster_set_destroy_fn(&cluster, NULL), pcmk_rc_ok);
    assert_ptr_equal(cluster.destroy, NULL);
}

static void
previous_fn_null(void **state)
{
    pcmk_cluster_t cluster = {
        .destroy = NULL,
    };

    assert_int_equal(pcmk_cluster_set_destroy_fn(&cluster, destroy_fn1),
                     pcmk_rc_ok);
    assert_ptr_equal(cluster.destroy, destroy_fn1);
}

static void
previous_fn_nonnull(void **state)
{
    pcmk_cluster_t cluster = {
        .destroy = destroy_fn2,
    };

    assert_int_equal(pcmk_cluster_set_destroy_fn(&cluster, destroy_fn1),
                     pcmk_rc_ok);
    assert_ptr_equal(cluster.destroy, destroy_fn1);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_cluster),
                cmocka_unit_test(null_fn),
                cmocka_unit_test(previous_fn_null),
                cmocka_unit_test(previous_fn_nonnull))
