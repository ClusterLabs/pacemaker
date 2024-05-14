/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>                         // uint32_t
#include <sys/types.h>                      // size_t

#include <crm/cluster.h>                    // pcmk_cluster_t, etc.
#include <crm/common/unittest_internal.h>

#if SUPPORT_COROSYNC
#include <corosync/cpg.h>                   // cpg_handle_t, struct cpg_name

static void
deliver_fn1(cpg_handle_t handle, const struct cpg_name *group_name,
            uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    return;
}

static void
deliver_fn2(cpg_handle_t handle, const struct cpg_name *group_name,
            uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    return;
}

static void
null_cluster(void **state)
{
    assert_int_equal(pcmk_cpg_set_deliver_fn(NULL, NULL), EINVAL);
    assert_int_equal(pcmk_cpg_set_deliver_fn(NULL, deliver_fn1), EINVAL);
}

static void
null_fn(void **state)
{
    pcmk_cluster_t cluster = {
        .cpg = {
            .cpg_deliver_fn = NULL,
        },
    };

    assert_int_equal(pcmk_cpg_set_deliver_fn(&cluster, NULL), pcmk_rc_ok);
    assert_ptr_equal(cluster.cpg.cpg_deliver_fn, NULL);

    cluster.cpg.cpg_deliver_fn = deliver_fn1;
    assert_int_equal(pcmk_cpg_set_deliver_fn(&cluster, NULL), pcmk_rc_ok);
    assert_ptr_equal(cluster.cpg.cpg_deliver_fn, NULL);
}

static void
previous_fn_null(void **state)
{
    pcmk_cluster_t cluster = {
        .cpg = {
            .cpg_deliver_fn = NULL,
        },
    };

    assert_int_equal(pcmk_cpg_set_deliver_fn(&cluster, deliver_fn1),
                     pcmk_rc_ok);
    assert_ptr_equal(cluster.cpg.cpg_deliver_fn, deliver_fn1);
}

static void
previous_fn_nonnull(void **state)
{
    pcmk_cluster_t cluster = {
        .cpg = {
            .cpg_deliver_fn = deliver_fn2,
        },
    };

    assert_int_equal(pcmk_cpg_set_deliver_fn(&cluster, deliver_fn1),
                     pcmk_rc_ok);
    assert_ptr_equal(cluster.cpg.cpg_deliver_fn, deliver_fn1);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_cluster),
                cmocka_unit_test(null_fn),
                cmocka_unit_test(previous_fn_null),
                cmocka_unit_test(previous_fn_nonnull))
#else
PCMK__UNIT_TEST(NULL, NULL)
#endif  // SUPPORT_COROSYNC
