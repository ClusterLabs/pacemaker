/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>      // NULL
#include <glib.h>       // GList, TRUE, FALSE

#include <crm/common/nodes.h>
#include <crm/common/resources.h>
#include <crm/common/unittest_internal.h>

static int counter = 1;
static int return_false = -1;

static char rsc1_id[] = "rsc1";
static char rsc2_id[] = "rsc2";
static char rsc3_id[] = "rsc3";

static pcmk_resource_t rsc1 = {
    .id = rsc1_id,
};
static pcmk_resource_t rsc2 = {
    .id = rsc2_id,
};
static pcmk_resource_t rsc3 = {
    .id = rsc3_id,
};

static bool
fn(pcmk_resource_t *rsc, void *user_data)
{
    char *expected_id = crm_strdup_printf("rsc%d", counter);

    assert_string_equal(rsc->id, expected_id);
    free(expected_id);

    return counter++ != return_false;
}

static void
null_args(void **state)
{
    struct pe_node_shared_s shared = {
        .running_rsc = NULL,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    counter = 1;

    // These just test that it doesn't crash
    pcmk_foreach_active_resource(NULL, NULL, NULL);
    pcmk_foreach_active_resource(&node, NULL, NULL);

    pcmk_foreach_active_resource(NULL, fn, NULL);
    assert_int_equal(counter, 1);
}

static void
list_of_0(void **state)
{
    struct pe_node_shared_s shared = {
        .running_rsc = NULL,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    counter = 1;
    pcmk_foreach_active_resource(&node, fn, NULL);
    assert_int_equal(counter, 1);
}

static void
list_of_1(void **state)
{
    struct pe_node_shared_s shared = {
        .running_rsc = NULL,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    shared.running_rsc = g_list_append(shared.running_rsc, &rsc1);

    counter = 1;
    pcmk_foreach_active_resource(&node, fn, NULL);
    assert_int_equal(counter, 2);

    g_list_free(shared.running_rsc);
}

static void
list_of_3(void **state)
{
    struct pe_node_shared_s shared = {
        .running_rsc = NULL,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    shared.running_rsc = g_list_append(shared.running_rsc, &rsc1);
    shared.running_rsc = g_list_append(shared.running_rsc, &rsc2);
    shared.running_rsc = g_list_append(shared.running_rsc, &rsc3);

    counter = 1;
    pcmk_foreach_active_resource(&node, fn, NULL);
    assert_int_equal(counter, 4);

    g_list_free(shared.running_rsc);
}

static void
list_of_3_return_false(void **state)
{
    struct pe_node_shared_s shared = {
        .running_rsc = NULL,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    shared.running_rsc = g_list_append(shared.running_rsc, &rsc1);
    shared.running_rsc = g_list_append(shared.running_rsc, &rsc2);
    shared.running_rsc = g_list_append(shared.running_rsc, &rsc3);

    counter = 1;
    return_false = 2;
    pcmk_foreach_active_resource(&node, fn, NULL);
    assert_int_equal(counter, 3);

    g_list_free(shared.running_rsc);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_args),
                cmocka_unit_test(list_of_0),
                cmocka_unit_test(list_of_1),
                cmocka_unit_test(list_of_3),
                cmocka_unit_test(list_of_3_return_false))
