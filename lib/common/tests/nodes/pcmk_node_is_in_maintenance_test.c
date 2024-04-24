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
#include <glib.h>       // TRUE, FALSE

#include <crm/common/nodes.h>
#include <crm/common/unittest_internal.h>

static void
null_is_not_in_maintenance(void **state)
{
    assert_false(pcmk_node_is_in_maintenance(NULL));
}

static void
node_is_in_maintenance(void **state)
{
    struct pe_node_shared_s shared = {
        .maintenance = TRUE,
    };

    pcmk_node_t node = {
        .details = &shared,
    };

    assert_true(pcmk_node_is_in_maintenance(&node));
}

static void
node_is_not_in_maintenance(void **state)
{
    struct pe_node_shared_s shared = {
        .maintenance = FALSE,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    assert_false(pcmk_node_is_in_maintenance(&node));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_is_not_in_maintenance),
                cmocka_unit_test(node_is_in_maintenance),
                cmocka_unit_test(node_is_not_in_maintenance))
