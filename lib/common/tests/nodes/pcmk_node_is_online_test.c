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
null_is_offline(void **state)
{
    assert_false(pcmk_node_is_online(NULL));
}

static void
node_is_online(void **state)
{
    struct pe_node_shared_s shared = {
        .online = TRUE,
    };

    pcmk_node_t node = {
        .details = &shared,
    };

    assert_true(pcmk_node_is_online(&node));
}

static void
node_is_offline(void **state)
{
    struct pe_node_shared_s shared = {
        .online = FALSE,
    };
    pcmk_node_t node = {
        .details = &shared,
    };

    assert_false(pcmk_node_is_online(&node));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_is_offline),
                cmocka_unit_test(node_is_online),
                cmocka_unit_test(node_is_offline))
