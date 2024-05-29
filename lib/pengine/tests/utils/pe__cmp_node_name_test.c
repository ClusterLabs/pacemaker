/*
 * Copyright 2022-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/pengine/internal.h>

struct pcmk__node_private node1_private;
struct pcmk__node_private node2_private;

pcmk_node_t node1 = { .private = &node1_private };
pcmk_node_t node2 = { .private = &node2_private };

static void
nodes_equal(void **state)
{
    assert_int_equal(pe__cmp_node_name(NULL, NULL), 0);

    node1.private->name = "node10";
    node2.private->name = "node10";
    assert_int_equal(pe__cmp_node_name(&node1, &node2), 0);
}

static void
node1_first(void **state)
{
    assert_int_equal(pe__cmp_node_name(NULL, &node2), -1);

    // The heavy testing is done in pcmk__numeric_strcasecmp()'s unit tests
    node1.private->name = "node9";
    node2.private->name = "node10";
    assert_int_equal(pe__cmp_node_name(&node1, &node2), -1);
}

static void
node2_first(void **state)
{
    assert_int_equal(pe__cmp_node_name(&node1, NULL), 1);

    node1.private->name = "node10";
    node2.private->name = "node9";
    assert_int_equal(pe__cmp_node_name(&node1, &node2), 1);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(nodes_equal),
                cmocka_unit_test(node1_first),
                cmocka_unit_test(node2_first))
