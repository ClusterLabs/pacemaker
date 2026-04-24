/*
 * Copyright 2022-2026 the Pacemaker project contributors
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

pcmk_node_t node1 = { .priv = &node1_private };
pcmk_node_t node2 = { .priv = &node2_private };

static void
nodes_equal(void **state)
{
    assert_int_equal(pe__cmp_node_name(NULL, NULL), 0);

    node1.priv->name = pcmk__str_copy("node10");
    node2.priv->name = pcmk__str_copy("node10");

    assert_int_equal(pe__cmp_node_name(&node1, &node2), 0);

    free(node1.priv->name);
    free(node2.priv->name);
}

static void
node1_first(void **state)
{
    assert_int_equal(pe__cmp_node_name(NULL, &node2), -1);

    // The heavy testing is done in pcmk__numeric_strcasecmp()'s unit tests
    node1.priv->name = pcmk__str_copy("node9");
    node2.priv->name = pcmk__str_copy("node10");

    assert_int_equal(pe__cmp_node_name(&node1, &node2), -1);

    free(node1.priv->name);
    free(node2.priv->name);
}

static void
node2_first(void **state)
{
    assert_int_equal(pe__cmp_node_name(&node1, NULL), 1);

    node1.priv->name = pcmk__str_copy("node10");
    node2.priv->name = pcmk__str_copy("node9");

    assert_int_equal(pe__cmp_node_name(&node1, &node2), 1);

    free(node1.priv->name);
    free(node2.priv->name);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(nodes_equal),
                cmocka_unit_test(node1_first),
                cmocka_unit_test(node2_first))
