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

static void
empty_list(void **state)
{
    assert_null(pcmk__find_node_in_list(NULL, NULL));
    assert_null(pcmk__find_node_in_list(NULL, "cluster1"));
}

static void
non_null_list(void **state)
{
    struct pcmk__node_private node1_priv = { .name = "cluster1" };
    struct pcmk__node_private node2_priv = { .name = "cluster2" };
    pcmk_node_t node1 = { .priv = &node1_priv };
    pcmk_node_t node2 = { .priv = &node2_priv };
    GList *nodes = NULL;

    nodes = g_list_prepend(nodes, &node1);
    nodes = g_list_prepend(nodes, &node2);

    assert_ptr_equal(&node1, pcmk__find_node_in_list(nodes, "cluster1"));
    assert_null(pcmk__find_node_in_list(nodes, "cluster10"));
    assert_null(pcmk__find_node_in_list(nodes, "nodecluster1"));
    assert_ptr_equal(&node2, pcmk__find_node_in_list(nodes, "CLUSTER2"));
    assert_null(pcmk__find_node_in_list(nodes, "xyz"));

    g_list_free(nodes);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_list),
                cmocka_unit_test(non_null_list))
