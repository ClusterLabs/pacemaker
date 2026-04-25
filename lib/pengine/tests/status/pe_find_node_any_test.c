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
    assert_null(pe_find_node_any(NULL, NULL, NULL));
    assert_null(pe_find_node_any(NULL, NULL, "cluster1"));
    assert_null(pe_find_node_any(NULL, "id1", NULL));
    assert_null(pe_find_node_any(NULL, "id1", "cluster1"));
}

static void
non_null_list(void **state)
{
    struct pcmk__node_private node1_priv = {
        .id = pcmk__str_copy("id1"),
        .name = pcmk__str_copy("cluster1"),
    };
    struct pcmk__node_private node2_priv = {
        .id = pcmk__str_copy("id2"),
        .name = pcmk__str_copy("cluster2"),
    };
    pcmk_node_t node1 = { .priv = &node1_priv };
    pcmk_node_t node2 = { .priv = &node2_priv };
    GList *nodes = NULL;

    nodes = g_list_prepend(nodes, &node1);
    nodes = g_list_prepend(nodes, &node2);

    assert_ptr_equal(&node1, pe_find_node_any(nodes, "xyz", "cluster1"));
    assert_ptr_equal(&node1, pe_find_node_any(nodes, NULL, "cluster1"));

    assert_ptr_equal(&node2, pe_find_node_any(nodes, "id2", NULL));
    assert_ptr_equal(&node2, pe_find_node_any(nodes, "ID2", NULL));

    assert_null(pe_find_node_any(nodes, "id10", NULL));
    assert_null(pe_find_node_any(nodes, "nodeid1", NULL));
    assert_null(pe_find_node_any(nodes, NULL, "cluster10"));
    assert_null(pe_find_node_any(nodes, NULL, "nodecluster1"));
    assert_null(pe_find_node_any(nodes, "id3", "cluster3"));
    assert_null(pe_find_node_any(nodes, NULL, NULL));

    free(node1_priv.id);
    free(node1_priv.name);
    free(node2_priv.id);
    free(node2_priv.name);
    g_list_free(nodes);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_list),
                cmocka_unit_test(non_null_list))
