/*
 * Copyright 2022-2024 the Pacemaker project contributors
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
    GList *nodes = NULL;

    pcmk_node_t *a = pcmk__assert_alloc(1, sizeof(pcmk_node_t));
    pcmk_node_t *b = pcmk__assert_alloc(1, sizeof(pcmk_node_t));

    a->details = pcmk__assert_alloc(1, sizeof(struct pe_node_shared_s));
    a->details->uname = "cluster1";
    b->details = pcmk__assert_alloc(1, sizeof(struct pe_node_shared_s));
    b->details->uname = "cluster2";

    nodes = g_list_append(nodes, a);
    nodes = g_list_append(nodes, b);

    assert_ptr_equal(a, pcmk__find_node_in_list(nodes, "cluster1"));
    assert_null(pcmk__find_node_in_list(nodes, "cluster10"));
    assert_null(pcmk__find_node_in_list(nodes, "nodecluster1"));
    assert_ptr_equal(b, pcmk__find_node_in_list(nodes, "CLUSTER2"));
    assert_null(pcmk__find_node_in_list(nodes, "xyz"));

    free(a->details);
    free(a);
    free(b->details);
    free(b);
    g_list_free(nodes);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_list),
                cmocka_unit_test(non_null_list))
