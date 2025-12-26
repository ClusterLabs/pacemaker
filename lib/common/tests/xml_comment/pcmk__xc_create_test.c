/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "crmcommon_private.h"

/* This tests new_private_data() indirectly for comment nodes. Testing
 * free_private_data() would be much less straightforward and is not worth the
 * hassle.
 */

#define CONTENT "some content"

#define assert_create_comment(content, doc_ptr, node_ptr)                   \
    do {                                                                    \
        xml_doc_private_t *docpriv = NULL;                                  \
        xml_node_private_t *nodepriv = NULL;                                \
                                                                            \
        *(doc_ptr) = pcmk__xml_new_doc();                                   \
        pcmk__xml_doc_set_flags(*(doc_ptr), pcmk__xf_tracking);             \
                                                                            \
        *(node_ptr) = pcmk__xc_create(*(doc_ptr), content);                 \
        assert_non_null(*(node_ptr));                                       \
        assert_int_equal((*(node_ptr))->type, XML_COMMENT_NODE);            \
        assert_ptr_equal((*(node_ptr))->doc, *(doc_ptr));                   \
                                                                            \
        docpriv = (*(doc_ptr))->_private;                                   \
        assert_true(pcmk__is_set(docpriv->flags, pcmk__xf_dirty));          \
                                                                            \
        nodepriv = (*(node_ptr))->_private;                                 \
        assert_non_null(nodepriv);                                          \
        assert_int_equal(nodepriv->check, PCMK__XML_NODE_PRIVATE_MAGIC);    \
        assert_true(pcmk__all_flags_set(nodepriv->flags,                    \
                                        pcmk__xf_dirty|pcmk__xf_created));  \
    } while (0)

static void
null_doc(void **state)
{
    pcmk__assert_asserts(pcmk__xc_create(NULL, NULL));
    pcmk__assert_asserts(pcmk__xc_create(NULL, "some content"));
}

static void
with_doc(void **state)
{
    xmlDoc *doc = NULL;
    xmlNode *node = NULL;

    assert_create_comment(NULL, &doc, &node);
    assert_null(node->content);

    g_clear_pointer(&node, pcmk__xml_free);
    g_clear_pointer(&doc, pcmk__xml_free_doc);

    assert_create_comment(CONTENT, &doc, &node);
    assert_non_null(node->content);
    assert_string_equal((const char *) node->content, CONTENT);

    g_clear_pointer(&node, pcmk__xml_free);
    g_clear_pointer(&doc, pcmk__xml_free_doc);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_doc),
                cmocka_unit_test(with_doc));
