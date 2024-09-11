/*
 * Copyright 2024 the Pacemaker project contributors
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

static void
assert_comment(xmlDoc *doc, const char *content)
{
    xmlNode *node = NULL;
    xml_node_private_t *nodepriv = NULL;
    xml_doc_private_t *docpriv = doc->_private;

    // Also clears existing doc flags
    xml_track_changes((xmlNode *) doc, NULL, NULL, false);

    node = pcmk__xc_create(doc, content);
    assert_non_null(node);
    assert_int_equal(node->type, XML_COMMENT_NODE);
    assert_ptr_equal(node->doc, doc);

    if (content == NULL) {
        assert_null(node->content);
    } else {
        assert_non_null(node->content);
        assert_string_equal((const char *) node->content, content);
    }

    nodepriv = node->_private;
    assert_non_null(nodepriv);
    assert_int_equal(nodepriv->check, PCMK__XML_NODE_PRIVATE_MAGIC);
    assert_true(pcmk_all_flags_set(nodepriv->flags,
                                   pcmk__xf_dirty|pcmk__xf_created));

    assert_true(pcmk_is_set(docpriv->flags, pcmk__xf_dirty));

    free_xml(node);
}

static void
null_doc(void **state)
{
    pcmk__assert_asserts(pcmk__xc_create(NULL, NULL));
    pcmk__assert_asserts(pcmk__xc_create(NULL, "some content"));
}

static void
with_doc(void **state)
{
    xmlDoc *doc = pcmk__xml_new_doc();

    assert_non_null(doc);
    assert_non_null(doc->_private);

    assert_comment(doc, NULL);
    assert_comment(doc, "some content");

    pcmk__xml_free_doc(doc);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_doc),
                cmocka_unit_test(with_doc));
