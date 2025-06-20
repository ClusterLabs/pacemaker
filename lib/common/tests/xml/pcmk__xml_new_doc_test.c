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

/* This tests new_private_data() indirectly for document nodes. Testing
 * free_private_data() would be much less straightforward and is not worth the
 * hassle.
 */

static void
create_document_node(void **state) {
    xml_doc_private_t *docpriv = NULL;
    xmlDoc *doc = pcmk__xml_new_doc();

    assert_non_null(doc);
    assert_int_equal(doc->type, XML_DOCUMENT_NODE);

    docpriv = doc->_private;
    assert_non_null(docpriv);
    assert_int_equal(docpriv->check, PCMK__XML_DOC_PRIVATE_MAGIC);
    assert_int_equal(docpriv->flags, pcmk__xf_none);

    pcmk__xml_free_doc(doc);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(create_document_node))
