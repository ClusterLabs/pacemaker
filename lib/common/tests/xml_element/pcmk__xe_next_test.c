/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>

static void
null_xml(void **state)
{
    assert_null(pcmk__xe_next(NULL, NULL));
    assert_null(pcmk__xe_next(NULL, "test"));
}


#define XML_NO_SIBLINGS             \
    "<xml>\n"                       \
    "  <!-- comment -->"            \
    "  <foo id='child1'>text</foo>" \
    "  <!-- another comment -->"    \
    "</xml>"

static void
no_siblings(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_NO_SIBLINGS);
    xmlNode *child = NULL;

    assert_non_null(xml);

    child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
    assert_non_null(child);
    assert_string_equal(pcmk__xe_id(child), "child1");

    assert_null(pcmk__xe_next(child, NULL));
    assert_null(pcmk__xe_next(child, "foo"));

    pcmk__xml_free(xml);
}

#define XML_SIBLINGS                    \
    "<xml>\n"                           \
    "  <!-- comment -->"                \
    "  <foo id='child1'>text</foo>"     \
    "  <!-- another comment -->"        \
    "  <bar id='child2'>text</bar>"     \
    "  <!-- yet another comment -->"    \
    "  <foo id='child3'>text</foo>"     \
    "</xml>"

static void
with_siblings(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_SIBLINGS);
    xmlNode *child = NULL;
    xmlNode *next = NULL;

    assert_non_null(xml);

    child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
    assert_non_null(child);
    assert_string_equal(pcmk__xe_id(child), "child1");

    next = pcmk__xe_next(child, NULL);
    assert_non_null(next);
    assert_string_equal(pcmk__xe_id(next), "child2");

    next = pcmk__xe_next(child, "bar");
    assert_non_null(next);
    assert_string_equal(pcmk__xe_id(next), "child2");

    next = pcmk__xe_next(child, "foo");
    assert_non_null(next);
    assert_string_equal(pcmk__xe_id(next), "child3");

    next = pcmk__xe_next(child, "foobar");
    assert_null(next);

    pcmk__xml_free(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_xml),
                cmocka_unit_test(no_siblings),
                cmocka_unit_test(with_siblings));
