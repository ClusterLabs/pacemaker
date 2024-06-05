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
#include <crm/common/xml_internal.h>

static void
null_node(void **state)
{
    pcmk__xe_set_id(NULL, "test_id");
}

static void
null_format(void **state)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");

    pcmk__assert_asserts(pcmk__xe_set_id(NULL, NULL));
    pcmk__assert_asserts(pcmk__xe_set_id(test_xml, NULL));

#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
#endif  // HAVE_FORMAT_NONLITERAL
    pcmk__assert_asserts(pcmk__xe_set_id(test_xml, ""));
#ifdef HAVE_FORMAT_NONLITERAL
#pragma GCC diagnostic pop
#endif  // HAVE_FORMAT_NONLITERAL

    pcmk__xml_free(test_xml);
}

static void
valid_id(void **state)
{
    // IDs that are already valid XML names
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");
    const char *id = NULL;

    // No ID set initially
    pcmk__xe_set_id(test_xml, "test_id");
    assert_string_equal(pcmk__xe_id(test_xml), "test_id");

    // ID already set: test overwrite
    // #xEFFFF (NameStartChar), #xB7 (NameChar)
    id = "\xF3\xAF\xBF\xBF" "\xC2\xB7";
    pcmk__xe_set_id(test_xml, "%s", id);
    assert_string_equal(pcmk__xe_id(test_xml), id);

    pcmk__xml_free(test_xml);
}

static void
invalid_id(void **state)
{
    // IDs that need sanitization
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");

    // No ID set initially
    pcmk__xe_set_id(test_xml, "-ab");
    assert_string_equal(pcmk__xe_id(test_xml), "_ab");

    // ID already set: test overwrite
    pcmk__xe_set_id(test_xml, "a$b");
    assert_string_equal(pcmk__xe_id(test_xml), "a.b");

    pcmk__xe_set_id(test_xml, "ab$");
    assert_string_equal(pcmk__xe_id(test_xml), "ab.");

    pcmk__xe_set_id(test_xml, "$$$");
    assert_string_equal(pcmk__xe_id(test_xml), "_..");

    pcmk__xml_free(test_xml);
}

static void
format_args(void **state)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");
    const char *str = "test";
    int num = 42;

    pcmk__xe_set_id(test_xml, "rsc-%s-%d", str, num);
    assert_string_equal(pcmk__xe_id(test_xml), "rsc-test-42");

    pcmk__xml_free(test_xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_node),
                cmocka_unit_test(null_format),
                cmocka_unit_test(valid_id),
                cmocka_unit_test(invalid_id),
                cmocka_unit_test(format_args))
