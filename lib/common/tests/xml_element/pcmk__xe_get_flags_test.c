/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>         // UINT32_MAX
#include <libxml/tree.h>

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>
#include <crm/common/xml.h>

#define ATTR_NAME "attribute"
#define DEFAULT_VALUE 0xfff

#define assert_flags(value, expected_rc, expected_flags)                \
    do {                                                                \
        int rc = pcmk_rc_ok;                                            \
        uint32_t flags = 0;                                             \
        xmlNode *xml = pcmk__xe_create(NULL, "element");                \
                                                                        \
        pcmk__xe_set(xml, ATTR_NAME, value);                            \
                                                                        \
        /* Without output argument */                                   \
        rc = pcmk__xe_get_flags(xml, ATTR_NAME, NULL, DEFAULT_VALUE);   \
        assert_int_equal(rc, expected_rc);                              \
                                                                        \
        /* With output argument */                                      \
        rc = pcmk__xe_get_flags(xml, ATTR_NAME, &flags, DEFAULT_VALUE); \
        assert_int_equal(rc, expected_rc);                              \
        assert_true(flags == expected_flags);                           \
                                                                        \
        pcmk__xml_free(xml);                                            \
    } while (0)

static void
null_name_invalid(void **state)
{
    int rc = pcmk_rc_ok;
    uint32_t flags = 0U;
    xmlNode *xml = pcmk__xe_create(NULL, "element");

    assert_non_null(xml);

    assert_int_equal(pcmk__xe_get_flags(NULL, NULL, NULL, DEFAULT_VALUE),
                     EINVAL);

    assert_int_equal(pcmk__xe_get_flags(xml, NULL, NULL, DEFAULT_VALUE),
                     EINVAL);

    rc = pcmk__xe_get_flags(xml, NULL, &flags, DEFAULT_VALUE);
    assert_int_equal(rc, EINVAL);
    assert_true(flags == DEFAULT_VALUE);

    flags = 0U;
    rc = pcmk__xe_get_flags(NULL, NULL, &flags, DEFAULT_VALUE);
    assert_int_equal(rc, EINVAL);
    assert_true(flags == DEFAULT_VALUE);

    pcmk__xml_free(xml);
}

static void
null_xml_default(void **state)
{
    int rc = pcmk_rc_ok;
    uint32_t flags = 0U;

    assert_int_equal(pcmk__xe_get_flags(NULL, ATTR_NAME, NULL, DEFAULT_VALUE),
                     pcmk_rc_ok);

    rc = pcmk__xe_get_flags(NULL, ATTR_NAME, &flags, DEFAULT_VALUE);
    assert_int_equal(rc, pcmk_rc_ok);
    assert_true(flags == DEFAULT_VALUE);
}

static void
no_attr_default(void **state)
{
    assert_flags(NULL, pcmk_rc_ok, DEFAULT_VALUE);
}

static void
invalid_attr_default(void **state)
{
    char *too_big = pcmk__assert_asprintf("%lld", UINT32_MAX + 1LL);

    assert_flags("x", pcmk_rc_bad_input, DEFAULT_VALUE);
    assert_flags("-1", pcmk_rc_bad_input, DEFAULT_VALUE);
    assert_flags(too_big, pcmk_rc_bad_input, DEFAULT_VALUE);
    free(too_big);
}

static void
valid_attr(void **state)
{
    assert_flags("0", pcmk_rc_ok, 0x0);
    assert_flags("15", pcmk_rc_ok, 0x0f);
    assert_flags("61462", pcmk_rc_ok, 0xf016);
    assert_flags("4294967295", pcmk_rc_ok, 0xffffffff);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_name_invalid),
                cmocka_unit_test(null_xml_default),
                cmocka_unit_test(no_attr_default),
                cmocka_unit_test(invalid_attr_default),
                cmocka_unit_test(valid_attr))
