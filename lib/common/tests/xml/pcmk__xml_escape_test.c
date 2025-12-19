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

#define assert_escape(str, reference, type)         \
    do {                                            \
        gchar *buf = pcmk__xml_escape(str, type);   \
                                                    \
        assert_string_equal(buf, reference);        \
        g_free(buf);                                \
    } while (0)

static void
null_empty(void **state)
{
    assert_null(pcmk__xml_escape(NULL, pcmk__xml_escape_text));
    assert_null(pcmk__xml_escape(NULL, pcmk__xml_escape_attr));
    assert_null(pcmk__xml_escape(NULL, pcmk__xml_escape_attr_pretty));

    assert_escape("", "", pcmk__xml_escape_text);
    assert_escape("", "", pcmk__xml_escape_attr);
    assert_escape("", "", pcmk__xml_escape_attr_pretty);
}

static void
invalid_type(void **state)
{
    const enum pcmk__xml_escape_type type = (enum pcmk__xml_escape_type) -1;

    // Easier to ignore invalid type for NULL or empty string
    assert_null(pcmk__xml_escape(NULL, type));
    assert_escape("", "", type);

    // Otherwise, assert if we somehow passed an invalid type
    pcmk__assert_asserts(pcmk__xml_escape("he<>llo", type));
}

static void
escape_unchanged(void **state)
{
    // No escaped characters (note: this string includes single quote at end)
    const char *unchanged = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
                            "`~!@#$%^*()-_=+/|\\[]{}?.,'";

    assert_escape(unchanged, unchanged, pcmk__xml_escape_text);
    assert_escape(unchanged, unchanged, pcmk__xml_escape_attr);
    assert_escape(unchanged, unchanged, pcmk__xml_escape_attr_pretty);
}

// Ensure special characters get escaped at start, middle, and end

static void
escape_left_angle(void **state)
{
    const char *l_angle = "<abc<def<";
    const char *l_angle_esc = PCMK__XML_ENTITY_LT "abc"
                              PCMK__XML_ENTITY_LT "def" PCMK__XML_ENTITY_LT;

    assert_escape(l_angle, l_angle_esc, pcmk__xml_escape_text);
    assert_escape(l_angle, l_angle_esc, pcmk__xml_escape_attr);
    assert_escape(l_angle, l_angle, pcmk__xml_escape_attr_pretty);
}

static void
escape_right_angle(void **state)
{
    const char *r_angle = ">abc>def>";
    const char *r_angle_esc = PCMK__XML_ENTITY_GT "abc"
                              PCMK__XML_ENTITY_GT "def" PCMK__XML_ENTITY_GT;

    assert_escape(r_angle, r_angle_esc, pcmk__xml_escape_text);
    assert_escape(r_angle, r_angle_esc, pcmk__xml_escape_attr);
    assert_escape(r_angle, r_angle, pcmk__xml_escape_attr_pretty);
}

static void
escape_ampersand(void **state)
{
    const char *ampersand = "&abc&def&";
    const char *ampersand_esc = PCMK__XML_ENTITY_AMP "abc"
                                PCMK__XML_ENTITY_AMP "def" PCMK__XML_ENTITY_AMP;

    assert_escape(ampersand, ampersand_esc, pcmk__xml_escape_text);
    assert_escape(ampersand, ampersand_esc, pcmk__xml_escape_attr);
    assert_escape(ampersand, ampersand, pcmk__xml_escape_attr_pretty);
}

static void
escape_double_quote(void **state)
{
    const char *double_quote = "\"abc\"def\"";
    const char *double_quote_esc_ref = PCMK__XML_ENTITY_QUOT "abc"
                                       PCMK__XML_ENTITY_QUOT "def"
                                       PCMK__XML_ENTITY_QUOT;
    const char *double_quote_esc_backslash = "\\\"abc\\\"def\\\"";

    assert_escape(double_quote, double_quote, pcmk__xml_escape_text);
    assert_escape(double_quote, double_quote_esc_ref, pcmk__xml_escape_attr);
    assert_escape(double_quote, double_quote_esc_backslash,
                  pcmk__xml_escape_attr_pretty);
}

static void
escape_newline(void **state)
{
    const char *newline = "\nabc\ndef\n";
    const char *newline_esc_ref = "&#x0A;abc&#x0A;def&#x0A;";
    const char *newline_esc_backslash = "\\nabc\\ndef\\n";

    assert_escape(newline, newline, pcmk__xml_escape_text);
    assert_escape(newline, newline_esc_ref, pcmk__xml_escape_attr);
    assert_escape(newline, newline_esc_backslash, pcmk__xml_escape_attr_pretty);
}

static void
escape_tab(void **state)
{
    const char *tab = "\tabc\tdef\t";
    const char *tab_esc_ref = "&#x09;abc&#x09;def&#x09;";
    const char *tab_esc_backslash = "\\tabc\\tdef\\t";

    assert_escape(tab, tab, pcmk__xml_escape_text);
    assert_escape(tab, tab_esc_ref, pcmk__xml_escape_attr);
    assert_escape(tab, tab_esc_backslash, pcmk__xml_escape_attr_pretty);
}

static void
escape_carriage_return(void **state)
{
    const char *cr = "\rabc\rdef\r";
    const char *cr_esc_ref = "&#x0D;abc&#x0D;def&#x0D;";
    const char *cr_esc_backslash = "\\rabc\\rdef\\r";

    assert_escape(cr, cr_esc_ref, pcmk__xml_escape_text);
    assert_escape(cr, cr_esc_ref, pcmk__xml_escape_attr);
    assert_escape(cr, cr_esc_backslash, pcmk__xml_escape_attr_pretty);
}

static void
escape_nonprinting(void **state)
{
    const char *nonprinting = "\a\x7F\x1B";
    const char *nonprinting_esc = "&#x07;&#x7F;&#x1B;";

    assert_escape(nonprinting, nonprinting_esc, pcmk__xml_escape_text);
    assert_escape(nonprinting, nonprinting_esc, pcmk__xml_escape_attr);
    assert_escape(nonprinting, nonprinting, pcmk__xml_escape_attr_pretty);
}

static void
escape_utf8(void **state)
{
    /* Non-ASCII UTF-8 characters may be two, three, or four 8-bit bytes wide
     * and should not be escaped.
     */
    const char *chinese = "仅高级使用";
    const char *two_byte = "abc""\xCF\xA6""d<ef";
    const char *two_byte_esc = "abc""\xCF\xA6""d" PCMK__XML_ENTITY_LT "ef";

    const char *three_byte = "abc""\xEF\x98\x98""d<ef";
    const char *three_byte_esc = "abc""\xEF\x98\x98""d"
                                 PCMK__XML_ENTITY_LT "ef";

    const char *four_byte = "abc""\xF0\x94\x81\x90""d<ef";
    const char *four_byte_esc = "abc""\xF0\x94\x81\x90""d"
                                PCMK__XML_ENTITY_LT "ef";

    assert_escape(chinese, chinese, pcmk__xml_escape_text);
    assert_escape(chinese, chinese, pcmk__xml_escape_attr);
    assert_escape(chinese, chinese, pcmk__xml_escape_attr_pretty);

    assert_escape(two_byte, two_byte_esc, pcmk__xml_escape_text);
    assert_escape(two_byte, two_byte_esc, pcmk__xml_escape_attr);
    assert_escape(two_byte, two_byte, pcmk__xml_escape_attr_pretty);

    assert_escape(three_byte, three_byte_esc, pcmk__xml_escape_text);
    assert_escape(three_byte, three_byte_esc, pcmk__xml_escape_attr);
    assert_escape(three_byte, three_byte, pcmk__xml_escape_attr_pretty);

    assert_escape(four_byte, four_byte_esc, pcmk__xml_escape_text);
    assert_escape(four_byte, four_byte_esc, pcmk__xml_escape_attr);
    assert_escape(four_byte, four_byte, pcmk__xml_escape_attr_pretty);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_empty),
                cmocka_unit_test(invalid_type),
                cmocka_unit_test(escape_unchanged),
                cmocka_unit_test(escape_left_angle),
                cmocka_unit_test(escape_right_angle),
                cmocka_unit_test(escape_ampersand),
                cmocka_unit_test(escape_double_quote),
                cmocka_unit_test(escape_newline),
                cmocka_unit_test(escape_tab),
                cmocka_unit_test(escape_carriage_return),
                cmocka_unit_test(escape_nonprinting),
                cmocka_unit_test(escape_utf8));
