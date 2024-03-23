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
null_empty(void **state)
{
    gchar *str = NULL;

    str = pcmk__xml_escape(NULL, false);
    assert_null(str);

    str = pcmk__xml_escape(NULL, true);
    assert_null(str);

    str = pcmk__xml_escape("", false);
    assert_string_equal(str, "");
    g_free(str);

    str = pcmk__xml_escape("", true);
    assert_string_equal(str, "");
    g_free(str);
}

static void
escape_unchanged(void **state)
{
    // No escaped characters (note: this string includes single quote at end)
    const char *unchanged = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
                            "`~!@#$%^*()-_=+/|\\[]{}?.,'";
    gchar *str = NULL;

    str = pcmk__xml_escape(unchanged, false);
    assert_string_equal(str, unchanged);
    g_free(str);

    str = pcmk__xml_escape(unchanged, true);
    assert_string_equal(str, unchanged);
    g_free(str);
}

// Ensure special characters get escaped at start, middle, and end

static void
escape_left_angle(void **state)
{
    const char *l_angle = "<abc<def<";
    const char *l_angle_esc = "&lt;abc&lt;def&lt;";
    gchar *str = NULL;

    str = pcmk__xml_escape(l_angle, false);
    assert_string_equal(str, l_angle_esc);
    g_free(str);

    str = pcmk__xml_escape(l_angle, true);
    assert_string_equal(str, l_angle_esc);
    g_free(str);
}

static void
escape_right_angle(void **state)
{
    const char *r_angle = ">abc>def>";
    const char *r_angle_esc = "&gt;abc&gt;def&gt;";
    gchar *str = NULL;

    str = pcmk__xml_escape(r_angle, false);
    assert_string_equal(str, r_angle_esc);
    g_free(str);

    str = pcmk__xml_escape(r_angle, true);
    assert_string_equal(str, r_angle_esc);
    g_free(str);
}

static void
escape_ampersand(void **state)
{
    const char *ampersand = "&abc&def&";
    const char *ampersand_esc = "&amp;abc&amp;def&amp;";
    gchar *str = NULL;

    str = pcmk__xml_escape(ampersand, false);
    assert_string_equal(str, ampersand_esc);
    g_free(str);

    str = pcmk__xml_escape(ampersand, true);
    assert_string_equal(str, ampersand_esc);
    g_free(str);
}

static void
escape_double_quote(void **state)
{
    const char *double_quote = "\"abc\"def\"";
    const char *double_quote_esc = "&quot;abc&quot;def&quot;";
    gchar *str = NULL;

    str = pcmk__xml_escape(double_quote, false);
    assert_string_equal(str, double_quote);
    g_free(str);

    str = pcmk__xml_escape(double_quote, true);
    assert_string_equal(str, double_quote_esc);
    g_free(str);
}

static void
escape_newline(void **state)
{
    const char *newline = "\nabc\ndef\n";
    const char *newline_esc = "&#x0A;abc&#x0A;def&#x0A;";
    gchar *str = NULL;

    str = pcmk__xml_escape(newline, false);
    assert_string_equal(str, newline);
    g_free(str);

    str = pcmk__xml_escape(newline, true);
    assert_string_equal(str, newline_esc);
    g_free(str);
}

static void
escape_tab(void **state)
{
    const char *tab = "\tabc\tdef\t";
    const char *tab_esc = "&#x09;abc&#x09;def&#x09;";
    gchar *str = NULL;

    str = pcmk__xml_escape(tab, false);
    assert_string_equal(str, tab);
    g_free(str);

    str = pcmk__xml_escape(tab, true);
    assert_string_equal(str, tab_esc);
    g_free(str);
}

static void
escape_carriage_return(void **state)
{
    const char *cr = "\rabc\rdef\r";
    const char *cr_esc = "&#x0D;abc&#x0D;def&#x0D;";
    gchar *str = NULL;

    str = pcmk__xml_escape(cr, false);
    assert_string_equal(str, cr_esc);
    g_free(str);

    str = pcmk__xml_escape(cr, true);
    assert_string_equal(str, cr_esc);
    g_free(str);
}

static void
escape_nonprinting(void **state)
{
    const char *nonprinting = "\a\x7F\x1B";
    const char *nonprinting_esc = "&#x07;&#x7F;&#x1B;";
    gchar *str = NULL;

    str = pcmk__xml_escape(nonprinting, false);
    assert_string_equal(str, nonprinting_esc);
    g_free(str);

    str = pcmk__xml_escape(nonprinting, true);
    assert_string_equal(str, nonprinting_esc);
    g_free(str);
}

static void
escape_utf8(void **state)
{
    /* Non-ASCII UTF-8 characters may be two, three, or four 8-bit bytes wide
     * and should not be escaped.
     */
    const char *chinese = "仅高级使用";
    const char *two_byte = "abc""\xCF\xA6""d<ef";
    const char *two_byte_esc = "abc""\xCF\xA6""d&lt;ef";
    const char *three_byte = "abc""\xEF\x98\x98""d<ef";
    const char *three_byte_esc = "abc""\xEF\x98\x98""d&lt;ef";
    const char *four_byte = "abc""\xF0\x94\x81\x90""d<ef";
    const char *four_byte_esc = "abc""\xF0\x94\x81\x90""d&lt;ef";
    gchar *str = NULL;

    str = pcmk__xml_escape(chinese, false);
    assert_string_equal(str, chinese);
    g_free(str);

    str = pcmk__xml_escape(chinese, true);
    assert_string_equal(str, chinese);
    g_free(str);

    str = pcmk__xml_escape(two_byte, false);
    assert_string_equal(str, two_byte_esc);
    g_free(str);

    str = pcmk__xml_escape(two_byte, true);
    assert_string_equal(str, two_byte_esc);
    g_free(str);

    str = pcmk__xml_escape(three_byte, false);
    assert_string_equal(str, three_byte_esc);
    g_free(str);

    str = pcmk__xml_escape(three_byte, true);
    assert_string_equal(str, three_byte_esc);
    g_free(str);

    str = pcmk__xml_escape(four_byte, false);
    assert_string_equal(str, four_byte_esc);
    g_free(str);

    str = pcmk__xml_escape(four_byte, true);
    assert_string_equal(str, four_byte_esc);
    g_free(str);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_empty),
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
