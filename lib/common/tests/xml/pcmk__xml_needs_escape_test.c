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

#include "crmcommon_private.h"

static void
null_empty(void **state)
{
    assert_false(pcmk__xml_needs_escape(NULL, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(NULL, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(NULL, pcmk__xml_escape_attr_pretty));

    assert_false(pcmk__xml_needs_escape("", pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape("", pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape("", pcmk__xml_escape_attr_pretty));
}

static void
invalid_type(void **state)
{
    const enum pcmk__xml_escape_type type = (enum pcmk__xml_escape_type) -1;

    // Easier to ignore invalid type for NULL or empty string
    assert_false(pcmk__xml_needs_escape(NULL, type));
    assert_false(pcmk__xml_needs_escape("", type));

    // Otherwise, assert if we somehow passed an invalid type
    pcmk__assert_asserts(pcmk__xml_needs_escape("he<>llo", type));
}

static void
escape_unchanged(void **state)
{
    // No escaped characters (note: this string includes single quote at end)
    const char *unchanged = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
                            "`~!@#$%^*()-_=+/|\\[]{}?.,'";

    assert_false(pcmk__xml_needs_escape(unchanged, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(unchanged, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(unchanged,
                                        pcmk__xml_escape_attr_pretty));
}

// Ensure special characters get escaped at start, middle, and end

static void
escape_left_angle(void **state)
{
    const char *l_angle_left = "<abcdef";
    const char *l_angle_mid = "abc<def";
    const char *l_angle_right = "abcdef<";

    assert_true(pcmk__xml_needs_escape(l_angle_left, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(l_angle_mid, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(l_angle_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(l_angle_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(l_angle_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(l_angle_right, pcmk__xml_escape_attr));

    assert_false(pcmk__xml_needs_escape(l_angle_left,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(l_angle_mid,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(l_angle_right,
                                        pcmk__xml_escape_attr_pretty));
}

static void
escape_right_angle(void **state)
{
    const char *r_angle_left = ">abcdef";
    const char *r_angle_mid = "abc>def";
    const char *r_angle_right = "abcdef>";

    assert_true(pcmk__xml_needs_escape(r_angle_left, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(r_angle_mid, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(r_angle_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(r_angle_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(r_angle_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(r_angle_right, pcmk__xml_escape_attr));

    assert_false(pcmk__xml_needs_escape(r_angle_left,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(r_angle_mid,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(r_angle_right,
                                        pcmk__xml_escape_attr_pretty));
}

static void
escape_ampersand(void **state)
{
    const char *ampersand_left = "&abcdef";
    const char *ampersand_mid = "abc&def";
    const char *ampersand_right = "abcdef&";

    assert_true(pcmk__xml_needs_escape(ampersand_left, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(ampersand_mid, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(ampersand_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(ampersand_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(ampersand_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(ampersand_right, pcmk__xml_escape_attr));

    assert_false(pcmk__xml_needs_escape(ampersand_left,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(ampersand_mid,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(ampersand_right,
                                        pcmk__xml_escape_attr_pretty));
}

static void
escape_double_quote(void **state)
{
    const char *double_quote_left = "\"abcdef";
    const char *double_quote_mid = "abc\"def";
    const char *double_quote_right = "abcdef\"";

    assert_false(pcmk__xml_needs_escape(double_quote_left,
                                        pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(double_quote_mid,
                                        pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(double_quote_right,
                                        pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(double_quote_left,
                                       pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(double_quote_mid,
                                       pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(double_quote_right,
                                       pcmk__xml_escape_attr));

    assert_true(pcmk__xml_needs_escape(double_quote_left,
                                       pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(double_quote_mid,
                                       pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(double_quote_right,
                                       pcmk__xml_escape_attr_pretty));
}

static void
escape_newline(void **state)
{
    const char *newline_left = "\nabcdef";
    const char *newline_mid = "abc\ndef";
    const char *newline_right = "abcdef\n";

    assert_false(pcmk__xml_needs_escape(newline_left, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(newline_mid, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(newline_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(newline_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(newline_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(newline_right, pcmk__xml_escape_attr));

    assert_true(pcmk__xml_needs_escape(newline_left,
                                       pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(newline_mid,
                                       pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(newline_right,
                                       pcmk__xml_escape_attr_pretty));
}

static void
escape_tab(void **state)
{
    const char *tab_left = "\tabcdef";
    const char *tab_mid = "abc\tdef";
    const char *tab_right = "abcdef\t";

    assert_false(pcmk__xml_needs_escape(tab_left, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(tab_mid, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(tab_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(tab_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(tab_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(tab_right, pcmk__xml_escape_attr));

    assert_true(pcmk__xml_needs_escape(tab_left, pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(tab_mid, pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(tab_right,
                                       pcmk__xml_escape_attr_pretty));
}

static void
escape_carriage_return(void **state)
{
    const char *cr_left = "\rabcdef";
    const char *cr_mid = "abc\rdef";
    const char *cr_right = "abcdef\r";

    assert_true(pcmk__xml_needs_escape(cr_left, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(cr_mid, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(cr_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(cr_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(cr_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(cr_right, pcmk__xml_escape_attr));

    assert_true(pcmk__xml_needs_escape(cr_left, pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(cr_mid, pcmk__xml_escape_attr_pretty));
    assert_true(pcmk__xml_needs_escape(cr_right, pcmk__xml_escape_attr_pretty));
}

static void
escape_nonprinting(void **state)
{
    const char *alert_left = "\aabcdef";
    const char *alert_mid = "abc\adef";
    const char *alert_right = "abcdef\a";

    const char *delete_left = "\x7F""abcdef";
    const char *delete_mid = "abc\x7F""def";
    const char *delete_right = "abcdef\x7F";

    const char *nonprinting_all = "\a\x7F\x1B";

    assert_true(pcmk__xml_needs_escape(alert_left, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(alert_mid, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(alert_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(alert_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(alert_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(alert_right, pcmk__xml_escape_attr));

    assert_false(pcmk__xml_needs_escape(alert_left,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(alert_mid,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(alert_right,
                                        pcmk__xml_escape_attr_pretty));

    assert_true(pcmk__xml_needs_escape(delete_left, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(delete_mid, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(delete_right, pcmk__xml_escape_text));

    assert_true(pcmk__xml_needs_escape(delete_left, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(delete_mid, pcmk__xml_escape_attr));
    assert_true(pcmk__xml_needs_escape(delete_right, pcmk__xml_escape_attr));

    assert_false(pcmk__xml_needs_escape(delete_left,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(delete_mid,
                                        pcmk__xml_escape_attr_pretty));
    assert_false(pcmk__xml_needs_escape(delete_right,
                                        pcmk__xml_escape_attr_pretty));

    assert_true(pcmk__xml_needs_escape(nonprinting_all, pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(nonprinting_all, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(nonprinting_all,
                                        pcmk__xml_escape_attr_pretty));
}

static void
escape_utf8(void **state)
{
    /* Non-ASCII UTF-8 characters may be two, three, or four 8-bit bytes wide
     * and should not be escaped.
     */
    const char *chinese = "仅高级使用";
    const char *two_byte = "abc""\xCF\xA6""def";
    const char *two_byte_special = "abc""\xCF\xA6""d<ef";
    const char *three_byte = "abc""\xEF\x98\x98""def";
    const char *three_byte_special = "abc""\xEF\x98\x98""d<ef";
    const char *four_byte = "abc""\xF0\x94\x81\x90""def";
    const char *four_byte_special = "abc""\xF0\x94\x81\x90""d<ef";

    assert_false(pcmk__xml_needs_escape(chinese, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(chinese, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(chinese, pcmk__xml_escape_attr_pretty));

    assert_false(pcmk__xml_needs_escape(two_byte, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(two_byte, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(two_byte,
                                        pcmk__xml_escape_attr_pretty));

    assert_true(pcmk__xml_needs_escape(two_byte_special,
                                       pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(two_byte_special,
                                       pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(two_byte_special,
                                        pcmk__xml_escape_attr_pretty));

    assert_false(pcmk__xml_needs_escape(three_byte, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(three_byte, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(three_byte,
                                        pcmk__xml_escape_attr_pretty));

    assert_true(pcmk__xml_needs_escape(three_byte_special,
                                       pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(three_byte_special,
                                       pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(three_byte_special,
                                        pcmk__xml_escape_attr_pretty));

    assert_false(pcmk__xml_needs_escape(four_byte, pcmk__xml_escape_text));
    assert_false(pcmk__xml_needs_escape(four_byte, pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(four_byte,
                                        pcmk__xml_escape_attr_pretty));

    assert_true(pcmk__xml_needs_escape(four_byte_special,
                                       pcmk__xml_escape_text));
    assert_true(pcmk__xml_needs_escape(four_byte_special,
                                       pcmk__xml_escape_attr));
    assert_false(pcmk__xml_needs_escape(four_byte_special,
                                        pcmk__xml_escape_attr_pretty));
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
