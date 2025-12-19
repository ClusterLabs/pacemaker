/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <glib.h>                           // gchar, g_ascii_isalnum(), etc.

#include <crm/common/unittest_internal.h>

#include "crmcommon_private.h"              // pcmk__xml_is_name_char()

/*!
 * \internal
 * \brief Assert that a Unicode character is a valid XML \c NameChar
 *
 * \param[in] code_pt  Unicode code point of character to check
 */
static void
assert_name_char(int code_pt)
{
    gchar utf8_buf[6] = { 0, };
    int len = 4;
    int ref_len = g_unichar_to_utf8(code_pt, utf8_buf);

    assert_true(pcmk__xml_is_name_char(utf8_buf, &len));
    assert_int_equal(len, ref_len);
}

/*!
 * \internal
 * \brief Assert that a Unicode character is not a valid XML \c NameChar
 *
 * \param[in] code_pt  Unicode code point of character to check
 */
static void
assert_not_name_char(int code_pt)
{
    gchar utf8_buf[6] = { 0, };
    int len = 4;
    int ref_len = g_unichar_to_utf8(code_pt, utf8_buf);

    assert_false(pcmk__xml_is_name_char(utf8_buf, &len));
    assert_int_equal(len, ref_len);
}

static void
null_len(void **state)
{
    assert_true(pcmk__xml_is_name_char("a", NULL));
    assert_false(pcmk__xml_is_name_char("@", NULL));
}

static void
ascii(void **state)
{
    for (int c = 0x00; c <= 0x7F; c++) {
        if (g_ascii_isalnum(c)
            || c == ':' || c == '_' || c == '-' || c == '.') {

            assert_name_char(c);
        } else {
            assert_not_name_char(c);
        }
    }
}

static void
unicode_0x80_to_0xB6(void **state)
{
    for (int c = 0x80; c <= 0xB6; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0xB7(void **state)
{
    assert_name_char(0xB7);
}

static void
unicode_0xB8_to_0xBF(void **state)
{
    for (int c = 0xB8; c <= 0xBF; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0xC0_to_0xD6(void **state)
{
    for (int c = 0xC0; c <= 0xD6; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0xD7(void **state)
{
    assert_not_name_char(0xD7);
}

static void
unicode_0xD8_to_0xF6(void **state)
{
    for (int c = 0xD8; c <= 0xF6; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0xF7(void **state)
{
    assert_not_name_char(0xF7);
}

static void
unicode_0xF8_to_0x2FF(void **state)
{
    for (int c = 0xF8; c <= 0x2FF; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x300_to_0x36F(void **state)
{
    for (int c = 0x300; c <= 0x36F; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x370_to_0x37D(void **state)
{
    for (int c = 0x370; c <= 0x37D; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x37E(void **state)
{
    assert_not_name_char(0x37E);
}

static void
unicode_0x37F_to_0x1FFF(void **state)
{
    for (int c = 0x37F; c <= 0x1FFF; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x2000_to_0x200B(void **state)
{
    for (int c = 0x2000; c <= 0x200B; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0x200C_to_0x200D(void **state)
{
    for (int c = 0x200C; c <= 0x200D; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x200E_to_0x203E(void **state)
{
    for (int c = 0x200E; c <= 0x203E; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0x203F_to_0x2040(void **state)
{
    for (int c = 0x203F; c <= 0x2040; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x2041_to_0x206F(void **state)
{
    for (int c = 0x2041; c <= 0x206F; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0x2070_to_0x218F(void **state)
{
    for (int c = 0x2070; c <= 0x218F; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x2190_to_0x2BFF(void **state)
{
    for (int c = 0x2190; c <= 0x2BFF; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0x2C00_to_0x2FEF(void **state)
{
    for (int c = 0x2C00; c <= 0x2FEF; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0x2FF0_to_0x3000(void **state)
{
    for (int c = 0x2FF0; c <= 0x3000; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0x3001_to_0xD7FF(void **state)
{
    for (int c = 0x3001; c <= 0xD7FF; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0xD800_to_0xDFFF(void **state)
{
    /* Unicode code points in the range D800 to DFFF are UTF-16 surrogate pair
     * halves. They can be represented in UTF-8, but they shouldn't appear in
     * valid UTF-8-encoded text. RFC 3629 (Nov 2003) says they should be treated
     * as invalid:
     * https://en.wikipedia.org/wiki/UTF-8#Invalid_sequences_and_error_handling.
     *
     * GLib treats these characters as valid and returns a length of 3 bytes. So
     * did libxml until v2.12 (commit 845bd99). Since that commit, libxml treats
     * these characters as invalid and returns a length of 0. To avoid version-
     * dependent testing behavior, skip the length check for code points in that
     * range. This means we don't use the helper.
     */
    for (int c = 0xD800; c <= 0xDFFF; c++) {
        gchar utf8_buf[6] = { 0, };

        g_unichar_to_utf8(c, utf8_buf);

        assert_false(pcmk__xml_is_name_char(utf8_buf, NULL));
    }
}

static void
unicode_0xE000_to_0xF8FF(void **state)
{
    for (int c = 0xE000; c <= 0xF8FF; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0xF900_to_0xFDCF(void **state)
{
    for (int c = 0xF900; c <= 0xFDCF; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0xFDD0_to_0xFDEF(void **state)
{
    for (int c = 0xFDD0; c <= 0xFDEF; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0xFDF0_to_0xFFFD(void **state)
{
    for (int c = 0xFDF0; c <= 0xFFFD; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0xFFFE_to_0xFFFF(void **state)
{
    for (int c = 0xFFFE; c <= 0xFFFF; c++) {
        assert_not_name_char(c);
    }
}

static void
unicode_0x10000_to_0xEFFFF(void **state)
{
    for (int c = 0x10000; c <= 0xEFFFF; c++) {
        assert_name_char(c);
    }
}

static void
unicode_0xF0000_to_0x10FFFF(void **state)
{
    for (int c = 0xF0000; c <= 0x10FFFF; c++) {
        assert_not_name_char(c);
    }
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_len),
                cmocka_unit_test(ascii),
                cmocka_unit_test(unicode_0x80_to_0xB6),
                cmocka_unit_test(unicode_0xB7),
                cmocka_unit_test(unicode_0xB8_to_0xBF),
                cmocka_unit_test(unicode_0xC0_to_0xD6),
                cmocka_unit_test(unicode_0xD7),
                cmocka_unit_test(unicode_0xD8_to_0xF6),
                cmocka_unit_test(unicode_0xF7),
                cmocka_unit_test(unicode_0xF8_to_0x2FF),
                cmocka_unit_test(unicode_0x300_to_0x36F),
                cmocka_unit_test(unicode_0x370_to_0x37D),
                cmocka_unit_test(unicode_0x37E),
                cmocka_unit_test(unicode_0x37F_to_0x1FFF),
                cmocka_unit_test(unicode_0x2000_to_0x200B),
                cmocka_unit_test(unicode_0x200C_to_0x200D),
                cmocka_unit_test(unicode_0x200E_to_0x203E),
                cmocka_unit_test(unicode_0x203F_to_0x2040),
                cmocka_unit_test(unicode_0x2041_to_0x206F),
                cmocka_unit_test(unicode_0x2070_to_0x218F),
                cmocka_unit_test(unicode_0x2190_to_0x2BFF),
                cmocka_unit_test(unicode_0x2C00_to_0x2FEF),
                cmocka_unit_test(unicode_0x2FF0_to_0x3000),
                cmocka_unit_test(unicode_0x3001_to_0xD7FF),
                cmocka_unit_test(unicode_0xD800_to_0xDFFF),
                cmocka_unit_test(unicode_0xE000_to_0xF8FF),
                cmocka_unit_test(unicode_0xF900_to_0xFDCF),
                cmocka_unit_test(unicode_0xFDD0_to_0xFDEF),
                cmocka_unit_test(unicode_0xFDF0_to_0xFFFD),
                cmocka_unit_test(unicode_0xFFFE_to_0xFFFF),
                cmocka_unit_test(unicode_0x10000_to_0xEFFFF),
                cmocka_unit_test(unicode_0xF0000_to_0x10FFFF))
