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

#define assert_sanitized(str, expected)     \
    do {                                    \
        char *buf = pcmk__str_copy(str);    \
                                            \
        pcmk__xml_sanitize_id(buf);         \
        assert_string_equal(buf, expected); \
        free(buf);                          \
    } while (0)

static void
null_empty(void **state)
{
    char *buf = pcmk__str_copy("");

    pcmk__assert_asserts(pcmk__xml_sanitize_id(NULL));
    pcmk__assert_asserts(pcmk__xml_sanitize_id(buf));

    free(buf);
}

static void
all_valid(void **state)
{
    const char *str = NULL;

    // All NameStartChars
    str = "abc";
    assert_sanitized(str, str);

    // '-' NameChar but not NameStartChar
    str = "b-c";
    assert_sanitized(str, str);
    str = "bc-";
    assert_sanitized(str, str);

    // #xC2 (NameStartChar), #xB7 (NameChar)
    str = "a" "\xC2\xB7" "b";
    assert_sanitized(str, str);

    // #xEFFFF (NameStartChar)
    str = "\xF3\xAF\xBF\xBF" "a";
    assert_sanitized(str, str);

    // #xEFFFF (NameStartChar), #xB7 (NameChar)
    str = "\xF3\xAF\xBF\xBF" "\xC2\xB7";
    assert_sanitized(str, str);
}

static void
start_invalid(void **state)
{
    // '-' NameChar but not NameStartChar
    assert_sanitized("-ab", "_ab");

    // '$' neither NameChar nor NameStartChar
    assert_sanitized("$ab", "_ab");

    // #xB7 NameChar but not NameStartChar (two-byte character)
    assert_sanitized("\xC2\xB7" "ab", "_.ab");

    // #xB8 neither NameChar nor NameStartChar (two-byte character)
    assert_sanitized("\xC2\xB8" "ab", "_.ab");
}

static void
middle_invalid(void **state)
{
    // '$' not a NameChar
    assert_sanitized("a$b", "a.b");

    // #xB8 not a NameChar (two-byte character)
    assert_sanitized("a" "\xC2\xB8" "b", "a..b");
}

static void
end_invalid(void **state)
{
    // '$' not a NameChar
    assert_sanitized("ab$", "ab.");

    // #xB8 not a NameChar (two-byte character)
    assert_sanitized("ab" "\xC2\xB8", "ab..");
}

static void
all_invalid(void **state)
{
    // None are NameChars (all ASCII)
    assert_sanitized("$!%", "_..");

    // None are NameChars (#xB8 two-byte character)
    assert_sanitized("$!" "\xC2\xB8", "_...");

    // None are NameChars (all multi-byte characters)
    assert_sanitized("\xC2\xB7" "\xCD\xBE" "\xF3\xB0\x80\x80",
                     "_." ".." "....");
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_empty),
                cmocka_unit_test(all_valid),
                cmocka_unit_test(start_invalid),
                cmocka_unit_test(middle_invalid),
                cmocka_unit_test(end_invalid),
                cmocka_unit_test(all_invalid))
