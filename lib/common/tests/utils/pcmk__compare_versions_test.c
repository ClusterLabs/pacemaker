/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

/*!
 * \internal
 * \brief Compare two version strings in both directions
 *
 * \param[in] v1           First argument for \c pcmk__compare_versions()
 * \param[in] v2           Second argument for \c pcmk__compare_versions()
 * \param[in] expected_rc  Expected return code from
 *                         <tt>pcmk__compare_versions(v1, v2)</tt>
 */
static void
assert_compare_versions(const char *v1, const char *v2, int expected_rc)
{
    assert_int_equal(pcmk__compare_versions(v1, v2), expected_rc);
    assert_int_equal(pcmk__compare_versions(v2, v1), -expected_rc);
}

static void
empty_params(void **state)
{
    assert_compare_versions(NULL, NULL, 0);
    assert_compare_versions(NULL, "", 0);
    assert_compare_versions("", "", 0);

    assert_compare_versions(NULL, "1.0.1", -1);
    assert_compare_versions("", "1.0.1", -1);

    // NULL or empty is treated as equal to an invalid version
    assert_compare_versions(NULL, "abc", 0);
    assert_compare_versions("", "abc", 0);
}

static void
equal_versions(void **state)
{
    assert_compare_versions("0.4.7", "0.4.7", 0);
    assert_compare_versions("1.0", "1.0", 0);
}

static void
unequal_versions(void **state)
{
    assert_compare_versions("0.4.7", "0.4.8", -1);
    assert_compare_versions("0.2.3", "0.3", -1);
    assert_compare_versions("0.99", "1.0", -1);
}

static void
shorter_versions(void **state)
{
    assert_compare_versions("1.0", "1.0.1", -1);
    assert_compare_versions("1.0", "1", 0);
    assert_compare_versions("1", "1.2", -1);
    assert_compare_versions("1.0.0", "1.0", 0);
    assert_compare_versions("1.0.0", "1.2", -1);
    assert_compare_versions("0.99", "1", -1);
}

static void
leading_zeros(void **state)
{
    // Equal to self
    assert_compare_versions("00001.0", "00001.0", 0);

    // Leading zeros in each segment are ignored
    assert_compare_versions("0001.0", "1", 0);
    assert_compare_versions("0.0001", "0.1", 0);
    assert_compare_versions("0001.1", "1.0001", 0);
}

static void
negative_sign(void **state)
{
    // Equal to self
    assert_compare_versions("-1", "-1", 0);
    assert_compare_versions("1.-1.5", "1.-1.5", 0);

    // Negative version is treated as 0 (invalid)
    assert_compare_versions("-1", "0", 0);
    assert_compare_versions("-1", "0.0", 0);
    assert_compare_versions("-1", "0.1", -1);
    assert_compare_versions("-1", "1.0", -1);

    assert_compare_versions("-1", "-0", 0);
    assert_compare_versions("-1", "-0.0", 0);
    assert_compare_versions("-1", "-0.1", 0);
    assert_compare_versions("-1", "-1.0", 0);
    assert_compare_versions("-1", "-2.0", 0);

    // Negative sign inside version is treated as garbage
    assert_compare_versions("1.-1.5", "1.0", 0);
    assert_compare_versions("1.-1.5", "1.0.5", -1);

    assert_compare_versions("1.-1.5", "1.-0", 0);
    assert_compare_versions("1.-1.5", "1.-0.5", 0);

    assert_compare_versions("1.-1.5", "1.-1", 0);
    assert_compare_versions("1.-1.5", "1.-1.9", 0);

    assert_compare_versions("1.-1.5", "1.-2", 0);
    assert_compare_versions("1.-1.5", "1.-2.5", 0);

    assert_compare_versions("1.-1.5", "2.0.5", -1);
    assert_compare_versions("1.-1.5", "0.0.5", 1);
}

static void
positive_sign(void **state)
{
    // Equal to self
    assert_compare_versions("+1", "+1", 0);
    assert_compare_versions("1.+1.5", "1.+1.5", 0);

    // Version with explicit positive sign is treated as 0 (invalid)
    assert_compare_versions("+1", "0", 0);
    assert_compare_versions("+1", "0.0", 0);
    assert_compare_versions("+1", "0.1", -1);
    assert_compare_versions("+1", "1.0", -1);
    assert_compare_versions("+1", "2.0", -1);

    assert_compare_versions("+1", "+0", 0);
    assert_compare_versions("+1", "+0.0", 0);
    assert_compare_versions("+1", "+0.1", 0);
    assert_compare_versions("+1", "+1.0", 0);
    assert_compare_versions("+1", "+2.0", 0);

    // Positive sign inside version is treated as garbage
    assert_compare_versions("1.+1.5", "1.0", 0);
    assert_compare_versions("1.+1.5", "1.0.5", -1);

    assert_compare_versions("1.+1.5", "1.+0", 0);
    assert_compare_versions("1.+1.5", "1.+0.5", 0);

    assert_compare_versions("1.+1.5", "1.+1", 0);
    assert_compare_versions("1.+1.5", "1.+1.9", 0);

    assert_compare_versions("1.+1.5", "1.+2", 0);
    assert_compare_versions("1.+1.5", "1.+2.5", 0);

    assert_compare_versions("1.+1.5", "2.0.5", -1);
    assert_compare_versions("1.+1.5", "0.0.5", 1);
}

static void
hex_digits(void **state)
{
    // Equal to self
    assert_compare_versions("a", "a", 0);

    // Hex digits > 9 are garbage
    assert_compare_versions("a", "0", 0);
    assert_compare_versions("a111", "0", 0);
    assert_compare_versions("a", "1", -1);
    assert_compare_versions("a111", "1", -1);

    assert_compare_versions("1a", "1", 0);
    assert_compare_versions("1a111", "1", 0);
    assert_compare_versions("1a", "2", -1);
    assert_compare_versions("1a111", "2", -1);
    assert_compare_versions("1a", "0", 1);
    assert_compare_versions("1a111", "0", 1);
}

static void
bare_dot(void **state)
{
    // Equal to self
    assert_compare_versions(".", ".", 0);

    // Bare dot is treated as 0
    assert_compare_versions(".", "0", 0);
    assert_compare_versions(".", "0.1", -1);
    assert_compare_versions(".", "1.0", -1);
}

static void
leading_dot(void **state)
{
    // Equal to self
    assert_compare_versions(".0", ".0", 0);
    assert_compare_versions(".1", ".1", 0);

    // Version with leading dot is treated as 0 (invalid)
    assert_compare_versions(".0", "0", 0);
    assert_compare_versions(".0", "0.0", 0);
    assert_compare_versions(".0", "0.0.0", 0);
    assert_compare_versions(".0", "0.1", -1);

    assert_compare_versions(".1", "0", 0);
    assert_compare_versions(".1", "0.0", 0);
    assert_compare_versions(".1", "0.0.0", 0);
    assert_compare_versions(".1", "0.1", -1);
    assert_compare_versions(".1", "0.1.0", -1);
}

static void
trailing_dot(void **state)
{
    // Equal to self
    assert_compare_versions("0.", "0.", 0);
    assert_compare_versions("0.1.", "0.1.", 0);

    // Trailing dot is ignored
    assert_compare_versions("0.", "0", 0);
    assert_compare_versions("0.", "0.0", 0);
    assert_compare_versions("0.", "0.1", -1);
    assert_compare_versions("0.1.", "0.1", 0);
    assert_compare_versions("0.1.", "0.1.0", 0);
    assert_compare_versions("0.1.", "0.2", -1);
    assert_compare_versions("0.1.", "0", 1);
}

static void
leading_spaces(void **state)
{
    // Equal to self
    assert_compare_versions("    ", "    ", 0);
    assert_compare_versions("   1", "   1", 0);

    // Leading spaces are ignored
    assert_compare_versions("   1", "1.0", 0);
    assert_compare_versions("1", "   1.0", 0);
    assert_compare_versions("   1", "   1.0", 0);
    assert_compare_versions("   1", "1.1", -1);
    assert_compare_versions("1", "   1.1", -1);
    assert_compare_versions("   1", "   1.1", -1);
}

static void
trailing_spaces(void **state)
{
    // Equal to self
    assert_compare_versions("1   ", "1   ", 0);

    // Trailing spaces are ignored
    assert_compare_versions("1   ", "1.0", 0);
    assert_compare_versions("1", "1.0   ", 0);
    assert_compare_versions("1   ", "1.0   ", 0);
    assert_compare_versions("1   ", "1.1", -1);
    assert_compare_versions("1", "1.1   ", -1);
    assert_compare_versions("1   ", "1.1   ", -1);
}

static void
leading_garbage(void **state)
{
    // Equal to self
    assert_compare_versions("@1", "@1", 0);

    // Version with leading garbage is treated as 0
    assert_compare_versions("@1", "0", 0);
    assert_compare_versions("@1", "1", -1);

    assert_compare_versions("@0.1", "0", 0);
    assert_compare_versions("@0.1", "1", -1);
}

static void
trailing_garbage(void **state)
{
    // Equal to self
    assert_compare_versions("0.1@", "0.1@", 0);

    // Trailing garbage is ignored
    assert_compare_versions("0.1@", "0.1", 0);
    assert_compare_versions("0.1.@", "0.1", 0);
    assert_compare_versions("0.1    @", "0.1", 0);
    assert_compare_versions("0.1.    @", "0.1", 0);
    assert_compare_versions("0.1    .@", "0.1", 0);

    // This includes more numbers after spaces
    assert_compare_versions("0.1    1", "0.1", 0);
    assert_compare_versions("0.1.    1", "0.1", 0);
    assert_compare_versions("0.1    .1", "0.1", 0);

    // Second consecutive dot is treated as garbage
    assert_compare_versions("1..", "1", 0);
    assert_compare_versions("1..1", "1", 0);
    assert_compare_versions("1..", "1.0.0", 0);
    assert_compare_versions("1..1", "1.0.0", 0);
    assert_compare_versions("1..", "1.0.1", -1);
    assert_compare_versions("1..1", "1.0.1", -1);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_params),
                cmocka_unit_test(equal_versions),
                cmocka_unit_test(unequal_versions),
                cmocka_unit_test(shorter_versions),
                cmocka_unit_test(leading_zeros),
                cmocka_unit_test(negative_sign),
                cmocka_unit_test(positive_sign),
                cmocka_unit_test(hex_digits),
                cmocka_unit_test(bare_dot),
                cmocka_unit_test(leading_dot),
                cmocka_unit_test(trailing_dot),
                cmocka_unit_test(leading_spaces),
                cmocka_unit_test(trailing_spaces),
                cmocka_unit_test(leading_garbage),
                cmocka_unit_test(trailing_garbage))
