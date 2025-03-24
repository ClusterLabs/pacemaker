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
 * \param[in] v1           First argument for \c compare_version()
 * \param[in] v2           Second argument for \c compare_version()
 * \param[in] expected_rc  Expected return code from
 *                         <tt>compare_version(v1, v2)</tt>
 */
static void
assert_compare_version(const char *v1, const char *v2, int expected_rc)
{
    assert_int_equal(compare_version(v1, v2), expected_rc);

    if (v1 != v2) {
        /* Try reverse order even if expected_rc == 0, if v1 and v2 are
         * different strings
         */
        assert_int_equal(compare_version(v2, v1), -expected_rc);
    }
}

static void
empty_params(void **state)
{
    // @FIXME Treat empty string the same as NULL
    assert_compare_version(NULL, NULL, 0);
    assert_compare_version(NULL, "", -1);   // Should be 0
    assert_compare_version("", "", 0);

    assert_compare_version(NULL, "1.0.1", -1);
    assert_compare_version("", "1.0.1", -1);

    // @FIXME NULL/empty should be equal to an invalid version
    assert_compare_version(NULL, "abc", -1);    // Should be 0
    assert_compare_version("", "abc", -1);      // Should be 0
}

static void
equal_versions(void **state)
{
    assert_compare_version("0.4.7", "0.4.7", 0);
    assert_compare_version("1.0", "1.0", 0);
}

static void
unequal_versions(void **state)
{
    assert_compare_version("0.4.7", "0.4.8", -1);
    assert_compare_version("0.2.3", "0.3", -1);
    assert_compare_version("0.99", "1.0", -1);
}

static void
shorter_versions(void **state)
{
    assert_compare_version("1.0", "1.0.1", -1);
    assert_compare_version("1.0", "1", 0);
    assert_compare_version("1", "1.2", -1);
    assert_compare_version("1.0.0", "1.0", 0);
    assert_compare_version("1.0.0", "1.2", -1);
    assert_compare_version("0.99", "1", -1);
}

static void
leading_zeros(void **state)
{
    // Equal to self
    assert_compare_version("00001.0", "00001.0", 0);

    // Leading zeros in each segment are ignored
    assert_compare_version("0001.0", "1", 0);
    assert_compare_version("0.0001", "0.1", 0);
    assert_compare_version("0001.1", "1.0001", 0);
}

static void
negative_sign(void **state)
{
    // Equal to self
    assert_compare_version("-1", "-1", 0);
    assert_compare_version("1.-1.5", "1.-1.5", 0);

    // @FIXME Treat negative version as 0 (invalid)
    assert_compare_version("-1", "0", -1);          // Should be 0
    assert_compare_version("-1", "0.0", -1);        // Should be 0
    assert_compare_version("-1", "0.1", -1);
    assert_compare_version("-1", "1.0", -1);

    assert_compare_version("-1", "-0", -1);         // Should be 0
    assert_compare_version("-1", "-0.0", -1);       // Should be 0
    assert_compare_version("-1", "-0.1", -1);       // Should be 0
    assert_compare_version("-1", "-1.0", 0);
    assert_compare_version("-1", "-2.0", 1);        // Should be 0

    // @FIXME Treat negative sign inside version as garbage
    assert_compare_version("1.-1.5", "1.0", -1);    // Should be 0
    assert_compare_version("1.-1.5", "1.0.5", -1);

    assert_compare_version("1.-1.5", "1.-0", -1);   // Should be 0
    assert_compare_version("1.-1.5", "1.-0.5", -1); // Should be 0

    assert_compare_version("1.-1.5", "1.-1", 1);    // Should be 0
    assert_compare_version("1.-1.5", "1.-1.9", -1); // Should be 0

    assert_compare_version("1.-1.5", "1.-2", 1);    // Should be 0
    assert_compare_version("1.-1.5", "1.-2.5", 1);  // Should be 0

    assert_compare_version("1.-1.5", "2.0.5", -1);
    assert_compare_version("1.-1.5", "0.0.5", 1);
}

static void
positive_sign(void **state)
{
    // Equal to self
    assert_compare_version("+1", "+1", 0);
    assert_compare_version("1.+1.5", "1.+1.5", 0);

    // @FIXME Treat version with explicit positive sign as 0 (invalid)
    assert_compare_version("+1", "0", 1);           // Should be 0
    assert_compare_version("+1", "0.0", 1);         // Should be 0
    assert_compare_version("+1", "0.1", 1);         // Should be -1
    assert_compare_version("+1", "1.0", 0);         // Should be -1
    assert_compare_version("+1", "2.0", -1);        // Should be -1

    assert_compare_version("+1", "+0", 1);          // Should be 0
    assert_compare_version("+1", "+0.0", 1);        // Should be 0
    assert_compare_version("+1", "+0.1", 1);        // Should be 0
    assert_compare_version("+1", "+1.0", 0);
    assert_compare_version("+1", "+2.0", -1);       // Should be 0

    // @FIXME Treat positive sign inside version as garbage
    assert_compare_version("1.+1.5", "1.0", 1);     // Should be 0
    assert_compare_version("1.+1.5", "1.0.5", 1);   // Should be -1

    assert_compare_version("1.+1.5", "1.+0", 1);    // Should be 0
    assert_compare_version("1.+1.5", "1.+0.5", 1);  // Should be 0

    assert_compare_version("1.+1.5", "1.+1", 1);    // Should be 0
    assert_compare_version("1.+1.5", "1.+1.9", -1); // Should be 0

    assert_compare_version("1.+1.5", "1.+2", -1);   // Should be 0
    assert_compare_version("1.+1.5", "1.+2.5", -1); // Should be 0

    assert_compare_version("1.+1.5", "2.0.5", -1);
    assert_compare_version("1.+1.5", "0.0.5", 1);
}

/*
static void
hex_digits(void **state)
{
    // Equal to self
    assert_compare_version("a", "a", 0);

    // Hex digits > 9 are garbage
    assert_compare_version("a", "0", 0);
    assert_compare_version("a111", "0", 0);
    assert_compare_version("a", "1", -1);
    assert_compare_version("a111", "1", -1);

    assert_compare_version("1a", "1", 0);
    assert_compare_version("1a111", "1", 0);
    assert_compare_version("1a", "2", -1);
    assert_compare_version("1a111", "2", -1);
    assert_compare_version("1a", "0", 1);
    assert_compare_version("1a111", "0", 1);
}
*/

static void
bare_dot(void **state)
{
    // Equal to self
    assert_compare_version(".", ".", 0);

    // Bare dot is treated as 0
    assert_compare_version(".", "0", 0);
    assert_compare_version(".", "0.1", -1);
    assert_compare_version(".", "1.0", -1);
}

static void
leading_dot(void **state)
{
    // Equal to self
    assert_compare_version(".0", ".0", 0);
    assert_compare_version(".1", ".1", 0);

    // Leading dot is treated as 0
    assert_compare_version(".0", "0", 0);
    assert_compare_version(".0", "0.0", 0);
    assert_compare_version(".0", "0.0.0", 0);
    assert_compare_version(".0", "0.1", -1);

    // @FIXME .1 should equal 0, not 0.1
    assert_compare_version(".1", "0", 1);
    assert_compare_version(".1", "0.0", 1);
    assert_compare_version(".1", "0.0.0", 1);
    assert_compare_version(".1", "0.1", 0);
    assert_compare_version(".1", "0.1.0", 0);
    assert_compare_version(".1", "0.2", -1);
}

static void
trailing_dot(void **state)
{
    // Equal to self
    assert_compare_version("0.", "0.", 0);
    assert_compare_version("0.1.", "0.1.", 0);

    // Trailing dot is ignored
    assert_compare_version("0.", "0", 0);
    assert_compare_version("0.", "0.0", 0);
    assert_compare_version("0.", "0.1", -1);
    assert_compare_version("0.1.", "0.1", 0);
    assert_compare_version("0.1.", "0.1.0", 0);
    assert_compare_version("0.1.", "0.2", -1);
    assert_compare_version("0.1.", "0", 1);
}

static void
leading_spaces(void **state)
{
    // Equal to self
    assert_compare_version("    ", "    ", 0);
    assert_compare_version("   1", "   1", 0);

    // Leading spaces are ignored
    assert_compare_version("   1", "1.0", 0);
    assert_compare_version("1", "   1.0", 0);
    assert_compare_version("   1", "   1.0", 0);
    assert_compare_version("   1", "1.1", -1);
    assert_compare_version("1", "   1.1", -1);
    assert_compare_version("   1", "   1.1", -1);
}

/*
static void
trailing_spaces(void **state)
{
    // Equal to self
    assert_compare_version("1   ", "1   ", 0);

    // Trailing spaces are ignored
    assert_compare_version("1   ", "1.0", 0);
    assert_compare_version("1", "1.0   ", 0);
    assert_compare_version("1   ", "1.0   ", 0);
    assert_compare_version("1   ", "1.1", -1);
    assert_compare_version("1", "1.1   ", -1);
    assert_compare_version("1   ", "1.1   ", -1);
}

static void
leading_garbage(void **state)
{
    // Equal to self
    assert_compare_version("@1", "@1", 0);

    // Leading garbage means rest of string is ignored
    assert_compare_version("@1", "0", 0);
    assert_compare_version("@1", "1", -1);

    assert_compare_version("@0.1", "0", 0);
    assert_compare_version("@0.1", "1", -1);
}

static void
trailing_garbage(void **state)
{
    // Equal to self
    assert_compare_version("0.1@", "0.1@", 0);

    // Trailing garbage is ignored
    assert_compare_version("0.1@", "0.1", 0);
    assert_compare_version("0.1.@", "0.1", 0);
    assert_compare_version("0.1    @", "0.1", 0);
    assert_compare_version("0.1.    @", "0.1", 0);
    assert_compare_version("0.1    .@", "0.1", 0);

    // This includes more numbers after spaces
    assert_compare_version("0.1    1", "0.1", 0);
    assert_compare_version("0.1.    1", "0.1", 0);
    assert_compare_version("0.1    .1", "0.1", 0);

    // Second consecutive dot is treated as garbage (end of valid input)
    assert_compare_version("1..", "1", 0);
    assert_compare_version("1..1", "1", 0);
    assert_compare_version("1..", "1.0.0", 0);
    assert_compare_version("1..1", "1.0.0", 0);
    assert_compare_version("1..", "1.0.1", -1);
    assert_compare_version("1..1", "1.0.1", -1);
}
*/

// @FIXME Commented-out tests cause infinite loops
PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_params),
                cmocka_unit_test(equal_versions),
                cmocka_unit_test(unequal_versions),
                cmocka_unit_test(shorter_versions),
                cmocka_unit_test(leading_zeros),
                cmocka_unit_test(negative_sign),
                cmocka_unit_test(positive_sign),
                //cmocka_unit_test(hex_digits),
                cmocka_unit_test(bare_dot),
                cmocka_unit_test(leading_dot),
                cmocka_unit_test(trailing_dot),
                cmocka_unit_test(leading_spaces))
                /*
                cmocka_unit_test(trailing_spaces))
                cmocka_unit_test(leading_garbage))
                cmocka_unit_test(trailing_garbage))
                */
