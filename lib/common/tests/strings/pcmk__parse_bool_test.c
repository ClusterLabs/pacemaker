/*
 * Copyright 2021-2025 the Pacemaker project contributors
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
 * \brief Check a call with given input against expected return value and result
 *
 * \param[in] input            Input string
 * \param[in] expected_rc      Expected return code
 * \param[in] expected_result  Expected parsed value (ignored unless
 *                             \p expected_rc is \c pcmk_rc_ok)
 */
static void
assert_parse_bool(const char *input, int expected_rc, bool expected_result)
{
    bool result = false;

    // Ensure we still validate the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool(input, NULL), expected_rc);

    if (expected_rc != pcmk_rc_ok) {
        // Make sure the value of result does not change on failure
        expected_result = result;
    }

    assert_int_equal(pcmk__parse_bool(input, &result), expected_rc);
    if (expected_result) {
        assert_true(result);
    } else {
        assert_false(result);
    }

    // Repeat with result initially set to true
    result = true;
    if (expected_rc != pcmk_rc_ok) {
        expected_result = result;
    }

    assert_int_equal(pcmk__parse_bool(input, &result), expected_rc);
    if (expected_result) {
        assert_true(result);
    } else {
        assert_false(result);
    }
}

static void
bad_input(void **state)
{
    // Dumps core via CRM_CHECK()
    assert_parse_bool(NULL, EINVAL, false);

    assert_parse_bool("", pcmk_rc_bad_input, false);
    assert_parse_bool("blahblah", pcmk_rc_bad_input, false);
}

static void
is_true(void **state)
{
    assert_parse_bool("true", pcmk_rc_ok, true);
    assert_parse_bool("TrUe", pcmk_rc_ok, true);
    assert_parse_bool("on", pcmk_rc_ok, true);
    assert_parse_bool("ON", pcmk_rc_ok, true);
    assert_parse_bool("yes", pcmk_rc_ok, true);
    assert_parse_bool("yES", pcmk_rc_ok, true);
    assert_parse_bool("y", pcmk_rc_ok, true);
    assert_parse_bool("Y", pcmk_rc_ok, true);
    assert_parse_bool("1", pcmk_rc_ok, true);
}

static void
is_not_true(void **state)
{
    assert_parse_bool("truedat", pcmk_rc_bad_input, false);
    assert_parse_bool("onnn", pcmk_rc_bad_input, false);
    assert_parse_bool("yep", pcmk_rc_bad_input, false);
    assert_parse_bool("Y!", pcmk_rc_bad_input, false);
    assert_parse_bool("100", pcmk_rc_bad_input, false);
}

static void
is_false(void **state)
{
    assert_parse_bool("false", pcmk_rc_ok, false);
    assert_parse_bool("fAlSe", pcmk_rc_ok, false);
    assert_parse_bool("off", pcmk_rc_ok, false);
    assert_parse_bool("OFF", pcmk_rc_ok, false);
    assert_parse_bool("no", pcmk_rc_ok, false);
    assert_parse_bool("No", pcmk_rc_ok, false);
    assert_parse_bool("n", pcmk_rc_ok, false);
    assert_parse_bool("N", pcmk_rc_ok, false);
    assert_parse_bool("0", pcmk_rc_ok, false);
}

static void
is_not_false(void **state)
{
    assert_parse_bool("falseee", pcmk_rc_bad_input, false);
    assert_parse_bool("of", pcmk_rc_bad_input, false);
    assert_parse_bool("nope", pcmk_rc_bad_input, false);
    assert_parse_bool("N!", pcmk_rc_bad_input, false);
    assert_parse_bool("000", pcmk_rc_bad_input, false);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(is_true),
                cmocka_unit_test(is_not_true),
                cmocka_unit_test(is_false),
                cmocka_unit_test(is_not_false))
