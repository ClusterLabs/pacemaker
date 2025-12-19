/*
 * Copyright 2021-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>

/*!
 * \internal
 * \brief Check \c pcmk__parse_bool() succeeds and parses the input as expected
 *
 * \param[in] input            Input string
 * \param[in] expected_result  Expected parsed value
 */
static void
assert_parse_bool(const char *input, bool expected_result)
{
    bool result = false;

    // Ensure we still validate the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool(input, NULL), pcmk_rc_ok);

    assert_int_equal(pcmk__parse_bool(input, &result), pcmk_rc_ok);

    if (expected_result) {
        assert_true(result);
    } else {
        assert_false(result);
    }

    // Repeat with result initially set to true
    result = true;

    assert_int_equal(pcmk__parse_bool(input, &result), pcmk_rc_ok);

    if (expected_result) {
        assert_true(result);
    } else {
        assert_false(result);
    }
}

/*!
 * \internal
 * \brief Check that \c pcmk__parse_bool() fails and returns the expected value
 *
 * \param[in] input        Input string
 * \param[in] expected_rc  Expected return code
 */
static void
assert_parse_bool_failure(const char *input, int expected_rc)
{
    bool result = false;

    // Ensure we still validate the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool(input, NULL), expected_rc);

    // Make sure the value of result does not change on failure
    assert_int_equal(pcmk__parse_bool(input, &result), expected_rc);
    assert_false(result);

    // Repeat with result initially set to true
    result = true;

    assert_int_equal(pcmk__parse_bool(input, &result), expected_rc);
    assert_true(result);
}

static void
bad_input(void **state)
{
    // Dumps core via CRM_CHECK()
    assert_parse_bool_failure(NULL, EINVAL);

    assert_parse_bool_failure("", pcmk_rc_bad_input);
    assert_parse_bool_failure("blahblah", pcmk_rc_bad_input);
}

static void
is_true(void **state)
{
    assert_parse_bool("true", true);
    assert_parse_bool("TrUe", true);
    assert_parse_bool("on", true);
    assert_parse_bool("ON", true);
    assert_parse_bool("yes", true);
    assert_parse_bool("yES", true);
    assert_parse_bool("y", true);
    assert_parse_bool("Y", true);
    assert_parse_bool("1", true);
}

static void
is_not_true(void **state)
{
    assert_parse_bool_failure("truedat", pcmk_rc_bad_input);
    assert_parse_bool_failure("onnn", pcmk_rc_bad_input);
    assert_parse_bool_failure("yep", pcmk_rc_bad_input);
    assert_parse_bool_failure("Y!", pcmk_rc_bad_input);
    assert_parse_bool_failure("100", pcmk_rc_bad_input);
}

static void
is_false(void **state)
{
    assert_parse_bool("false", false);
    assert_parse_bool("fAlSe", false);
    assert_parse_bool("off", false);
    assert_parse_bool("OFF", false);
    assert_parse_bool("no", false);
    assert_parse_bool("No", false);
    assert_parse_bool("n", false);
    assert_parse_bool("N", false);
    assert_parse_bool("0", false);
}

static void
is_not_false(void **state)
{
    assert_parse_bool_failure("falseee", pcmk_rc_bad_input);
    assert_parse_bool_failure("of", pcmk_rc_bad_input);
    assert_parse_bool_failure("nope", pcmk_rc_bad_input);
    assert_parse_bool_failure("N!", pcmk_rc_bad_input);
    assert_parse_bool_failure("000", pcmk_rc_bad_input);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(is_true),
                cmocka_unit_test(is_not_true),
                cmocka_unit_test(is_false),
                cmocka_unit_test(is_not_false))
