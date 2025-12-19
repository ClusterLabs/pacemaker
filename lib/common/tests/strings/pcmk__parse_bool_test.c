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
 * \brief Check \c pcmk__parse_bool() succeeds and parses the input to true
 *
 * \param[in] input  Input string
 */
static void
assert_parse_bool_true(const char *input)
{
    bool result = false;

    // Ensure we still validate the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool(input, NULL), pcmk_rc_ok);

    assert_int_equal(pcmk__parse_bool(input, &result), pcmk_rc_ok);
    assert_true(result);

    // Repeat with result initially set to true
    result = true;

    assert_int_equal(pcmk__parse_bool(input, &result), pcmk_rc_ok);
    assert_true(result);
}

/*!
 * \internal
 * \brief Check \c pcmk__parse_bool() succeeds and parses the input to false
 *
 * \param[in] input  Input string
 */
static void
assert_parse_bool_false(const char *input)
{
    bool result = false;

    // Ensure we still validate the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool(input, NULL), pcmk_rc_ok);

    assert_int_equal(pcmk__parse_bool(input, &result), pcmk_rc_ok);
    assert_false(result);

    // Repeat with result initially set to true
    result = true;

    assert_int_equal(pcmk__parse_bool(input, &result), pcmk_rc_ok);
    assert_false(result);
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
    assert_parse_bool_true("true");
    assert_parse_bool_true("TrUe");
    assert_parse_bool_true("on");
    assert_parse_bool_true("ON");
    assert_parse_bool_true("yes");
    assert_parse_bool_true("yES");
    assert_parse_bool_true("y");
    assert_parse_bool_true("Y");
    assert_parse_bool_true("1");
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
    assert_parse_bool_false("false");
    assert_parse_bool_false("fAlSe");
    assert_parse_bool_false("off");
    assert_parse_bool_false("OFF");
    assert_parse_bool_false("no");
    assert_parse_bool_false("No");
    assert_parse_bool_false("n");
    assert_parse_bool_false("N");
    assert_parse_bool_false("0");
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
