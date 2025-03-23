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

static void
bad_input(void **state) {
    // Dumps core via CRM_CHECK()
    assert_int_equal(pcmk__parse_bool(NULL, NULL), EINVAL);

    assert_int_equal(pcmk__parse_bool("", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("blahblah", NULL), pcmk_rc_bad_input);
}

static void
is_true(void **state) {
    bool result;

    assert_int_equal(pcmk__parse_bool("true", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("TrUe", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("on", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("ON", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("yes", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("yES", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("y", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("Y", &result), pcmk_rc_ok);
    assert_true(result);
    assert_int_equal(pcmk__parse_bool("1", &result), pcmk_rc_ok);
    assert_true(result);

    // Ensure it still validates the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool("true", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("on", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("yes", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("y", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("1", NULL), pcmk_rc_ok);
}

static void
is_not_true(void **state) {
    assert_int_equal(pcmk__parse_bool("truedat", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("onnn", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("yep", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("Y!", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("100", NULL), pcmk_rc_bad_input);
}

static void
is_false(void **state) {
    bool result;

    assert_int_equal(pcmk__parse_bool("false", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("fAlSe", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool(PCMK_VALUE_OFF, &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("OFF", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("no", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("No", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("n", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("N", &result), pcmk_rc_ok);
    assert_false(result);
    assert_int_equal(pcmk__parse_bool("0", &result), pcmk_rc_ok);
    assert_false(result);

    // Ensure it still validates the string with a NULL result argument
    assert_int_equal(pcmk__parse_bool("false", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool(PCMK_VALUE_OFF, NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("no", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("n", NULL), pcmk_rc_ok);
    assert_int_equal(pcmk__parse_bool("0", NULL), pcmk_rc_ok);
}

static void
is_not_false(void **state) {
    assert_int_equal(pcmk__parse_bool("falseee", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("of", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("nope", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("N!", NULL), pcmk_rc_bad_input);
    assert_int_equal(pcmk__parse_bool("000", NULL), pcmk_rc_bad_input);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(is_true),
                cmocka_unit_test(is_not_true),
                cmocka_unit_test(is_false),
                cmocka_unit_test(is_not_false))
