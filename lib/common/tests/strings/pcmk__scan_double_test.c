/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <float.h>  // DBL_MAX, etc.
#include <math.h>   // fabs()

// Ensure plenty of characters for %f display
#define LOCAL_BUF_SIZE 2 * DBL_MAX_10_EXP

static void
empty_input_string(void **state)
{
    double result;

    // Without default_text
    assert_int_equal(pcmk__scan_double(NULL, &result, NULL, NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);

    assert_int_equal(pcmk__scan_double("", &result, NULL, NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);

    // With default_text
    assert_int_equal(pcmk__scan_double(NULL, &result, "2.0", NULL), pcmk_rc_ok);
    assert_float_equal(result, 2.0, DBL_EPSILON);

    assert_int_equal(pcmk__scan_double("", &result, "2.0", NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);
}

static void
bad_input_string(void **state)
{
    double result;

    // Without default text
    assert_int_equal(pcmk__scan_double("asdf", &result, NULL, NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);

    assert_int_equal(pcmk__scan_double("as2.0", &result, NULL, NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);

    // With default text (not used)
    assert_int_equal(pcmk__scan_double("asdf", &result, "2.0", NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);

    assert_int_equal(pcmk__scan_double("as2.0", &result, "2.0", NULL), EINVAL);
    assert_float_equal(result, PCMK__PARSE_DBL_DEFAULT, DBL_EPSILON);
}

static void
trailing_chars(void **state)
{
    double result;

    assert_int_equal(pcmk__scan_double("2.0asdf", &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, 2.0, DBL_EPSILON);
}

static void
typical_case(void **state)
{
    char str[LOCAL_BUF_SIZE];
    double result;

    assert_int_equal(pcmk__scan_double("0.0", &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, 0.0, DBL_EPSILON);

    assert_int_equal(pcmk__scan_double("1.0", &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, 1.0, DBL_EPSILON);

    assert_int_equal(pcmk__scan_double("-1.0", &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, -1.0, DBL_EPSILON);

    snprintf(str, LOCAL_BUF_SIZE, "%f", DBL_MAX);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, DBL_MAX, DBL_EPSILON);

    snprintf(str, LOCAL_BUF_SIZE, "%f", -DBL_MAX);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, -DBL_MAX, DBL_EPSILON);
}

static void
double_overflow(void **state)
{
    char str[LOCAL_BUF_SIZE];
    double result;

    /*
     * 1e(DBL_MAX_10_EXP + 1) produces an inf value
     * Can't use assert_float_equal() because (inf - inf) == NaN
     */
    snprintf(str, LOCAL_BUF_SIZE, "1e%d", DBL_MAX_10_EXP + 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), EOVERFLOW);
    assert_true(result > DBL_MAX);

    snprintf(str, LOCAL_BUF_SIZE, "-1e%d", DBL_MAX_10_EXP + 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), EOVERFLOW);
    assert_true(result < -DBL_MAX);
}

static void
double_underflow(void **state)
{
    char str[LOCAL_BUF_SIZE];
    double result;

    /*
     * 1e(DBL_MIN_10_EXP - 1) produces a denormalized value (between 0
     * and DBL_MIN)
     *
     * C99/C11: result will be **no greater than** DBL_MIN
     */
    snprintf(str, LOCAL_BUF_SIZE, "1e%d", DBL_MIN_10_EXP - 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_underflow);
    assert_true(result >= 0.0);
    assert_true(result <= DBL_MIN);

    snprintf(str, LOCAL_BUF_SIZE, "-1e%d", DBL_MIN_10_EXP - 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_underflow);
    assert_true(result <= 0.0);
    assert_true(result >= -DBL_MIN);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        // Test for input string issues
        cmocka_unit_test(empty_input_string),
        cmocka_unit_test(bad_input_string),
        cmocka_unit_test(trailing_chars),

        // Test for numeric issues
        cmocka_unit_test(typical_case),
        cmocka_unit_test(double_overflow),
        cmocka_unit_test(double_underflow),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

