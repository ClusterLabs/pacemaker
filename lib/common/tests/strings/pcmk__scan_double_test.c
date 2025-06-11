/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <float.h>  // DBL_MAX, etc.
#include <math.h>   // fabs()

// Ensure plenty of characters for %f display
#define LOCAL_BUF_SIZE 2 * DBL_MAX_10_EXP

/*
 * assert_float_equal doesn't exist for older versions of cmocka installed on some
 * of our builders, so define it in terms of regular assert() here in that case.
 */
#if HAVE_DECL_ASSERT_FLOAT_EQUAL == 0
#define assert_float_equal(a, b, epsilon) assert_true(fabs((a) - (b)) < (epsilon))
#endif

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
    char *end_text;

    assert_int_equal(pcmk__scan_double("2.0asdf", &result, NULL, &end_text), pcmk_rc_ok);
    assert_float_equal(result, 2.0, DBL_EPSILON);
    assert_string_equal(end_text, "asdf");
}

static void
no_result_variable(void **state)
{
    pcmk__assert_asserts(pcmk__scan_double("asdf", NULL, NULL, NULL));
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

    pcmk__snprintf(str, LOCAL_BUF_SIZE, "%f", DBL_MAX);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_ok);
    assert_float_equal(result, DBL_MAX, DBL_EPSILON);

    pcmk__snprintf(str, LOCAL_BUF_SIZE, "%f", -DBL_MAX);
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
    pcmk__snprintf(str, LOCAL_BUF_SIZE, "1e%d", DBL_MAX_10_EXP + 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), EOVERFLOW);
    assert_true(result > DBL_MAX);

    pcmk__snprintf(str, LOCAL_BUF_SIZE, "-1e%d", DBL_MAX_10_EXP + 1);
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
    pcmk__snprintf(str, LOCAL_BUF_SIZE, "1e%d", DBL_MIN_10_EXP - 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_underflow);
    assert_true(result >= 0.0);
    assert_true(result <= DBL_MIN);

    pcmk__snprintf(str, LOCAL_BUF_SIZE, "-1e%d", DBL_MIN_10_EXP - 1);
    assert_int_equal(pcmk__scan_double(str, &result, NULL, NULL), pcmk_rc_underflow);
    assert_true(result <= 0.0);
    assert_true(result >= -DBL_MIN);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input_string),
                cmocka_unit_test(bad_input_string),
                cmocka_unit_test(trailing_chars),
                cmocka_unit_test(no_result_variable),
                cmocka_unit_test(typical_case),
                cmocka_unit_test(double_overflow),
                cmocka_unit_test(double_underflow))
