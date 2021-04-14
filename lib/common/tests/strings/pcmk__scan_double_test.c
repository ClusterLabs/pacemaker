/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <float.h>  // DBL_MAX, etc.
#include <math.h>   // fabs()
#include <glib.h>

// Ensure plenty of characters for %f display
#define LOCAL_BUF_SIZE 2 * DBL_MAX_10_EXP

/*
 * Avoids compiler warnings for floating-point equality checks.
 * Use for comparing numbers (e.g., 1.0 == 1.0), not expression values.
 */
#define ASSERT_DBL_EQ(d1, d2) g_assert_cmpfloat(fabs(d1 - d2), \
                                                <, DBL_EPSILON);

static void
empty_input_string(void)
{
    double result;

    // Without default_text
    g_assert_cmpint(pcmk__scan_double(NULL, &result, NULL, NULL), ==, EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);

    g_assert_cmpint(pcmk__scan_double("", &result, NULL, NULL), ==, EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);

    // With default_text
    g_assert_cmpint(pcmk__scan_double(NULL, &result, "2.0", NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, 2.0);

    g_assert_cmpint(pcmk__scan_double("", &result, "2.0", NULL), ==, EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);
}

static void
bad_input_string(void)
{
    double result;

    // Without default text
    g_assert_cmpint(pcmk__scan_double("asdf", &result, NULL, NULL), ==, EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);

    g_assert_cmpint(pcmk__scan_double("as2.0", &result, NULL, NULL), ==,
                    EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);

    // With default text (not used)
    g_assert_cmpint(pcmk__scan_double("asdf", &result, "2.0", NULL), ==,
                    EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);

    g_assert_cmpint(pcmk__scan_double("as2.0", &result, "2.0", NULL), ==,
                    EINVAL);
    ASSERT_DBL_EQ(result, PCMK__PARSE_DBL_DEFAULT);
}

static void
trailing_chars(void)
{
    double result;

    g_assert_cmpint(pcmk__scan_double("2.0asdf", &result, NULL, NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, 2.0);
}

static void
typical_case(void)
{
    char str[LOCAL_BUF_SIZE];
    double result;

    g_assert_cmpint(pcmk__scan_double("0.0", &result, NULL, NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, 0.0);

    g_assert_cmpint(pcmk__scan_double("1.0", &result, NULL, NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, 1.0);

    g_assert_cmpint(pcmk__scan_double("-1.0", &result, NULL, NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, -1.0);

    snprintf(str, LOCAL_BUF_SIZE, "%f", DBL_MAX);
    g_assert_cmpint(pcmk__scan_double(str, &result, NULL, NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, DBL_MAX);

    snprintf(str, LOCAL_BUF_SIZE, "%f", -DBL_MAX);
    g_assert_cmpint(pcmk__scan_double(str, &result, NULL, NULL), ==,
                    pcmk_rc_ok);
    ASSERT_DBL_EQ(result, -DBL_MAX);
}

static void
double_overflow(void)
{
    char str[LOCAL_BUF_SIZE];
    double result;

    /*
     * 1e(DBL_MAX_10_EXP + 1) produces an inf value
     * Can't use ASSERT_DBL_EQ() because (inf - inf) == NaN
     */
    snprintf(str, LOCAL_BUF_SIZE, "1e%d", DBL_MAX_10_EXP + 1);
    g_assert_cmpint(pcmk__scan_double(str, &result, NULL, NULL), ==, EOVERFLOW);
    g_assert_cmpfloat(result, >, DBL_MAX);

    snprintf(str, LOCAL_BUF_SIZE, "-1e%d", DBL_MAX_10_EXP + 1);
    g_assert_cmpint(pcmk__scan_double(str, &result, NULL, NULL), ==, EOVERFLOW);
    g_assert_cmpfloat(result, <, -DBL_MAX);
}

static void
double_underflow(void)
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
    g_assert_cmpint(pcmk__scan_double(str, &result, NULL, NULL), ==,
                    pcmk_rc_underflow);
    g_assert_cmpfloat(result, >=, 0.0);
    g_assert_cmpfloat(result, <=, DBL_MIN);

    snprintf(str, LOCAL_BUF_SIZE, "-1e%d", DBL_MIN_10_EXP - 1);
    g_assert_cmpint(pcmk__scan_double(str, &result, NULL, NULL), ==,
                    pcmk_rc_underflow);
    g_assert_cmpfloat(result, <=, 0.0);
    g_assert_cmpfloat(result, >=, -DBL_MIN);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    // Test for input string issues
    g_test_add_func("/common/strings/double/empty_input", empty_input_string);
    g_test_add_func("/common/strings/double/bad_input", bad_input_string);
    g_test_add_func("/common/strings/double/trailing_chars", trailing_chars);

    // Test for numeric issues
    g_test_add_func("/common/strings/double/typical", typical_case);
    g_test_add_func("/common/strings/double/overflow", double_overflow);
    g_test_add_func("/common/strings/double/underflow", double_underflow);

    return g_test_run();
}

