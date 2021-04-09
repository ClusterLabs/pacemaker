/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

static void
empty_input_string(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range(NULL, &start, &end), ==,
                    pcmk_rc_unknown_format);
    g_assert_cmpint(pcmk__parse_ll_range("", &start, &end), ==,
                    pcmk_rc_unknown_format);
}

static void
missing_separator(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range("1234", &start, &end), ==, pcmk_rc_ok);
    g_assert_cmpint(start, ==, 1234);
    g_assert_cmpint(end, ==, 1234);
}

static void
only_separator(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range("-", &start, &end), ==,
                    pcmk_rc_unknown_format);
    g_assert_cmpint(start, ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(end, ==, PCMK__PARSE_INT_DEFAULT);
}

static void
no_range_end(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range("2000-", &start, &end), ==,
                    pcmk_rc_ok);
    g_assert_cmpint(start, ==, 2000);
    g_assert_cmpint(end, ==, PCMK__PARSE_INT_DEFAULT);
}

static void
no_range_start(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range("-2020", &start, &end), ==,
                    pcmk_rc_ok);
    g_assert_cmpint(start, ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(end, ==, 2020);
}

static void
range_start_and_end(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range("2000-2020", &start, &end), ==,
                    pcmk_rc_ok);
    g_assert_cmpint(start, ==, 2000);
    g_assert_cmpint(end, ==, 2020);
}

static void
garbage(void)
{
    long long start, end;

    g_assert_cmpint(pcmk__parse_ll_range("2000x-", &start, &end), ==,
                    pcmk_rc_unknown_format);
    g_assert_cmpint(start, ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(end, ==, PCMK__PARSE_INT_DEFAULT);

    g_assert_cmpint(pcmk__parse_ll_range("-x2000", &start, &end), ==,
                    pcmk_rc_unknown_format);
    g_assert_cmpint(start, ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(end, ==, PCMK__PARSE_INT_DEFAULT);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/range/empty", empty_input_string);
    g_test_add_func("/common/strings/range/no_sep", missing_separator);
    g_test_add_func("/common/strings/range/only_sep", only_separator);
    g_test_add_func("/common/strings/range/no_end", no_range_end);
    g_test_add_func("/common/strings/range/no_start", no_range_start);
    g_test_add_func("/common/strings/range/start_and_end", range_start_and_end);

    g_test_add_func("/common/strings/range/garbage", garbage);

    return g_test_run();
}
