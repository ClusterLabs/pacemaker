#include <glib.h>

#include <crm_internal.h>

static void
empty_input_string(void) {
    long long start, end;

    g_assert(pcmk__split_range(NULL, &start, &end) == pcmk_rc_unknown_format);
    g_assert(pcmk__split_range("", &start, &end) == pcmk_rc_unknown_format);
}

static void
missing_separator(void) {
    long long start, end;

    g_assert(pcmk__split_range("1234", &start, &end) == pcmk_rc_ok);
    g_assert_cmpint(start, ==, 1234);
    g_assert_cmpint(end, ==, 1234);
}

static void
only_separator(void) {
    long long start, end;

    g_assert(pcmk__split_range("-", &start, &end) == pcmk_rc_unknown_format);
    g_assert_cmpint(start, ==, -1);
    g_assert_cmpint(end, ==, -1);
}

static void
no_range_end(void) {
    long long start, end;

    g_assert(pcmk__split_range("2000-", &start, &end) == pcmk_rc_ok);
    g_assert_cmpint(start, ==, 2000);
    g_assert_cmpint(end, ==, -1);
}

static void
no_range_start(void) {
    long long start, end;

    g_assert(pcmk__split_range("-2020", &start, &end) == pcmk_rc_ok);
    g_assert_cmpint(start, ==, -1);
    g_assert_cmpint(end, ==, 2020);
}

static void
range_start_and_end(void) {
    long long start, end;

    g_assert(pcmk__split_range("2000-2020", &start, &end) == pcmk_rc_ok);
    g_assert_cmpint(start, ==, 2000);
    g_assert_cmpint(end, ==, 2020);
}

static void
garbage(void) {
    long long start, end;

    g_assert(pcmk__parse_ll_range("2000x-", &start, &end) == pcmk_rc_unknown_format);
    g_assert_cmpint(start, ==, -1);
    g_assert_cmpint(end, ==, -1);

    g_assert(pcmk__parse_ll_range("-x2000", &start, &end) == pcmk_rc_unknown_format);
    g_assert_cmpint(start, ==, -1);
    g_assert_cmpint(end, ==, -1);
}

int main(int argc, char **argv) {
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
