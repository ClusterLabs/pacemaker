#include <glib.h>

#include <crm_internal.h>

static void
empty_input_string(void) {
    char *start = NULL;
    char *end = NULL;

    g_assert(pcmk__split_range(NULL, '-', &start, &end) == false);
    g_assert(pcmk__split_range("", '-', &start, &end) == false);
}

static void
missing_separator(void) {
    char *start = NULL;
    char *end = NULL;

    g_assert(pcmk__split_range("1234", '-', &start, &end) == false);
    g_assert(start == NULL);
    g_assert(end == NULL);
}

static void
no_range_end(void) {
    char *start = NULL;
    char *end = NULL;

    g_assert(pcmk__split_range("2000-", '-', &start, &end) == true);
    g_assert_cmpstr(start, ==, "2000");
    g_assert(end == NULL);

    free(start);
}

static void
range_start_and_end(void) {
    char *start = NULL;
    char *end = NULL;

    g_assert(pcmk__split_range("2000-2020", '-', &start, &end) == true);
    g_assert_cmpstr(start, ==, "2000");
    g_assert_cmpstr(end, ==, "2020");

    free(start);
    free(end);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/range/empty", empty_input_string);
    g_test_add_func("/common/strings/range/no_sep", missing_separator);
    g_test_add_func("/common/strings/range/no_end", no_range_end);
    g_test_add_func("/common/strings/range/start_and_end", range_start_and_end);

    return g_test_run();
}
