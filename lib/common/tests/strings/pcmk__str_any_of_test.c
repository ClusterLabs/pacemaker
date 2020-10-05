#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#include <crm_internal.h>

static void
empty_input_list(void) {
    g_assert_cmpint(pcmk__strcase_any_of("xxx", NULL), ==, false);
    g_assert_cmpint(pcmk__str_any_of("xxx", NULL), ==, false);
    g_assert_cmpint(pcmk__strcase_any_of("", NULL), ==, false);
    g_assert_cmpint(pcmk__str_any_of("", NULL), ==, false);
}

static void
empty_string(void) {
    g_assert_cmpint(pcmk__strcase_any_of("", "xxx", "yyy", NULL), ==, false);
    g_assert_cmpint(pcmk__str_any_of("", "xxx", "yyy", NULL), ==, false);
    g_assert_cmpint(pcmk__strcase_any_of(NULL, "xxx", "yyy", NULL), ==, false);
    g_assert_cmpint(pcmk__str_any_of(NULL, "xxx", "yyy", NULL), ==, false);
}

static void
in_list(void) {
    g_assert_cmpint(pcmk__strcase_any_of("xxx", "aaa", "bbb", "xxx", NULL), ==, true);
    g_assert_cmpint(pcmk__str_any_of("xxx", "aaa", "bbb", "xxx", NULL), ==, true);
    g_assert_cmpint(pcmk__strcase_any_of("XXX", "aaa", "bbb", "xxx", NULL), ==, true);
}

static void
not_in_list(void) {
    g_assert_cmpint(pcmk__strcase_any_of("xxx", "aaa", "bbb", NULL), ==, false);
    g_assert_cmpint(pcmk__str_any_of("xxx", "aaa", "bbb", NULL), ==, false);
    g_assert_cmpint(pcmk__str_any_of("AAA", "aaa", "bbb", NULL), ==, false);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/any_of/empty_list", empty_input_list);
    g_test_add_func("/common/strings/any_of/empty_string", empty_string);
    g_test_add_func("/common/strings/any_of/in", in_list);
    g_test_add_func("/common/strings/any_of/not_in", not_in_list);

    return g_test_run();
}
