#include <glib.h>

#include <crm_internal.h>

static void
empty_input_list(void) {
    g_assert_false(pcmk__strcase_any_of("xxx", NULL));
    g_assert_false(pcmk__str_any_of("xxx", NULL));
    g_assert_false(pcmk__strcase_any_of("", NULL));
    g_assert_false(pcmk__str_any_of("", NULL));
}

static void
empty_string(void) {
    g_assert_false(pcmk__strcase_any_of("", "xxx", "yyy", NULL));
    g_assert_false(pcmk__str_any_of("", "xxx", "yyy", NULL));
    g_assert_false(pcmk__strcase_any_of(NULL, "xxx", "yyy", NULL));
    g_assert_false(pcmk__str_any_of(NULL, "xxx", "yyy", NULL));
}

static void
in_list(void) {
    g_assert_true(pcmk__strcase_any_of("xxx", "aaa", "bbb", "xxx", NULL));
    g_assert_true(pcmk__str_any_of("xxx", "aaa", "bbb", "xxx", NULL));
    g_assert_true(pcmk__strcase_any_of("XXX", "aaa", "bbb", "xxx", NULL));
}

static void
not_in_list(void) {
    g_assert_false(pcmk__strcase_any_of("xxx", "aaa", "bbb", NULL));
    g_assert_false(pcmk__str_any_of("xxx", "aaa", "bbb", NULL));
    g_assert_false(pcmk__str_any_of("AAA", "aaa", "bbb", NULL));
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
