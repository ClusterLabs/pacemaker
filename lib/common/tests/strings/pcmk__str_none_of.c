#include <glib.h>

#include <crm_internal.h>

static void
empty_input_list(void) {
    g_assert(pcmk__str_none_of("xxx", NULL) == true);
    g_assert(pcmk__str_none_of("", NULL) == true);
}

static void
empty_string(void) {
    g_assert(pcmk__str_none_of("", "xxx", "yyy", NULL) == true);
    g_assert(pcmk__str_none_of(NULL, "xxx", "yyy", NULL) == true);
}

static void
in_list(void) {
    g_assert(pcmk__str_none_of("xxx", "aaa", "bbb", "xxx", NULL) == false);
    g_assert(pcmk__str_none_of("XXX", "aaa", "bbb", "xxx", NULL) == false);
}

static void
not_in_list(void) {
    g_assert(pcmk__str_none_of("xxx", "aaa", "bbb", NULL) == true);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/none_of/empty_list", empty_input_list);
    g_test_add_func("/common/strings/none_of/empty_string", empty_string);
    g_test_add_func("/common/strings/none_of/in", in_list);
    g_test_add_func("/common/strings/none_of/not_in", not_in_list);

    return g_test_run();
}
