/*
 * Copyright 2020-2021 the Pacemaker project contributors
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

static void
same_pointer(void **state) {
    const char *s1 = "abcd";
    const char *s2 = "wxyz";

    assert_int_equal(pcmk__strcmp(s1, s1, pcmk__str_none), 0);
    assert_true(pcmk__str_eq(s1, s1, pcmk__str_none));
    assert_int_not_equal(pcmk__strcmp(s1, s2, pcmk__str_none), 0);
    assert_false(pcmk__str_eq(s1, s2, pcmk__str_none));
    assert_int_equal(pcmk__strcmp(NULL, NULL, pcmk__str_none), 0);
}

static void
one_is_null(void **state) {
    const char *s1 = "abcd";

    assert_int_equal(pcmk__strcmp(s1, NULL, pcmk__str_null_matches), 0);
    assert_true(pcmk__str_eq(s1, NULL, pcmk__str_null_matches));
    assert_int_equal(pcmk__strcmp(NULL, s1, pcmk__str_null_matches), 0);
    assert_true(pcmk__strcmp(s1, NULL, pcmk__str_none) > 0);
    assert_false(pcmk__str_eq(s1, NULL, pcmk__str_none));
    assert_true(pcmk__strcmp(NULL, s1, pcmk__str_none) < 0);
}

static void
case_matters(void **state) {
    const char *s1 = "abcd";
    const char *s2 = "ABCD";

    assert_true(pcmk__strcmp(s1, s2, pcmk__str_none) > 0);
    assert_false(pcmk__str_eq(s1, s2, pcmk__str_none));
    assert_true(pcmk__strcmp(s2, s1, pcmk__str_none) < 0);
}

static void
case_insensitive(void **state) {
    const char *s1 = "abcd";
    const char *s2 = "ABCD";

    assert_int_equal(pcmk__strcmp(s1, s2, pcmk__str_casei), 0);
    assert_true(pcmk__str_eq(s1, s2, pcmk__str_casei));
}

static void
regex(void **state) {
    const char *s1 = "abcd";
    const char *s2 = "ABCD";

    assert_true(pcmk__strcmp(NULL, "a..d", pcmk__str_regex) > 0);
    assert_true(pcmk__strcmp(s1, NULL, pcmk__str_regex) > 0);
    assert_int_equal(pcmk__strcmp(s1, "a..d", pcmk__str_regex), 0);
    assert_true(pcmk__str_eq(s1, "a..d", pcmk__str_regex));
    assert_int_not_equal(pcmk__strcmp(s1, "xxyy", pcmk__str_regex), 0);
    assert_false(pcmk__str_eq(s1, "xxyy", pcmk__str_regex));
    assert_int_equal(pcmk__strcmp(s2, "a..d", pcmk__str_regex|pcmk__str_casei), 0);
    assert_true(pcmk__str_eq(s2, "a..d", pcmk__str_regex|pcmk__str_casei));
    assert_int_not_equal(pcmk__strcmp(s2, "a..d", pcmk__str_regex), 0);
    assert_false(pcmk__str_eq(s2, "a..d", pcmk__str_regex));
    assert_true(pcmk__strcmp(s2, "*ab", pcmk__str_regex) > 0);
}

int main(int argc, char **argv) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(same_pointer),
        cmocka_unit_test(one_is_null),
        cmocka_unit_test(case_matters),
        cmocka_unit_test(case_insensitive),
        cmocka_unit_test(regex),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
