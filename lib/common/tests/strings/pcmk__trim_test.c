/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <string.h>

static void
empty_input(void **state)
{
    char *s = strdup("");

    assert_null(pcmk__trim(NULL));
    assert_string_equal(pcmk__trim(s), "");

    free(s);
}

static void
leading_newline(void **state)
{
    char *s = strdup("\nabcd");

    assert_string_equal(pcmk__trim(s), "\nabcd");
    free(s);
}

static void
middle_newline(void **state)
{
    char *s = strdup("ab\ncd");

    assert_string_equal(pcmk__trim(s), "ab\ncd");
    free(s);
}

static void
trailing_newline(void **state)
{
    char *s = strdup("abcd\n\n");

    assert_string_equal(pcmk__trim(s), "abcd");
    free(s);

    s = strdup("abcd\n ");
    assert_string_equal(pcmk__trim(s), "abcd\n ");
    free(s);
}

static void
other_whitespace(void **state)
{
    char *s = strdup("  ab\t\ncd  \t");

    assert_string_equal(pcmk__trim(s), "  ab\t\ncd  \t");
    free(s);
}

int main(int argc, char **argv) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input),
        cmocka_unit_test(leading_newline),
        cmocka_unit_test(middle_newline),
        cmocka_unit_test(trailing_newline),
        cmocka_unit_test(other_whitespace),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
