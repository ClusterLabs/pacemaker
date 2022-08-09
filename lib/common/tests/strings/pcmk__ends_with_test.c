/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
bad_input(void **state) {
    assert_false(pcmk__ends_with(NULL, "xyz"));

    assert_true(pcmk__ends_with(NULL, NULL));
    assert_true(pcmk__ends_with(NULL, ""));
    assert_true(pcmk__ends_with("", NULL));
    assert_true(pcmk__ends_with("", ""));
    assert_true(pcmk__ends_with("abc", NULL));
    assert_true(pcmk__ends_with("abc", ""));
}

static void
ends_with(void **state) {
    assert_true(pcmk__ends_with("abc", "abc"));
    assert_true(pcmk__ends_with("abc", "bc"));
    assert_true(pcmk__ends_with("abc", "c"));
    assert_true(pcmk__ends_with("abcbc", "bc"));

    assert_false(pcmk__ends_with("abc", "def"));
    assert_false(pcmk__ends_with("abc", "defg"));
    assert_false(pcmk__ends_with("abc", "bcd"));
    assert_false(pcmk__ends_with("abc", "ab"));

    assert_false(pcmk__ends_with("abc", "BC"));
}

static void
ends_with_ext(void **state) {
    assert_true(pcmk__ends_with_ext("ab.c", ".c"));
    assert_true(pcmk__ends_with_ext("ab.cb.c", ".c"));

    assert_false(pcmk__ends_with_ext("ab.c", ".def"));
    assert_false(pcmk__ends_with_ext("ab.c", ".defg"));
    assert_false(pcmk__ends_with_ext("ab.c", ".cd"));
    assert_false(pcmk__ends_with_ext("ab.c", "ab"));

    assert_false(pcmk__ends_with_ext("ab.c", ".C"));
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(bad_input),
        cmocka_unit_test(ends_with),
        cmocka_unit_test(ends_with_ext),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
