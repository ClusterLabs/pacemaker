/*
 * Copyright 2022 the Pacemaker project contributors
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
invalid_params(void **state)
{
    char *buf = malloc(9);

    assert_null(score2char_stack(100, NULL, 9));
    assert_null(score2char_stack(100, buf, 9));

    free(buf);
}

static void
outside_limits(void **state)
{
    char *buf = malloc(10);

    buf = score2char_stack(CRM_SCORE_INFINITY * 2, buf, 10);
    assert_string_equal(buf, CRM_INFINITY_S);

    buf = score2char_stack(-CRM_SCORE_INFINITY * 2, buf, 10);
    assert_string_equal(buf, CRM_MINUS_INFINITY_S);

    free(buf);
}

static void
inside_limits(void **state)
{
    char *buf = malloc(10);

    buf = score2char_stack(0, buf, 10);
    assert_string_equal(buf, "0");

    buf = score2char_stack(1024, buf, 10);
    assert_string_equal(buf, "1024");

    buf = score2char_stack(-1024, buf, 10);
    assert_string_equal(buf, "-1024");

    free(buf);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(invalid_params),
        cmocka_unit_test(outside_limits),
        cmocka_unit_test(inside_limits),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
