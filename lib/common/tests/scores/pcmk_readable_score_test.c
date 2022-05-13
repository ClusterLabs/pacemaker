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
outside_limits(void **state)
{
    assert_string_equal(pcmk_readable_score(CRM_SCORE_INFINITY * 2),
                        CRM_INFINITY_S);
    assert_string_equal(pcmk_readable_score(-CRM_SCORE_INFINITY * 2),
                        CRM_MINUS_INFINITY_S);
}

static void
inside_limits(void **state)
{
    assert_string_equal(pcmk_readable_score(0), "0");
    assert_string_equal(pcmk_readable_score(1024), "1024");
    assert_string_equal(pcmk_readable_score(-1024), "-1024");
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(outside_limits),
        cmocka_unit_test(inside_limits),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
