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

extern int pcmk__score_red;
extern int pcmk__score_green;
extern int pcmk__score_yellow;

static void
empty_input(void **state)
{
    assert_int_equal(char2score(NULL), 0);
}

static void
bad_input(void **state)
{
    assert_int_equal(char2score("PQRST"), 0);
    assert_int_equal(char2score("3.141592"), 3);
    assert_int_equal(char2score("0xf00d"), 0);
}

static void
special_values(void **state)
{
    assert_int_equal(char2score("-INFINITY"), -CRM_SCORE_INFINITY);
    assert_int_equal(char2score("INFINITY"), CRM_SCORE_INFINITY);
    assert_int_equal(char2score("+INFINITY"), CRM_SCORE_INFINITY);

    pcmk__score_red = 10;
    pcmk__score_green = 20;
    pcmk__score_yellow = 30;

    assert_int_equal(char2score("red"), pcmk__score_red);
    assert_int_equal(char2score("green"), pcmk__score_green);
    assert_int_equal(char2score("yellow"), pcmk__score_yellow);

    assert_int_equal(char2score("ReD"), pcmk__score_red);
    assert_int_equal(char2score("GrEeN"), pcmk__score_green);
    assert_int_equal(char2score("yElLoW"), pcmk__score_yellow);
}

/* These ridiculous macros turn an integer constant into a string constant. */
#define A(x) #x
#define B(x) A(x)

static void
outside_limits(void **state)
{
    assert_int_equal(char2score(B(CRM_SCORE_INFINITY) "00"), CRM_SCORE_INFINITY);
    assert_int_equal(char2score("-" B(CRM_SCORE_INFINITY) "00"), -CRM_SCORE_INFINITY);
}

static void
inside_limits(void **state)
{
    assert_int_equal(char2score("1234"), 1234);
    assert_int_equal(char2score("-1234"), -1234);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input),
        cmocka_unit_test(bad_input),
        cmocka_unit_test(special_values),
        cmocka_unit_test(outside_limits),
        cmocka_unit_test(inside_limits),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
