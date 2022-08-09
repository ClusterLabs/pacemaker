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
    assert_false(crm_is_true(NULL));
}

static void
is_true(void **state) {
    assert_true(crm_is_true("true"));
    assert_true(crm_is_true("TrUe"));
    assert_true(crm_is_true("on"));
    assert_true(crm_is_true("ON"));
    assert_true(crm_is_true("yes"));
    assert_true(crm_is_true("yES"));
    assert_true(crm_is_true("y"));
    assert_true(crm_is_true("Y"));
    assert_true(crm_is_true("1"));
}

static void
is_false(void **state) {
    assert_false(crm_is_true("false"));
    assert_false(crm_is_true("fAlSe"));
    assert_false(crm_is_true("off"));
    assert_false(crm_is_true("OFF"));
    assert_false(crm_is_true("no"));
    assert_false(crm_is_true("No"));
    assert_false(crm_is_true("n"));
    assert_false(crm_is_true("N"));
    assert_false(crm_is_true("0"));

    assert_false(crm_is_true(""));
    assert_false(crm_is_true("blahblah"));

    assert_false(crm_is_true("truedat"));
    assert_false(crm_is_true("onnn"));
    assert_false(crm_is_true("yep"));
    assert_false(crm_is_true("Y!"));
    assert_false(crm_is_true("100"));
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(bad_input),
        cmocka_unit_test(is_true),
        cmocka_unit_test(is_false),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
