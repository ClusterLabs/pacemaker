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

static void
s_is_null(void **state) {
    assert_null(pcmk__s(NULL, NULL));
    assert_string_equal(pcmk__s(NULL, ""), "");
    assert_string_equal(pcmk__s(NULL, "something"), "something");
}

static void
s_is_not_null(void **state) {
    assert_string_equal(pcmk__s("something", NULL), "something");
    assert_string_equal(pcmk__s("something", "default"), "something");
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(s_is_null),
        cmocka_unit_test(s_is_not_null),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
