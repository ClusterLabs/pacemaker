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
all_set(void **state) {
    assert_false(pcmk_all_flags_set(0x000, 0x003));
    assert_true(pcmk_all_flags_set(0x00f, 0x003));
    assert_false(pcmk_all_flags_set(0x00f, 0x010));
    assert_false(pcmk_all_flags_set(0x00f, 0x011));
    assert_true(pcmk_all_flags_set(0x000, 0x000));
    assert_true(pcmk_all_flags_set(0x00f, 0x000));
}

static void
one_is_set(void **state) {
    // pcmk_is_set() is a simple macro alias for pcmk_all_flags_set()
    assert_true(pcmk_is_set(0x00f, 0x001));
    assert_false(pcmk_is_set(0x00f, 0x010));
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(all_set),
        cmocka_unit_test(one_is_set),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
