/*
 * Copyright 2020-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
any_set(void **state) {
    assert_false(pcmk__any_flags_set(0x000, 0x000));
    assert_false(pcmk__any_flags_set(0x000, 0x001));
    assert_true(pcmk__any_flags_set(0x00f, 0x001));
    assert_false(pcmk__any_flags_set(0x00f, 0x010));
    assert_true(pcmk__any_flags_set(0x00f, 0x011));
    assert_false(pcmk__any_flags_set(0x000, 0x000));
    assert_false(pcmk__any_flags_set(0x00f, 0x000));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(any_set))
