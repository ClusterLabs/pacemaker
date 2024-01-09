/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
btoa(void **state) {
    assert_string_equal(pcmk__btoa(false), "false");
    assert_string_equal(pcmk__btoa(true), "true");
    assert_string_equal(pcmk__btoa(1 == 0), "false");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(btoa))
