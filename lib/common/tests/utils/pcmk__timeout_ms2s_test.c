/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
pcmk__timeout_ms2s_test(void **state)
{
    assert_int_equal(0, pcmk__timeout_ms2s(0));

    /* Any non-zero amount should return 1 */
    assert_int_equal(1, pcmk__timeout_ms2s(1));
    assert_int_equal(1, pcmk__timeout_ms2s(499));
    assert_int_equal(1, pcmk__timeout_ms2s(500));
    assert_int_equal(1, pcmk__timeout_ms2s(501));

    assert_int_equal(1, pcmk__timeout_ms2s(1001));
    assert_int_equal(1, pcmk__timeout_ms2s(1499));
    assert_int_equal(2, pcmk__timeout_ms2s(1500));
    assert_int_equal(2, pcmk__timeout_ms2s(1501));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(pcmk__timeout_ms2s_test))
