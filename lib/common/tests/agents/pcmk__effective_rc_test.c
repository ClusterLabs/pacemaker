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
#include <crm/common/agents.h>

static void
pcmk__effective_rc_test(void **state) {
    /* All other PCMK_OCF_* values after UNKNOWN are deprecated and no longer used,
     * so probably not worth testing them.
     */
    assert_int_equal(PCMK_OCF_OK, pcmk__effective_rc(PCMK_OCF_OK));
    assert_int_equal(PCMK_OCF_OK, pcmk__effective_rc(PCMK_OCF_DEGRADED));
    assert_int_equal(PCMK_OCF_RUNNING_PROMOTED, pcmk__effective_rc(PCMK_OCF_DEGRADED_PROMOTED));
    assert_int_equal(PCMK_OCF_UNKNOWN, pcmk__effective_rc(PCMK_OCF_UNKNOWN));

    /* There's nothing that says pcmk__effective_rc is restricted to PCMK_OCF_*
     * values.  That's just how it's used.  Let's check some values outside
     * that range just to be sure.
     */
    assert_int_equal(-1, pcmk__effective_rc(-1));
    assert_int_equal(255, pcmk__effective_rc(255));
    assert_int_equal(INT_MAX, pcmk__effective_rc(INT_MAX));
    assert_int_equal(INT_MIN, pcmk__effective_rc(INT_MIN));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(pcmk__effective_rc_test))
