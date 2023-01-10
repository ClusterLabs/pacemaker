/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <limits.h>

static void
readable_interval(void **state)
{
    assert_string_equal(pcmk__readable_interval(0), "0s");
    assert_string_equal(pcmk__readable_interval(30000), "30s");
    assert_string_equal(pcmk__readable_interval(150000), "2m30s");
    assert_string_equal(pcmk__readable_interval(3333), "3.333s");
    assert_string_equal(pcmk__readable_interval(UINT_MAX), "49d17h2m47.295s");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(readable_interval))
