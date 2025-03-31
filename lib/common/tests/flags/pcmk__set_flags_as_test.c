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
set_flags(void **state) {
    assert_int_equal(pcmk__set_flags_as(__func__, __LINE__, PCMK__LOG_TRACE,
                                        "Test", "test", 0x0f0, 0x00f, NULL),
                     0x0ff);
    assert_int_equal(pcmk__set_flags_as(__func__, __LINE__, PCMK__LOG_TRACE,
                                        "Test", "test", 0x0f0, 0xf0f, NULL),
                     0xfff);
    assert_int_equal(pcmk__set_flags_as(__func__, __LINE__, PCMK__LOG_TRACE,
                                        "Test", "test", 0x0f0, 0xfff, NULL),
                     0xfff);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(set_flags))
