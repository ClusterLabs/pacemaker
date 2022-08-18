/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
clear_none(void **state) {
    assert_int_equal(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                          "test", 0x0f0, 0x00f, NULL), 0x0f0);
    assert_int_equal(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                          "test", 0x0f0, 0xf0f, NULL), 0x0f0);
}

static void
clear_some(void **state) {
    assert_int_equal(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                          "test", 0x0f0, 0x020, NULL), 0x0d0);
    assert_int_equal(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                          "test", 0x0f0, 0x030, NULL), 0x0c0);
}

static void
clear_all(void **state) {
    assert_int_equal(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                          "test", 0x0f0, 0x0f0, NULL), 0x000);
    assert_int_equal(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                          "test", 0x0f0, 0xfff, NULL), 0x000);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(clear_none),
                cmocka_unit_test(clear_some),
                cmocka_unit_test(clear_all))
