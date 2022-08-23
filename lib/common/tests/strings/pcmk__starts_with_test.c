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
    assert_false(pcmk__starts_with(NULL, "x"));
    assert_false(pcmk__starts_with("abc", NULL));
}

static void
starts_with(void **state) {
    assert_true(pcmk__starts_with("abc", "a"));
    assert_true(pcmk__starts_with("abc", "ab"));
    assert_true(pcmk__starts_with("abc", "abc"));

    assert_false(pcmk__starts_with("abc", "A"));
    assert_false(pcmk__starts_with("abc", "bc"));

    assert_false(pcmk__starts_with("", "x"));
    assert_true(pcmk__starts_with("xyz", ""));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(starts_with))
