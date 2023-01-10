/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/pengine/internal.h>

static void
bad_args(void **state) {
    assert_null(pe_base_name_end(NULL));
    assert_null(pe_base_name_end(""));
}

static void
no_suffix(void **state) {
    assert_string_equal(pe_base_name_end("rsc"), "c");
    assert_string_equal(pe_base_name_end("rsc0"), "0");
}

static void
has_suffix(void **state) {
    assert_string_equal(pe_base_name_end("rsc:0"), "c:0");
    assert_string_equal(pe_base_name_end("rsc:100"), "c:100");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_args),
                cmocka_unit_test(no_suffix),
                cmocka_unit_test(has_suffix))
