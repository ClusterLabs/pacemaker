/*
 * Copyright 2023-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static int
setup(void **state) {
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    crm_schema_init();
    return 0;
}

static int
teardown(void **state) {
    pcmk__schema_cleanup();
    unsetenv("PCMK_schema_directory");
    return 0;
}

static void
bad_input(void **state) {
    assert_int_equal(16, get_schema_version(NULL));
    assert_int_equal(-1, get_schema_version(""));
    assert_int_equal(-1, get_schema_version("blahblah"));
    assert_int_equal(-1, get_schema_version("pacemaker-2.47"));
    assert_int_equal(-1, get_schema_version("pacemaker-47.0"));
}

static void
typical_usage(void **state) {
    assert_int_equal(0, get_schema_version("pacemaker-1.0"));
    assert_int_equal(0, get_schema_version("PACEMAKER-1.0"));
    assert_int_equal(1, get_schema_version("pacemaker-1.2"));
    assert_int_equal(3, get_schema_version("pacemaker-2.0"));
    assert_int_equal(3, get_schema_version("pAcEmAkEr-2.0"));
    assert_int_equal(8, get_schema_version("pacemaker-2.5"));
    assert_int_equal(14, get_schema_version("pacemaker-3.0"));
    assert_int_equal(14, get_schema_version("paceMAKER-3.0"));
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(typical_usage));
