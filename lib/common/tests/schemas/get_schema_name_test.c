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
setup(void **state)
{
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    crm_schema_init();
    return 0;
}

static int
teardown(void **state)
{
    crm_schema_cleanup();
    unsetenv("PCMK_schema_directory");
    return 0;
}

static void
bad_input(void **state)
{
    assert_string_equal("unknown", get_schema_name(-1));
    assert_string_equal("unknown", get_schema_name(47000));
}

static void
typical_usage(void **state)
{
    assert_string_equal("pacemaker-1.0", get_schema_name(0));
    assert_string_equal("pacemaker-1.2", get_schema_name(1));
    assert_string_equal("pacemaker-2.0", get_schema_name(3));
    assert_string_equal("pacemaker-2.5", get_schema_name(8));
    assert_string_equal("pacemaker-3.0", get_schema_name(14));

    // @COMPAT pacemaker-next is deprecated since 2.1.5
    assert_string_equal("pacemaker-next", get_schema_name(15));

    assert_string_equal(PCMK_VALUE_NONE, get_schema_name(16));
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(typical_usage));
