/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

static int
setup(void **state)
{
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    pcmk__xml_test_setup_group(state);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__xml_test_teardown_group(state);
    unsetenv("PCMK_schema_directory");
    return 0;
}

// Unknown schemas (including NULL) are unsupported, but sort first as failsafe
static void
unknown_is_lesser(void **state)
{
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-0.1",
                                          "pacemaker-0.2") == 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-0.1",
                                          "pacemaker-1.0") < 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-1.0",
                                          "pacemaker-0.1") > 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-0.1",
                                          PCMK_VALUE_NONE) < 0);
    assert_true(pcmk__cmp_schemas_by_name(PCMK_VALUE_NONE,
                                          "pacemaker-0.1") > 0);
    assert_true(pcmk__cmp_schemas_by_name(NULL, NULL) == 0);
    assert_true(pcmk__cmp_schemas_by_name(NULL, "pacemaker-0.0") == 0);
    assert_true(pcmk__cmp_schemas_by_name(NULL, "pacemaker-2.0") < 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-1.3", NULL) > 0);
    assert_true(pcmk__cmp_schemas_by_name(NULL, PCMK_VALUE_NONE) < 0);
    assert_true(pcmk__cmp_schemas_by_name(PCMK_VALUE_NONE, NULL) > 0);
}

// @COMPAT none is deprecated since 2.1.8
static void
none_is_greater(void **state)
{
    assert_true(pcmk__cmp_schemas_by_name(PCMK_VALUE_NONE,
                                          PCMK_VALUE_NONE) == 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-3.10",
                                          PCMK_VALUE_NONE) < 0);
    assert_true(pcmk__cmp_schemas_by_name(PCMK_VALUE_NONE,
                                          "pacemaker-1.0") > 0);
}

static void
known_numeric(void **state)
{
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-1.0",
                                          "pacemaker-1.0") == 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-1.2",
                                          "pacemaker-1.0") > 0);
    assert_true(pcmk__cmp_schemas_by_name("pacemaker-1.2",
                                          "pacemaker-2.0") < 0);
}

static void
case_sensitive(void **state)
{
    assert_true(pcmk__cmp_schemas_by_name("Pacemaker-1.0",
                                          "pacemaker-1.0") != 0);
    assert_true(pcmk__cmp_schemas_by_name("PACEMAKER-1.2",
                                          "pacemaker-1.2") != 0);
    assert_true(pcmk__cmp_schemas_by_name("PaceMaker-2.0",
                                          "pacemaker-2.0") != 0);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(unknown_is_lesser),
                cmocka_unit_test(none_is_greater),
                cmocka_unit_test(known_numeric),
                cmocka_unit_test(case_sensitive));
