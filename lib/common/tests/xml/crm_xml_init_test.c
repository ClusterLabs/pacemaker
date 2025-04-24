/*
 * Copyright 2023-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "crmcommon_private.h"

static void
schemas_initialized(void **state)
{
    assert_non_null(pcmk__find_x_0_schema());
}

// The group setup/teardown functions call crm_xml_init()/crm_xml_cleanup()
PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(schemas_initialized))
