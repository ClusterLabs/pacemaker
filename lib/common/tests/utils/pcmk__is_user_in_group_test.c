/*
 * Copyright 2020-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/acl.h>

#include "../../crmcommon_private.h"
#include "mock_private.h"

static void
is_pcmk__is_user_in_group(void **state)
{
    pcmk__mock_grent = true;

    // null user
    assert_false(pcmk__is_user_in_group(NULL, "grp0"));
    // null group
    assert_false(pcmk__is_user_in_group("user0", NULL));
    // nonexistent group
    assert_false(pcmk__is_user_in_group("user0", "nonexistent_group"));
    // user is in group
    assert_true(pcmk__is_user_in_group("user0", "grp0"));
    // user is not in group
    assert_false(pcmk__is_user_in_group("user2", "grp0"));

    pcmk__mock_grent = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(is_pcmk__is_user_in_group))
