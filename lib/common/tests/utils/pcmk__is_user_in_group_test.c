/*
 * Copyright 2020-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "mock_private.h"

static int
setup(void **state)
{
    pcmk__mock_getgrnam = true;
    return 0;
}

static int
teardown(void **state)
{
    pcmk__mock_getgrnam = false;
    return 0;
}

static void
null_args(void **state)
{
    pcmk__assert_asserts(pcmk__is_user_in_group(NULL, NULL));
    pcmk__assert_asserts(pcmk__is_user_in_group(NULL, "grp0"));
    pcmk__assert_asserts(pcmk__is_user_in_group("user0", NULL));
}

static void
user_in_group(void **state)
{
    assert_true(pcmk__is_user_in_group("user0", "grp0"));
}

static void
user_not_in_group(void **state)
{
    assert_false(pcmk__is_user_in_group("user0", "nonexistent_group"));
    assert_false(pcmk__is_user_in_group("user2", "grp0"));
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(null_args),
                cmocka_unit_test(user_in_group),
                cmocka_unit_test(user_not_in_group))
