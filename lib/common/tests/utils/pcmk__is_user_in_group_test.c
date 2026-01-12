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

#include "../../crmcommon_private.h"
#include "mock_private.h"

#define assert_user_in_group(user, group, expected)             \
    do {                                                        \
        /* Primary group: grp1 */                               \
        const struct passwd entry = { .pw_gid = 1 };            \
                                                                \
        expect_string(__wrap_getpwnam, name, user);             \
        will_return(__wrap_getpwnam, 0);                        \
        will_return(__wrap_getpwnam, &entry);                   \
                                                                \
        if (expected) {                                         \
            assert_true(pcmk__is_user_in_group(user, group));   \
        } else {                                                \
            assert_false(pcmk__is_user_in_group(user, group));  \
        }                                                       \
    } while (0);

static int
setup(void **state)
{
    pcmk__mock_getgrnam = true;
    pcmk__mock_getpwnam = true;
    return 0;
}

static int
teardown(void **state)
{
    pcmk__mock_getgrnam = false;
    pcmk__mock_getpwnam = false;
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
    // user0 is not in grp1's member list
    assert_user_in_group("user0", "grp1", true);

    // user1 has grp1 as primary group and is also in grp1's member list
    assert_user_in_group("user1", "grp1", true);

    // user1 has grp1 as primary group but is in grp0's member list
    assert_user_in_group("user1", "grp0", true);
}

static void
user_not_in_group(void **state)
{
    // Group does not exist
    assert_user_in_group("user0", "nonexistent_group", false);

    // Group exists but user is not a member
    assert_user_in_group("user2", "grp0", false);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(null_args),
                cmocka_unit_test(user_in_group),
                cmocka_unit_test(user_not_in_group))
