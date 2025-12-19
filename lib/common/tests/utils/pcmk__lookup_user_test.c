/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>

#include "crmcommon_private.h"
#include "mock_private.h"

#include <pwd.h>
#include <sys/types.h>

/*!
 * \internal
 * \brief Perform one test of \c pcmk__lookup_user() with non-NULL name
 *
 * \param[in] errno_to_set  Value that \c getpwnam() should set \c errno to
 * \param[in] returned_ent  Passwd entry that \c getpwnam() should return
 * \param[in] expected_rc   Expected return code of \c pcmk__lookup_user()
 * \param[in] expected_uid  Expected value at \p *uid after
 *                          \c pcmk__lookup_user() call
 * \param[in] expected_gid  Expected value at \p *gid after
 *                          \c pcmk__lookup_user() call
 */
static void
assert_lookup_user(int errno_to_set, struct passwd *returned_ent,
                   int expected_rc, uid_t expected_uid, gid_t expected_gid)
{
    static const char *user_name = "ha_user";
    uid_t uid = 0;
    gid_t gid = 0;

    pcmk__mock_getpwnam = true;

    expect_string(__wrap_getpwnam, name, user_name);
    will_return(__wrap_getpwnam, errno_to_set);
    will_return(__wrap_getpwnam, returned_ent);
    assert_int_equal(pcmk__lookup_user(user_name, NULL, NULL), expected_rc);

    expect_string(__wrap_getpwnam, name, user_name);
    will_return(__wrap_getpwnam, errno_to_set);
    will_return(__wrap_getpwnam, returned_ent);
    assert_int_equal(pcmk__lookup_user(user_name, &uid, NULL), expected_rc);
    assert_int_equal(uid, expected_uid);
    uid = 0;

    expect_string(__wrap_getpwnam, name, user_name);
    will_return(__wrap_getpwnam, errno_to_set);
    will_return(__wrap_getpwnam, returned_ent);
    assert_int_equal(pcmk__lookup_user(user_name, NULL, &gid), expected_rc);
    assert_int_equal(gid, expected_gid);
    gid = 0;

    expect_string(__wrap_getpwnam, name, user_name);
    will_return(__wrap_getpwnam, errno_to_set);
    will_return(__wrap_getpwnam, returned_ent);
    assert_int_equal(pcmk__lookup_user(user_name, &uid, &gid), expected_rc);
    assert_int_equal(uid, expected_uid);
    assert_int_equal(gid, expected_gid);

    pcmk__mock_getpwnam = false;
}

static void
null_name(void **state)
{
    uid_t uid = 0;
    gid_t gid = 0;

    // These dump core via CRM_CHECK()
    assert_int_equal(pcmk__lookup_user(NULL, NULL, NULL), EINVAL);

    assert_int_equal(pcmk__lookup_user(NULL, &uid, 0), EINVAL);
    assert_int_equal(uid, 0);

    assert_int_equal(pcmk__lookup_user(NULL, NULL, &gid), EINVAL);
    assert_int_equal(gid, 0);

    assert_int_equal(pcmk__lookup_user(NULL, &uid, &gid), EINVAL);
    assert_int_equal(uid, 0);
    assert_int_equal(gid, 0);
}

static void
getpwnam_fails(void **state)
{
    assert_lookup_user(EIO, NULL, EIO, 0, 0);
}

static void
no_matching_pwent(void **state)
{
    /* errno may or may not be set when no matching passwd entry is found.
     * However, if the return value is NULL and errno == 0, then we can be sure
     * no entry was found. In other words, it's sufficient but not necessary. So
     * this is our test case for "no matching entry," and we should return
     * ENOENT.
     */
    assert_lookup_user(0, NULL, ENOENT, 0, 0);
}

static void
entry_found(void **state)
{
    // We don't care about the other fields of the passwd entry
    struct passwd returned_ent = { .pw_uid = 1000, .pw_gid = 1000 };

    assert_lookup_user(0, &returned_ent, pcmk_rc_ok, 1000, 1000);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_name),
                cmocka_unit_test(getpwnam_fails),
                cmocka_unit_test(no_matching_pwent),
                cmocka_unit_test(entry_found))
