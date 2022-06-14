/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "mock_private.h"

#include <pwd.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <sys/types.h>

static void
calloc_fails(void **state)
{
    uid_t uid;
    gid_t gid;

    pcmk__mock_calloc = true;   // calloc() will return NULL

    assert_int_equal(crm_user_lookup("hauser", &uid, &gid), -ENOMEM);

    pcmk__mock_calloc = false;  // Use real calloc()
}

static void
getpwnam_r_fails(void **state)
{
    uid_t uid;
    gid_t gid;

    // Set getpwnam_r() return value and result parameter
    pcmk__mock_getpwnam_r = true;
    will_return(__wrap_getpwnam_r, EIO);
    will_return(__wrap_getpwnam_r, NULL);

    assert_int_equal(crm_user_lookup("hauser", &uid, &gid), -EIO);

    pcmk__mock_getpwnam_r = false;
}

static void
no_matching_pwent(void **state)
{
    uid_t uid;
    gid_t gid;

    // Set getpwnam_r() return value and result parameter
    pcmk__mock_getpwnam_r = true;
    will_return(__wrap_getpwnam_r, 0);
    will_return(__wrap_getpwnam_r, NULL);

    assert_int_equal(crm_user_lookup("hauser", &uid, &gid), -EINVAL);

    pcmk__mock_getpwnam_r = false;
}

static void
entry_found(void **state)
{
    uid_t uid;
    gid_t gid;

    /* We don't care about any of the other fields of the password entry, so just
     * leave them blank.
     */
    struct passwd returned_ent = { .pw_uid = 1000, .pw_gid = 1000 };

    /* Test getpwnam_r returning a valid passwd entry, but we don't pass uid or gid. */

    // Set getpwnam_r() return value and result parameter
    pcmk__mock_getpwnam_r = true;
    will_return(__wrap_getpwnam_r, 0);
    will_return(__wrap_getpwnam_r, &returned_ent);

    assert_int_equal(crm_user_lookup("hauser", NULL, NULL), 0);

    /* Test getpwnam_r returning a valid passwd entry, and we do pass uid and gid. */

    // Set getpwnam_r() return value and result parameter
    will_return(__wrap_getpwnam_r, 0);
    will_return(__wrap_getpwnam_r, &returned_ent);

    assert_int_equal(crm_user_lookup("hauser", &uid, &gid), 0);
    assert_int_equal(uid, 1000);
    assert_int_equal(gid, 1000);

    pcmk__mock_getpwnam_r = false;
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(calloc_fails),
        cmocka_unit_test(getpwnam_r_fails),
        cmocka_unit_test(no_matching_pwent),
        cmocka_unit_test(entry_found),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
