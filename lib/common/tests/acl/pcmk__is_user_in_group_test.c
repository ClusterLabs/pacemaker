/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/acl.h>
#include "../../crmcommon_private.h"

#include "mock_private.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

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

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(is_pcmk__is_user_in_group)
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
