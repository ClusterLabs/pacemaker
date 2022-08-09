/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "mock_private.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>

#if SUPPORT_PROCFS

static void
has_pids(void **state)
{
    // Set readlink() errno and link contents (for /proc/PID/exe)
    pcmk__mock_readlink = true;
    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, "/ok");

    assert_true(pcmk__procfs_has_pids());

    pcmk__mock_readlink = false;
}

#endif // SUPPORT_PROCFS

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
#if SUPPORT_PROCFS
        cmocka_unit_test(has_pids),
#endif
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
