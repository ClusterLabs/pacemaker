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

#if HAVE_PROCFS

static void
has_pids(void **state)
{
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "/proc/%u/exe", getpid());

    // Set readlink() errno and link contents (for /proc/PID/exe)
    pcmk__mock_readlink = true;

    expect_string(__wrap_readlink, path, path);
    expect_any(__wrap_readlink, buf);
    expect_value(__wrap_readlink, bufsize, PATH_MAX - 1);
    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, "/ok");

    assert_true(pcmk__procfs_has_pids());

    pcmk__mock_readlink = false;
}

#endif // HAVE_PROCFS

PCMK__UNIT_TEST(NULL, NULL,
#if HAVE_PROCFS
                cmocka_unit_test(has_pids)
#endif
               )
