/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "mock_private.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>


static void
no_pids(void **state)
{
    char path[PATH_MAX];

    pcmk__snprintf(path, PATH_MAX, "/proc/%u/exe", getpid());

    // Set readlink() errno and link contents (for /proc/PID/exe)
    pcmk__mock_readlink = true;

    expect_string(__wrap_readlink, path, path);
    expect_any(__wrap_readlink, buf);
    expect_value(__wrap_readlink, bufsize, PATH_MAX - 1);
    will_return(__wrap_readlink, ENOENT);
    will_return(__wrap_readlink, NULL);

    assert_false(pcmk__procfs_has_pids());

    pcmk__mock_readlink = false;
}

PCMK__UNIT_TEST(NULL, NULL, cmocka_unit_test(no_pids))
