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
has_pids(void **state)
{
    char *exe_path = crm_strdup_printf("/proc/%lld/exe", (long long) getpid());

    // Set readlink() errno and link contents (for /proc/PID/exe)
    pcmk__mock_readlink = true;

    expect_string(__wrap_readlink, path, exe_path);
    expect_value(__wrap_readlink, bufsize, PATH_MAX);
    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, "/ok");

    assert_true(pcmk__procfs_has_pids());

    pcmk__mock_readlink = false;
    free(exe_path);
}

PCMK__UNIT_TEST(NULL, NULL, cmocka_unit_test(has_pids))
