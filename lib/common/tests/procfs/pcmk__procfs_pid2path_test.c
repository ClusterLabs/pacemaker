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

static void
no_exe_file(void **state)
{
    size_t len = PATH_MAX;
    char *path = calloc(len, sizeof(char));

    // Set readlink() errno and link contents
    pcmk__mock_readlink = true;

    expect_string(__wrap_readlink, path, "/proc/1000/exe");
    expect_value(__wrap_readlink, buf, path);
    expect_value(__wrap_readlink, bufsize, len - 1);
    will_return(__wrap_readlink, ENOENT);
    will_return(__wrap_readlink, NULL);

    assert_int_equal(pcmk__procfs_pid2path(1000, path, len), ENOENT);

    pcmk__mock_readlink = false;

    free(path);
}

static void
contents_too_long(void **state)
{
    size_t len = 10;
    char *path = calloc(len, sizeof(char));

    // Set readlink() errno and link contents
    pcmk__mock_readlink = true;

    expect_string(__wrap_readlink, path, "/proc/1000/exe");
    expect_value(__wrap_readlink, buf, path);
    expect_value(__wrap_readlink, bufsize, len - 1);
    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, "/more/than/10/characters");

    assert_int_equal(pcmk__procfs_pid2path(1000, path, len),
                     ENAMETOOLONG);

    pcmk__mock_readlink = false;

    free(path);
}

static void
contents_ok(void **state)
{
    size_t len = PATH_MAX;
    char *path = calloc(len, sizeof(char));

    // Set readlink() errno and link contents
    pcmk__mock_readlink = true;

    expect_string(__wrap_readlink, path, "/proc/1000/exe");
    expect_value(__wrap_readlink, buf, path);
    expect_value(__wrap_readlink, bufsize, len - 1);
    will_return(__wrap_readlink, 0);
    will_return(__wrap_readlink, "/ok");

    assert_int_equal(pcmk__procfs_pid2path((pid_t) 1000, path, len),
                     pcmk_rc_ok);
    assert_string_equal(path, "/ok");

    pcmk__mock_readlink = false;

    free(path);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(no_exe_file),
                cmocka_unit_test(contents_too_long),
                cmocka_unit_test(contents_ok))
