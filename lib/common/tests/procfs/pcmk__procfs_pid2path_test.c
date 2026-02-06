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

#include "mock_private.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>

#define assert_pid2path_one(errno_to_set, link_contents, dest, expected_rc) \
    do {                                                                    \
        pcmk__mock_readlink = true;                                         \
                                                                            \
        expect_string(__wrap_readlink, path, "/proc/1000/exe");             \
        expect_uint_value(__wrap_readlink, bufsize, PATH_MAX);              \
        will_return(__wrap_readlink, errno_to_set);                         \
        will_return(__wrap_readlink, link_contents);                        \
                                                                            \
        assert_int_equal(pcmk__procfs_pid2path(1000, dest), expected_rc);   \
                                                                            \
        pcmk__mock_readlink = false;                                        \
    } while (0)

#define assert_pid2path_null(errno_to_set, link_contents, expected_rc)      \
    do {                                                                    \
        char *dest = NULL;                                                  \
                                                                            \
        assert_pid2path_one(errno_to_set, link_contents, NULL,              \
                            expected_rc);                                   \
        assert_pid2path_one(errno_to_set, link_contents, &dest,             \
                            expected_rc);                                   \
        assert_null(dest);                                                  \
    } while (0)

#define assert_pid2path_equals(errno_to_set, link_contents, expected_rc,    \
                               expected_result)                             \
    do {                                                                    \
        char *dest = NULL;                                                  \
                                                                            \
        assert_pid2path_one(errno_to_set, link_contents, NULL,              \
                            expected_rc);                                   \
        assert_pid2path_one(errno_to_set, link_contents, &dest,             \
                            expected_rc);                                   \
        assert_string_equal(dest, expected_result);                         \
        free(dest);                                                         \
    } while (0)

static void
no_exe_file(void **state)
{
    assert_pid2path_null(ENOENT, NULL, ENOENT);
}

static void
contents_too_long(void **state)
{
    // String length equals PATH_MAX
    char *long_path = pcmk__assert_asprintf("%0*d", PATH_MAX, 0);

    assert_pid2path_null(0, long_path, ENAMETOOLONG);
    free(long_path);
}

static void
contents_ok(void **state)
{
    char *real_path = pcmk__str_copy("/ok");

    assert_pid2path_equals(0, real_path, pcmk_rc_ok, real_path);
    free(real_path);

    // String length equals PATH_MAX - 1
    real_path = pcmk__assert_asprintf("%0*d", PATH_MAX - 1, 0);

    assert_pid2path_equals(0, real_path, pcmk_rc_ok, real_path);
    free(real_path);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(no_exe_file),
                cmocka_unit_test(contents_too_long),
                cmocka_unit_test(contents_ok))
