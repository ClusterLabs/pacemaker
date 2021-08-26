/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <crm_internal.h>

static void
full_path(void)
{
    char *path = NULL;

    path = pcmk__full_path("file", "/dir");
    g_assert_cmpint(strcmp(path, "/dir/file"), ==, 0);
    free(path);

    path = pcmk__full_path("/full/path", "/dir");
    g_assert_cmpint(strcmp(path, "/full/path"), ==, 0);
    free(path);

    path = pcmk__full_path("../relative/path", "/dir");
    g_assert_cmpint(strcmp(path, "/dir/../relative/path"), ==, 0);
    free(path);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/io/full_path/full_path", full_path);

    return g_test_run();
}
