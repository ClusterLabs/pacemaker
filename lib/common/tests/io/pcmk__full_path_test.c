/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
full_path(void **state)
{
    char *path = NULL;

    path = pcmk__full_path("file", "/dir");
    assert_int_equal(strcmp(path, "/dir/file"), 0);
    free(path);

    path = pcmk__full_path("/full/path", "/dir");
    assert_int_equal(strcmp(path, "/full/path"), 0);
    free(path);

    path = pcmk__full_path("../relative/path", "/dir");
    assert_int_equal(strcmp(path, "/dir/../relative/path"), 0);
    free(path);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(full_path),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
