/*
 * Copyright 2020-2025 the Pacemaker project contributors
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

static void
function_asserts(void **state)
{
    pcmk__assert_asserts(pcmk__full_path(NULL, "/dir"));
    pcmk__assert_asserts(pcmk__full_path("file", NULL));
}

static void
function_exits(void **state)
{
    pcmk__assert_exits(
        CRM_EX_OSERR,
        {
            pcmk__mock_strdup = true;   // strdup() will return NULL
            expect_string(__wrap_strdup, s, "/full/path");
            pcmk__full_path("/full/path", "/dir");
            pcmk__mock_strdup = false;  // Use real strdup()
        }
    );
}

static void
full_path(void **state)
{
    char *path = NULL;

    path = pcmk__full_path("file", "/dir");
    assert_string_equal(path, "/dir/file");
    free(path);

    path = pcmk__full_path("/full/path", "/dir");
    assert_string_equal(path, "/full/path");
    free(path);

    path = pcmk__full_path("../relative/path", "/dir");
    assert_string_equal(path, "/dir/../relative/path");
    free(path);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(function_asserts),
                cmocka_unit_test(function_exits),
                cmocka_unit_test(full_path))
