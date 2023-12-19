/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "mock_private.h"

static void
bad_size(void **state)
{
    char *ptr = NULL;

    pcmk__assert_asserts(pcmk__realloc(ptr, 0));
}

static void
realloc_fails(void **state)
{
    char *ptr = NULL;

    pcmk__assert_aborts(
        {
            pcmk__mock_realloc = true;   // realloc() will return NULL
            expect_any(__wrap_realloc, ptr);
            expect_value(__wrap_realloc, size, 1000);
            pcmk__realloc(ptr, 1000);
            pcmk__mock_realloc = false;  // Use real realloc()
        }
    );
}

static void
realloc_succeeds(void **state)
{
    char *ptr = NULL;

    /* We can't really test that the resulting pointer is the size we asked
     * for - it might be larger if that's what the memory allocator decides
     * to do.  And anyway, testing realloc isn't really the point.  All we
     * want to do here is make sure the function works when given good input.
     */

    /* Allocate new memory */
    ptr = pcmk__realloc(ptr, 1000);
    assert_non_null(ptr);

    /* Grow previously allocated memory */
    ptr = pcmk__realloc(ptr, 2000);
    assert_non_null(ptr);

    /* Shrink previously allocated memory */
    ptr = pcmk__realloc(ptr, 500);
    assert_non_null(ptr);

    free(ptr);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_size),
                cmocka_unit_test(realloc_fails),
                cmocka_unit_test(realloc_succeeds))
