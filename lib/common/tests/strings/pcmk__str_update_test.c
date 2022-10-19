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

static void
update_null(void **state) {
    char *str = NULL;

    // These just make sure they don't crash
    pcmk__str_update(NULL, NULL);
    pcmk__str_update(NULL, "value");

    // Update an already NULL string to NULL
    pcmk__str_update(&str, NULL);
    assert_null(str);

    // Update an already allocated string to NULL
    str = strdup("hello");
    pcmk__str_update(&str, NULL);
    assert_null(str);
}

static void
update_same(void **state) {
    char *str = NULL;
    char *saved = NULL;

    str = strdup("hello");
    saved = str;
    pcmk__str_update(&str, "hello");
    assert_ptr_equal(saved, str); // No free and reallocation
    free(str);
}

static void
update_different(void **state) {
    char *str = NULL;

    str = strdup("hello");
    pcmk__str_update(&str, "world");
    assert_string_equal(str, "world");
    free(str);
}

static void
strdup_fails(void **state) {
    char *str = NULL;

    str = strdup("hello");

    pcmk__assert_asserts(
        {
            pcmk__mock_strdup = true;   // strdup() will return NULL
            expect_string(__wrap_strdup, s, "world");
            pcmk__str_update(&str, "world");
            pcmk__mock_strdup = false;  // Use the real strdup()
        }
    );

    free(str);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(update_null),
                cmocka_unit_test(update_same),
                cmocka_unit_test(update_different),
                cmocka_unit_test(strdup_fails))
