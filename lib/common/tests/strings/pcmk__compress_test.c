/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "mock_private.h"

#define SIMPLE_DATA "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

const char *SIMPLE_COMPRESSED = "BZh41AY&SYO\x1ai";

static void
simple_compress(void **state)
{
    char *result = calloc(1024, sizeof(char));
    unsigned int len;

    assert_int_equal(pcmk__compress(SIMPLE_DATA, 40, 0, &result, &len), pcmk_rc_ok);
    assert_memory_equal(result, SIMPLE_COMPRESSED, 13);
}

static void
max_too_small(void **state)
{
    char *result = calloc(1024, sizeof(char));
    unsigned int len;

    assert_int_equal(pcmk__compress(SIMPLE_DATA, 40, 10, &result, &len), pcmk_rc_error);
}

static void
calloc_fails(void **state) {
    char *result = calloc(1024, sizeof(char));
    unsigned int len;

    pcmk__assert_asserts(
        {
            pcmk__mock_calloc = true;   // calloc() will return NULL
            expect_value(__wrap_calloc, nmemb, (size_t) ((40 * 1.01) + 601));
            expect_value(__wrap_calloc, size, sizeof(char));
            pcmk__compress(SIMPLE_DATA, 40, 0, &result, &len);
            pcmk__mock_calloc = false;  // Use the real calloc()
        }
    );
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(simple_compress),
                cmocka_unit_test(max_too_small),
                cmocka_unit_test(calloc_fails))
