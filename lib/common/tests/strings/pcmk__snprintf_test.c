/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h> /* Should come first */

#include <stdio.h>
#include <string.h>

#include <crm/common/strings_internal.h>
#include <crm/common/unittest_internal.h>
#include "mock_private.h"

static int
group_setup_vsnprintf_mock(void **state)
{
    pcmk__mock_vsnprintf = false;
    return 0;
}

static int
group_teardown_vsnprintf_mock(void **state)
{
    pcmk__mock_vsnprintf = false;
    return 0;
}

static void
test_basic_functionality(void **state)
{
    char buffer[100];
    const char *name = "world";
    int expected_ret;
    int actual_ret;

    pcmk__mock_vsnprintf = false;
    expected_ret = snprintf(NULL, 0, "Hello, %s!", name);
    actual_ret = pcmk__snprintf(buffer, sizeof(buffer), "Hello, %s!", name);

    assert_int_equal(actual_ret, expected_ret);
    assert_string_equal(buffer, "Hello, world!");
}

static void
test_buffer_truncation(void **state)
{
    char buffer[10];
    int expected_ret;
    int actual_ret;

    pcmk__mock_vsnprintf = false;
    expected_ret = snprintf(NULL, 0, "This is a long string");
    actual_ret = pcmk__snprintf(buffer, sizeof(buffer), "This is a long string");

    assert_int_equal(actual_ret, expected_ret);
    assert_string_equal(buffer, "This is a");
    assert_int_equal(strlen(buffer), sizeof(buffer) - 1);
}

static void
test_zero_size_buffer(void **state)
{
    char buffer[1];
    int expected_ret;
    int actual_ret;

    pcmk__mock_vsnprintf = false;
    expected_ret = snprintf(NULL, 0, "Test");
    actual_ret = pcmk__snprintf(buffer, 0, "Test");

    assert_int_equal(actual_ret, expected_ret);
}

static void
test_assertion_on_negative_return(void **state)
{
    char buffer[100];

    pcmk__assert_asserts({
        will_return(__wrap_vsnprintf, -1);
        pcmk__mock_vsnprintf = true;
        pcmk__snprintf(buffer, sizeof(buffer), "format %s", "string");
        pcmk__mock_vsnprintf = false;
    });
}

PCMK__UNIT_TEST(group_setup_vsnprintf_mock, group_teardown_vsnprintf_mock,
                cmocka_unit_test(test_basic_functionality),
                cmocka_unit_test(test_buffer_truncation),
                cmocka_unit_test(test_zero_size_buffer),
                cmocka_unit_test(test_assertion_on_negative_return));
