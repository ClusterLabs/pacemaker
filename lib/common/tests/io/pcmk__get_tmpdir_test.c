/*
 * Copyright 2021-2022 the Pacemaker project contributors
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
getenv_returns_invalid(void **state)
{
    const char *result;

    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "TMPDIR");
    will_return(__wrap_getenv, NULL);                   // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp");

    expect_string(__wrap_getenv, name, "TMPDIR");
    will_return(__wrap_getenv, "");                     // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp");

    expect_string(__wrap_getenv, name, "TMPDIR");
    will_return(__wrap_getenv, "subpath");              // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp");

    pcmk__mock_getenv = false;
}

static void
getenv_returns_valid(void **state)
{
    const char *result;

    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "TMPDIR");
    will_return(__wrap_getenv, "/var/tmp");             // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/var/tmp");

    expect_string(__wrap_getenv, name, "TMPDIR");
    will_return(__wrap_getenv, "/");                    // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/");

    expect_string(__wrap_getenv, name, "TMPDIR");
    will_return(__wrap_getenv, "/tmp/abcd.1234");       // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp/abcd.1234");

    pcmk__mock_getenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(getenv_returns_invalid),
                cmocka_unit_test(getenv_returns_valid))
