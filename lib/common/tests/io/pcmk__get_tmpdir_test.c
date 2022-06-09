/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "mock_private.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

static void
getenv_returns_invalid(void **state)
{
    const char *result;

    pcmk__mock_getenv = true;

    will_return(__wrap_getenv, NULL);                   // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp");

    will_return(__wrap_getenv, "");                     // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp");

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

    will_return(__wrap_getenv, "/var/tmp");             // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/var/tmp");

    will_return(__wrap_getenv, "/");                    // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/");

    will_return(__wrap_getenv, "/tmp/abcd.1234");       // getenv("TMPDIR") return value
    result = pcmk__get_tmpdir();
    assert_string_equal(result, "/tmp/abcd.1234");

    pcmk__mock_getenv = false;
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(getenv_returns_invalid),
        cmocka_unit_test(getenv_returns_valid),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
