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

static void
empty_input_string(void **state)
{
    pcmk__mock_getenv = true;

    // getenv() not called
    assert_null(pcmk__env_option(NULL));
    assert_null(pcmk__env_option(""));

    pcmk__mock_getenv = false;
}

static void
input_too_long_for_both(void **state)
{
    /* pcmk__env_option() prepends "PCMK_" before lookup. If the option name is
     * too long for the buffer or isn't found in the env, then it prepends "HA_"
     * and tries again. A string of length (NAME_MAX - 3) will set us just over
     * just over the edge for both tries.
     */
    char long_opt[NAME_MAX - 2];

    for (int i = 0; i < NAME_MAX - 3; i++) {
        long_opt[i] = 'a';
    }
    long_opt[NAME_MAX - 3] = '\0';

    pcmk__mock_getenv = true;

    // getenv() not called
    assert_null(pcmk__env_option(long_opt));

    pcmk__mock_getenv = false;
}

static void
input_too_long_for_pcmk(void **state)
{
    /* If an input is too long for "PCMK_<option>", make sure we fall through
     * to try "HA_<option>".
     *
     * pcmk__env_option() prepends "PCMK_" first. A string of length
     * (NAME_MAX - 5) will set us just over the edge, still short enough for
     * "HA_<option>" to fit.
     */
    char long_opt[NAME_MAX - 4];
    char buf[NAME_MAX];

    for (int i = 0; i < NAME_MAX - 5; i++) {
        long_opt[i] = 'a';
    }
    long_opt[NAME_MAX - 5] = '\0';

    pcmk__mock_getenv = true;

    /* NULL/non-NULL retval doesn't really matter here; just testing that we
     * call getenv() for "HA_" prefix after too long for "PCMK_".
     */
    snprintf(buf, NAME_MAX, "HA_%s", long_opt);
    expect_string(__wrap_getenv, name, buf);
    will_return(__wrap_getenv, "value");
    assert_string_equal(pcmk__env_option(long_opt), "value");

    pcmk__mock_getenv = false;
}

static void
value_not_found(void **state)
{
    // Value not found using PCMK_ or HA_ prefix. Should return NULL.
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, NULL);

    expect_string(__wrap_getenv, name, "HA_env_var");
    will_return(__wrap_getenv, NULL);

    assert_null(pcmk__env_option("env_var"));

    pcmk__mock_getenv = false;
}

static void
value_found_pcmk(void **state)
{
    // Value found using PCMK_. Should return value and skip HA_ lookup.
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "value");
    assert_string_equal(pcmk__env_option("env_var"), "value");

    pcmk__mock_getenv = false;
}

static void
value_found_ha(void **state)
{
    // Value not found using PCMK_. Move on to HA_ lookup, find, and return.
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, NULL);

    expect_string(__wrap_getenv, name, "HA_env_var");
    will_return(__wrap_getenv, "value");

    assert_string_equal(pcmk__env_option("env_var"), "value");

    pcmk__mock_getenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input_string),
                cmocka_unit_test(input_too_long_for_both),
                cmocka_unit_test(input_too_long_for_pcmk),
                cmocka_unit_test(value_not_found),
                cmocka_unit_test(value_found_pcmk),
                cmocka_unit_test(value_found_ha))
