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
bad_input_string(void **state)
{
    // Bad setenv()/unsetenv() input: NULL, empty, or containing '='

    // Never call setenv()
    pcmk__mock_setenv = true;

    pcmk__set_env_option(NULL, "new_value");
    pcmk__set_env_option("", "new_value");
    pcmk__set_env_option("name=val", "new_value");

    pcmk__mock_setenv = false;

    // Never call unsetenv()
    pcmk__mock_unsetenv = true;

    pcmk__set_env_option(NULL, NULL);
    pcmk__set_env_option("", NULL);
    pcmk__set_env_option("name=val", NULL);

    pcmk__mock_unsetenv = false;
}

static void
input_too_long_for_both(void **state)
{
    /* pcmk__set_env_option() wants to set "PCMK_<option>" and "HA_<option>". If
     * "PCMK_<option>" is too long for the buffer, it simply moves on to
     * "HA_<option>". A string of length (NAME_MAX - 3) will set us just over
     * the edge for both tries.
     */
    char long_opt[NAME_MAX - 2];

    for (int i = 0; i < NAME_MAX - 3; i++) {
        long_opt[i] = 'a';
    }
    long_opt[NAME_MAX - 3] = '\0';

    // Never call setenv() or unsetenv()
    pcmk__mock_setenv = true;
    pcmk__set_env_option(long_opt, "new_value");
    pcmk__mock_setenv = false;

    pcmk__mock_unsetenv = true;
    pcmk__set_env_option(long_opt, NULL);
    pcmk__mock_unsetenv = false;
}

static void
input_too_long_for_pcmk(void **state)
{
    /* If an input is too long to set "PCMK_<option>", make sure we fall through
     * to try to set "HA_<option>".
     *
     * A string of length (NAME_MAX - 5) will set us just over the edge for
     * "PCMK_<option>", while still short enough for "HA_<option>" to fit.
     */
    char long_opt[NAME_MAX - 4];
    char buf[NAME_MAX];

    for (int i = 0; i < NAME_MAX - 5; i++) {
        long_opt[i] = 'a';
    }
    long_opt[NAME_MAX - 5] = '\0';

    snprintf(buf, NAME_MAX, "HA_%s", long_opt);

    // Call setenv() for "HA_" only
    pcmk__mock_setenv = true;

    expect_string(__wrap_setenv, name, buf);
    expect_string(__wrap_setenv, value, "new_value");
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    pcmk__set_env_option(long_opt, "new_value");

    pcmk__mock_setenv = false;

    // Call unsetenv() for "HA_" only
    pcmk__mock_unsetenv = true;

    expect_string(__wrap_unsetenv, name, buf);
    will_return(__wrap_unsetenv, 0);
    pcmk__set_env_option(long_opt, NULL);

    pcmk__mock_unsetenv = false;
}

static void
valid_inputs_set(void **state)
{
    // Make sure we set "PCMK_<option>" and "HA_<option>"
    pcmk__mock_setenv = true;

    expect_string(__wrap_setenv, name, "PCMK_env_var");
    expect_string(__wrap_setenv, value, "new_value");
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    expect_string(__wrap_setenv, name, "HA_env_var");
    expect_string(__wrap_setenv, value, "new_value");
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    pcmk__set_env_option("env_var", "new_value");

    // Empty string is also a valid value
    expect_string(__wrap_setenv, name, "PCMK_env_var");
    expect_string(__wrap_setenv, value, "");
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    expect_string(__wrap_setenv, name, "HA_env_var");
    expect_string(__wrap_setenv, value, "");
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    pcmk__set_env_option("env_var", "");

    pcmk__mock_setenv = false;
}

static void
valid_inputs_unset(void **state)
{
    // Make sure we unset "PCMK_<option>" and "HA_<option>"
    pcmk__mock_unsetenv = true;

    expect_string(__wrap_unsetenv, name, "PCMK_env_var");
    will_return(__wrap_unsetenv, 0);
    expect_string(__wrap_unsetenv, name, "HA_env_var");
    will_return(__wrap_unsetenv, 0);
    pcmk__set_env_option("env_var", NULL);

    pcmk__mock_unsetenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input_string),
                cmocka_unit_test(input_too_long_for_both),
                cmocka_unit_test(input_too_long_for_pcmk),
                cmocka_unit_test(valid_inputs_set),
                cmocka_unit_test(valid_inputs_unset))
