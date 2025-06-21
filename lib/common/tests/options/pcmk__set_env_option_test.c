/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/unittest_internal.h>

#include "mock_private.h"

#define OPT_NAME      "env_var"
#define OPT_NAME_PCMK "PCMK_" OPT_NAME
#define OPT_NAME_HA   "HA_" OPT_NAME

static void
bad_input_string(void **state)
{
    // Bad setenv()/unsetenv() input: NULL, empty, or containing '='

    // Never call setenv()
    pcmk__mock_setenv = true;

    pcmk__set_env_option(NULL, "new_value", true);
    pcmk__set_env_option("", "new_value", true);

    pcmk__mock_setenv = false;

    // Never call unsetenv()
    pcmk__mock_unsetenv = true;

    pcmk__set_env_option(NULL, NULL, true);
    pcmk__set_env_option("", NULL, true);

    pcmk__mock_unsetenv = false;
}

static void
valid_inputs_set(void **state)
{
    const char *new_value = NULL;

    // Make sure we set "PCMK_<option>" and "HA_<option>"
    pcmk__mock_setenv = true;

    new_value = "new_value";
    expect_string(__wrap_setenv, name, OPT_NAME_PCMK);
    expect_string(__wrap_setenv, value, new_value);
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    expect_string(__wrap_setenv, name, OPT_NAME_HA);
    expect_string(__wrap_setenv, value, new_value);
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    pcmk__set_env_option(OPT_NAME, new_value, true);

    // Empty string is also a valid value
    new_value = "";
    expect_string(__wrap_setenv, name, OPT_NAME_PCMK);
    expect_string(__wrap_setenv, value, new_value);
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    expect_string(__wrap_setenv, name, OPT_NAME_HA);
    expect_string(__wrap_setenv, value, new_value);
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    pcmk__set_env_option(OPT_NAME, new_value, true);

    pcmk__mock_setenv = false;
}

static void
valid_inputs_unset(void **state)
{
    // Make sure we unset "PCMK_<option>" and "HA_<option>"
    pcmk__mock_unsetenv = true;

    expect_string(__wrap_unsetenv, name, OPT_NAME_PCMK);
    will_return(__wrap_unsetenv, 0);
    expect_string(__wrap_unsetenv, name, OPT_NAME_HA);
    will_return(__wrap_unsetenv, 0);
    pcmk__set_env_option(OPT_NAME, NULL, true);

    pcmk__mock_unsetenv = false;
}

static void
disable_compat(void **state)
{
    const char *new_value = "new_value";

    // Make sure we set only "PCMK_<option>" and not "HA_<option>"
    pcmk__mock_setenv = true;

    expect_string(__wrap_setenv, name, OPT_NAME_PCMK);
    expect_string(__wrap_setenv, value, new_value);
    expect_value(__wrap_setenv, overwrite, 1);
    will_return(__wrap_setenv, 0);
    pcmk__set_env_option(OPT_NAME, new_value, false);

    pcmk__mock_setenv = false;

    // Make sure we clear both "PCMK_<option>" and "HA_<option>"
    pcmk__mock_unsetenv = true;

    expect_string(__wrap_unsetenv, name, OPT_NAME_PCMK);
    will_return(__wrap_unsetenv, 0);
    expect_string(__wrap_unsetenv, name, OPT_NAME_HA);
    will_return(__wrap_unsetenv, 0);
    pcmk__set_env_option(OPT_NAME, NULL, false);

    pcmk__mock_unsetenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input_string),
                cmocka_unit_test(valid_inputs_set),
                cmocka_unit_test(valid_inputs_unset),
                cmocka_unit_test(disable_compat))
