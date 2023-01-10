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
disabled_null_value(void **state)
{
    // Return false if option value not found (NULL accomplishes this)
    assert_false(pcmk__env_option_enabled(NULL, NULL));
    assert_false(pcmk__env_option_enabled("pacemaker-execd", NULL));
}

static void
enabled_true_value(void **state)
{
    // Return true if option value is true, with or without daemon name
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "true");
    assert_true(pcmk__env_option_enabled(NULL, "env_var"));

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "true");
    assert_true(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    pcmk__mock_getenv = false;
}

static void
disabled_false_value(void **state)
{
    // Return false if option value is false (no daemon list)
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "false");
    assert_false(pcmk__env_option_enabled(NULL, "env_var"));

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "false");
    assert_false(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    pcmk__mock_getenv = false;
}

static void
enabled_daemon_in_list(void **state)
{
    // Return true if daemon is in the option's value
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "pacemaker-execd");
    assert_true(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "pacemaker-execd,pacemaker-fenced");
    assert_true(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "pacemaker-controld,pacemaker-execd");
    assert_true(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv,
                "pacemaker-controld,pacemaker-execd,pacemaker-fenced");
    assert_true(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    pcmk__mock_getenv = false;
}

static void
disabled_daemon_not_in_list(void **state)
{
    // Return false if value is not true and daemon is not in the option's value
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, "PCMK_env_var");
    will_return(__wrap_getenv, "pacemaker-controld,pacemaker-fenced");
    assert_false(pcmk__env_option_enabled("pacemaker-execd", "env_var"));

    pcmk__mock_getenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(disabled_null_value),
                cmocka_unit_test(enabled_true_value),
                cmocka_unit_test(disabled_false_value),
                cmocka_unit_test(enabled_daemon_in_list),
                cmocka_unit_test(disabled_daemon_not_in_list))
