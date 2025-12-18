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

#define OPTION "env_var"
#define ENV_VAR "PCMK_" OPTION

static void
disabled_null_value(void **state)
{
    // Return false if option value not found (NULL accomplishes this)
    assert_false(pcmk__env_option_enabled(NULL, NULL));
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, NULL));
}

static void
enabled_true_value(void **state)
{
    // Return true if option value parses to true, with or without daemon name
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "true");
    assert_true(pcmk__env_option_enabled(NULL, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "1");
    assert_true(pcmk__env_option_enabled(NULL, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "true");
    assert_true(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "1");
    assert_true(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    pcmk__mock_getenv = false;
}

static void
disabled_false_value(void **state)
{
    // Return false if option value parses to false, with or without daemon name
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "false");
    assert_false(pcmk__env_option_enabled(NULL, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "0");
    assert_false(pcmk__env_option_enabled(NULL, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "false");
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "0");
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    pcmk__mock_getenv = false;
}

static void
enabled_daemon_in_list(void **state)
{
    // Return true if daemon is in the option's value
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_EXECD);
    assert_true(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_EXECD "," PCMK__SERVER_FENCED);
    assert_true(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_CONTROLD "," PCMK__SERVER_EXECD);
    assert_true(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv,
                PCMK__SERVER_CONTROLD "," PCMK__SERVER_EXECD
                "," PCMK__SERVER_FENCED);
    assert_true(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    pcmk__mock_getenv = false;
}

static void
disabled_daemon_not_in_list(void **state)
{
    // Return false if value is not true and daemon is not in the option's value
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_CONTROLD "," PCMK__SERVER_FENCED);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    pcmk__mock_getenv = false;
}

static void
disabled_inexact_match(void **state)
{
    /* Return false if the daemon name is a substring of the value but does not
     * exactly match any piece of the comma-separated list.
     *
     * Perform each test case using a single-item list and a multi-item list.
     */
    pcmk__mock_getenv = true;

    // Leading space
    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, " " PCMK__SERVER_EXECD);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, " " PCMK__SERVER_EXECD "," PCMK__SERVER_FENCED);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    // Trailing space
    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_EXECD " ");
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_EXECD " ," PCMK__SERVER_FENCED);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    // Leading garbage
    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "asdf" PCMK__SERVER_EXECD);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv,
                "asdf" PCMK__SERVER_EXECD "," PCMK__SERVER_FENCED);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    // Trailing garbage
    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_EXECD "1234");
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, PCMK__SERVER_EXECD "1234," PCMK__SERVER_FENCED);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    // Leading and trailing garbage
    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv, "asdf" PCMK__SERVER_EXECD "1234");
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    expect_string(__wrap_getenv, name, ENV_VAR);
    will_return(__wrap_getenv,
                "asdf" PCMK__SERVER_EXECD "1234," PCMK__SERVER_FENCED);
    assert_false(pcmk__env_option_enabled(PCMK__SERVER_EXECD, OPTION));

    pcmk__mock_getenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(disabled_null_value),
                cmocka_unit_test(enabled_true_value),
                cmocka_unit_test(disabled_false_value),
                cmocka_unit_test(enabled_daemon_in_list),
                cmocka_unit_test(disabled_daemon_not_in_list),
                cmocka_unit_test(disabled_inexact_match))
