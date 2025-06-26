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
empty_input_string(void **state)
{
    pcmk__mock_getenv = true;

    // getenv() not called
    assert_null(pcmk__env_option(NULL));
    assert_null(pcmk__env_option(""));

    pcmk__mock_getenv = false;
}

static void
value_not_found(void **state)
{
    // Value not found using PCMK_ or HA_ prefix. Should return NULL.
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, OPT_NAME_PCMK);
    will_return(__wrap_getenv, NULL);

    expect_string(__wrap_getenv, name, OPT_NAME_HA);
    will_return(__wrap_getenv, NULL);

    assert_null(pcmk__env_option(OPT_NAME));

    pcmk__mock_getenv = false;
}

static void
value_found_pcmk(void **state)
{
    const char *value = "value";

    // Value found using PCMK_. Should return value and skip HA_ lookup.
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, OPT_NAME_PCMK);
    will_return(__wrap_getenv, value);
    assert_string_equal(pcmk__env_option(OPT_NAME), value);

    pcmk__mock_getenv = false;
}

static void
value_found_ha(void **state)
{
    const char *value = "value";

    // Value not found using PCMK_. Move on to HA_ lookup, find, and return.
    pcmk__mock_getenv = true;

    expect_string(__wrap_getenv, name, OPT_NAME_PCMK);
    will_return(__wrap_getenv, NULL);

    expect_string(__wrap_getenv, name, OPT_NAME_HA);
    will_return(__wrap_getenv, value);

    assert_string_equal(pcmk__env_option(OPT_NAME), value);

    pcmk__mock_getenv = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input_string),
                cmocka_unit_test(value_not_found),
                cmocka_unit_test(value_found_pcmk),
                cmocka_unit_test(value_found_ha))
