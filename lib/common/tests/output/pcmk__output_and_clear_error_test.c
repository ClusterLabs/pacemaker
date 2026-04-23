/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

static int
setup(void **state)
{
    pcmk__set_testing_output_and_clear_error(true);
    pcmk__output_test_setup_group(state);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__output_test_teardown_group(state);
    pcmk__set_testing_output_and_clear_error(false);
    return 0;
}

static void
standard_usage(void **state)
{
    GError *error = NULL;
    pcmk__output_t *out = NULL;

    pcmk__output_new(&out, "text", NULL, NULL);
    g_set_error(&error, PCMK__RC_ERROR, pcmk_rc_bad_nvpair,
                "some error message");

    pcmk__expect_fake_text_err();
    pcmk__output_and_clear_error(&error, out);

    pcmk__output_free(out);
    assert_null(error);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(standard_usage))
