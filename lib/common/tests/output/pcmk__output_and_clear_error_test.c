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

static bool
fake_text_init(pcmk__output_t *out)
{
    return true;
}

static void
fake_text_free_priv(pcmk__output_t *out)
{
    /* This function intentionally left blank */
}

G_GNUC_PRINTF(2, 3)
static void
fake_text_err(pcmk__output_t *out, const char *format, ...)
{
    function_called();
}

static pcmk__output_t *
mk_fake_text_output(char **argv)
{
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "text";
    retval->init = fake_text_init;
    retval->free_priv = fake_text_free_priv;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->err = fake_text_err;

    return retval;
}

static int
setup(void **state)
{
    pcmk__register_format(NULL, "text", mk_fake_text_output, NULL);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__unregister_formats();
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

    expect_function_call(fake_text_err);
    pcmk__output_and_clear_error(&error, out);

    pcmk__output_free(out);
    assert_null(error);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test_setup_teardown(standard_usage, setup, teardown))
