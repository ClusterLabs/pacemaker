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

static int
null_message_fn(pcmk__output_t *out, va_list args)
{
    return pcmk_rc_ok;
}

static int
setup(void **state)
{
    pcmk__set_testing_output_free(true);
    pcmk__register_format(NULL, "text", pcmk__mk_fake_text_output, NULL);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__unregister_formats();
    pcmk__set_testing_output_free(false);
    return 0;
}

static void
no_messages(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__output_new(&out, "text", NULL, NULL);

    pcmk__expect_fake_text_free_priv();
    pcmk__output_free(out);
}

static void
messages(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__output_new(&out, "text", NULL, NULL);
    pcmk__register_message(out, "fake", null_message_fn);

    pcmk__expect_fake_text_free_priv();
    pcmk__output_free(out);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(no_messages),
                cmocka_unit_test(messages))
