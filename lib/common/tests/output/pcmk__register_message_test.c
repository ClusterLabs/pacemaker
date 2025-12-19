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

#include "../../crmcommon_private.h"

static int
null_message_fn(pcmk__output_t *out, va_list args)
{
    return pcmk_rc_ok;
}

static int
null_message_fn_2(pcmk__output_t *out, va_list args)
{
    return pcmk_rc_ok;
}

static int
setup(void **state)
{
    pcmk__register_format(NULL, "text", pcmk__mk_fake_text_output, NULL);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__unregister_formats();
    return 0;
}

static void
null_params(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__output_new(&out, "text", NULL, NULL);

    pcmk__assert_asserts(pcmk__register_message(NULL, "fake", null_message_fn));
    pcmk__assert_asserts(pcmk__register_message(out, NULL, null_message_fn));
    pcmk__assert_asserts(pcmk__register_message(out, "", null_message_fn));
    pcmk__assert_asserts(pcmk__register_message(out, "fake", NULL));

    pcmk__output_free(out);
}

static void
add_message(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    /* For starters, there should be no messages defined. */
    assert_int_equal(g_hash_table_size(out->messages), 0);

    /* Add a fake function and check that it's the only item in the hash table. */
    pcmk__register_message(out, "fake", null_message_fn);
    assert_int_equal(g_hash_table_size(out->messages), 1);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "fake"),
                     null_message_fn);

    /* Add a second fake function which should overwrite the first one, leaving
     * only one item in the hash table but pointing at the new function.
     */
    pcmk__register_message(out, "fake", null_message_fn_2);
    assert_int_equal(g_hash_table_size(out->messages), 1);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "fake"),
                     null_message_fn_2);

    pcmk__output_free(out);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(null_params),
                cmocka_unit_test(add_message))
