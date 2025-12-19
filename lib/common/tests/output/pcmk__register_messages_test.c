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
invalid_entries(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        /* We can't test a NULL message_id here because that's the marker for
         * the end of the table.
         */
        { "", "", null_message_fn },
        { "", NULL, null_message_fn },
        { "", "text", NULL },
        { NULL },
    };

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    pcmk__assert_asserts(pcmk__register_messages(out, entries));
    assert_int_equal(g_hash_table_size(out->messages), 0);

    pcmk__output_free(out);
}

static void
valid_entries(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "text", null_message_fn },
        { "msg2", "text", null_message_fn_2 },
        { NULL },
    };

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    pcmk__register_messages(out, entries);
    assert_int_equal(g_hash_table_size(out->messages), 2);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg1"),
                     null_message_fn);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg2"),
                     null_message_fn_2);

    pcmk__output_free(out);
}

static void
duplicate_message_ids(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "text", null_message_fn },
        { "msg1", "text", null_message_fn_2 },
        { NULL },
    };

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    pcmk__register_messages(out, entries);
    assert_int_equal(g_hash_table_size(out->messages), 1);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg1"),
                     null_message_fn_2);

    pcmk__output_free(out);
}

static void
duplicate_functions(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "text", null_message_fn },
        { "msg2", "text", null_message_fn },
        { NULL },
    };

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    pcmk__register_messages(out, entries);
    assert_int_equal(g_hash_table_size(out->messages), 2);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg1"),
                     null_message_fn);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg2"),
                     null_message_fn);

    pcmk__output_free(out);
}

static void
default_handler(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "default", null_message_fn },
        { NULL },
    };

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    pcmk__register_messages(out, entries);
    assert_int_equal(g_hash_table_size(out->messages), 1);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg1"),
                     null_message_fn);

    pcmk__output_free(out);
}

static void
override_default_handler(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "default", null_message_fn },
        { "msg1", "text", null_message_fn_2 },
        { NULL },
    };

    pcmk__bare_output_new(&out, "text", NULL, NULL);

    pcmk__register_messages(out, entries);
    assert_int_equal(g_hash_table_size(out->messages), 1);
    assert_ptr_equal(g_hash_table_lookup(out->messages, "msg1"),
                     null_message_fn_2);

    pcmk__output_free(out);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test_setup_teardown(invalid_entries, setup, teardown),
                cmocka_unit_test_setup_teardown(valid_entries, setup, teardown),
                cmocka_unit_test_setup_teardown(duplicate_message_ids, setup, teardown),
                cmocka_unit_test_setup_teardown(duplicate_functions, setup, teardown),
                cmocka_unit_test_setup_teardown(default_handler, setup, teardown),
                cmocka_unit_test_setup_teardown(override_default_handler, setup, teardown))
