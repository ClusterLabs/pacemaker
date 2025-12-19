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

PCMK__UNIT_TEST(pcmk__output_test_setup_group, pcmk__output_test_teardown_group,
                cmocka_unit_test(invalid_entries),
                cmocka_unit_test(valid_entries),
                cmocka_unit_test(duplicate_message_ids),
                cmocka_unit_test(duplicate_functions),
                cmocka_unit_test(default_handler),
                cmocka_unit_test(override_default_handler))
