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
default_message_fn(pcmk__output_t *out, va_list args)
{
    function_called();
    return pcmk_rc_ok;
}

static int
failed_message_fn(pcmk__output_t *out, va_list args)
{
    function_called();
    return pcmk_rc_no_output;
}

static int
message_fn_1(pcmk__output_t *out, va_list args)
{
    function_called();
    return pcmk_rc_ok;
}

static int
message_fn_2(pcmk__output_t *out, va_list args)
{
    function_called();
    return pcmk_rc_ok;
}

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
no_such_message(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__output_new(&out, "text", NULL, NULL);

    assert_int_equal(out->message(out, "fake"), EINVAL);
    pcmk__assert_asserts(out->message(out, ""));
    pcmk__assert_asserts(out->message(out, NULL));

    pcmk__output_free(out);
}

static void
message_return_value(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "text", message_fn_1 },
        { "msg2", "text", message_fn_2 },
        { "fail", "text", failed_message_fn },
        { NULL },
    };

    pcmk__output_new(&out, "text", NULL, NULL);
    pcmk__register_messages(out, entries);

    expect_function_call(message_fn_1);
    assert_int_equal(out->message(out, "msg1"), pcmk_rc_ok);
    expect_function_call(message_fn_2);
    assert_int_equal(out->message(out, "msg2"), pcmk_rc_ok);
    expect_function_call(failed_message_fn);
    assert_int_equal(out->message(out, "fail"), pcmk_rc_no_output);

    pcmk__output_free(out);
}

static void
wrong_format(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "xml", message_fn_1 },
        { NULL },
    };

    pcmk__output_new(&out, "text", NULL, NULL);
    pcmk__register_messages(out, entries);

    assert_int_equal(out->message(out, "msg1"), EINVAL);

    pcmk__output_free(out);
}

static void
default_called(void **state)
{
    pcmk__output_t *out = NULL;

    pcmk__message_entry_t entries[] = {
        { "msg1", "default", default_message_fn },
        { "msg1", "xml", message_fn_1 },
        { NULL },
    };

    pcmk__output_new(&out, "text", NULL, NULL);
    pcmk__register_messages(out, entries);

    expect_function_call(default_message_fn);
    assert_int_equal(out->message(out, "msg1"), pcmk_rc_ok);

    pcmk__output_free(out);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test_setup_teardown(no_such_message, setup, teardown),
                cmocka_unit_test_setup_teardown(message_return_value, setup, teardown),
                cmocka_unit_test_setup_teardown(wrong_format, setup, teardown),
                cmocka_unit_test_setup_teardown(default_called, setup, teardown))
