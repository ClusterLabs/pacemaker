/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
add_to_null(void **state)
{
    pcmk__assert_asserts(pcmk__g_strcat(NULL, NULL));
    pcmk__assert_asserts(pcmk__g_strcat(NULL, "hello", NULL));
}

static void
add_nothing(void **state)
{
    GString *buf = g_string_new(NULL);

    // Start with empty string
    pcmk__g_strcat(buf, NULL);
    assert_string_equal((const char *) buf->str, "");

    pcmk__g_strcat(buf, "", NULL);
    assert_string_equal((const char *) buf->str, "");

    // Start with populated string
    g_string_append(buf, "hello");
    pcmk__g_strcat(buf, NULL);
    assert_string_equal((const char *) buf->str, "hello");

    pcmk__g_strcat(buf, "", NULL);
    assert_string_equal((const char *) buf->str, "hello");
    g_string_free(buf, TRUE);
}

static void
add_words(void **state)
{
    GString *buf = g_string_new(NULL);

    // Verify a call with multiple words
    pcmk__g_strcat(buf, "hello", " ", NULL);
    assert_string_equal((const char *) buf->str, "hello ");

    // Verify that a second call doesn't overwrite the first one
    pcmk__g_strcat(buf, "world", NULL);
    assert_string_equal((const char *) buf->str, "hello world");
    g_string_free(buf, TRUE);
}

static void
stop_early(void **state)
{
    GString *buf = g_string_new(NULL);

    // NULL anywhere after buf in the arg list should cause a return
    pcmk__g_strcat(buf, "hello", NULL, " world", NULL);
    assert_string_equal((const char *) buf->str, "hello");
    g_string_free(buf, TRUE);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(add_to_null),
                cmocka_unit_test(add_nothing),
                cmocka_unit_test(add_words),
                cmocka_unit_test(stop_early))
