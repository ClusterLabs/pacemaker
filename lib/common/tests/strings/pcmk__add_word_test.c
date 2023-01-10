/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
add_words(void **state)
{
    GString *list = NULL;

    pcmk__add_word(&list, 16, "hello");
    pcmk__add_word(&list, 16, "world");
    assert_int_equal(strcmp((const char *) list->str, "hello world"), 0);
    g_string_free(list, TRUE);
}

static void
add_with_no_len(void **state)
{
    GString *list = NULL;

    pcmk__add_word(&list, 0, "hello");
    pcmk__add_word(&list, 0, "world");
    assert_int_equal(strcmp((const char *) list->str, "hello world"), 0);
    g_string_free(list, TRUE);
}

static void
add_nothing(void **state)
{
    GString *list = NULL;

    pcmk__add_word(&list, 0, "hello");
    pcmk__add_word(&list, 0, NULL);
    pcmk__add_word(&list, 0, "");
    assert_int_equal(strcmp((const char *) list->str, "hello"), 0);
    g_string_free(list, TRUE);
}

static void
add_with_null(void **state)
{
    GString *list = NULL;

    pcmk__add_separated_word(&list, 32, "hello", NULL);
    pcmk__add_separated_word(&list, 32, "world", NULL);
    pcmk__add_separated_word(&list, 32, "I am a unit test", NULL);
    assert_int_equal(strcmp((const char *) list->str,
                            "hello world I am a unit test"), 0);
    g_string_free(list, TRUE);
}

static void
add_with_comma(void **state)
{
    GString *list = NULL;

    pcmk__add_separated_word(&list, 32, "hello", ",");
    pcmk__add_separated_word(&list, 32, "world", ",");
    pcmk__add_separated_word(&list, 32, "I am a unit test", ",");
    assert_int_equal(strcmp((const char *) list->str,
                            "hello,world,I am a unit test"), 0);
    g_string_free(list, TRUE);
}

static void
add_with_comma_and_space(void **state)
{
    GString *list = NULL;

    pcmk__add_separated_word(&list, 32, "hello", ", ");
    pcmk__add_separated_word(&list, 32, "world", ", ");
    pcmk__add_separated_word(&list, 32, "I am a unit test", ", ");
    assert_int_equal(strcmp((const char *) list->str,
                            "hello, world, I am a unit test"), 0);
    g_string_free(list, TRUE);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(add_words),
                cmocka_unit_test(add_with_no_len),
                cmocka_unit_test(add_nothing),
                cmocka_unit_test(add_with_null),
                cmocka_unit_test(add_with_comma),
                cmocka_unit_test(add_with_comma_and_space))
