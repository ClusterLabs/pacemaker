/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
add_words(void **state)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_word(&list, &list_len, "hello");
    pcmk__add_word(&list, &list_len, "world");
    assert_int_equal(strcmp(list, "hello world"), 0);
    free(list);
}

static void
add_with_no_len(void **state)
{
    char *list = NULL;

    pcmk__add_word(&list, NULL, "hello");
    pcmk__add_word(&list, NULL, "world");
    assert_int_equal(strcmp(list, "hello world"), 0);
    free(list);
}

static void
add_nothing(void **state)
{
    char *list = NULL;

    pcmk__add_word(&list, NULL, "hello");
    pcmk__add_word(&list, NULL, NULL);
    pcmk__add_word(&list, NULL, "");
    assert_int_equal(strcmp(list, "hello"), 0);
    free(list);
}

static void
add_with_null(void **state)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_separated_word(&list, &list_len, "hello", NULL);
    pcmk__add_separated_word(&list, &list_len, "world", NULL);
    pcmk__add_separated_word(&list, &list_len, "I am a unit test", NULL);
    assert_int_equal(strcmp(list, "hello world I am a unit test"), 0);
    free(list);
}

static void
add_with_comma(void **state)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_separated_word(&list, &list_len, "hello", ",");
    pcmk__add_separated_word(&list, &list_len, "world", ",");
    pcmk__add_separated_word(&list, &list_len, "I am a unit test", ",");
    assert_int_equal(strcmp(list, "hello,world,I am a unit test"), 0);
    free(list);
}

static void
add_with_comma_and_space(void **state)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_separated_word(&list, &list_len, "hello", ", ");
    pcmk__add_separated_word(&list, &list_len, "world", ", ");
    pcmk__add_separated_word(&list, &list_len, "I am a unit test", ", ");
    assert_int_equal(strcmp(list, "hello, world, I am a unit test"), 0);
    free(list);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(add_words),
                cmocka_unit_test(add_with_no_len),
                cmocka_unit_test(add_nothing),
                cmocka_unit_test(add_with_null),
                cmocka_unit_test(add_with_comma),
                cmocka_unit_test(add_with_comma_and_space))
