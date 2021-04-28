/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <crm_internal.h>

static void
add_words(void)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_word(&list, &list_len, "hello");
    pcmk__add_word(&list, &list_len, "world");
    g_assert_cmpint(strcmp(list, "hello world"), ==, 0);
    free(list);
}

static void
add_with_no_len(void)
{
    char *list = NULL;

    pcmk__add_word(&list, NULL, "hello");
    pcmk__add_word(&list, NULL, "world");
    g_assert_cmpint(strcmp(list, "hello world"), ==, 0);
    free(list);
}

static void
add_nothing(void)
{
    char *list = NULL;

    pcmk__add_word(&list, NULL, "hello");
    pcmk__add_word(&list, NULL, NULL);
    pcmk__add_word(&list, NULL, "");
    g_assert_cmpint(strcmp(list, "hello"), ==, 0);
    free(list);
}

static void
add_with_null(void)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_separated_word(&list, &list_len, "hello", NULL);
    pcmk__add_separated_word(&list, &list_len, "world", NULL);
    pcmk__add_separated_word(&list, &list_len, "I am a unit test", NULL);
    g_assert_cmpint(strcmp(list, "hello world I am a unit test"), ==, 0);
    free(list);
}

static void
add_with_comma(void)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_separated_word(&list, &list_len, "hello", ",");
    pcmk__add_separated_word(&list, &list_len, "world", ",");
    pcmk__add_separated_word(&list, &list_len, "I am a unit test", ",");
    g_assert_cmpint(strcmp(list, "hello,world,I am a unit test"), ==, 0);
    free(list);
}

static void
add_with_comma_and_space(void)
{
    char *list = NULL;
    size_t list_len = 0;

    pcmk__add_separated_word(&list, &list_len, "hello", ", ");
    pcmk__add_separated_word(&list, &list_len, "world", ", ");
    pcmk__add_separated_word(&list, &list_len, "I am a unit test", ", ");
    g_assert_cmpint(strcmp(list, "hello, world, I am a unit test"), ==, 0);
    free(list);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/add_word/add_words", add_words);
    g_test_add_func("/common/strings/add_word/add_with_no_len",
                    add_with_no_len);
    g_test_add_func("/common/strings/add_word/add_nothing", add_nothing);
    g_test_add_func("/common/strings/add_word/add_with_null", add_with_null);
    g_test_add_func("/common/strings/add_word/add_with_comma", add_with_comma);
    g_test_add_func("/common/strings/add_word/add_with_comma_and_space",
                    add_with_comma_and_space);

    return g_test_run();
}
