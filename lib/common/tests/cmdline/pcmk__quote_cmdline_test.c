/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

/* g_shell_quote currently always uses single quotes. However, the documentation
 * says "The quoting style used is undefined (single or double quotes may be
 * used)."
 */
static void
assert_quote_cmdline(const char **argv, const gchar *expected_single,
                     const gchar *expected_double)
{
    gchar *processed = pcmk__quote_cmdline((const char *const *) argv);

    assert_true(pcmk__str_any_of(processed, expected_single, expected_double,
                                 NULL));
    g_free(processed);
}

static void
empty_input(void **state)
{
    assert_null(pcmk__quote_cmdline(NULL));
}

static void
no_spaces(void **state)
{
    const char *argv[] = {
        "crm_resource", "-r", "rsc1", "--meta", "-p", "comment",
        "-v", "hello", "--output-as=xml", NULL,
    };

    assert_quote_cmdline(argv,
                         "crm_resource -r rsc1 --meta -p comment "
                         "-v hello --output-as=xml",
                         "crm_resource -r rsc1 --meta -p comment "
                         "-v hello --output-as=xml");
}

static void
spaces_no_quote(void **state)
{
    const char *argv[] = {
        "crm_resource", "-r", "rsc1", "--meta", "-p", "comment",
        "-v", "hello world", "--output-as=xml", NULL,
    };

    assert_quote_cmdline(argv,
                         "crm_resource -r rsc1 --meta -p comment "
                         "-v 'hello world' --output-as=xml",
                         "crm_resource -r rsc1 --meta -p comment "
                         "-v \"hello world\" --output-as=xml");
}

static void
spaces_with_quote(void **state) {
    const char *argv[] = {
        "crm_resource", "-r", "rsc1", "--meta", "-p", "comment",
        "-v", "here's johnny", "--output-as=xml", NULL,
    };

    assert_quote_cmdline(argv,
                         "crm_resource -r rsc1 --meta -p comment "
                         "-v 'here'\\''s johnny' --output-as=xml",
                         "crm_resource -r rsc1 --meta -p comment "
                         "-v \"here's johnny\" --output-as=xml");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input),
                cmocka_unit_test(no_spaces),
                cmocka_unit_test(spaces_no_quote),
                cmocka_unit_test(spaces_with_quote))
