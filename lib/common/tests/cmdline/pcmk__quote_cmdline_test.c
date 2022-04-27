/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/cmdline_internal.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <glib.h>

static void
empty_input(void **state) {
    assert_null(pcmk__quote_cmdline(NULL));
}

static void
no_spaces(void **state) {
    const char *argv[] = { "crm_resource", "-r", "rsc1", "--meta", "-p", "comment", "-v", "hello", "--output-as=xml", NULL };
    const gchar *expected = "crm_resource -r rsc1 --meta -p comment -v hello --output-as=xml";

    gchar *processed = pcmk__quote_cmdline((gchar **) argv);
    assert_string_equal(processed, expected);
    g_free(processed);
}

static void
spaces_no_quote(void **state) {
    const char *argv[] = { "crm_resource", "-r", "rsc1", "--meta", "-p", "comment", "-v", "hello world", "--output-as=xml", NULL };
    const gchar *expected = "crm_resource -r rsc1 --meta -p comment -v 'hello world' --output-as=xml";

    gchar *processed = pcmk__quote_cmdline((gchar **) argv);
    assert_string_equal(processed, expected);
    g_free(processed);
}

static void
spaces_with_quote(void **state) {
    const char *argv[] = { "crm_resource", "-r", "rsc1", "--meta", "-p", "comment", "-v", "here's johnny", "--output-as=xml", NULL };
    const gchar *expected = "crm_resource -r rsc1 --meta -p comment -v 'here\\\'s johnny' --output-as=xml";

    gchar *processed = pcmk__quote_cmdline((gchar **) argv);
    assert_string_equal(processed, expected);
    g_free(processed);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input),
        cmocka_unit_test(no_spaces),
        cmocka_unit_test(spaces_no_quote),
        cmocka_unit_test(spaces_with_quote),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
