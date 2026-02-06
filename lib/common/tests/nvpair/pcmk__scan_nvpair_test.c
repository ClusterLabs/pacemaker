/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>       // gchar, g_free

#include <crm/common/unittest_internal.h>

#define assert_scan_nvpair_success(input, expected_name, expected_value)    \
    do {                                                                    \
        gchar *name = NULL;                                                 \
        gchar *value = NULL;                                                \
        int rc = pcmk__scan_nvpair(input, &name, &value);                   \
                                                                            \
        assert_int_equal(rc, pcmk_rc_ok);                                   \
        assert_string_equal(name, expected_name);                           \
        assert_string_equal(value, expected_value);                         \
                                                                            \
        g_free(name);                                                       \
        g_free(value);                                                      \
    } while (0)

#define assert_scan_nvpair_failure(input)                   \
    do {                                                    \
        gchar *name = NULL;                                 \
        gchar *value = NULL;                                \
        int rc = pcmk__scan_nvpair(input, &name, &value);   \
                                                            \
        assert_int_equal(rc, pcmk_rc_bad_nvpair);           \
        assert_null(name);                                  \
        assert_null(value);                                 \
    } while (0)

static void
null_asserts(void **state)
{
    const gchar *input = "key=value";
    gchar *name = NULL;
    gchar *value = NULL;

    pcmk__assert_asserts(pcmk__scan_nvpair(NULL, &name, &value));
    pcmk__assert_asserts(pcmk__scan_nvpair(input, NULL, &value));
    pcmk__assert_asserts(pcmk__scan_nvpair(input, &name, NULL));
}

static void
already_allocated_asserts(void **state)
{
    const gchar *input = "key=value";
    gchar *buf_null = NULL;
    gchar *buf_allocated = g_strdup("allocated string");

    pcmk__assert_asserts(pcmk__scan_nvpair(input, &buf_allocated, &buf_null));
    pcmk__assert_asserts(pcmk__scan_nvpair(input, &buf_null, &buf_allocated));

    g_free(buf_allocated);
}

static void
empty_input(void **state)
{
    assert_scan_nvpair_failure("");
}

static void
equal_sign_only(void **state)
{
    assert_scan_nvpair_failure("=");
}

static void
name_only(void **state)
{
    assert_scan_nvpair_failure("name");
}

static void
value_only(void **state)
{
    assert_scan_nvpair_failure("=value");
}

static void
valid(void **state)
{
    assert_scan_nvpair_success("name=value", "name", "value");

    // Empty value
    assert_scan_nvpair_success("name=", "name", "");

    // Whitespace is kept (checking only space characters here)
    assert_scan_nvpair_success(" name=value", " name", "value");
    assert_scan_nvpair_success("name =value", "name ", "value");
    assert_scan_nvpair_success("name= value", "name", " value");
    assert_scan_nvpair_success("name=value ", "name", "value ");
    assert_scan_nvpair_success("name =   value", "name ", "   value");

    // Trailing characters are kept
    assert_scan_nvpair_success("name=value=", "name", "value=");
    assert_scan_nvpair_success("name=value=\n\n", "name", "value=\n\n");
    assert_scan_nvpair_success("name=value=e", "name", "value=e");
    assert_scan_nvpair_success("name=value=e\n\n", "name", "value=e\n\n");

    // Quotes are not treated specially
    assert_scan_nvpair_success("name=''", "name", "''");
    assert_scan_nvpair_success("name='value'", "name", "'value'");
    assert_scan_nvpair_success("'name'=value", "'name'", "value");
    assert_scan_nvpair_success("'name=value'", "'name", "value'");
    assert_scan_nvpair_success("name=\"value\"", "name", "\"value\"");
    assert_scan_nvpair_success("\"name\"=value", "\"name\"", "value");
    assert_scan_nvpair_success("\"name=value\"", "\"name", "value\"");

    // Other special characters are not treated specially (small sample)
    assert_scan_nvpair_success("!@#$%=^&*()", "!@#$%", "^&*()");
    assert_scan_nvpair_success("name=$value", "name", "$value");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_asserts),
                cmocka_unit_test(already_allocated_asserts),
                cmocka_unit_test(empty_input),
                cmocka_unit_test(equal_sign_only),
                cmocka_unit_test(name_only),
                cmocka_unit_test(value_only),
                cmocka_unit_test(valid))
