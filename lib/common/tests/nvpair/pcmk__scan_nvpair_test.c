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

static void
assert_scan_nvpair(const gchar *input, int expected_rc,
                   const gchar *expected_name, const gchar *expected_value)
{
    gchar *name = NULL;
    gchar *value = NULL;

    assert_int_equal(pcmk__scan_nvpair(input, &name, &value),
                     expected_rc);

    if (expected_name == NULL) {
        assert_null(name);
    } else {
        assert_string_equal(name, expected_name);
    }

    if (expected_value == NULL) {
        assert_null(value);
    } else {
        assert_string_equal(value, expected_value);
    }

    g_free(name);
    g_free(value);
}

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
    assert_scan_nvpair("", pcmk_rc_bad_nvpair, NULL, NULL);
}

static void
equal_sign_only(void **state)
{
    assert_scan_nvpair("=", pcmk_rc_bad_nvpair, NULL, NULL);
}

static void
name_only(void **state)
{
    assert_scan_nvpair("name", pcmk_rc_bad_nvpair, NULL, NULL);
    assert_scan_nvpair("name=", pcmk_rc_bad_nvpair, NULL, NULL);
}

static void
value_only(void **state)
{
    assert_scan_nvpair("=value", pcmk_rc_bad_nvpair, NULL, NULL);
}

static void
valid(void **state)
{
    assert_scan_nvpair("name=value", pcmk_rc_ok, "name", "value");

    // Whitespace is kept (checking only space characters here)
    assert_scan_nvpair(" name=value", pcmk_rc_ok, " name", "value");
    assert_scan_nvpair("name =value", pcmk_rc_ok, "name ", "value");
    assert_scan_nvpair("name= value", pcmk_rc_ok, "name", " value");
    assert_scan_nvpair("name=value ", pcmk_rc_ok, "name", "value ");
    assert_scan_nvpair("name =   value", pcmk_rc_ok, "name ", "   value");

    // Trailing characters are kept
    assert_scan_nvpair("name=value=", pcmk_rc_ok, "name", "value=");
    assert_scan_nvpair("name=value=\n\n", pcmk_rc_ok, "name", "value=\n\n");
    assert_scan_nvpair("name=value=e", pcmk_rc_ok, "name", "value=e");
    assert_scan_nvpair("name=value=e\n\n", pcmk_rc_ok, "name", "value=e\n\n");

    // Quotes are not treated specially
    assert_scan_nvpair("name='value'", pcmk_rc_ok, "name", "'value'");
    assert_scan_nvpair("'name'=value", pcmk_rc_ok, "'name'", "value");
    assert_scan_nvpair("'name=value'", pcmk_rc_ok, "'name", "value'");
    assert_scan_nvpair("name=\"value\"", pcmk_rc_ok, "name", "\"value\"");
    assert_scan_nvpair("\"name\"=value", pcmk_rc_ok, "\"name\"", "value");
    assert_scan_nvpair("\"name=value\"", pcmk_rc_ok, "\"name", "value\"");

    // Other special characters are not treated specially (small sample)
    assert_scan_nvpair("!@#$%=^&*()", pcmk_rc_ok, "!@#$%", "^&*()");
    assert_scan_nvpair("name=$value", pcmk_rc_ok, "name", "$value");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_asserts),
                cmocka_unit_test(already_allocated_asserts),
                cmocka_unit_test(empty_input),
                cmocka_unit_test(equal_sign_only),
                cmocka_unit_test(name_only),
                cmocka_unit_test(value_only),
                cmocka_unit_test(valid))
