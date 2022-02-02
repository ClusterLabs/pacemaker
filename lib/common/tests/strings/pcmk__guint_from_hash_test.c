/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <glib.h>

static void
null_args(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);
    guint result;

    assert_int_equal(pcmk__guint_from_hash(NULL, "abc", 123, &result), EINVAL);
    assert_int_equal(pcmk__guint_from_hash(tbl, NULL, 123, &result), EINVAL);

    g_hash_table_destroy(tbl);
}

static void
missing_key(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);
    guint result;

    assert_int_equal(pcmk__guint_from_hash(tbl, "abc", 123, &result), pcmk_rc_ok);
    assert_int_equal(result, 123);

    g_hash_table_destroy(tbl);
}

static void
standard_usage(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);
    guint result;

    g_hash_table_insert(tbl, strdup("abc"), strdup("123"));

    assert_int_equal(pcmk__guint_from_hash(tbl, "abc", 456, &result), pcmk_rc_ok);
    assert_int_equal(result, 123);

    g_hash_table_destroy(tbl);
}

static void
conversion_errors(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);
    guint result;

    g_hash_table_insert(tbl, strdup("negative"), strdup("-3"));
    g_hash_table_insert(tbl, strdup("toobig"), strdup("20000000000000000"));

    assert_int_equal(pcmk__guint_from_hash(tbl, "negative", 456, &result), ERANGE);
    assert_int_equal(result, 456);

    assert_int_equal(pcmk__guint_from_hash(tbl, "toobig", 456, &result), ERANGE);
    assert_int_equal(result, 456);

    g_hash_table_destroy(tbl);
}

int main(int argc, char **argv) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_args),
        cmocka_unit_test(missing_key),
        cmocka_unit_test(standard_usage),
        cmocka_unit_test(conversion_errors),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
