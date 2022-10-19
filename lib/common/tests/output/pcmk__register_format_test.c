/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/output_internal.h>

static pcmk__output_t *
null_create_fn(char **argv) {
    return NULL;
}

static pcmk__output_t *
null_create_fn_2(char **argv) {
    return NULL;
}

static void
invalid_params(void **state) {
    pcmk__assert_asserts(pcmk__register_format(NULL, "fake", NULL, NULL));
    pcmk__assert_asserts(pcmk__register_format(NULL, "", null_create_fn, NULL));
    pcmk__assert_asserts(pcmk__register_format(NULL, NULL, null_create_fn, NULL));
}

static void
add_format(void **state) {
    GHashTable *formatters = NULL;
    gpointer value;

    /* For starters, there should be no formatters defined. */
    assert_null(pcmk__output_formatters());

    /* Add a fake formatter and check that it's the only item in the hash table. */
    assert_int_equal(pcmk__register_format(NULL, "fake", null_create_fn, NULL), pcmk_rc_ok);
    formatters = pcmk__output_formatters();
    assert_int_equal(g_hash_table_size(formatters), 1);

    value = g_hash_table_lookup(formatters, "fake");
    assert_ptr_equal(value, null_create_fn);

    /* Add a second fake formatter which should overwrite the first one, leaving
     * only one item in the hash table but pointing at the new function.
     */
    assert_int_equal(pcmk__register_format(NULL, "fake", null_create_fn_2, NULL), pcmk_rc_ok);
    formatters = pcmk__output_formatters();
    assert_int_equal(g_hash_table_size(formatters), 1);

    value = g_hash_table_lookup(formatters, "fake");
    assert_ptr_equal(value, null_create_fn_2);

    pcmk__unregister_formats();
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_params),
                cmocka_unit_test(add_format))
