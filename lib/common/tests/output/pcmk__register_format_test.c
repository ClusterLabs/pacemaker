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

static void
invalid_params(void **state)
{
    pcmk__assert_asserts(pcmk__register_format(NULL, "fake", NULL, NULL));
    pcmk__assert_asserts(pcmk__register_format(NULL, "",
                                               pcmk__output_setup_dummy1,
                                               NULL));
    pcmk__assert_asserts(pcmk__register_format(NULL, NULL,
                                               pcmk__output_setup_dummy1,
                                               NULL));
}

static void
add_format(void **state)
{
    int rc = pcmk_rc_ok;
    GHashTable *formatters = NULL;
    gpointer value = NULL;

    /* For starters, there should be no formatters defined. */
    assert_null(pcmk__output_formatters());

    /* Add a fake formatter and check that it's the only item in the hash
     * table
     */
    rc = pcmk__register_format(NULL, "fake", pcmk__output_setup_dummy1, NULL);
    assert_int_equal(rc, pcmk_rc_ok);

    formatters = pcmk__output_formatters();
    assert_int_equal(g_hash_table_size(formatters), 1);

    value = g_hash_table_lookup(formatters, "fake");
    assert_ptr_equal(value, pcmk__output_setup_dummy1);

    /* Add a second fake formatter that should overwrite the first one, leaving
     * only one item (with the new function) in the hash table
     */
    rc = pcmk__register_format(NULL, "fake", pcmk__output_setup_dummy2, NULL);
    assert_int_equal(rc, pcmk_rc_ok);

    formatters = pcmk__output_formatters();
    assert_int_equal(g_hash_table_size(formatters), 1);

    value = g_hash_table_lookup(formatters, "fake");
    assert_ptr_equal(value, pcmk__output_setup_dummy2);

    pcmk__unregister_formats();
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_params),
                cmocka_unit_test(add_format))
