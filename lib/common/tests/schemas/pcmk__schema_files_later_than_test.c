/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/lists_internal.h>

#include <glib.h>

static int
setup(void **state)
{
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    crm_schema_init();
    return 0;
}

static int
teardown(void **state)
{
    crm_schema_cleanup();
    unsetenv("PCMK_schema_directory");
    return 0;
}

static void
invalid_name(void **state)
{
    assert_null(pcmk__schema_files_later_than("xyz"));
    assert_null(pcmk__schema_files_later_than("pacemaker-"));
}

static void
valid_name(void **state)
{
    GList *schemas = NULL;

    schemas = pcmk__schema_files_later_than("pacemaker-1.0");
    assert_int_equal(g_list_length(schemas), 18);
    /* There is no "pacemaker-1.1". */
    assert_string_equal("pacemaker-1.2.rng", g_list_nth_data(schemas, 0));
    assert_string_equal("upgrade-1.3.xsl", g_list_nth_data(schemas, 1));
    assert_string_equal("pacemaker-1.3.rng", g_list_nth_data(schemas, 2));
    assert_string_equal("pacemaker-2.0.rng", g_list_nth_data(schemas, 3));
    assert_string_equal("pacemaker-2.1.rng", g_list_nth_data(schemas, 4));
    assert_string_equal("pacemaker-2.2.rng", g_list_nth_data(schemas, 5));
    assert_string_equal("pacemaker-2.3.rng", g_list_nth_data(schemas, 6));
    assert_string_equal("pacemaker-2.4.rng", g_list_nth_data(schemas, 7));
    assert_string_equal("pacemaker-2.5.rng", g_list_nth_data(schemas, 8));
    assert_string_equal("pacemaker-2.6.rng", g_list_nth_data(schemas, 9));
    assert_string_equal("pacemaker-2.7.rng", g_list_nth_data(schemas, 10));
    assert_string_equal("pacemaker-2.8.rng", g_list_nth_data(schemas, 11));
    assert_string_equal("pacemaker-2.9.rng", g_list_nth_data(schemas, 12));
    assert_string_equal("upgrade-2.10-leave.xsl", g_list_nth_data(schemas, 13));
    assert_string_equal("upgrade-2.10-enter.xsl", g_list_nth_data(schemas, 14));
    assert_string_equal("upgrade-2.10.xsl", g_list_nth_data(schemas, 15));
    assert_string_equal("pacemaker-2.10.rng", g_list_nth_data(schemas, 16));
    assert_string_equal("pacemaker-3.0.rng", g_list_nth_data(schemas, 17));
    g_list_free_full(schemas, free);

    /* Adding .rng to the end of the schema we're requesting is also valid. */
    schemas = pcmk__schema_files_later_than("pacemaker-2.0.rng");
    assert_int_equal(g_list_length(schemas), 14);
    assert_string_equal("pacemaker-2.1.rng", g_list_nth_data(schemas, 0));
    assert_string_equal("pacemaker-2.2.rng", g_list_nth_data(schemas, 1));
    assert_string_equal("pacemaker-2.3.rng", g_list_nth_data(schemas, 2));
    assert_string_equal("pacemaker-2.4.rng", g_list_nth_data(schemas, 3));
    assert_string_equal("pacemaker-2.5.rng", g_list_nth_data(schemas, 4));
    assert_string_equal("pacemaker-2.6.rng", g_list_nth_data(schemas, 5));
    assert_string_equal("pacemaker-2.7.rng", g_list_nth_data(schemas, 6));
    assert_string_equal("pacemaker-2.8.rng", g_list_nth_data(schemas, 7));
    assert_string_equal("pacemaker-2.9.rng", g_list_nth_data(schemas, 8));
    assert_string_equal("upgrade-2.10-leave.xsl", g_list_nth_data(schemas, 9));
    assert_string_equal("upgrade-2.10-enter.xsl", g_list_nth_data(schemas, 10));
    assert_string_equal("upgrade-2.10.xsl", g_list_nth_data(schemas, 11));
    assert_string_equal("pacemaker-2.10.rng", g_list_nth_data(schemas, 12));
    assert_string_equal("pacemaker-3.0.rng", g_list_nth_data(schemas, 13));
    g_list_free_full(schemas, free);

    /* Check that "pacemaker-2.10" counts as later than "pacemaker-2.9". */
    schemas = pcmk__schema_files_later_than("pacemaker-2.9");
    assert_int_equal(g_list_length(schemas), 5);
    assert_string_equal("upgrade-2.10-leave.xsl", g_list_nth_data(schemas, 0));
    assert_string_equal("upgrade-2.10-enter.xsl", g_list_nth_data(schemas, 1));
    assert_string_equal("upgrade-2.10.xsl", g_list_nth_data(schemas, 2));
    assert_string_equal("pacemaker-2.10.rng", g_list_nth_data(schemas, 3));
    assert_string_equal("pacemaker-3.0.rng", g_list_nth_data(schemas, 4));
    g_list_free_full(schemas, free);

    /* And then something way in the future that will never apply due to our
     * special schema directory.
     */
    schemas = pcmk__schema_files_later_than("pacemaker-9.0");
    assert_null(schemas);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(invalid_name),
                cmocka_unit_test(valid_name))
