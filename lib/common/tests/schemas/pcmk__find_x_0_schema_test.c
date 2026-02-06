/*
 * Copyright 2023-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>  // NULL, rename()
#include <stdlib.h> // setenv(), unsetenv()
#include <glib.h>

#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

#define SCHEMA_PREFIX PCMK__TEST_SCHEMA_DIR "/find_x_0/pacemaker-"

static int
setup(void **state)
{
    // Use a unique schema directory so we can move files around
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR "/find_x_0", 1);
    return 0;
}

static int
teardown(void **state)
{
    unsetenv("PCMK_schema_directory");
    return 0;
}

#define assert_schema_0(schema_idx, schema_name)                \
    do {                                                        \
        GList *entry = NULL;                                    \
        pcmk__schema_t *schema = NULL;                          \
                                                                \
        entry = pcmk__find_x_0_schema();                        \
        assert_non_null(entry);                                 \
                                                                \
        schema = entry->data;                                   \
        assert_non_null(schema);                                \
                                                                \
        assert_int_equal(schema->schema_index, schema_idx);     \
        assert_string_equal(schema->name, schema_name);         \
    } while (0)

static void
last_is_0(void **state)
{
    /* This loads all the schemas normally linked for unit testing, so we have
     * many 1.x and 2.x schemas and a single pacemaker-3.0 schema at index 14.
     */
    pcmk__schema_init();
    assert_schema_0(14, "pacemaker-3.0");
    pcmk__schema_cleanup();
}

static void
last_is_not_0(void **state)
{
    /* Disable the pacemaker-3.0 schema, so we now should get pacemaker-2.0 at
     * index 3.
     */
    assert_int_equal(0, rename(SCHEMA_PREFIX "3.0.rng",
                               SCHEMA_PREFIX "3.0.bak"));
    pcmk__schema_init();
    assert_schema_0(3, "pacemaker-2.0");
    assert_int_equal(0, rename(SCHEMA_PREFIX "3.0.bak",
                               SCHEMA_PREFIX "3.0.rng"));
    pcmk__schema_cleanup();
}

static void
schema_0_missing(void **state)
{
    /* Disable the pacemaker-3.0 and pacemaker-2.0 schemas, so we now should get
     * pacemaker-2.1 at index 3.
     */
    assert_int_equal(0, rename(SCHEMA_PREFIX "3.0.rng",
                               SCHEMA_PREFIX "3.0.bak"));
    assert_int_equal(0, rename(SCHEMA_PREFIX "2.0.rng",
                               SCHEMA_PREFIX "2.0.bak"));
    pcmk__schema_init();
    assert_schema_0(3, "pacemaker-2.1");
    assert_int_equal(0, rename(SCHEMA_PREFIX "2.0.bak",
                               SCHEMA_PREFIX "2.0.rng"));
    assert_int_equal(0, rename(SCHEMA_PREFIX "3.0.bak",
                               SCHEMA_PREFIX "3.0.rng"));
    pcmk__schema_cleanup();
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(last_is_0),
                cmocka_unit_test(last_is_not_0),
                cmocka_unit_test(schema_0_missing))
