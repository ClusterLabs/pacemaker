/*
 * Copyright 2023-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

static int
setup(void **state)
{
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    pcmk__xml_test_setup_group(state);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__xml_test_teardown_group(state);
    unsetenv("PCMK_schema_directory");
    return 0;
}

#define assert_schema(name, expected_index)                     \
    do {                                                        \
        GList *schema_entry = NULL;                             \
        pcmk__schema_t *schema = NULL;                          \
                                                                \
        schema_entry = pcmk__get_schema(name);                  \
        assert_non_null(schema_entry);                          \
                                                                \
        schema = schema_entry->data;                            \
        assert_non_null(schema);                                \
                                                                \
        assert_int_equal(schema->schema_index, expected_index); \
    } while (0)

static void
unknown_schema(void **state)
{
    assert_null(pcmk__get_schema(NULL));
    assert_null(pcmk__get_schema(""));
    assert_null(pcmk__get_schema("blahblah"));
    assert_null(pcmk__get_schema("pacemaker-2.47"));
    assert_null(pcmk__get_schema("pacemaker-47.0"));
}

static void
known_schema(void **state)
{
    assert_schema("pacemaker-1.0", 0);
    assert_schema("pacemaker-1.2", 1);
    assert_schema("pacemaker-2.0", 3);
    assert_schema("pacemaker-2.5", 8);
    assert_schema("pacemaker-3.0", 14);
}

static void
case_sensitive(void **state)
{
    assert_null(pcmk__get_schema("PACEMAKER-1.0"));
    assert_null(pcmk__get_schema("pAcEmAkEr-2.0"));
    assert_null(pcmk__get_schema("paceMAKER-3.0"));
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(unknown_schema),
                cmocka_unit_test(known_schema),
                cmocka_unit_test(case_sensitive));
