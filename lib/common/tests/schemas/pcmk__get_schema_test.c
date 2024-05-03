/*
 * Copyright 2023-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>
#include "crmcommon_private.h"

static int
setup(void **state)
{
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    pcmk__schema_init();
    return 0;
}

static int
teardown(void **state)
{
    pcmk__schema_cleanup();
    unsetenv("PCMK_schema_directory");
    return 0;
}

static void
assert_schema(const char *name, int expected_index)
{
    GList *schema_entry = NULL;
    pcmk__schema_t *schema = NULL;

    schema_entry = pcmk__get_schema(name);
    assert_non_null(schema_entry);

    schema = schema_entry->data;
    assert_non_null(schema);

    assert_int_equal(schema->schema_index, expected_index);
}

static void
unknown_schema(void **state)
{
    assert_null(pcmk__get_schema(""));
    assert_null(pcmk__get_schema("blahblah"));
    assert_null(pcmk__get_schema("pacemaker-2.47"));
    assert_null(pcmk__get_schema("pacemaker-47.0"));
}

static void
known_schema(void **state)
{
    // @COMPAT none is deprecated since 2.1.8
    assert_schema(NULL, 16); // defaults to "none"

    assert_schema("pacemaker-1.0", 0);
    assert_schema("pacemaker-1.2", 1);
    assert_schema("pacemaker-2.0", 3);
    assert_schema("pacemaker-2.5", 8);
    assert_schema("pacemaker-3.0", 14);
}

static void
case_insensitive(void **state)
{
    assert_schema("PACEMAKER-1.0", 0);
    assert_schema("pAcEmAkEr-2.0", 3);
    assert_schema("paceMAKER-3.0", 14);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(unknown_schema),
                cmocka_unit_test(known_schema),
                cmocka_unit_test(case_insensitive));
