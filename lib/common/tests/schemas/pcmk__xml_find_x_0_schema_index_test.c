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

#include <glib.h>

#include "crmcommon_private.h"

static pcmk__schema_t *
mk_schema(const char *name, unsigned char x, unsigned char y)
{
    pcmk__schema_t *schema = malloc(sizeof(pcmk__schema_t));

    schema->name = strdup(name);
    schema->version.v[0] = x;
    schema->version.v[1] = y;
    return schema;
}

static void
free_schema(void *data)
{
    pcmk__schema_t *schema = data;
    free(schema->name);
    free(schema);
}

static void
empty_schema_list(void **state)
{
    pcmk__assert_asserts(pcmk__find_x_0_schema_index(NULL));
}

static void
singleton_schema_list(void **state)
{
    GList *schemas = NULL;

    schemas = g_list_append(schemas, mk_schema("pacemaker-1.0", 1, 0));
    assert_int_equal(0, pcmk__find_x_0_schema_index(schemas));
    g_list_free_full(schemas, free_schema);
}

static void
one_major_version(void **state)
{
    GList *schemas = NULL;

    schemas = g_list_append(schemas, mk_schema("pacemaker-1.0", 1, 0));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.2", 1, 2));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.3", 1, 3));
    assert_int_equal(0, pcmk__find_x_0_schema_index(schemas));
    g_list_free_full(schemas, free_schema);
}

static void
first_version_is_not_0(void **state)
{
    GList *schemas = NULL;

    schemas = g_list_append(schemas, mk_schema("pacemaker-1.1", 1, 1));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.2", 1, 2));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.3", 1, 3));
    assert_int_equal(0, pcmk__find_x_0_schema_index(schemas));
    g_list_free_full(schemas, free_schema);
}

static void
multiple_major_versions(void **state)
{
    GList *schemas = NULL;

    schemas = g_list_append(schemas, mk_schema("pacemaker-1.0", 1, 0));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.1", 1, 1));
    schemas = g_list_append(schemas, mk_schema("pacemaker-2.0", 2, 0));
    assert_int_equal(2, pcmk__find_x_0_schema_index(schemas));
    g_list_free_full(schemas, free_schema);
}

static void
many_versions(void **state)
{
    GList *schemas = NULL;

    schemas = g_list_append(schemas, mk_schema("pacemaker-1.0", 1, 0));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.1", 1, 1));
    schemas = g_list_append(schemas, mk_schema("pacemaker-1.2", 1, 2));
    schemas = g_list_append(schemas, mk_schema("pacemaker-2.0", 2, 0));
    schemas = g_list_append(schemas, mk_schema("pacemaker-2.1", 2, 1));
    schemas = g_list_append(schemas, mk_schema("pacemaker-2.2", 2, 2));
    schemas = g_list_append(schemas, mk_schema("pacemaker-3.0", 3, 0));
    schemas = g_list_append(schemas, mk_schema("pacemaker-3.1", 3, 1));
    schemas = g_list_append(schemas, mk_schema("pacemaker-3.2", 3, 2));
    assert_int_equal(6, pcmk__find_x_0_schema_index(schemas));
    g_list_free_full(schemas, free_schema);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_schema_list),
                cmocka_unit_test(singleton_schema_list),
                cmocka_unit_test(one_major_version),
                cmocka_unit_test(first_version_is_not_0),
                cmocka_unit_test(multiple_major_versions),
                cmocka_unit_test(many_versions))
