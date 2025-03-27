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
#include <crm/common/lists_internal.h>

#include <glib.h>

const char *rngs1[] = { "pacemaker-3.0.rng", "status-1.0.rng", "alerts-2.10.rng",
                        "nvset-2.9.rng", "score.rng", "rule-2.9.rng",
                        "tags-1.3.rng", "acls-2.0.rng", "fencing-2.4.rng",
                        "constraints-3.0.rng", "resources-3.0.rng", "nvset-3.0.rng",
                        "nodes-3.0.rng", "options-3.0.rng", NULL };

const char *rngs2[] = { "pacemaker-2.0.rng", "status-1.0.rng", "tags-1.3.rng",
                        "acls-2.0.rng", "fencing-1.2.rng", "constraints-1.2.rng",
                        "rule.rng", "score.rng", "resources-1.3.rng",
                        "nvset-1.3.rng", "nodes-1.3.rng", "options-1.0.rng",
                        "nvset.rng", "cib-1.2.rng", NULL };

const char *rngs3[] = { "pacemaker-2.1.rng", "constraints-2.1.rng", NULL };

static int
setup(void **state)
{
    setenv("PCMK_schema_directory", PCMK__TEST_SCHEMA_DIR, 1);
    pcmk__schema_init();
    pcmk__xml_test_setup_group(state);
    return 0;
}

static int
teardown(void **state)
{
    pcmk__xml_test_teardown_group(state);
    pcmk__schema_cleanup();
    unsetenv("PCMK_schema_directory");
    return 0;
}

static void
invalid_name(void **state)
{
    GList *already_included = NULL;
    xmlNode *parent = pcmk__xe_create(NULL, PCMK__XA_SCHEMAS);

    pcmk__build_schema_xml_node(parent, "pacemaker-9.0", &already_included);
    assert_null(parent->children);
    assert_null(already_included);
    pcmk__xml_free(parent);
}

static void
single_schema(void **state)
{
    GList *already_included = NULL;
    xmlNode *parent = pcmk__xe_create(NULL, PCMK__XA_SCHEMAS);
    xmlNode *schema_node = NULL;
    xmlNode *file_node = NULL;
    int i = 0;

    pcmk__build_schema_xml_node(parent, "pacemaker-3.0", &already_included);

    assert_non_null(already_included);
    assert_non_null(parent->children);

    /* Test that the result looks like this:
     *
     * <schemas>
     *   <schema version="pacemaker-3.0">
     *     <file path="pacemaker-3.0.rng">CDATA</file>
     *     <file path="status-1.0.rng">CDATA</file>
     *     ...
     *   </schema>
     * </schemas>
     */
    schema_node = pcmk__xe_first_child(parent, NULL, NULL, NULL);
    assert_string_equal("pacemaker-3.0",
                        pcmk__xe_get(schema_node, PCMK_XA_VERSION));

    file_node = pcmk__xe_first_child(schema_node, NULL, NULL, NULL);
    while (file_node != NULL && rngs1[i] != NULL) {
        assert_string_equal(rngs1[i], pcmk__xe_get(file_node, PCMK_XA_PATH));
        assert_int_equal(pcmk__xml_first_child(file_node)->type, XML_CDATA_SECTION_NODE);

        file_node = pcmk__xe_next(file_node, NULL);
        i++;
    }

    g_list_free_full(already_included, free);
    pcmk__xml_free(parent);
}

static void
multiple_schemas(void **state)
{
    GList *already_included = NULL;
    xmlNode *parent = pcmk__xe_create(NULL, PCMK__XA_SCHEMAS);
    xmlNode *schema_node = NULL;
    xmlNode *file_node = NULL;
    int i = 0;

    pcmk__build_schema_xml_node(parent, "pacemaker-2.0", &already_included);
    pcmk__build_schema_xml_node(parent, "pacemaker-2.1", &already_included);

    assert_non_null(already_included);
    assert_non_null(parent->children);

    /* Like single_schema, but make sure files aren't included multiple times
     * when the function is called repeatedly.
     */
    schema_node = pcmk__xe_first_child(parent, NULL, NULL, NULL);
    assert_string_equal("pacemaker-2.0",
                        pcmk__xe_get(schema_node, PCMK_XA_VERSION));

    file_node = pcmk__xe_first_child(schema_node, NULL, NULL, NULL);
    while (file_node != NULL && rngs2[i] != NULL) {
        assert_string_equal(rngs2[i], pcmk__xe_get(file_node, PCMK_XA_PATH));
        assert_int_equal(pcmk__xml_first_child(file_node)->type, XML_CDATA_SECTION_NODE);

        file_node = pcmk__xe_next(file_node, NULL);
        i++;
    }

    schema_node = pcmk__xe_next(schema_node, NULL);
    assert_string_equal("pacemaker-2.1",
                        pcmk__xe_get(schema_node, PCMK_XA_VERSION));

    file_node = pcmk__xe_first_child(schema_node, NULL, NULL, NULL);
    i = 0;

    while (file_node != NULL && rngs3[i] != NULL) {
        assert_string_equal(rngs3[i], pcmk__xe_get(file_node, PCMK_XA_PATH));
        assert_int_equal(pcmk__xml_first_child(file_node)->type, XML_CDATA_SECTION_NODE);

        file_node = pcmk__xe_next(file_node, NULL);
        i++;
    }

    g_list_free_full(already_included, free);
    pcmk__xml_free(parent);
}

PCMK__UNIT_TEST(setup, teardown,
                cmocka_unit_test(invalid_name),
                cmocka_unit_test(single_schema),
                cmocka_unit_test(multiple_schemas))
