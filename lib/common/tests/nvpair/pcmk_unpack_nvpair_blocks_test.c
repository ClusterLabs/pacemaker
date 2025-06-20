/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>
#include <crm/common/xml.h>

/* The test XML is designed so that:
 * - The blocks are, lowest score to highest, #2 #3 #1 (to test sorting)
 * - The first block can be used to test rule evaluation by setting "now"
 * - The first block has a different element name than the other two,
 *   to test specifying an element name
 * - The middle block can be used to test ID precedence
*/
#define XML_BLOCKS                                                  \
    "<xml>\n"                                                       \
      "<" PCMK_XE_META_ATTRIBUTES " " PCMK_XA_ID "='ia1' "          \
          PCMK_XA_SCORE "='100' >"                                  \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp1-1' "            \
              PCMK_XA_NAME "='name1' " PCMK_XA_VALUE "='1' />\n"    \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp1-2' "            \
              PCMK_XA_NAME "='name2' " PCMK_XA_VALUE "='1' />\n"    \
          "<" PCMK_XE_RULE " " PCMK_XA_ID "='rp' >\n"               \
            "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='ep' "     \
                PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "           \
                PCMK_XA_START "='2024-11-05 00:00:00' />\n"         \
          "</" PCMK_XE_RULE ">\n"                                   \
      "</" PCMK_XE_META_ATTRIBUTES ">\n"                            \
      "<" PCMK_XE_INSTANCE_ATTRIBUTES " " PCMK_XA_ID "='ia2' "      \
          PCMK_XA_SCORE "='2' >"                                    \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp2-1' "            \
              PCMK_XA_NAME "='name1' " PCMK_XA_VALUE "='2' />\n"    \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp2-2' "            \
              PCMK_XA_NAME "='name2' " PCMK_XA_VALUE "='2' />\n"    \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp2-3' "            \
              PCMK_XA_NAME "='name3' " PCMK_XA_VALUE "='2' />\n"    \
      "</" PCMK_XE_INSTANCE_ATTRIBUTES ">\n"                        \
      "<" PCMK_XE_INSTANCE_ATTRIBUTES " " PCMK_XA_ID "='ia3' "      \
          PCMK_XA_SCORE "='30' >"                                   \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp3-1' "            \
              PCMK_XA_NAME "='name1' " PCMK_XA_VALUE "='3' />\n"    \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp3-2' "            \
              PCMK_XA_NAME "='name2' " PCMK_XA_VALUE "='3' />\n"    \
          "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp3-3' "            \
              PCMK_XA_NAME "='name3' " PCMK_XA_VALUE "='3' />\n"    \
      "</" PCMK_XE_INSTANCE_ATTRIBUTES ">\n"                        \
    "</xml>\n"


static void
null_xml(void **state)
{
    GHashTable *values = pcmk__strkey_table(free, free);
    crm_time_t *now = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *next_change = crm_time_new("2024-01-01 20:00:00");
    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    // This mainly tests that it doesn't crash
    pcmk_unpack_nvpair_blocks(NULL, PCMK_XE_INSTANCE_ATTRIBUTES, "id1",
                              &rule_input, values, next_change);
    assert_int_equal(g_hash_table_size(values), 0);
    g_hash_table_destroy(values);
    crm_time_free(now);
    crm_time_free(next_change);
}

static void
null_table(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_BLOCKS);
    crm_time_t *now = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *next_change = crm_time_new("2024-01-01 20:00:00");
    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    assert_non_null(xml);
    pcmk__assert_asserts(pcmk_unpack_nvpair_blocks(xml,
                                                   PCMK_XE_INSTANCE_ATTRIBUTES,
                                                   "id1", &rule_input, NULL,
                                                   next_change));
    pcmk__xml_free(xml);
    crm_time_free(next_change);
    crm_time_free(now);
}

static void
rule_passes(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_BLOCKS);
    crm_time_t *now = crm_time_new("2024-11-06 15:00:00");
    crm_time_t *next_change = crm_time_new("2024-11-06 20:00:00");
    GHashTable *values = pcmk__strkey_table(free, free);
    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    assert_non_null(xml);
    pcmk_unpack_nvpair_blocks(xml, NULL, "id1", &rule_input, values,
                              next_change);
    assert_int_equal(g_hash_table_size(values), 3);
    assert_string_equal(g_hash_table_lookup(values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(values, "name2"), "1");
    assert_string_equal(g_hash_table_lookup(values, "name3"), "3");

    pcmk__xml_free(xml);
    crm_time_free(next_change);
    crm_time_free(now);
    g_hash_table_destroy(values);
}

static void
rule_fails(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_BLOCKS);
    crm_time_t *now = crm_time_new("2024-11-04 15:00:00");
    crm_time_t *next_change = crm_time_new("2024-11-05 20:00:00");
    crm_time_t *expected_next_change = crm_time_new("2024-11-05 00:00:01");
    GHashTable *values = pcmk__strkey_table(free, free);
    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    // This also tests that next_change is set when appropriate

    assert_non_null(xml);
    pcmk_unpack_nvpair_blocks(xml, NULL, "id1", &rule_input, values,
                              next_change);
    assert_int_equal(g_hash_table_size(values), 3);
    assert_string_equal(g_hash_table_lookup(values, "name1"), "3");
    assert_string_equal(g_hash_table_lookup(values, "name2"), "3");
    assert_string_equal(g_hash_table_lookup(values, "name3"), "3");
    assert_int_equal(crm_time_compare(next_change, expected_next_change), 0);

    pcmk__xml_free(xml);
    crm_time_free(now);
    crm_time_free(next_change);
    crm_time_free(expected_next_change);
    g_hash_table_destroy(values);
}

static void
element_name(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_BLOCKS);
    crm_time_t *now = crm_time_new("2024-11-06 15:00:00");
    GHashTable *values = pcmk__strkey_table(free, free);
    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    assert_non_null(xml);

    /* This also tests that NULL first_id and next_change are handled without
     * problems
     */

    pcmk_unpack_nvpair_blocks(xml, PCMK_XE_META_ATTRIBUTES, NULL, &rule_input,
                              values, NULL);
    assert_int_equal(g_hash_table_size(values), 2);
    assert_string_equal(g_hash_table_lookup(values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(values, "name2"), "1");
    assert_null(g_hash_table_lookup(values, "name3"));
    g_hash_table_remove_all(values);

    pcmk_unpack_nvpair_blocks(xml, PCMK_XE_INSTANCE_ATTRIBUTES, NULL,
                              &rule_input, values, NULL);
    assert_int_equal(g_hash_table_size(values), 3);
    assert_string_equal(g_hash_table_lookup(values, "name1"), "3");
    assert_string_equal(g_hash_table_lookup(values, "name2"), "3");
    assert_string_equal(g_hash_table_lookup(values, "name3"), "3");

    pcmk__xml_free(xml);
    crm_time_free(now);
    g_hash_table_destroy(values);
}

static void
first_id(void **state)
{
    xmlNode *xml = pcmk__xml_parse(XML_BLOCKS);
    GHashTable *values = pcmk__strkey_table(free, free);

    assert_non_null(xml);

    // This also tests that NULL rule_input is handled without problems

    pcmk_unpack_nvpair_blocks(xml, NULL, "ia2", NULL, values, NULL);
    assert_int_equal(g_hash_table_size(values), 3);
    assert_string_equal(g_hash_table_lookup(values, "name1"), "2");
    assert_string_equal(g_hash_table_lookup(values, "name2"), "2");
    assert_string_equal(g_hash_table_lookup(values, "name3"), "2");

    pcmk__xml_free(xml);
    g_hash_table_destroy(values);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_xml),
                cmocka_unit_test(null_table),
                cmocka_unit_test(rule_passes),
                cmocka_unit_test(rule_fails),
                cmocka_unit_test(element_name),
                cmocka_unit_test(first_id))
