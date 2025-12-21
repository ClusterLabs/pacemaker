/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

#define XML_PASSING_RULE                                    \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='rp' >\n"             \
      "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='ep' "   \
          PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "         \
          PCMK_XA_START "='1950-01-01 00:00:00' />\n"       \
    "</" PCMK_XE_RULE ">\n"

#define XML_FAILING_RULE                                    \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='rf' >\n"             \
      "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='ef' "   \
          PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' "         \
          PCMK_XA_END "='1950-01-01 00:00:00' />\n"         \
    "</" PCMK_XE_RULE ">\n"

#define XML_NVPAIRS_1                                       \
    "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp1-1' "          \
        PCMK_XA_NAME "='name1' " PCMK_XA_VALUE "='1' />\n"  \
    "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp1-2' "          \
        PCMK_XA_NAME "='name2' " PCMK_XA_VALUE "='1' />\n"

#define XML_NVPAIRS_2                                       \
    "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp2-1' "          \
        PCMK_XA_NAME "='name1' " PCMK_XA_VALUE "='2' />\n"  \
    "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp2-2' "          \
        PCMK_XA_NAME "='name2' " PCMK_XA_VALUE "='2' />\n"  \
    "<" PCMK_XE_NVPAIR " " PCMK_XA_ID "='nvp2-3' "          \
        PCMK_XA_NAME "='name3' " PCMK_XA_VALUE "='2' />\n"

static void
invalid_args(void **state)
{
    pcmk__nvpair_unpack_t unpack_data = {
        .values = NULL,
        .rule_input = {
            .now = NULL,
        },
    };

    xmlNode *xml = pcmk__xml_parse("<xml/>");

    assert_non_null(xml);

    pcmk__assert_asserts(pcmk__unpack_nvpair_block(NULL, NULL));
    pcmk__assert_asserts(pcmk__unpack_nvpair_block(NULL, &unpack_data));
    pcmk__assert_asserts(pcmk__unpack_nvpair_block(xml, NULL));
    pcmk__assert_asserts(pcmk__unpack_nvpair_block(xml, &unpack_data));

    unpack_data.values = g_hash_table_new(NULL, NULL);
    pcmk__assert_asserts(pcmk__unpack_nvpair_block(NULL, &unpack_data));
    g_hash_table_destroy(unpack_data.values);

    pcmk__xml_free(xml);
}

static void
with_rules(void **state) {
    crm_time_t *now = crm_time_new("2024-01-01 15:00:00");
    pcmk__nvpair_unpack_t unpack_data = {
        .values = pcmk__strkey_table(free, free),
        .rule_input = {
            .now = now,
        },
    };

    xmlNode *xml = NULL;

    xml = pcmk__xml_parse("<xml>\n" XML_NVPAIRS_1 XML_PASSING_RULE "</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 2);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "1");
    pcmk__xml_free(xml);

    xml = pcmk__xml_parse("<xml>\n" XML_NVPAIRS_2 XML_FAILING_RULE "</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 2);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "1");
    assert_null(g_hash_table_lookup(unpack_data.values, "name3"));

    pcmk__xml_free(xml);
    crm_time_free(now);
    g_hash_table_destroy(unpack_data.values);
}

static void
without_overwrite(void **state)
{
    pcmk__nvpair_unpack_t unpack_data = {
        .values = pcmk__strkey_table(free, free),
        .overwrite = false,
    };

    xmlNode *xml = NULL;

    xml = pcmk__xml_parse("<xml>\n" XML_NVPAIRS_1 "</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 2);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "1");
    pcmk__xml_free(xml);

    xml = pcmk__xml_parse("<xml>\n" XML_NVPAIRS_2 "</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 3);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name3"), "2");
    pcmk__xml_free(xml);

    g_hash_table_destroy(unpack_data.values);
}

static void
with_overwrite(void **state)
{
    pcmk__nvpair_unpack_t unpack_data = {
        .values = pcmk__strkey_table(free, free),
        .overwrite = true,
    };

    xmlNode *xml = NULL;

    xml = pcmk__xml_parse("<xml>\n" XML_NVPAIRS_1 "</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 2);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "1");
    pcmk__xml_free(xml);

    xml = pcmk__xml_parse("<xml>\n" XML_NVPAIRS_2 "</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 3);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "2");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "2");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name3"), "2");
    pcmk__xml_free(xml);

    g_hash_table_destroy(unpack_data.values);
}

static void
attributes_child(void **state)
{
    pcmk__nvpair_unpack_t unpack_data = {
        .values = pcmk__strkey_table(free, free),
    };

    xmlNode *xml = pcmk__xml_parse("<xml>\n<" PCMK__XE_ATTRIBUTES ">\n"
                                   XML_NVPAIRS_1
                                   "</" PCMK__XE_ATTRIBUTES ">\n</xml>\n");
    assert_non_null(xml);
    pcmk__unpack_nvpair_block(xml, &unpack_data);
    assert_int_equal(g_hash_table_size(unpack_data.values), 2);
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name1"), "1");
    assert_string_equal(g_hash_table_lookup(unpack_data.values, "name2"), "1");
    pcmk__xml_free(xml);

    g_hash_table_destroy(unpack_data.values);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(invalid_args),
                cmocka_unit_test(with_rules),
                cmocka_unit_test(without_overwrite),
                cmocka_unit_test(with_overwrite),
                cmocka_unit_test(attributes_child))
