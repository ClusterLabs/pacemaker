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

#define FIRST_ID "foo"

#define XML_FIRST_ID "<block " PCMK_XA_ID "=\"" FIRST_ID "\" "  \
                               PCMK_XA_SCORE "=\"0\" />"
#define XML_NO_ID "<block " PCMK_XA_SCORE "=\"5\" />"
#define XML_LOW   "<block " PCMK_XA_ID "=\"low\"  " PCMK_XA_SCORE "=\"1\"   />"
#define XML_HIGH  "<block " PCMK_XA_ID "=\"high\" " PCMK_XA_SCORE "=\"100\" />"
#define XML_BAD   "<block " PCMK_XA_ID "=\"high\" " PCMK_XA_SCORE "=\"x\"   />"

static pcmk__nvpair_unpack_t unpack_data = {
    .first_id = FIRST_ID,
};

static void
null_lowest(void **state)
{
    xmlNode *block = pcmk__xml_parse(XML_LOW);

    assert_non_null(block);

    assert_int_equal(pcmk__cmp_nvpair_blocks(NULL, block, NULL), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(block, NULL, NULL), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(NULL, NULL, NULL), 0);

    unpack_data.overwrite = false;
    assert_int_equal(pcmk__cmp_nvpair_blocks(NULL, block, &unpack_data), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(block, NULL, &unpack_data), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(NULL, NULL, &unpack_data), 0);

    unpack_data.overwrite = true;
    assert_int_equal(pcmk__cmp_nvpair_blocks(NULL, block, &unpack_data), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(block, NULL, &unpack_data), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(NULL, NULL, &unpack_data), 0);

    pcmk__xml_free(block);
}

static void
special_id_highest(void **state)
{
    xmlNode *first_id = pcmk__xml_parse(XML_FIRST_ID);
    xmlNode *not_first_id = pcmk__xml_parse(XML_HIGH);
    xmlNode *no_id = pcmk__xml_parse(XML_NO_ID);

    assert_non_null(first_id);
    assert_non_null(not_first_id);
    assert_non_null(no_id);

    unpack_data.overwrite = false;
    assert_int_equal(pcmk__cmp_nvpair_blocks(first_id, not_first_id,
                                             &unpack_data), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(not_first_id, first_id,
                                             &unpack_data), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(first_id, no_id,
                                             &unpack_data), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(no_id, first_id,
                                             &unpack_data), 1);

    unpack_data.overwrite = true;
    assert_int_equal(pcmk__cmp_nvpair_blocks(first_id, not_first_id,
                                             &unpack_data), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(not_first_id, first_id,
                                             &unpack_data), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(first_id, no_id,
                                             &unpack_data), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(no_id, first_id,
                                             &unpack_data), -1);

    pcmk__xml_free(first_id);
    pcmk__xml_free(not_first_id);
    pcmk__xml_free(no_id);
}

static void
null_special_id_ignored(void **state)
{
    xmlNode *no_id = pcmk__xml_parse(XML_NO_ID);
    xmlNode *high = pcmk__xml_parse(XML_HIGH);

    assert_non_null(no_id);
    assert_non_null(high);

    unpack_data.first_id = NULL;

    unpack_data.overwrite = false;
    assert_int_equal(pcmk__cmp_nvpair_blocks(no_id, high, &unpack_data), 1);

    unpack_data.overwrite = true;
    assert_int_equal(pcmk__cmp_nvpair_blocks(no_id, high, &unpack_data), -1);

    unpack_data.first_id = FIRST_ID;

    pcmk__xml_free(no_id);
    pcmk__xml_free(high);
}

static void
highest_score_wins(void **state)
{
    xmlNode *low = pcmk__xml_parse(XML_LOW);
    xmlNode *low2 = pcmk__xml_parse(XML_LOW);
    xmlNode *high = pcmk__xml_parse(XML_HIGH);

    assert_non_null(low);
    assert_non_null(high);

    unpack_data.overwrite = false;
    assert_int_equal(pcmk__cmp_nvpair_blocks(low, high, &unpack_data), 1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(low, low2, &unpack_data), 0);

    unpack_data.overwrite = true;
    assert_int_equal(pcmk__cmp_nvpair_blocks(low, high, &unpack_data), -1);
    assert_int_equal(pcmk__cmp_nvpair_blocks(low, low2, &unpack_data), 0);

    pcmk__xml_free(low);
    pcmk__xml_free(high);
}

static void
invalid_score_is_0(void **state)
{
    xmlNode *zero = pcmk__xml_parse(XML_FIRST_ID);
    xmlNode *bad = pcmk__xml_parse(XML_BAD);

    assert_non_null(zero);
    assert_non_null(bad);

    assert_int_equal(pcmk__cmp_nvpair_blocks(zero, bad, NULL), 0);
    assert_int_equal(pcmk__cmp_nvpair_blocks(bad, zero, NULL), 0);

    pcmk__xml_free(zero);
    pcmk__xml_free(bad);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_lowest),
                cmocka_unit_test(special_id_highest),
                cmocka_unit_test(null_special_id_ignored),
                cmocka_unit_test(highest_score_wins),
                cmocka_unit_test(invalid_score_is_0))
