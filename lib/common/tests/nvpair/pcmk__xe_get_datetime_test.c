/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <libxml/tree.h>

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>
#include <crm/common/xml.h>
#include <crm/common/nvpair_internal.h>

#define REFERENCE_ISO8601 "2024-001"
#define ATTR_PRESENT "start"
#define ATTR_MISSING "end"
#define REFERENCE_XML "<date_expression id=\"id1\" "            \
                      ATTR_PRESENT "=\"" REFERENCE_ISO8601 "\"" \
                      " operation=\"gt\">"
#define BAD_XML       "<date_expression id=\"id1\" "            \
                      ATTR_PRESENT "=\"not_a_time\""            \
                      " operation=\"gt\">"

static void
null_invalid(void **state)
{
    xmlNode *xml = pcmk__xml_parse(REFERENCE_XML);
    crm_time_t *t = NULL;

    assert_int_equal(pcmk__xe_get_datetime(NULL, NULL, NULL), EINVAL);
    assert_int_equal(pcmk__xe_get_datetime(xml, NULL, NULL), EINVAL);
    assert_int_equal(pcmk__xe_get_datetime(xml, ATTR_PRESENT, NULL), EINVAL);
    assert_int_equal(pcmk__xe_get_datetime(xml, NULL, &t), EINVAL);
    assert_null(t);
    assert_int_equal(pcmk__xe_get_datetime(NULL, ATTR_PRESENT, NULL), EINVAL);
    assert_int_equal(pcmk__xe_get_datetime(NULL, ATTR_PRESENT, &t), EINVAL);
    assert_null(t);
    assert_int_equal(pcmk__xe_get_datetime(NULL, NULL, &t), EINVAL);
    assert_null(t);

    free_xml(xml);
}

static void
nonnull_time_invalid(void **state)
{
    xmlNode *xml = pcmk__xml_parse(REFERENCE_XML);
    crm_time_t *t = crm_time_new_undefined();

    assert_int_equal(pcmk__xe_get_datetime(xml, ATTR_PRESENT, &t), EINVAL);

    crm_time_free(t);
    free_xml(xml);
}

static void
attr_missing(void **state)
{
    xmlNode *xml = pcmk__xml_parse(REFERENCE_XML);
    crm_time_t *t = NULL;

    assert_int_equal(pcmk__xe_get_datetime(xml, ATTR_MISSING, &t), pcmk_rc_ok);
    assert_null(t);

    free_xml(xml);
}

static void
attr_valid(void **state)
{
    xmlNode *xml = pcmk__xml_parse(REFERENCE_XML);
    crm_time_t *t = NULL;
    crm_time_t *reference = crm_time_new(REFERENCE_ISO8601);

    assert_int_equal(pcmk__xe_get_datetime(xml, ATTR_PRESENT, &t), pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
attr_invalid(void **state)
{
    xmlNode *xml = pcmk__xml_parse(BAD_XML);
    crm_time_t *t = NULL;

    assert_int_equal(pcmk__xe_get_datetime(xml, ATTR_PRESENT, &t),
                     pcmk_rc_unpack_error);
    assert_null(t);

    free_xml(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(nonnull_time_invalid),
                cmocka_unit_test(attr_missing),
                cmocka_unit_test(attr_valid),
                cmocka_unit_test(attr_invalid))
