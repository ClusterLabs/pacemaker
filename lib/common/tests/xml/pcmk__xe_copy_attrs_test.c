 /*
 * Copyright 2022-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

static void
null_args(void **state)
{
    // This test dumps core via CRM_CHECK()
    xmlNode *xml = pcmk__xe_create(NULL, "test");

    assert_int_equal(pcmk__xe_copy_attrs(NULL, NULL, pcmk__xaf_none), EINVAL);
    assert_int_equal(pcmk__xe_copy_attrs(NULL, xml, pcmk__xaf_none), EINVAL);
    assert_int_equal(pcmk__xe_copy_attrs(xml, NULL, pcmk__xaf_none), EINVAL);
    assert_ptr_equal(xml->properties, NULL);

    free_xml(xml);
}

static void
no_source_attrs(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    // Ensure copying from empty source doesn't create target properties
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_ptr_equal(target->properties, NULL);

    // Ensure copying from empty source doesn't delete target attributes
    crm_xml_add(target, "attr", "value");
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(target, "attr"), "value");

    free_xml(src);
    free_xml(target);
}

static void
copy_one(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    crm_xml_add(src, "attr", "value");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(src, "attr"),
                        crm_element_value(target, "attr"));

    free_xml(src);
    free_xml(target);
}

static void
copy_multiple(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set_props(src,
                       "attr1", "value1",
                       "attr2", "value2",
                       "attr3", "value3",
                       NULL);

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(src, "attr1"),
                        crm_element_value(target, "attr1"));
    assert_string_equal(crm_element_value(src, "attr2"),
                        crm_element_value(target, "attr2"));
    assert_string_equal(crm_element_value(src, "attr3"),
                        crm_element_value(target, "attr3"));

    free_xml(src);
    free_xml(target);
}

static void
overwrite(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    crm_xml_add(src, "attr", "src_value");
    crm_xml_add(target, "attr", "target_value");

    // Overwrite enabled by default
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(src, "attr"),
                        crm_element_value(target, "attr"));
    free_xml(src);
    free_xml(target);
}

static void
no_overwrite(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    crm_xml_add(src, "attr", "src_value");
    crm_xml_add(target, "attr", "target_value");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_no_overwrite),
                     pcmk_rc_ok);
    assert_string_not_equal(crm_element_value(src, "attr"),
                            crm_element_value(target, "attr"));

    // no_overwrite doesn't prevent copy if there's no conflict
    pcmk__xe_remove_attr(target, "attr");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_no_overwrite),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(src, "attr"),
                        crm_element_value(target, "attr"));

    free_xml(src);
    free_xml(target);
}

static void
score_update(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    crm_xml_add(src, "plus_plus_attr", "plus_plus_attr++");
    crm_xml_add(src, "plus_two_attr", "plus_two_attr+=2");
    crm_xml_add(target, "plus_plus_attr", "1");
    crm_xml_add(target, "plus_two_attr", "1");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_score_update),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(target, "plus_plus_attr"), "2");
    assert_string_equal(crm_element_value(target, "plus_two_attr"), "3");

    free_xml(src);
    free_xml(target);
}

static void
no_score_update(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    crm_xml_add(src, "plus_plus_attr", "plus_plus_attr++");
    crm_xml_add(src, "plus_two_attr", "plus_two_attr+=2");
    crm_xml_add(target, "plus_plus_attr", "1");
    crm_xml_add(target, "plus_two_attr", "1");

    // Score update disabled by default
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(crm_element_value(target, "plus_plus_attr"),
                        "plus_plus_attr++");
    assert_string_equal(crm_element_value(target, "plus_two_attr"),
                        "plus_two_attr+=2");

    free_xml(src);
    free_xml(target);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test(null_args),
                cmocka_unit_test(no_source_attrs),
                cmocka_unit_test(copy_one),
                cmocka_unit_test(copy_multiple),
                cmocka_unit_test(overwrite),
                cmocka_unit_test(no_overwrite),
                cmocka_unit_test(score_update),
                cmocka_unit_test(no_score_update));
