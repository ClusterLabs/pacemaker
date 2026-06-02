 /*
 * Copyright 2022-2025 the Pacemaker project contributors
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

    pcmk__xml_free(xml);
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
    pcmk__xe_set(target, "attr", "value");
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(target, "attr"), "value");

    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

static void
copy_one(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set(src, "attr", "value");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(src, "attr"),
                        pcmk__xe_get(target, "attr"));

    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

static void
copy_multiple(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set(src, "attr1", "value1");
    pcmk__xe_set(src, "attr2", "value2");
    pcmk__xe_set(src, "attr3", "value3");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(src, "attr1"),
                        pcmk__xe_get(target, "attr1"));
    assert_string_equal(pcmk__xe_get(src, "attr2"),
                        pcmk__xe_get(target, "attr2"));
    assert_string_equal(pcmk__xe_get(src, "attr3"),
                        pcmk__xe_get(target, "attr3"));

    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

static void
overwrite(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set(src, "attr", "src_value");
    pcmk__xe_set(target, "attr", "target_value");

    // Overwrite enabled by default
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(src, "attr"),
                        pcmk__xe_get(target, "attr"));
    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

static void
no_overwrite(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set(src, "attr", "src_value");
    pcmk__xe_set(target, "attr", "target_value");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_no_overwrite),
                     pcmk_rc_ok);
    assert_string_not_equal(pcmk__xe_get(src, "attr"),
                            pcmk__xe_get(target, "attr"));

    // no_overwrite doesn't prevent copy if there's no conflict
    pcmk__xe_remove_attr(target, "attr");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_no_overwrite),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(src, "attr"),
                        pcmk__xe_get(target, "attr"));

    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

static void
score_update(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set(src, "plus_plus_attr", "plus_plus_attr++");
    pcmk__xe_set(src, "plus_two_attr", "plus_two_attr+=2");
    pcmk__xe_set(target, "plus_plus_attr", "1");
    pcmk__xe_set(target, "plus_two_attr", "1");

    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_score_update),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(target, "plus_plus_attr"), "2");
    assert_string_equal(pcmk__xe_get(target, "plus_two_attr"), "3");

    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

static void
no_score_update(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_set(src, "plus_plus_attr", "plus_plus_attr++");
    pcmk__xe_set(src, "plus_two_attr", "plus_two_attr+=2");
    pcmk__xe_set(target, "plus_plus_attr", "1");
    pcmk__xe_set(target, "plus_two_attr", "1");

    // Score update disabled by default
    assert_int_equal(pcmk__xe_copy_attrs(target, src, pcmk__xaf_none),
                     pcmk_rc_ok);
    assert_string_equal(pcmk__xe_get(target, "plus_plus_attr"),
                        "plus_plus_attr++");
    assert_string_equal(pcmk__xe_get(target, "plus_two_attr"),
                        "plus_two_attr+=2");

    pcmk__xml_free(src);
    pcmk__xml_free(target);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_args),
                cmocka_unit_test(no_source_attrs),
                cmocka_unit_test(copy_one),
                cmocka_unit_test(copy_multiple),
                cmocka_unit_test(overwrite),
                cmocka_unit_test(no_overwrite),
                cmocka_unit_test(score_update),
                cmocka_unit_test(no_score_update));
