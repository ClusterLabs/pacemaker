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
null_target(void **state)
{
    // This test dumps core via CRM_CHECK()
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = NULL;

    crm_xml_add(src, "attr", "value");
    pcmk__xe_copy_attrs(target, src, pcmk__xaf_none);

    assert_ptr_equal(target, NULL);

    free_xml(src);
}

static void
null_source(void **state)
{
    // This test dumps core via CRM_CHECK()
    xmlNode *src = NULL;
    xmlNode *target = pcmk__xe_create(NULL, "test");

    pcmk__xe_copy_attrs(target, src, pcmk__xaf_none);

    assert_ptr_equal(target->properties, NULL);

    free_xml(target);
}

static void
copy_one(void **state)
{
    xmlNode *src = pcmk__xe_create(NULL, "test");
    xmlNode *target = pcmk__xe_create(NULL, "test");

    crm_xml_add(src, "attr", "value");
    pcmk__xe_copy_attrs(target, src, pcmk__xaf_none);

    assert_string_equal(crm_element_value(src, "attr"),
                        crm_element_value(target, "attr"));

    free_xml(src);
    free_xml(target);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_target),
                cmocka_unit_test(null_source),
                cmocka_unit_test(copy_one))
