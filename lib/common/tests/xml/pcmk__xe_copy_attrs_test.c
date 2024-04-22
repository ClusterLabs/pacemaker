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

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_args),
                cmocka_unit_test(copy_one))
