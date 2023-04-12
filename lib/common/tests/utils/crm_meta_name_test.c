/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/msg_xml.h>

static void
empty_params(void **state)
{
    assert_null(crm_meta_name(NULL));
}

static void
standard_usage(void **state)
{
    char *s = NULL;

    s = crm_meta_name(XML_RSC_ATTR_NOTIFY);
    assert_string_equal(s, "CRM_meta_notify");
    free(s);

    s = crm_meta_name(XML_RSC_ATTR_STICKINESS);
    assert_string_equal(s, "CRM_meta_resource_stickiness");
    free(s);

    s = crm_meta_name("blah");
    assert_string_equal(s, "CRM_meta_blah");
    free(s);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_params),
                cmocka_unit_test(standard_usage))
