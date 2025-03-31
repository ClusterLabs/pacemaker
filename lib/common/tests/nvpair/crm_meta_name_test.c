/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/nvpair.h>              // crm_meta_value()
#include <crm/common/unittest_internal.h>
#include <crm/common/xml.h>

static void
empty_params(void **state)
{
    pcmk__assert_asserts(crm_meta_name(NULL));
}

static void
standard_usage(void **state)
{
    char *s = NULL;

    s = crm_meta_name(PCMK_META_NOTIFY);
    assert_string_equal(s, "CRM_meta_notify");
    free(s);

    s = crm_meta_name(PCMK_META_RESOURCE_STICKINESS);
    assert_string_equal(s, "CRM_meta_resource_stickiness");
    free(s);

    s = crm_meta_name("blah");
    assert_string_equal(s, "CRM_meta_blah");
    free(s);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_params),
                cmocka_unit_test(standard_usage))
