/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>  // NULL

#include <crm/common/resources.h>
#include <crm/common/unittest_internal.h>

static void
null_resource(void **state)
{
    assert_false(pcmk_resource_is_managed(NULL));
}

static void
resource_is_managed(void **state)
{
    pcmk_resource_t rsc1 = {
        .flags = pcmk_rsc_managed,
    };

    assert_true(pcmk_resource_is_managed(&rsc1));
}

static void
resource_is_not_managed(void **state)
{
    pcmk_resource_t rsc1 = {
        .flags = 0,
    };

    assert_false(pcmk_resource_is_managed(&rsc1));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_resource),
                cmocka_unit_test(resource_is_managed),
                cmocka_unit_test(resource_is_not_managed))
