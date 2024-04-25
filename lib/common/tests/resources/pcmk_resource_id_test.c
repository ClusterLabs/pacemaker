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
    assert_null(pcmk_resource_id(NULL));
}

static void
resource_with_id(void **state)
{
    char rsc1_id[] = "rsc1";
    pcmk_resource_t rsc1 = {
        .id = rsc1_id,
    };

    assert_string_equal(pcmk_resource_id(&rsc1), "rsc1");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_resource),
                cmocka_unit_test(resource_with_id))
