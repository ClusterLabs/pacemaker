/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/pengine/internal.h>

#include "pe_status_private.h"

pe_resource_t rsc1;
pe_resource_t rsc2;

static void
rscs_equal(void **state)
{
    rsc1.priority = 0;
    rsc2.priority = 0;
    assert_int_equal(pe__cmp_rsc_priority(NULL, NULL), 0);
    assert_int_equal(pe__cmp_rsc_priority(&rsc1, &rsc2), 0);
}

static void
rsc1_first(void **state)
{
    rsc1.priority = 1;
    rsc2.priority = 0;
    assert_int_equal(pe__cmp_rsc_priority(&rsc1, NULL), -1);
    assert_int_equal(pe__cmp_rsc_priority(&rsc1, &rsc2), -1);
}

static void
rsc2_first(void **state)
{
    rsc1.priority = 0;
    rsc2.priority = 1;
    assert_int_equal(pe__cmp_rsc_priority(NULL, &rsc2), 1);
    assert_int_equal(pe__cmp_rsc_priority(&rsc1, &rsc2), 1);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(rscs_equal),
                cmocka_unit_test(rsc1_first),
                cmocka_unit_test(rsc2_first))
