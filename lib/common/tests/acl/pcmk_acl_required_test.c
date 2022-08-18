/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/acl.h>

static void
is_pcmk_acl_required(void **state)
{
    assert_false(pcmk_acl_required(NULL));
    assert_false(pcmk_acl_required(""));
    assert_true(pcmk_acl_required("123"));
    assert_false(pcmk_acl_required(CRM_DAEMON_USER));
    assert_false(pcmk_acl_required("root"));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(is_pcmk_acl_required))
