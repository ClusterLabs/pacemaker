/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include "crmcommon_private.h"              // pcmk__md5sum()

static void
null_arg_test(void **state)
{
    assert_null(pcmk__md5sum(NULL));
}

static void
basic_usage_test(void **state)
{
    gchar *result = pcmk__md5sum("abcdefghijklmnopqrstuvwxyz");

    assert_string_equal(result, "c3fcd3d76192e4007dfb496cca67e13b");
    g_free(result);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_arg_test),
                cmocka_unit_test(basic_usage_test))
