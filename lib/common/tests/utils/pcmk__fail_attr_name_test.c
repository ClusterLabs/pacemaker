/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
null_arguments(void **state)
{
    assert_null(pcmk__fail_attr_name(NULL, NULL, NULL, 30000));
    assert_null(pcmk__fail_attr_name(NULL, "myrsc", "monitor", 30000));
    assert_null(pcmk__fail_attr_name("xyz", NULL, "monitor", 30000));
    assert_null(pcmk__fail_attr_name("xyz", "myrsc", NULL, 30000));
}

static void
standard_usage(void **state)
{
    char *s = NULL;

    assert_string_equal(pcmk__fail_attr_name("xyz", "myrsc", "monitor", 30000),
                        "xyz-myrsc#monitor_30000");

    free(s);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_arguments),
                cmocka_unit_test(standard_usage))
