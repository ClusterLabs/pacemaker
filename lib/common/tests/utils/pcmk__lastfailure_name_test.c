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
    assert_null(pcmk__lastfailure_name(NULL, NULL, 30000));
    assert_null(pcmk__lastfailure_name("myrsc", NULL, 30000));
    assert_null(pcmk__lastfailure_name(NULL, "monitor", 30000));
}

static void
standard_usage(void **state)
{
    char *s = NULL;

    assert_string_equal(pcmk__lastfailure_name("myrsc", "monitor", 30000),
                        "last-failure-myrsc#monitor_30000");

    free(s);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_arguments),
                cmocka_unit_test(standard_usage))
