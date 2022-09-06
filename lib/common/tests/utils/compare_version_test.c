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

static void
empty_params(void **state)
{
    assert_int_equal(compare_version(NULL, NULL), 0);
    assert_int_equal(compare_version(NULL, "abc"), -1);
    assert_int_equal(compare_version(NULL, "1.0.1"), -1);
    assert_int_equal(compare_version("abc", NULL), 1);
    assert_int_equal(compare_version("1.0.1", NULL), 1);
}

static void
equal_versions(void **state)
{
    assert_int_equal(compare_version("0.4.7", "0.4.7"), 0);
    assert_int_equal(compare_version("1.0", "1.0"), 0);
}

static void
unequal_versions(void **state)
{
    assert_int_equal(compare_version("0.4.7", "0.4.8"), -1);
    assert_int_equal(compare_version("0.4.8", "0.4.7"), 1);

    assert_int_equal(compare_version("0.2.3", "0.3"), -1);
    assert_int_equal(compare_version("0.3", "0.2.3"), 1);

    assert_int_equal(compare_version("0.99", "1.0"), -1);
    assert_int_equal(compare_version("1.0", "0.99"), 1);
}

static void
shorter_versions(void **state)
{
    assert_int_equal(compare_version("1.0", "1.0.1"), -1);
    assert_int_equal(compare_version("1.0.1", "1.0"), 1);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_params),
                cmocka_unit_test(equal_versions),
                cmocka_unit_test(unequal_versions),
                cmocka_unit_test(shorter_versions))
