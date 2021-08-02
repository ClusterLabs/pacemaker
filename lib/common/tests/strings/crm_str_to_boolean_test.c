/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

static void
bad_input(void) {
    g_assert_cmpint(crm_str_to_boolean(NULL, NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("blahblah", NULL), ==, -1);
}

static void
is_true(void) {
    int ret;

    g_assert_cmpint(crm_str_to_boolean("true", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("TrUe", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("on", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("ON", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("yes", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("yES", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("y", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("Y", &ret), ==, 1);
    g_assert_true(ret);
    g_assert_cmpint(crm_str_to_boolean("1", &ret), ==, 1);
    g_assert_true(ret);
}

static void
is_not_true(void) {
    g_assert_cmpint(crm_str_to_boolean("truedat", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("onnn", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("yep", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("Y!", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("100", NULL), ==, -1);
}

static void
is_false(void) {
    int ret;

    g_assert_cmpint(crm_str_to_boolean("false", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("fAlSe", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("off", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("OFF", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("no", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("No", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("n", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("N", &ret), ==, 1);
    g_assert_false(ret);
    g_assert_cmpint(crm_str_to_boolean("0", &ret), ==, 1);
    g_assert_false(ret);
}

static void
is_not_false(void) {
    g_assert_cmpint(crm_str_to_boolean("falseee", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("of", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("nope", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("N!", NULL), ==, -1);
    g_assert_cmpint(crm_str_to_boolean("000", NULL), ==, -1);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/crm_str_to_boolean/bad_input", bad_input);
    g_test_add_func("/common/strings/crm_str_to_boolean/is_true", is_true);
    g_test_add_func("/common/strings/crm_str_to_boolean/is_not_true", is_not_true);
    g_test_add_func("/common/strings/crm_str_to_boolean/is_false", is_false);
    g_test_add_func("/common/strings/crm_str_to_boolean/is_not_false", is_not_false);
    return g_test_run();
}
