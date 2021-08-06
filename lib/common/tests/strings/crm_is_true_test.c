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
    g_assert_false(crm_is_true(NULL));
}

static void
is_true(void) {
    g_assert_true(crm_is_true("true"));
    g_assert_true(crm_is_true("TrUe"));
    g_assert_true(crm_is_true("on"));
    g_assert_true(crm_is_true("ON"));
    g_assert_true(crm_is_true("yes"));
    g_assert_true(crm_is_true("yES"));
    g_assert_true(crm_is_true("y"));
    g_assert_true(crm_is_true("Y"));
    g_assert_true(crm_is_true("1"));
}

static void
is_false(void) {
    g_assert_false(crm_is_true("false"));
    g_assert_false(crm_is_true("fAlSe"));
    g_assert_false(crm_is_true("off"));
    g_assert_false(crm_is_true("OFF"));
    g_assert_false(crm_is_true("no"));
    g_assert_false(crm_is_true("No"));
    g_assert_false(crm_is_true("n"));
    g_assert_false(crm_is_true("N"));
    g_assert_false(crm_is_true("0"));

    g_assert_false(crm_is_true(""));
    g_assert_false(crm_is_true("blahblah"));

    g_assert_false(crm_is_true("truedat"));
    g_assert_false(crm_is_true("onnn"));
    g_assert_false(crm_is_true("yep"));
    g_assert_false(crm_is_true("Y!"));
    g_assert_false(crm_is_true("100"));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/crm_is_true/bad_input", bad_input);
    g_test_add_func("/common/strings/crm_is_true/is_true", is_true);
    g_test_add_func("/common/strings/crm_is_true/is_false", is_false);
    return g_test_run();
}
