/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <regex.h>  // regmatch_t

#include <crm/common/unittest_internal.h>

// An example matched string with submatches
static const char *match = "this is a string";
static const regmatch_t submatches[] = {
    { .rm_so = 0, .rm_eo = 16 },    // %0 = entire string
    { .rm_so = 5, .rm_eo = 7 },     // %1 = "is"
    { .rm_so = 9, .rm_eo = 9 },     // %2 = empty match
};
static const int nmatches = 3;

#define assert_submatch(string, expected)                                   \
    do {                                                                    \
        char *expanded = pcmk__replace_submatches(string, match,            \
                                                  submatches, nmatches);    \
                                                                            \
        assert_string_equal(expanded, expected);                            \
        free(expanded);                                                     \
    } while (0)

static void
no_source(void **state)
{
    assert_null(pcmk__replace_submatches(NULL, NULL, NULL, 0));
    assert_null(pcmk__replace_submatches(NULL, match, submatches, nmatches));
    assert_null(pcmk__replace_submatches("", match, submatches, nmatches));
}

static void
source_has_no_variables(void **state)
{
    assert_null(pcmk__replace_submatches("this has no submatch variables",
                                         match, submatches, nmatches));
    assert_null(pcmk__replace_submatches("this ends in a %",
                                         match, submatches, nmatches));
    assert_null(pcmk__replace_submatches("%this starts with one",
                                         match, submatches, nmatches));
}

static void
without_matches(void **state)
{
    assert_submatch("this has an empty submatch %2",
                    "this has an empty submatch ");
    assert_submatch("this has a nonexistent submatch %3",
                    "this has a nonexistent submatch ");
}

static void
with_matches(void **state)
{
    assert_submatch("%0", match); // %0 matches entire string
    assert_submatch("this %1", "this is");
    assert_submatch("%1 this %ok", "is this %ok");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(no_source),
                cmocka_unit_test(source_has_no_variables),
                cmocka_unit_test(without_matches),
                cmocka_unit_test(with_matches))
