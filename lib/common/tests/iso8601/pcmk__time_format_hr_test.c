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

#include <crm/common/iso8601_internal.h>
#include <crm/common/unittest_internal.h>

#define TEST_TIME pcmk__time_hr_new("2024-01-02 03:04:05 +00:00")

/*!
 * \internal
 * \brief Assert that pcmk__time_format_hr() produced expected result
 *
 * \param[in] format     Time format string
 * \param[in] expected   Assertion succeeds if result matches this
 * \param[in] alternate  If this is not NULL, assertion may also succeed if
 *                       result matches this
 *
 * \note This allows two possible results because different strftime()
 *       implementations handle certain format syntax differently.
 */
static void
assert_hr_format(const char *format, const char *expected,
                 const char *alternate)
{
    pcmk__time_hr_t *hr = TEST_TIME;
    char *result = pcmk__time_format_hr(format, hr);

    pcmk__time_hr_free(hr);

    if (expected == NULL) {
        assert_null(result);
        return;
    }

    assert_non_null(result);

    if (alternate == NULL) {
        assert_string_equal(result, expected);
    } else {
        assert_true((strcmp(result, expected) == 0)
                    || (strcmp(result, alternate) == 0));
    }

    free(result);
}

static void
null_format(void **state)
{
    assert_null(pcmk__time_format_hr(NULL, NULL));
    assert_hr_format(NULL, NULL, NULL); // for pcmk__time_format_hr(NULL, hr)
}

static void
no_specifiers(void **state)
{
    assert_hr_format("no specifiers", "no specifiers", NULL);
    assert_hr_format("this has a literal % in it",
                     "this has a literal % in it",
                     // *BSD strftime() strips single %
                     "this has a literal  in it");
    assert_hr_format("this has a literal %01 in it",
                     "this has a literal %01 in it",
                     // *BSD strftime() strips %0
                     "this has a literal 1 in it");
    assert_hr_format("%2 this starts and ends with %",
                     "%2 this starts and ends with %",
                     // *BSD strftime() strips % in front of nonzero number
                     "2 this starts and ends with %");

    /* strftime() treats % with a number (and no specifier) as a literal string
     * to be formatted with a field width (undocumented and probably a bug ...)
     */
    assert_hr_format("this ends with %10", "this ends with        %10",
                     // *BSD strftime() strips % in front of nonzero number
                     "this ends with 10");
}

static void
without_nano(void **state)
{
    assert_hr_format("%H:%M %a %b %d", "03:04 Tue Jan 02", NULL);
    assert_hr_format("%H:%M:%S", "03:04:05", NULL);
    assert_hr_format("The time is %H:%M right now",
                     "The time is 03:04 right now", NULL);
    assert_hr_format("%3S seconds", "005 seconds",
                     // *BSD strftime() doesn't support field widths
                     "3S seconds");

    // strftime() treats %% as a literal %
    assert_hr_format("%%H %%N", "%H %N", NULL);
}

static void
with_nano(void **state)
{
    assert_hr_format("%H:%M:%S.%06N", "03:04:05.000000", NULL);
    assert_hr_format("The time is %H:%M:%S.%06N right NOW",
                     "The time is 03:04:05.000000 right NOW", NULL);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_format),
                cmocka_unit_test(no_specifiers),
                cmocka_unit_test(without_nano),
                cmocka_unit_test(with_nano))
