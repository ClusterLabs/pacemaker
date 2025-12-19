/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>          // NULL
#include <sys/types.h>      // time_t

#include <crm/common/scheduler.h>
#include <crm/common/unittest_internal.h>

#define assert_recheck(now_time, orig_time, update_time, expected_time, \
                       reason)                                          \
    do {                                                                \
        pcmk_scheduler_t *scheduler = pcmk_new_scheduler();             \
                                                                        \
        scheduler->priv->now = pcmk__copy_timet(now_time);              \
        scheduler->priv->recheck_by = orig_time;                        \
        pcmk__update_recheck_time(update_time, scheduler, reason);      \
        assert_int_equal(scheduler->priv->recheck_by, expected_time);   \
        pcmk_free_scheduler(scheduler);                                 \
    } while (0)

// A NULL scheduler argument is invalid and should assert
static void
null_scheduler(void **state)
{
    pcmk__assert_asserts(pcmk__update_recheck_time(0, NULL, "reasons"));
}

// Do not update recheck time if new value is before or equal to "now"
static void
too_early(void **state)
{
    // Recheck time is initially unset
    assert_recheck(1423548000, 0, 1423547900, 0, NULL);
    assert_recheck(1423548000, 0, 1423548000, 0, NULL);

    // Recheck time is initially set
    assert_recheck(1423548000, 1423548100, 1423547900, 1423548100, NULL);
    assert_recheck(1423548000, 1423548100, 1423548000, 1423548100, NULL);
}

// Update recheck time if the existing value is 0
static void
first_time(void **state)
{
    // This also tests that a NULL reason does not crash
    assert_recheck(1423548000, 0, 1423548100, 1423548100, NULL);
}

// Update recheck time if new value is earlier than the existing one
static void
earlier_time(void **state)
{
    assert_recheck(1423548000, 1423548500, 1423548200, 1423548200, "reasons");
}

// Do not update recheck time if new value is later than the existing one
static void
later_time(void **state)
{
    assert_recheck(1423548000, 1423548500, 1423548600, 1423548500, "reasons");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_scheduler),
                cmocka_unit_test(too_early),
                cmocka_unit_test(first_time),
                cmocka_unit_test(earlier_time),
                cmocka_unit_test(later_time))
