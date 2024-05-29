/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scheduler.h>
#include <crm/common/unittest_internal.h>

static void
null_scheduler(void **state)
{
    xmlNode *cib = pcmk__xe_create(NULL, "test");

    assert_int_equal(pcmk_set_scheduler_cib(NULL, NULL), EINVAL);
    assert_int_equal(pcmk_set_scheduler_cib(NULL, cib), EINVAL);

    pcmk__xml_free(cib);
}

static void
null_cib(void **state)
{
    pcmk_scheduler_t scheduler = {
        .input = NULL,
    };

    assert_int_equal(pcmk_set_scheduler_cib(&scheduler, NULL), pcmk_rc_ok);
    assert_null(scheduler.input);
}

static void
previous_cib_null(void **state)
{
    pcmk_scheduler_t scheduler = {
        .input = NULL,
    };
    xmlNode *cib = pcmk__xe_create(NULL, "test");

    assert_int_equal(pcmk_set_scheduler_cib(&scheduler, cib), pcmk_rc_ok);
    assert_ptr_equal(scheduler.input, cib);

    pcmk__xml_free(cib);
}

static void
previous_cib_nonnull(void **state)
{
    xmlNode *old_cib = pcmk__xe_create(NULL, "old");
    xmlNode *new_cib = pcmk__xe_create(NULL, "new");
    pcmk_scheduler_t scheduler = {
        .input = old_cib,
    };

    assert_int_equal(pcmk_set_scheduler_cib(&scheduler, new_cib), pcmk_rc_ok);
    assert_ptr_equal(scheduler.input, new_cib);

    pcmk__xml_free(old_cib);
    pcmk__xml_free(new_cib);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_scheduler),
                cmocka_unit_test(null_cib),
                cmocka_unit_test(previous_cib_null),
                cmocka_unit_test(previous_cib_nonnull))
