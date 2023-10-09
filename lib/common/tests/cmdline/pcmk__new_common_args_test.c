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
#include <crm/common/cmdline_internal.h>

#include "mock_private.h"

#include <glib.h>

static void
calloc_fails(void **state)
{
    pcmk__assert_exits(CRM_EX_OSERR,
        {
            pcmk__mock_calloc = true;   // calloc() will return NULL
            expect_value(__wrap_calloc, nmemb, 1);
            expect_value(__wrap_calloc, size, sizeof(pcmk__common_args_t));
            pcmk__new_common_args("boring summary");
            pcmk__mock_calloc = false;  // Use real calloc()
        }
    );
}

static void
strdup_fails(void **state)
{
    pcmk__assert_exits(CRM_EX_OSERR,
        {
            pcmk__mock_strdup = true;   // strdup() will return NULL
            expect_string(__wrap_strdup, s, "boring summary");
            pcmk__new_common_args("boring summary");
            pcmk__mock_strdup = false;  // Use the real strdup()
        }
    );
}

static void
success(void **state)
{
    pcmk__common_args_t *args = pcmk__new_common_args("boring summary");
    assert_string_equal(args->summary, "boring summary");
    assert_null(args->output_as_descr);
    assert_false(args->version);
    assert_false(args->quiet);
    assert_int_equal(args->verbosity, 0);
    assert_null(args->output_ty);
    assert_null(args->output_dest);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(calloc_fails),
                cmocka_unit_test(strdup_fails),
                cmocka_unit_test(success))
