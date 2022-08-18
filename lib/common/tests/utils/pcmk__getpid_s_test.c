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

#include "mock_private.h"

#include <sys/types.h>
#include <unistd.h>

static void
pcmk__getpid_s_test(void **state)
{
    char *retval;

    // Set getpid() return value
    pcmk__mock_getpid = true;
    will_return(__wrap_getpid, 1234);

    retval = pcmk__getpid_s();
    assert_non_null(retval);
    assert_string_equal("1234", retval);

    free(retval);

    pcmk__mock_getpid = false;
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(pcmk__getpid_s_test))
