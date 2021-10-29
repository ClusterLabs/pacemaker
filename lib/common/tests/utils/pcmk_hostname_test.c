/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "mock_private.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include <sys/utsname.h>

int
__wrap_uname(struct utsname *buf)
{
    int retval = mock_type(int);

    if (retval == 0) {
        strcpy(buf->nodename, mock_ptr_type(char *));
    }

    return retval;
}

static void
uname_succeeded_test(void **state)
{
    char *retval;

    will_return(__wrap_uname, 0);                       // uname() return value
    will_return(__wrap_uname, "somename");              // uname() buf->nodename

    retval = pcmk_hostname();
    assert_non_null(retval);
    assert_string_equal("somename", retval);

    free(retval);
}

static void
uname_failed_test(void **state)
{
    char *retval;

    will_return(__wrap_uname, -1);                      // uname() return value

    retval = pcmk_hostname();
    assert_null(retval);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(uname_succeeded_test),
        cmocka_unit_test(uname_failed_test),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
