/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/acl.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

static void
is_pcmk_acl_required(void **state)
{
    assert_false(pcmk_acl_required(NULL));
    assert_false(pcmk_acl_required(""));
    assert_true(pcmk_acl_required("123"));
    assert_false(pcmk_acl_required(CRM_DAEMON_USER));
    assert_false(pcmk_acl_required("root"));
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(is_pcmk_acl_required),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
