/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>                         // uint32_t

#include <crm/common/internal.h>
#include <crm/common/unittest_internal.h>

#include "mock_private.h"

static int
teardown(void **state)
{
    pcmk__mock_add_mainloop_ipc_server = false;
    return 0;
}

static void
executor_requires_locked_mappings(void **state)
{
    struct qb_ipcs_service_handlers callbacks = { 0, };
    qb_ipcs_service_t *expected = (qb_ipcs_service_t *) &callbacks;
    qb_ipcs_service_t *server = NULL;
    uint32_t expected_flags = 0U;

#ifdef HAVE_QB_IPCS_CREATE_2
    expected_flags = QB_IPCS_REQUIRE_LOCKED_MAPPINGS;
#endif

    pcmk__mock_add_mainloop_ipc_server = true;
    expect_string(__wrap_pcmk__add_mainloop_ipc_server, name,
                  PCMK__VALUE_LRMD);
    expect_value(__wrap_pcmk__add_mainloop_ipc_server, callbacks, &callbacks);
    expect_value(__wrap_pcmk__add_mainloop_ipc_server, flags, expected_flags);
    will_return(__wrap_pcmk__add_mainloop_ipc_server, expected);

    pcmk__serve_execd_ipc(&server, &callbacks);

    assert_ptr_equal(server, expected);
}

PCMK__UNIT_TEST(NULL, teardown,
                cmocka_unit_test(executor_requires_locked_mappings))
