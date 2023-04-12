/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/pengine/status.h>

#include "mock_private.h"

static void
check_defaults(void **state) {
    uint32_t flags;
    pe_working_set_t *data_set = calloc(1, sizeof(pe_working_set_t));

    set_working_set_defaults(data_set);

    flags = pe_flag_stop_rsc_orphans|pe_flag_symmetric_cluster|pe_flag_stop_action_orphans;

    if (!strcmp(PCMK__CONCURRENT_FENCING_DEFAULT, "true")) {
        flags |= pe_flag_concurrent_fencing;
    }


    assert_null(data_set->priv);
    assert_int_equal(data_set->order_id, 1);
    assert_int_equal(data_set->action_id, 1);
    assert_int_equal(data_set->no_quorum_policy, no_quorum_stop);
    assert_int_equal(data_set->flags, flags);

    /* Avoid calling pe_free_working_set here so we don't artificially
     * inflate the coverage numbers.
     */
    free(data_set);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(check_defaults))
