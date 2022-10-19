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
#include <crm/common/agents.h>

static void
all_params_null(void **state) {
    assert_null(crm_generate_ra_key(NULL, NULL, NULL));
}

static void
some_params_null(void **state) {
    char *retval;

    assert_null(crm_generate_ra_key("std", "prov", NULL));

    retval = crm_generate_ra_key("std", NULL, "ty");
    assert_string_equal(retval, "std:ty");
    free(retval);

    assert_null(crm_generate_ra_key(NULL, "prov", "ty"));
    assert_null(crm_generate_ra_key("std", NULL, NULL));
    assert_null(crm_generate_ra_key(NULL, "prov", NULL));
    assert_null(crm_generate_ra_key(NULL, NULL, "ty"));
}

static void
no_params_null(void **state) {
    char *retval;

    retval = crm_generate_ra_key("std", "prov", "ty");
    assert_string_equal(retval, "std:prov:ty");
    free(retval);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(all_params_null),
                cmocka_unit_test(some_params_null),
                cmocka_unit_test(no_params_null))
