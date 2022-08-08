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
    assert_int_equal(crm_parse_agent_spec(NULL, NULL, NULL, NULL), -EINVAL);
    assert_int_equal(crm_parse_agent_spec("", NULL, NULL, NULL), -EINVAL);
    assert_int_equal(crm_parse_agent_spec(":", NULL, NULL, NULL), -EINVAL);
    assert_int_equal(crm_parse_agent_spec("::", NULL, NULL, NULL), -EINVAL);
}

static void
no_prov_or_type(void **state) {
    assert_int_equal(crm_parse_agent_spec("ocf", NULL, NULL, NULL), -EINVAL);
    assert_int_equal(crm_parse_agent_spec("ocf:", NULL, NULL, NULL), -EINVAL);
    assert_int_equal(crm_parse_agent_spec("ocf::", NULL, NULL, NULL), -EINVAL);
}

static void
no_type(void **state) {
    assert_int_equal(crm_parse_agent_spec("ocf:pacemaker:", NULL, NULL, NULL), -EINVAL);
}

static void
get_std_and_ty(void **state) {
    char *std = NULL;
    char *prov = NULL;
    char *ty = NULL;

    assert_int_equal(crm_parse_agent_spec("stonith:fence_xvm", &std, &prov, &ty), pcmk_ok);
    assert_string_equal(std, "stonith");
    assert_null(prov);
    assert_string_equal(ty, "fence_xvm");

    free(std);
    free(ty);
}

static void
get_all_values(void **state) {
    char *std = NULL;
    char *prov = NULL;
    char *ty = NULL;

    assert_int_equal(crm_parse_agent_spec("ocf:pacemaker:ping", &std, &prov, &ty), pcmk_ok);
    assert_string_equal(std, "ocf");
    assert_string_equal(prov, "pacemaker");
    assert_string_equal(ty, "ping");

    free(std);
    free(prov);
    free(ty);
}

static void
get_systemd_values(void **state) {
    char *std = NULL;
    char *prov = NULL;
    char *ty = NULL;

    assert_int_equal(crm_parse_agent_spec("systemd:UNIT@A:B", &std, &prov, &ty), pcmk_ok);
    assert_string_equal(std, "systemd");
    assert_null(prov);
    assert_string_equal(ty, "UNIT@A:B");

    free(std);
    free(ty);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(all_params_null),
        cmocka_unit_test(no_prov_or_type),
        cmocka_unit_test(no_type),
        cmocka_unit_test(get_std_and_ty),
        cmocka_unit_test(get_all_values),
        cmocka_unit_test(get_systemd_values),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
