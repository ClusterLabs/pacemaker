/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/agents.h>

static void
assert_parse_agent_spec_as(int line, const char *spec, const char *expected_std,
                           const char *expected_prov, const char *expected_type,
                           int expected_rc, bool check_spt)
{
    char *std = NULL;
    char *prov = NULL;
    char *type = NULL;
    int rc = crm_parse_agent_spec(spec, &std, &prov, &type);

    /* @TODO Define pcmk__assert_int_equal() or similar to do the casting, for
     * reuse in other unit tests. See T222. It would be nice to convert all of
     * these "assert_X()" functions in unit tests into macro wrappers for
     * "assert_X_as()".
     */
    _assert_int_equal(cast_to_largest_integral_type(rc),
                      cast_to_largest_integral_type(expected_rc),
                      __FILE__, line);

    /* @TODO Move this definition to a common file, for reuse in other unit
     * tests. See other TODO above.
     *
     * Note: Commit 09621179 adds an _assert_ptr_equal() function and changes
     * the assert_null() and assert_ptr_equal() definitions to use it. However,
     * this commit is not in any cmocka release at the time of writing.
     */
#define pcmk__assert_null(c)    \
    _assert_int_equal(cast_ptr_to_largest_integral_type(c), \
                      cast_ptr_to_largest_integral_type(NULL), \
                      __FILE__, (line))

    if (!check_spt) {
        /* This is a temporary hack to work around an issue that will be fixed
         * in an upcoming commit
         */
        return;
    }

    if (expected_std == NULL) {
        pcmk__assert_null(std);
    } else {
        _assert_string_equal(std, expected_std, __FILE__, line);
        free(std);
    }

    if (expected_prov == NULL) {
        pcmk__assert_null(prov);
    } else {
        _assert_string_equal(prov, expected_prov, __FILE__, line);
        free(prov);
    }

    if (expected_type == NULL) {
        pcmk__assert_null(type);
    } else {
        _assert_string_equal(type, expected_type, __FILE__, line);
        free(type);
    }
}

#define assert_parse_agent_spec(spec, expected_std, expected_prov,      \
                                expected_type, expected_rc, check_spt)  \
    assert_parse_agent_spec_as(__LINE__, (spec), (expected_std),        \
                               (expected_prov), (expected_type),        \
                               (expected_rc), (check_spt))

static void
null_params(void **state)
{
    char *std = NULL;
    char *prov = NULL;
    char *type = NULL;
    int rc = pcmk_ok;

    rc = crm_parse_agent_spec(NULL, NULL, NULL, NULL);
    assert_int_equal(rc, -EINVAL);

    rc = crm_parse_agent_spec("", NULL, NULL, NULL);
    assert_int_equal(rc, -EINVAL);

    rc = crm_parse_agent_spec(":", NULL, NULL, NULL);
    assert_int_equal(rc, -EINVAL);

    rc = crm_parse_agent_spec("::", NULL, NULL, NULL);
    assert_int_equal(rc, -EINVAL);

    // With valid spec (no provider)
    rc = crm_parse_agent_spec("stonith:fence_xvm", NULL, NULL, NULL);
    assert_int_equal(rc, -EINVAL);

    // With valid spec (has provider)
    rc = crm_parse_agent_spec("ocf:pacemaker:ping", NULL, NULL, NULL);
    assert_int_equal(rc, -EINVAL);

    // Test varying NULL params with valid spec

    rc = crm_parse_agent_spec("ocf:pacemaker:ping", NULL, NULL, &type);
    assert_int_equal(rc, -EINVAL);
    assert_null(type);

    rc = crm_parse_agent_spec("ocf:pacemaker:ping", NULL, &prov, NULL);
    assert_int_equal(rc, -EINVAL);
    assert_null(prov);

    rc = crm_parse_agent_spec("ocf:pacemaker:ping", NULL, &prov, &type);
    assert_int_equal(rc, -EINVAL);
    assert_null(prov);
    assert_null(type);

    rc = crm_parse_agent_spec("ocf:pacemaker:ping", &std, NULL, NULL);
    assert_int_equal(rc, -EINVAL);
    assert_null(std);

    rc = crm_parse_agent_spec("ocf:pacemaker:ping", &std, NULL, &type);
    assert_int_equal(rc, -EINVAL);
    assert_null(std);
    assert_null(type);

    rc = crm_parse_agent_spec("ocf:pacemaker:ping", &std, &prov, NULL);
    assert_int_equal(rc, -EINVAL);
    assert_null(std);
    assert_null(prov);
}

static void
no_prov_or_type(void **state)
{
    assert_parse_agent_spec("ocf", NULL, NULL, NULL, -EINVAL, true);

    // @FIXME std is freed on error, so set it to NULL or don't check its value
    assert_parse_agent_spec("ocf:",  NULL, NULL, NULL, -EINVAL, false);
    assert_parse_agent_spec("ocf::", NULL, NULL, NULL, -EINVAL, false);
}

static void
no_type(void **state)
{
    /* @FIXME std and prov are freed on error, so set them to NULL or don't
     * check their values
     */
    assert_parse_agent_spec("ocf:pacemaker:", NULL, NULL, NULL, -EINVAL, false);
}

static void
get_std_and_ty(void **state)
{
    assert_parse_agent_spec("stonith:fence_xvm", "stonith", NULL, "fence_xvm",
                            pcmk_ok, true);
}

static void
get_all_values(void **state)
{
    assert_parse_agent_spec("ocf:pacemaker:ping", "ocf", "pacemaker", "ping",
                            pcmk_ok, true);
}

static void
get_systemd_values(void **state)
{
    assert_parse_agent_spec("systemd:UNIT@A:B", "systemd", NULL, "UNIT@A:B",
                            pcmk_ok, true);
}

static void
type_ends_with_colon(void **state)
{
    /* It's not clear that this would ever be allowed in practice. However, for
     * standards that support a provider, everything after the first colon
     * should be considered the type. This includes a trailing colon.
     */
    assert_parse_agent_spec("stonith:fence_xvm:", "stonith", NULL, "fence_xvm:",
                            pcmk_ok, true);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_params),
                cmocka_unit_test(no_prov_or_type),
                cmocka_unit_test(no_type),
                cmocka_unit_test(get_std_and_ty),
                cmocka_unit_test(get_all_values),
                cmocka_unit_test(get_systemd_values),
                cmocka_unit_test(type_ends_with_colon))
