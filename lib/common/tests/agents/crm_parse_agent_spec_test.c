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

/*!
 * \internal
 * \brief Perform one test of \c crm_parse_agent_spec()
 *
 * \param[in] spec           Agent specification to parse
 * \param[in] expected_std   Expected value of parsed agent standard
 * \param[in] expected_prov  Expected value of parsed agent provider
 * \param[in] expected_type  Expected value of parsed agent type
 * \param[in] expected_rc    Expected return value of \c crm_parse_agent_spec()
 *
 * \note This macro aborts if any value does not match its expected value.
 */
#define assert_parse_agent_spec(spec, expected_std, expected_prov,          \
                                expected_type, expected_rc)                 \
    do {                                                                    \
        char *std = NULL;                                                   \
        char *prov = NULL;                                                  \
        char *type = NULL;                                                  \
        int rc = crm_parse_agent_spec(spec, &std, &prov, &type);            \
                                                                            \
        assert_int_equal(rc, expected_rc);                                  \
                                                                            \
        if (expected_std == NULL) {                                         \
            assert_null(std);                                               \
        } else {                                                            \
            assert_string_equal(std, expected_std);                         \
        }                                                                   \
                                                                            \
        if (expected_prov == NULL) {                                        \
            assert_null(prov);                                              \
        } else {                                                            \
            assert_string_equal(prov, expected_prov);                       \
        }                                                                   \
                                                                            \
        if (expected_type == NULL) {                                        \
            assert_null(type);                                              \
        } else {                                                            \
            assert_string_equal(type, expected_type);                       \
        }                                                                   \
                                                                            \
        free(std);                                                          \
        free(prov);                                                         \
        free(type);                                                         \
    } while (0)

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
    assert_parse_agent_spec("ocf", NULL, NULL, NULL, -EINVAL);
    assert_parse_agent_spec("ocf:",  NULL, NULL, NULL, -EINVAL);
    assert_parse_agent_spec("ocf::", NULL, NULL, NULL, -EINVAL);
}

static void
no_type(void **state)
{
    /* @FIXME std and prov are freed on error, so set them to NULL or don't
     * check their values
     */
    assert_parse_agent_spec("ocf:pacemaker:", NULL, NULL, NULL, -EINVAL);
}

static void
get_std_and_ty(void **state)
{
    assert_parse_agent_spec("stonith:fence_xvm", "stonith", NULL, "fence_xvm",
                            pcmk_ok);
}

static void
get_all_values(void **state)
{
    assert_parse_agent_spec("ocf:pacemaker:ping", "ocf", "pacemaker", "ping",
                            pcmk_ok);
}

static void
get_systemd_values(void **state)
{
    assert_parse_agent_spec("systemd:UNIT@A:B", "systemd", NULL, "UNIT@A:B",
                            pcmk_ok);
}

static void
type_ends_with_colon(void **state)
{
    /* It's not clear that this would ever be allowed in practice. However, for
     * standards that don't support a provider, everything after the first colon
     * should be considered the type. This includes a trailing colon.
     */
    assert_parse_agent_spec("stonith:fence_xvm:", "stonith", NULL, "fence_xvm:",
                            pcmk_ok);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_params),
                cmocka_unit_test(no_prov_or_type),
                cmocka_unit_test(no_type),
                cmocka_unit_test(get_std_and_ty),
                cmocka_unit_test(get_all_values),
                cmocka_unit_test(get_systemd_values),
                cmocka_unit_test(type_ends_with_colon))
