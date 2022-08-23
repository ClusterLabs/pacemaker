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
ocf_standard(void **state) {
    uint32_t expected = pcmk_ra_cap_provider | pcmk_ra_cap_params |
                        pcmk_ra_cap_unique | pcmk_ra_cap_promotable;

    assert_int_equal(pcmk_get_ra_caps("ocf"), expected);
    assert_int_equal(pcmk_get_ra_caps("OCF"), expected);
}

static void
stonith_standard(void **state) {
    uint32_t expected = pcmk_ra_cap_params | pcmk_ra_cap_unique |
                        pcmk_ra_cap_stdin | pcmk_ra_cap_fence_params;

    assert_int_equal(pcmk_get_ra_caps("stonith"), expected);
    assert_int_equal(pcmk_get_ra_caps("StOnItH"), expected);
}

static void
service_standard(void **state) {
    assert_int_equal(pcmk_get_ra_caps("systemd"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("SYSTEMD"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("service"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("SeRvIcE"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("lsb"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("LSB"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("upstart"), pcmk_ra_cap_status);
    assert_int_equal(pcmk_get_ra_caps("uPsTaRt"), pcmk_ra_cap_status);
}

static void
nagios_standard(void **state) {
    assert_int_equal(pcmk_get_ra_caps("nagios"), pcmk_ra_cap_params);
    assert_int_equal(pcmk_get_ra_caps("NAGios"), pcmk_ra_cap_params);
}

static void
unknown_standard(void **state) {
    assert_int_equal(pcmk_get_ra_caps("blahblah"), pcmk_ra_cap_none);
    assert_int_equal(pcmk_get_ra_caps(""), pcmk_ra_cap_none);
    assert_int_equal(pcmk_get_ra_caps(NULL), pcmk_ra_cap_none);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(ocf_standard),
                cmocka_unit_test(stonith_standard),
                cmocka_unit_test(service_standard),
                cmocka_unit_test(nagios_standard),
                cmocka_unit_test(unknown_standard))
