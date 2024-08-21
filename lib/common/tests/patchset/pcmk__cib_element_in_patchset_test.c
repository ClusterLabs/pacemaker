/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

static void
empty_arguments(void **state) {
    xmlNode *missing = NULL;

    pcmk__assert_asserts(pcmk__cib_element_in_patchset(NULL, PCMK_XE_NODES));

    missing = pcmk__xml_parse("<diff format=\"2\"/>");
    assert_false(pcmk__cib_element_in_patchset(missing, NULL));
    pcmk__xml_free(missing);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(empty_arguments))
