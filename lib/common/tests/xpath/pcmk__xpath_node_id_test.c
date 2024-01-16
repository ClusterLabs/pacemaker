/*
 * Copyright 2021-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static void
empty_input(void **state) {
    assert_null(pcmk__xpath_node_id(NULL, PCMK__XE_LRM));
    assert_null(pcmk__xpath_node_id("", PCMK__XE_LRM));
    assert_null(pcmk__xpath_node_id("/blah/blah", NULL));
    assert_null(pcmk__xpath_node_id("/blah/blah", ""));
    assert_null(pcmk__xpath_node_id(NULL, NULL));
}

static void
no_quotes(void **state) {
    const char *xpath = "/some/xpath/" PCMK__XE_LRM "[@" PCMK_XA_ID "=xyz]";
    pcmk__assert_asserts(pcmk__xpath_node_id(xpath, PCMK__XE_LRM));
}

static void
not_present(void **state) {
    const char *xpath = "/some/xpath/string[@" PCMK_XA_ID "='xyz']";
    assert_null(pcmk__xpath_node_id(xpath, PCMK__XE_LRM));

    xpath = "/some/xpath/containing[@" PCMK_XA_ID "='" PCMK__XE_LRM "']";
    assert_null(pcmk__xpath_node_id(xpath, PCMK__XE_LRM));
}

static void
present(void **state) {
    char *s = NULL;
    const char *xpath = "/some/xpath/containing"
                        "/" PCMK__XE_LRM "[@" PCMK_XA_ID "='xyz']";

    s = pcmk__xpath_node_id(xpath, PCMK__XE_LRM);
    assert_int_equal(strcmp(s, "xyz"), 0);
    free(s);

    xpath = "/some/other/" PCMK__XE_LRM "[@" PCMK_XA_ID "='xyz']/xpath";
    s = pcmk__xpath_node_id(xpath, PCMK__XE_LRM);
    assert_int_equal(strcmp(s, "xyz"), 0);
    free(s);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input),
                cmocka_unit_test(no_quotes),
                cmocka_unit_test(not_present),
                cmocka_unit_test(present))
