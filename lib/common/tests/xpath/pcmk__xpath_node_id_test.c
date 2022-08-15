/*
 * Copyright 2021-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static void
empty_input(void **state) {
    assert_null(pcmk__xpath_node_id(NULL, "lrm"));
    assert_null(pcmk__xpath_node_id("", "lrm"));
    assert_null(pcmk__xpath_node_id("/blah/blah", NULL));
    assert_null(pcmk__xpath_node_id("/blah/blah", ""));
    assert_null(pcmk__xpath_node_id(NULL, NULL));
}

static void
no_quotes(void **state) {
    pcmk__assert_asserts(pcmk__xpath_node_id("/some/xpath/lrm[@id=xyz]", "lrm"));
}

static void
not_present(void **state) {
    assert_null(pcmk__xpath_node_id("/some/xpath/string[@id='xyz']", "lrm"));
    assert_null(pcmk__xpath_node_id("/some/xpath/containing[@id='lrm']", "lrm"));
}

static void
present(void **state) {
    char *s = NULL;

    s = pcmk__xpath_node_id("/some/xpath/containing/lrm[@id='xyz']", "lrm");
    assert_int_equal(strcmp(s, "xyz"), 0);
    free(s);

    s = pcmk__xpath_node_id("/some/other/lrm[@id='xyz']/xpath", "lrm");
    assert_int_equal(strcmp(s, "xyz"), 0);
    free(s);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input),
        cmocka_unit_test(no_quotes),
        cmocka_unit_test(not_present),
        cmocka_unit_test(present),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
