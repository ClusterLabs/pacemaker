/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/xml_internal.h>

static void
empty_input(void) {
    g_assert_null(pcmk__xpath_node_id(NULL, "lrm"));
    g_assert_null(pcmk__xpath_node_id("", "lrm"));
    g_assert_null(pcmk__xpath_node_id("/blah/blah", NULL));
    g_assert_null(pcmk__xpath_node_id("/blah/blah", ""));
    g_assert_null(pcmk__xpath_node_id(NULL, NULL));
}

static void
not_present(void) {
    g_assert_null(pcmk__xpath_node_id("/some/xpath/string[@id='xyz']", "lrm"));
    g_assert_null(pcmk__xpath_node_id("/some/xpath/containing[@id='lrm']", "lrm"));
}

static void
present(void) {
    char *s = NULL;

    s = pcmk__xpath_node_id("/some/xpath/containing/lrm[@id='xyz']", "lrm");
    g_assert_cmpint(strcmp(s, "xyz"), ==, 0);
    free(s);

    s = pcmk__xpath_node_id("/some/other/lrm[@id='xyz']/xpath", "lrm");
    g_assert_cmpint(strcmp(s, "xyz"), ==, 0);
    free(s);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/xpath/node_id/empty_input", empty_input);
    g_test_add_func("/common/xpath/node_id/not_present", not_present);
    g_test_add_func("/common/xpath/node_id/present", present);
    return g_test_run();
}
