/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
op_is_probe_test(void **state)
{
    xmlNode *node = NULL;

    assert_false(pcmk_xe_is_probe(NULL));

    node = string2xml("<lrm_rsc_op/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation_key=\"blah\" interval=\"30s\"/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"30s\"/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"start\" interval=\"0\"/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\"/>");
    assert_true(pcmk_xe_is_probe(node));
    free_xml(node);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(op_is_probe_test),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
