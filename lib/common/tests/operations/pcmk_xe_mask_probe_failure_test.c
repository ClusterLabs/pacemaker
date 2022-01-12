/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

static void
op_is_not_probe_test(void **state) {
    xmlNode *node = NULL;

    /* Not worth testing this thoroughly since it's just a duplicate of whether
     * pcmk_op_is_probe works or not.
     */

    node = string2xml("<lrm_rsc_op operation=\"start\" interval=\"0\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);
}

static void
op_does_not_have_right_values_test(void **state) {
    xmlNode *node = NULL;

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);
}

static void
check_values_test(void **state) {
    xmlNode *node = NULL;

    /* PCMK_EXEC_NOT_SUPPORTED */
    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"3\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"5\" op-status=\"3\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    /* PCMK_EXEC_DONE */
    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"0\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"2\" op-status=\"0\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"5\" op-status=\"0\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"6\" op-status=\"0\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"7\" op-status=\"0\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    /* PCMK_EXEC_NOT_INSTALLED */
    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"7\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"5\" op-status=\"7\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    /* PCMK_EXEC_ERROR */
    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"4\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"2\" op-status=\"4\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"5\" op-status=\"4\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"6\" op-status=\"4\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"7\" op-status=\"4\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    /* PCMK_EXEC_ERROR_HARD */
    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"5\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"2\" op-status=\"5\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"5\" op-status=\"5\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"6\" op-status=\"5\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"7\" op-status=\"5\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    /* PCMK_EXEC_ERROR_FATAL */
    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"0\" op-status=\"6\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"2\" op-status=\"6\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"5\" op-status=\"6\"/>");
    assert_true(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"6\" op-status=\"6\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);

    node = string2xml("<lrm_rsc_op operation=\"monitor\" interval=\"0\" rc-code=\"7\" op-status=\"6\"/>");
    assert_false(pcmk_xe_mask_probe_failure(node));
    free_xml(node);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(op_is_not_probe_test),
        cmocka_unit_test(op_does_not_have_right_values_test),
        cmocka_unit_test(check_values_test),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
