/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>           // pcmk__str_eq(), etc.

#include <stdio.h>                  // NULL
#include <stdbool.h>                // bool, true, false
#include <glib.h>                   // guint
#include <libxml/tree.h>            // xmlNode

#include <crm/common/options.h>     // PCMK_META_INTERVAL
#include <crm/msg_xml.h>            // PCMK_XA_OPERATION

bool
pcmk_is_probe(const char *task, guint interval)
{
    if (task == NULL) {
        return false;
    }

    return (interval == 0)
           && pcmk__str_eq(task, PCMK_ACTION_MONITOR, pcmk__str_none);
}

bool
pcmk_xe_is_probe(const xmlNode *xml_op)
{
    const char *task = crm_element_value(xml_op, PCMK_XA_OPERATION);
    const char *interval_ms_s = crm_element_value(xml_op, PCMK_META_INTERVAL);
    int interval_ms;

    pcmk__scan_min_int(interval_ms_s, &interval_ms, 0);
    return pcmk_is_probe(task, interval_ms);
}

bool
pcmk_xe_mask_probe_failure(const xmlNode *xml_op)
{
    int status = PCMK_EXEC_UNKNOWN;
    int rc = PCMK_OCF_OK;

    if (!pcmk_xe_is_probe(xml_op)) {
        return false;
    }

    crm_element_value_int(xml_op, PCMK__XA_OP_STATUS, &status);
    crm_element_value_int(xml_op, PCMK__XA_RC_CODE, &rc);

    return rc == PCMK_OCF_NOT_INSTALLED || rc == PCMK_OCF_INVALID_PARAM ||
           status == PCMK_EXEC_NOT_INSTALLED;
}
