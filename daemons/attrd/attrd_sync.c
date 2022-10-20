/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <crm/common/attrd_internal.h>

#include "pacemaker-attrd.h"

const char *
attrd_request_sync_point(xmlNode *xml)
{
    if (xml_has_children(xml)) {
        xmlNode *child = pcmk__xe_match(xml, XML_ATTR_OP, PCMK__XA_ATTR_SYNC_POINT, NULL);

        if (child) {
            return crm_element_value(child, PCMK__XA_ATTR_SYNC_POINT);
        } else {
            return NULL;
        }

    } else {
        return crm_element_value(xml, PCMK__XA_ATTR_SYNC_POINT);
    }
}

bool
attrd_request_has_sync_point(xmlNode *xml)
{
    return attrd_request_sync_point(xml) != NULL;
}
