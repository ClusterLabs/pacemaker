/*
 * Copyright 2017-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_TRACKING_INTERNAL__H
#define PCMK__CRM_COMMON_XML_TRACKING_INTERNAL__H

/*
 * Internal-only functions for tracking, calculating, and committing XML changes
 */

#include <libxml/tree.h>    // xmlDoc, xmlNode

#ifdef __cplusplus
extern "C" {
#endif

void pcmk__xml_mark_changes(xmlNode *old_xml, xmlNode *new_xml);
void pcmk__xml_commit_changes(xmlDoc *doc);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_XML_TRACKING_INTERNAL__H
