/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <xml_comment_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_XML_COMMENT_INTERNAL__H
#define PCMK__CRM_COMMON_XML_COMMENT_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 XML comment functions
 */

#include <libxml/tree.h>    // xmlDoc, xmlNode

#ifdef __cplusplus
extern "C" {
#endif

xmlNode *pcmk__xc_create(xmlDoc *doc, const char *content);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__XML_COMMENT_INTERNAL__H
