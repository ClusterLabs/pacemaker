/*
 * Copyright 2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_ATTR_INTERNAL__H
#define PCMK__CRM_COMMON_XML_ATTR_INTERNAL__H

/*
 * Internal-only wrappers for and extensions to libxml2 for processing XML
 * attributes
 */

#include <stdbool.h>        // bool

#include <libxml/tree.h>    // xmlAttr

#ifdef __cplusplus
extern "C" {
#endif

bool pcmk__xa_insert_dup(const xmlAttr *attr, void *user_data);

#ifdef __cplusplus
}
#endif

#endif  // PCMK__XML_ATTR_INTERNAL__H
