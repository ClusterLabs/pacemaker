/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XML_IDREF_INTERNAL__H
#define PCMK__CRM_COMMON_XML_IDREF_INTERNAL__H

#include <glib.h>           // gboolean, GList, GHashTable
#include <libxml/tree.h>    // xmlNode

// An XML ID and references to it (used for tags and templates)
typedef struct {
    char *id;       // XML ID of primary element
    GList *refs;    // XML IDs of elements that reference the primary element
} pcmk__idref_t;

gboolean add_tag_ref(GHashTable * tags, const char * tag_name,  const char * obj_ref);

xmlNode *pcmk__xe_resolve_idref(xmlNode *xml, xmlNode *search);

#endif // PCMK__CRM_COMMON_XML_IDREF_INTERNAL__H
