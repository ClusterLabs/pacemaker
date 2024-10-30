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

#include <glib.h>           // gboolean, gpointer, GList, GHashTable
#include <libxml/tree.h>    // xmlNode

// An XML ID and references to it (used for tags and templates)
typedef struct {
    char *id;       // XML ID of primary element
    GList *refs;    // XML IDs of elements that reference the primary element
} pcmk__idref_t;

void pcmk__add_idref(GHashTable *table, const char *id, const char *referrer);
void pcmk__free_idref(gpointer data);
xmlNode *pcmk__xe_resolve_idref(xmlNode *xml, xmlNode *search);
GList *pcmk__xe_dereference_children(const xmlNode *xml_obj,
                                     const char *set_name);

#endif // PCMK__CRM_COMMON_XML_IDREF_INTERNAL__H
