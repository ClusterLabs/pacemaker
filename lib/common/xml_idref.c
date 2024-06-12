/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>              // NULL
#include <stdlib.h>             // calloc(), free()
#include <string.h>             // strdup()
#include <glib.h>               // gboolean, GList, GHashTable, etc.
#include <libxml/tree.h>        // xmlNode

#include <crm/crm.h>
#include <crm/common/xml.h>     // get_xpath_object(), PCMK_XA_ID_REF

gboolean
add_tag_ref(GHashTable * tags, const char * tag_name,  const char * obj_ref)
{
    pcmk__idref_t *tag = NULL;
    GList *gIter = NULL;
    gboolean is_existing = FALSE;

    CRM_CHECK(tags && tag_name && obj_ref, return FALSE);

    tag = g_hash_table_lookup(tags, tag_name);
    if (tag == NULL) {
        tag = calloc(1, sizeof(pcmk__idref_t));
        if (tag == NULL) {
            pcmk__sched_err("Could not allocate memory for tag %s", tag_name);
            return FALSE;
        }
        tag->id = strdup(tag_name);
        tag->refs = NULL;
        g_hash_table_insert(tags, strdup(tag_name), tag);
    }

    for (gIter = tag->refs; gIter != NULL; gIter = gIter->next) {
        const char *existing_ref = (const char *) gIter->data;

        if (pcmk__str_eq(existing_ref, obj_ref, pcmk__str_none)){
            is_existing = TRUE;
            break;
        }
    }

    if (is_existing == FALSE) {
        tag->refs = g_list_append(tag->refs, strdup(obj_ref));
        crm_trace("Added: tag=%s ref=%s", tag->id, obj_ref);
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Get the XML element whose \c PCMK_XA_ID matches an \c PCMK_XA_ID_REF
 *
 * \param[in] xml     Element whose \c PCMK_XA_ID_REF attribute to check
 * \param[in] search  Node whose document to search for node with matching
 *                    \c PCMK_XA_ID (\c NULL to use \p xml)
 *
 * \return If \p xml has a \c PCMK_XA_ID_REF attribute, node in
 *         <tt>search</tt>'s document whose \c PCMK_XA_ID attribute matches;
 *         otherwise, \p xml
 */
xmlNode *
pcmk__xe_resolve_idref(xmlNode *xml, xmlNode *search)
{
    char *xpath = NULL;
    const char *ref = NULL;
    xmlNode *result = NULL;

    if (xml == NULL) {
        return NULL;
    }

    ref = crm_element_value(xml, PCMK_XA_ID_REF);
    if (ref == NULL) {
        return xml;
    }

    if (search == NULL) {
        search = xml;
    }

    xpath = crm_strdup_printf("//%s[@" PCMK_XA_ID "='%s']", xml->name, ref);
    result = get_xpath_object(xpath, search, LOG_DEBUG);
    if (result == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring invalid %s configuration: "
                         PCMK_XA_ID_REF " '%s' does not reference "
                         "a valid object " QB_XS " xpath=%s",
                         xml->name, ref, xpath);
    }
    free(xpath);
    return result;
}
