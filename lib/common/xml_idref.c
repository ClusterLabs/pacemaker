/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>              // NULL
#include <stdlib.h>             // free()
#include <glib.h>               // GList, GHashTable, etc.
#include <libxml/tree.h>        // xmlNode

#include <crm/crm.h>
#include <crm/common/xml.h>     // PCMK_XA_ID_REF

/*!
 * \internal
 * \brief Add an XML ID reference to a table
 *
 * \param[in,out] table      Table of ID references to add to
 * \param[in]     id         ID of primary element being referred to
 * \param[in]     referrer   ID of element referring to \p id
 *
 * \note This refers to an ID reference in general, not necessarily connected to
 *       an id-ref attribute.
 */
void
pcmk__add_idref(GHashTable *table, const char *id, const char *referrer)
{
    pcmk__idref_t *idref = NULL;

    pcmk__assert((table != NULL) && (id != NULL) && (referrer != NULL));

    idref = g_hash_table_lookup(table, id);
    if (idref == NULL) {
        idref = pcmk__assert_alloc(1, sizeof(pcmk__idref_t));
        idref->id = pcmk__str_copy(id);
        g_hash_table_insert(table, pcmk__str_copy(id), idref);
    }
    for (GList *iter = idref->refs; iter != NULL; iter = iter->next) {
        if (pcmk__str_eq(referrer, (const char *) iter->data,
                         pcmk__str_none)) {
            return; // Already present
        }
    }
    idref->refs = g_list_append(idref->refs, pcmk__str_copy(referrer));
    crm_trace("Added ID %s referrer %s", id, referrer);
}

/*!
 * \internal
 * \brief Free a pcmk__idref_t
 *
 * \param[in,out] data  pcmk__idref_t to free
 */
void
pcmk__free_idref(gpointer data)
{
    pcmk__idref_t *idref = data;

    if (idref != NULL) {
        free(idref->id);
        g_list_free_full(idref->refs, free);
        free(idref);
    }
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

    ref = pcmk__xe_get(xml, PCMK_XA_ID_REF);
    if (ref == NULL) {
        return xml;
    }

    if (search == NULL) {
        search = xml;
    }

    xpath = crm_strdup_printf("//%s[@" PCMK_XA_ID "='%s']", xml->name, ref);
    result = pcmk__xpath_find_one(search->doc, xpath, LOG_DEBUG);
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

/*!
 * \internal
 * \brief Get list of resolved ID references for child elements of given element
 *
 * \param[in] xml           XML element to get list for
 * \param[in] element_name  If not NULL, list only children of this element type
 *
 * \return Unordered list of XML elements corresponding to child elements of
 *         \p xml with any ID references resolved to the referenced elements
 */
GList *
pcmk__xe_dereference_children(const xmlNode *xml, const char *element_name)
{
    GList *result = NULL;

    if (xml == NULL) {
        return NULL;
    }
    for (xmlNode *child = pcmk__xe_first_child(xml, element_name, NULL, NULL);
         child != NULL; child = pcmk__xe_next(child, element_name)) {

        xmlNode *resolved = pcmk__xe_resolve_idref(child, NULL);

        if (resolved == NULL) {
            continue; // Not possible with schema validation enabled
        }
        result = g_list_prepend(result, resolved);
    }
    return result;
}
