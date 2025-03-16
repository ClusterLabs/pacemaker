/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>                    // bool, false
#include <stdio.h>                      // NULL

#include <libxml/tree.h>                // xmlDoc, xmlNode, etc.
#include <libxml/xmlstring.h>           // xmlChar

#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Create a new XML comment belonging to a given document
 *
 * \param[in] doc      Document that new comment will belong to
 * \param[in] content  Comment content
 *
 * \return Newly created XML comment (guaranteed not to be \c NULL)
 */
xmlNode *
pcmk__xc_create(xmlDoc *doc, const char *content)
{
    xmlNode *node = NULL;

    // Pacemaker typically assumes every xmlNode has a doc
    pcmk__assert(doc != NULL);

    node = xmlNewDocComment(doc, (const xmlChar *) content);
    pcmk__mem_assert(node);
    pcmk__xml_new_private_data(node);
    return node;
}

/*!
 * \internal
 * \brief Find a comment with matching content among children of specified XML
 *
 * \param[in] parent  XML whose children to search
 * \param[in] search  Comment whose content should be searched for
 * \param[in] exact   If true, comment must also be at same position
 *
 * \return Matching comment, or \c NULL if no match is found
 */
xmlNode *
pcmk__xc_match_child(const xmlNode *parent, const xmlNode *search, bool exact)
{
    int search_pos = 0;

    pcmk__assert((search != NULL) && (search->type == XML_COMMENT_NODE));

    search_pos = pcmk__xml_position(search, pcmk__xf_skip);

    for (xmlNode *child = pcmk__xml_first_child(parent); child != NULL;
         child = pcmk__xml_next(child)) {

        if (child->type != XML_COMMENT_NODE) {
            continue;
        }

        if (exact) {
            int pos = 0;
            xml_node_private_t *nodepriv = child->_private;

            if (pcmk_is_set(nodepriv->flags, pcmk__xf_skip)) {
                continue;
            }

            pos = pcmk__xml_position(child, pcmk__xf_skip);
            if (pos < search_pos) {
                // We have not yet reached the matching position
                continue;
            }
            if (pos > search_pos) {
                // We have already passed the matching position
                return NULL;
            }
            // Position matches
        }

        if (pcmk__str_eq((const char *) child->content,
                         (const char *) search->content, pcmk__str_casei)) {
            return child;
        }

        if (exact) {
            // We won't find another comment at the same position
            return NULL;
        }
    }

    return NULL;
}

/*!
 * \internal
 * \brief Make one XML comment match another (in content)
 *
 * \param[in,out] parent   If \p target is NULL and this is not, add or update
 *                         comment child of this XML node that matches \p update
 * \param[in,out] target   If not NULL, update this XML comment node
 * \param[in]     update   Make comment content match this (must not be NULL)
 *
 * \note At least one of \parent and \target must be non-NULL
 */
void
pcmk__xc_update(xmlNode *parent, xmlNode *target, xmlNode *update)
{
    CRM_CHECK(update != NULL, return);
    CRM_CHECK(update->type == XML_COMMENT_NODE, return);

    if (target == NULL) {
        target = pcmk__xc_match_child(parent, update, false);
    }

    if (target == NULL) {
        pcmk__xml_copy(parent, update);

    } else if (!pcmk__str_eq((const char *)target->content, (const char *)update->content, pcmk__str_casei)) {
        xmlFree(target->content);
        target->content = xmlStrdup(update->content);
    }
}
