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
 * \brief Check whether two comments have matching content (case-insensitive)
 *
 * \param[in] comment1  First comment node to compare
 * \param[in] comment2  Second comment node to compare
 *
 * \return \c true if \p comment1 and \p comment2 have matching content (by
 *         case-insensitive string comparison), or \c false otherwise
 */
bool
pcmk__xc_matches(const xmlNode *comment1, const xmlNode *comment2)
{
    pcmk__assert((comment1 != NULL) && (comment1->type == XML_COMMENT_NODE)
                 && (comment2 != NULL) && (comment2->type == XML_COMMENT_NODE));

    return pcmk__str_eq((const char *) comment1->content,
                        (const char *) comment2->content, pcmk__str_casei);
}

/*!
 * \internal
 * \brief Find a comment with matching content among children of specified XML
 *
 * \param[in] parent  XML whose children to search
 * \param[in] search  Comment whose content should be searched for
 *
 * \return Matching comment, or \c NULL if no match is found
 */
static xmlNode *
match_xc_child(const xmlNode *parent, const xmlNode *search)
{
    pcmk__assert((search != NULL) && (search->type == XML_COMMENT_NODE));

    for (xmlNode *child = pcmk__xml_first_child(parent); child != NULL;
         child = pcmk__xml_next(child)) {

        if (child->type != XML_COMMENT_NODE) {
            continue;
        }

        if (pcmk__xc_matches(child, search)) {
            return child;
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
        target = match_xc_child(parent, update);
    }

    if (target == NULL) {
        pcmk__xml_copy(parent, update);

    } else if (!pcmk__str_eq((const char *)target->content, (const char *)update->content, pcmk__str_casei)) {
        xmlFree(target->content);
        target->content = xmlStrdup(update->content);
    }
}
