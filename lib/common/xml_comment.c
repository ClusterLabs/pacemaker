/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>                      // NULL

#include <libxml/tree.h>                // xmlDoc, xmlNode, etc.

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
    /* @TODO Allocate comment private data here when we drop
     * new_private_data()/free_private_data()
     */
    xmlNode *node = NULL;

    // Pacemaker typically assumes every xmlNode has a doc
    CRM_ASSERT(doc != NULL);

    node = xmlNewDocComment(doc, (pcmkXmlStr) content);
    pcmk__mem_assert(node);
    pcmk__xml_mark_created(node);
    return node;
}
