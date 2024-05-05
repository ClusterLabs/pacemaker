/*
 * Copyright 2022-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XPATH_INTERNAL__H
#define PCMK__CRM_COMMON_XPATH_INTERNAL__H

#include <glib.h>               // GString
#include <libxml/tree.h>        // xmlDoc, xmlNode
#include <libxml/xpath.h>       // xmlXPathObject

/*
 * Internal-only wrappers for and extensions to libxml2 XPath utilities
 */

/*!
 * \internal
 * \brief Get the number of nodes in an XPath object's node set
 *
 * In other words, this is the number of results from evaluating an XPath
 * expression.
 *
 * \param[in] xpath_obj  XPath object
 *
 * \return Number of nodes in <tt>xpath_obj->nodesetval</tt>
 */
static inline int
pcmk__xpath_num_nodes(const xmlXPathObject *xpath_obj)
{
    if (xpath_obj == NULL) {
        return 0;
    }
    return xmlXPathNodeSetGetLength(xpath_obj->nodesetval);
}

void pcmk__xpath_free_object(xmlXPathObject *xpath_obj);

GString *pcmk__element_xpath(const xmlNode *xml);
char *pcmk__xpath_node_id(const char *xpath, const char *node);

xmlXPathObject *pcmk__xpath_search(xmlDoc *doc, const char *path);
xmlNode *pcmk__xpath_result_element(xmlXPathObject *xpath_obj, int index);
void pcmk__xpath_foreach_result(xmlDoc *doc, const char *path,
                                void (*helper)(xmlNode *, void *),
                                void *user_data);

void pcmk__warn_multiple_name_matches(pcmk__output_t *out, xmlNode *search,
                                      const char *name);

#endif  // PCMK__CRM_COMMON_XPATH_INTERNAL__H
