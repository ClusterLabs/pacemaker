/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_XPATH_INTERNAL__H
#define PCMK__CRM_COMMON_XPATH_INTERNAL__H

#include <stdint.h>                     // uint8_t

#include <glib.h>                       // GString
#include <libxml/tree.h>                // xmlDoc, xmlNode
#include <libxml/xpath.h>               // xmlXPathObject, etc.
#include <qb/qbdefs.h>                      // QB_MAX()

#include <crm/common/options.h>             // PCMK_META_*, PCMK_VALUE_*
#include <crm/common/output_internal.h>     // pcmk__output_t
#include <crm/common/xml_names.h>           // PCMK_XE_*, PCMK_XA_*, etc.
#include <crm/common/xml_names_internal.h>  // PCMK__XE_*

/*
 * Internal-only wrappers for and extensions to libxml2 XPath utilities
 */

//! XPath expression matching CIB node elements for cluster nodes
#define PCMK__XP_MEMBER_NODE_CONFIG                                 \
    "//" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION "/" PCMK_XE_NODES    \
    "/" PCMK_XE_NODE                                                \
    "[not(@" PCMK_XA_TYPE ") or @" PCMK_XA_TYPE "='" PCMK_VALUE_MEMBER "']"

//! XPath expression matching CIB primitive meta-attribute defining a guest node
#define PCMK__XP_GUEST_NODE_CONFIG \
    "//" PCMK_XE_CIB "//" PCMK_XE_CONFIGURATION "//" PCMK_XE_PRIMITIVE  \
    "//" PCMK_XE_META_ATTRIBUTES "//" PCMK_XE_NVPAIR                    \
    "[@" PCMK_XA_NAME "='" PCMK_META_REMOTE_NODE "']"

//! XPath expression matching CIB Pacemaker Remote connection resource
#define PCMK__XP_REMOTE_NODE_CONFIG                                     \
    "//" PCMK_XE_CIB "//" PCMK_XE_CONFIGURATION "//" PCMK_XE_PRIMITIVE  \
    "[@" PCMK_XA_TYPE "='" PCMK_VALUE_REMOTE "']"                       \
    "[@" PCMK_XA_PROVIDER "='pacemaker']"

//! XPath expression matching CIB node state elements for Pacemaker Remote nodes
#define PCMK__XP_REMOTE_NODE_STATUS                                 \
    "//" PCMK_XE_CIB "//" PCMK_XE_STATUS "//" PCMK__XE_NODE_STATE   \
    "[@" PCMK_XA_REMOTE_NODE "='" PCMK_VALUE_TRUE "']"

/*!
 * \internal
 * \brief Get the number of nodes in an XPath object's node set
 *
 * In other words, this is the number of results from evaluating an XPath
 * expression.
 *
 * \param[in] xpath_obj  XPath object
 *
 * \return Number of nodes in <tt>xpath_obj->nodesetval</tt> (guaranteed
 *         nonnegative)
 */
static inline int
pcmk__xpath_num_results(const xmlXPathObject *xpath_obj)
{
    int num_results = 0;

    if (xpath_obj != NULL) {
        num_results = xmlXPathNodeSetGetLength(xpath_obj->nodesetval);
    }

    // Negative num_results doesn't make sense
    return QB_MAX(num_results, 0);
}

GString *pcmk__element_xpath(const xmlNode *xml);
char *pcmk__xpath_node_id(const char *xpath, const char *node);

xmlXPathObject *pcmk__xpath_search(xmlDoc *doc, const char *path);
xmlNode *pcmk__xpath_result(xmlXPathObject *xpath_obj, int index);
xmlNode *pcmk__xpath_match_element(xmlNode *match);
void pcmk__xpath_foreach_result(xmlDoc *doc, const char *path,
                                void (*fn)(xmlNode *, void *), void *user_data);
xmlNode *pcmk__xpath_find_one(xmlDoc *doc, const char *path, uint8_t level);

void pcmk__warn_multiple_name_matches(pcmk__output_t *out, xmlNode *search,
                                      const char *name);

#endif  // PCMK__CRM_COMMON_XPATH_INTERNAL__H
