/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdint.h>                     // uint8_t
#include <stdio.h>
#include <string.h>

#include <libxml/tree.h>                // xmlNode
#include <libxml/xmlstring.h>           // xmlChar
#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <crm/common/xml.h>
#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Get a node from the result set of evaluating an XPath expression
 *
 * Evaluating an XPath expression stores the list of matching nodes in an
 * \c xmlXPathObject. This function gets the node at a particular index within
 * that list.
 *
 * \param[in,out] xpath_obj  XPath object containing result nodes
 * \param[in]     index      Index of result node to get
 *
 * \return Result node at the given index if possible, or \c NULL otherwise
 *
 * \note This has a side effect: it sets the result node at \p index to NULL
 *       within \p xpath_obj, so the result at a given index can be retrieved
 *       only once. This is a workaround to prevent a use-after-free error.
 *
 *       All elements returned by an XPath query are pointers to elements from
 *       the tree, except namespace nodes (which are allocated separately for
 *       the XPath object's node set). Accordingly, only namespace nodes and the
 *       node set itself are freed when libxml2 frees a node set.
 *
 *       This logic requires checking the type of every node in the node set.
 *       However, a node may have been freed already while processing an XPath
 *       object -- either directly (for example, with \c xmlFreeNode()) or
 *       indirectly (for example, with \c xmlNodeSetContent()). In that case,
 *       checking the freed node's type while freeing the XPath object is a
 *       use-after-free error.
 *
 *       To reduce the likelihood of this, when we access a node in the XPath
 *       object, we remove it from the XPath object's node set by setting it to
 *       \c NULL. This approach is adapted from \c xpath2.c in libxml2's
 *       examples. That file also describes a way to reproduce the
 *       use-after-free error.
 *
 *       However, there are still ways that a use-after-free can occur. For
 *       example, freeing the entire XML tree before freeing an XPath object
 *       that contains pointers to it would be an error. It's dangerous to mix
 *       processing XPath search results with modifications to a tree, and it
 *       must be done with care.
 */
xmlNode *
pcmk__xpath_result(xmlXPathObject *xpath_obj, int index)
{
    xmlNode *match = NULL;

    CRM_CHECK((xpath_obj != NULL) && (index >= 0), return NULL);

    match = xmlXPathNodeSetItem(xpath_obj->nodesetval, index);
    if (match == NULL) {
        // Previously requested or out of range
        return NULL;
    }

    if (match->type != XML_NAMESPACE_DECL) {
        xpath_obj->nodesetval->nodeTab[index] = NULL;
    }

    return match;
}

/*!
 * \internal
 * \brief Get an element node corresponding to an XPath match node
 *
 * Each node in an XPath object's result node set may be of an arbitrary type.
 * This function is guaranteed to return an element node (or \c NULL).
 *
 * \param[in] match  XML node that matched some XPath expression
 *
 * \retval \p match if \p match is an element
 * \retval Root element of \p match if \p match is a document
 * \retval <tt>match->parent</tt> if \p match is not an element but its parent
 *         is an element
 * \retval \c NULL otherwise
 *
 * \todo Phase this out. Code that relies on this behavior is likely buggy.
 */
xmlNode *
pcmk__xpath_match_element(xmlNode *match)
{
    pcmk__assert(match != NULL);

    switch (match->type) {
        case XML_ELEMENT_NODE:
            return match;

        case XML_DOCUMENT_NODE:
            // Happens if XPath expression is "/"; return root element instead
            return xmlDocGetRootElement((xmlDoc *) match);

        default:
            if ((match->parent != NULL)
                && (match->parent->type == XML_ELEMENT_NODE)) {

                // Probably an attribute; return parent element instead
                return match->parent;
            }
            pcmk__err("Cannot get element from XPath expression match of type "
                      "%s",
                      pcmk__xml_element_type_text(match->type));
            return NULL;
    }
}

/*!
 * \internal
 * \brief Search an XML document using an XPath expression
 *
 * \param[in] doc   XML document to search
 * \param[in] path  XPath expression to evaluate in the context of \p doc
 *
 * \return XPath object containing result of evaluating \p path against \p doc
 */
xmlXPathObject *
pcmk__xpath_search(xmlDoc *doc, const char *path)
{
    const xmlChar *xpath_expr = (const xmlChar *) path;
    xmlXPathContext *xpath_context = NULL;
    xmlXPathObject *xpath_obj = NULL;

    CRM_CHECK((doc != NULL) && !pcmk__str_empty(path), return NULL);

    xpath_context = xmlXPathNewContext(doc);
    pcmk__mem_assert(xpath_context);

    xpath_obj = xmlXPathEval(xpath_expr, xpath_context);

    xmlXPathFreeContext(xpath_context);
    return xpath_obj;
}

/*!
 * \internal
 * \brief Run a supplied function for each result of an XPath search
 *
 * \param[in,out] doc        XML document to search
 * \param[in]     path       XPath expression to evaluate in the context of
 *                           \p doc
 * \param[in]     fn         Function to call for each result XML element
 * \param[in,out] user_data  Data to pass to \p fn
 *
 * \note This function processes the result node set in forward order. If \p fn
 *       may free any part of any result node, then it is safer to process the
 *       result node set in reverse order. (The node set is in document order.)
 *       See comments in libxml's <tt>examples/xpath2.c</tt> file.
 */
void
pcmk__xpath_foreach_result(xmlDoc *doc, const char *path,
                           void (*fn)(xmlNode *, void *), void *user_data)
{
    xmlXPathObject *xpath_obj = NULL;
    int num_results = 0;

    CRM_CHECK((doc != NULL) && !pcmk__str_empty(path) && (fn != NULL), return);

    xpath_obj = pcmk__xpath_search(doc, path);
    num_results = pcmk__xpath_num_results(xpath_obj);

    for (int i = 0; i < num_results; i++) {
        xmlNode *result = pcmk__xpath_result(xpath_obj, i);

        if (result != NULL) {
            fn(result, user_data);
        }
    }
    xmlXPathFreeObject(xpath_obj);
}

/*!
 * \internal
 * \brief Search an XML document using an XPath expression and get result node
 *
 * This function requires a unique result node from evaluating the XPath
 * expression. If there are multiple result nodes or no result nodes, it returns
 * \c NULL.
 *
 * \param[in] doc    XML document to search
 * \param[in] path   XPath expression to evaluate in the context of \p doc
 * \param[in] level  Log level for errors
 *
 * \return Result node from evaluating \p path if unique, or \c NULL otherwise
 */
xmlNode *
pcmk__xpath_find_one(xmlDoc *doc, const char *path, uint8_t level)
{
    int num_results = 0;
    xmlNode *result = NULL;
    xmlXPathObject *xpath_obj = NULL;
    const xmlNode *root = NULL;
    const char *root_name = "(unknown)";

    CRM_CHECK((doc != NULL) && (path != NULL), goto done);

    xpath_obj = pcmk__xpath_search(doc, path);
    num_results = pcmk__xpath_num_results(xpath_obj);

    if (num_results == 1) {
        result = pcmk__xpath_result(xpath_obj, 0);
        goto done;
    }

    if (level >= PCMK__LOG_NEVER) {
        // For no matches or multiple matches, the rest is just logging
        goto done;
    }

    root = xmlDocGetRootElement(doc);
    if (root != NULL) {
        root_name = (const char *) root->name;
    }

    if (num_results < 1) {
        do_crm_log(level, "No match for %s in <%s>", path, root_name);

        if (root != NULL) {
            crm_log_xml_explicit(root, "no-match");
        }
        goto done;
    }

    do_crm_log(level, "Multiple matches for %s in <%s>", path, root_name);

    for (int i = 0; i < num_results; i++) {
        xmlNode *match = pcmk__xpath_result(xpath_obj, i);
        xmlChar *match_path = NULL;

        if (match == NULL) {
            CRM_LOG_ASSERT(match != NULL);
            continue;
        }

        match_path = xmlGetNodePath(match);
        do_crm_log(level, "%s[%d] = %s",
                   path, i, pcmk__s((const char *) match_path, "(unknown)"));
        free(match_path);
    }

    if (root != NULL) {
        crm_log_xml_explicit(root, "multiple-matches");
    }

done:
    xmlXPathFreeObject(xpath_obj);
    return result;
}

/*!
 * \internal
 * \brief Get an XPath string that matches an XML element as closely as possible
 *
 * \param[in] xml  The XML element for which to build an XPath string
 *
 * \return \c GString that matches \p xml, or \c NULL if \p xml is \c NULL
 *         (guaranteed not to be \c NULL if \p xml is not \c NULL)
 *
 * \note The caller is responsible for freeing the string using
 *       \c g_string_free().
 */
GString *
pcmk__element_xpath(const xmlNode *xml)
{
    const xmlNode *parent = NULL;
    GString *xpath = NULL;
    const char *id = NULL;

    if (xml == NULL) {
        return NULL;
    }

    parent = xml->parent;
    xpath = pcmk__element_xpath(parent);
    if (xpath == NULL) {
        xpath = g_string_sized_new(256);
    }

    // Build xpath like "/" -> "/cib" -> "/cib/configuration"
    if (parent == NULL) {
        g_string_append_c(xpath, '/');
    } else if (parent->parent == NULL) {
        g_string_append(xpath, (const gchar *) xml->name);
    } else {
        pcmk__g_strcat(xpath, "/", (const char *) xml->name, NULL);
    }

    id = pcmk__xe_id(xml);
    if (id != NULL) {
        pcmk__g_strcat(xpath, "[@" PCMK_XA_ID "='", id, "']", NULL);
    }

    return xpath;
}

/*!
 * \internal
 * \brief Extract the ID attribute from an XML element
 *
 * \param[in] xpath String to search
 * \param[in] node  Node to get the ID for
 *
 * \return ID attribute of \p node in xpath string \p xpath
 */
char *
pcmk__xpath_node_id(const char *xpath, const char *node)
{
    char *retval = NULL;
    char *patt = NULL;
    const char *start = NULL;
    const char *end = NULL;

    if (node == NULL || xpath == NULL) {
        return retval;
    }

    patt = pcmk__assert_asprintf("/%s[@" PCMK_XA_ID "=", node);

    start = strstr(xpath, patt);
    if (start == NULL) {
        goto done;
    }

    start += strlen(patt);
    start++;

    end = strchr(start, '\'');
    pcmk__assert(end != NULL);
    retval = strndup(start, end-start);

done:
    free(patt);
    return retval;
}

static int
output_attr_child(xmlNode *child, void *userdata)
{
    pcmk__output_t *out = userdata;

    out->info(out, "  Value: %s \t(id=%s)",
              pcmk__xe_get(child, PCMK_XA_VALUE),
              pcmk__s(pcmk__xe_id(child), "<none>"));
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Warn if an XPath query returned multiple nodes with the same ID
 *
 * \param[in,out] out     Output object
 * \param[in]     search  XPath search result, most typically the result of
 *                        calling <tt>cib->cmds->query()</tt>.
 * \param[in]     name    Name searched for
 */
void
pcmk__warn_multiple_name_matches(pcmk__output_t *out, xmlNode *search,
                                 const char *name)
{
    if (out == NULL || name == NULL || search == NULL ||
        search->children == NULL) {
        return;
    }

    out->info(out, "Multiple attributes match " PCMK_XA_NAME "=%s", name);
    pcmk__xe_foreach_child(search, NULL, output_attr_child, out);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

xmlXPathObjectPtr
xpath_search(const xmlNode *xml_top, const char *path)
{
    CRM_CHECK(xml_top != NULL, return NULL);

    return pcmk__xpath_search(xml_top->doc, path);
}

xmlNode *
getXpathResult(xmlXPathObjectPtr xpathObj, int index)
{
    xmlNode *match = NULL;
    int max = pcmk__xpath_num_results(xpathObj);

    CRM_CHECK(index >= 0, return NULL);
    CRM_CHECK(xpathObj != NULL, return NULL);

    if (index >= max) {
        pcmk__err("Requested index %d of only %d items", index, max);
        return NULL;

    } else if(xpathObj->nodesetval->nodeTab[index] == NULL) {
        /* Previously requested */
        return NULL;
    }

    match = xpathObj->nodesetval->nodeTab[index];
    CRM_CHECK(match != NULL, return NULL);

    if (xpathObj->nodesetval->nodeTab[index]->type != XML_NAMESPACE_DECL) {
        // See the comment for pcmk__xpath_result()
        xpathObj->nodesetval->nodeTab[index] = NULL;
    }

    switch (match->type) {
        case XML_ELEMENT_NODE:
            return match;

        case XML_DOCUMENT_NODE: // Searched for '/'
            return match->children;

        default:
           if ((match->parent != NULL)
               && (match->parent->type == XML_ELEMENT_NODE)) {
                return match->parent;
           }
           pcmk__warn("Unsupported XPath match type %d (bug?)", match->type);
           return NULL;
    }
}

void
freeXpathObject(xmlXPathObjectPtr xpathObj)
{
    int max = pcmk__xpath_num_results(xpathObj);

    if (xpathObj == NULL) {
        return;
    }

    for (int lpc = 0; lpc < max; lpc++) {
        if (xpathObj->nodesetval->nodeTab[lpc] && xpathObj->nodesetval->nodeTab[lpc]->type != XML_NAMESPACE_DECL) {
            xpathObj->nodesetval->nodeTab[lpc] = NULL;
        }
    }

    /* _Now_ it's safe to free it */
    xmlXPathFreeObject(xpathObj);
}

void
dedupXpathResults(xmlXPathObjectPtr xpathObj)
{
    int max = pcmk__xpath_num_results(xpathObj);

    if (xpathObj == NULL) {
        return;
    }

    for (int lpc = 0; lpc < max; lpc++) {
        xmlNode *xml = NULL;
        gboolean dedup = FALSE;

        if (xpathObj->nodesetval->nodeTab[lpc] == NULL) {
            continue;
        }

        xml = xpathObj->nodesetval->nodeTab[lpc]->parent;

        for (; xml; xml = xml->parent) {
            int lpc2 = 0;

            for (lpc2 = 0; lpc2 < max; lpc2++) {
                if (xpathObj->nodesetval->nodeTab[lpc2] == xml) {
                    xpathObj->nodesetval->nodeTab[lpc] = NULL;
                    dedup = TRUE;
                    break;
                }
            }

            if (dedup) {
                break;
            }
        }
    }
}

void
crm_foreach_xpath_result(xmlNode *xml, const char *xpath,
                         void (*helper)(xmlNode*, void*), void *user_data)
{
    xmlXPathObject *xpathObj = NULL;
    int nresults = 0;

    CRM_CHECK(xml != NULL, return);

    xpathObj = pcmk__xpath_search(xml->doc, xpath);
    nresults = pcmk__xpath_num_results(xpathObj);

    for (int i = 0; i < nresults; i++) {
        xmlNode *result = pcmk__xpath_result(xpathObj, i);

        CRM_LOG_ASSERT(result != NULL);

        if (result != NULL) {
            result = pcmk__xpath_match_element(result);

            CRM_LOG_ASSERT(result != NULL);

            if (result != NULL) {
                helper(result, user_data);
            }
        }
    }
    xmlXPathFreeObject(xpathObj);
}

xmlNode *
get_xpath_object(const char *xpath, xmlNode * xml_obj, int error_level)
{
    int max;
    xmlNode *result = NULL;
    xmlXPathObject *xpathObj = NULL;
    char *nodePath = NULL;
    char *matchNodePath = NULL;

    if (xpath == NULL) {
        return xml_obj;         /* or return NULL? */
    }

    xpathObj = pcmk__xpath_search(xml_obj->doc, xpath);
    nodePath = (char *)xmlGetNodePath(xml_obj);
    max = pcmk__xpath_num_results(xpathObj);

    if (max == 0) {
        if (error_level < PCMK__LOG_NEVER) {
            do_crm_log(error_level, "No match for %s in %s",
                       xpath, pcmk__s(nodePath, "unknown path"));
            crm_log_xml_explicit(xml_obj, "Unexpected Input");
        }

    } else if (max > 1) {
        if (error_level < PCMK__LOG_NEVER) {
            int lpc = 0;

            do_crm_log(error_level, "Too many matches for %s in %s",
                       xpath, pcmk__s(nodePath, "unknown path"));

            for (lpc = 0; lpc < max; lpc++) {
                xmlNode *match = pcmk__xpath_result(xpathObj, lpc);

                CRM_LOG_ASSERT(match != NULL);
                if (match != NULL) {
                    match = pcmk__xpath_match_element(match);

                    CRM_LOG_ASSERT(match != NULL);
                    if (match != NULL) {
                        matchNodePath = (char *) xmlGetNodePath(match);
                        do_crm_log(error_level, "%s[%d] = %s",
                                   xpath, lpc,
                                   pcmk__s(matchNodePath,
                                           "unrecognizable match"));
                        free(matchNodePath);
                    }
                }
            }
            crm_log_xml_explicit(xml_obj, "Bad Input");
        }

    } else {
        result = pcmk__xpath_result(xpathObj, 0);
        if (result != NULL) {
            result = pcmk__xpath_match_element(result);
        }
    }

    xmlXPathFreeObject(xpathObj);
    free(nodePath);

    return result;
}

// LCOV_EXCL_STOP
// End deprecated API
