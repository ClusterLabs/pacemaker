/*
 * Copyright 2004-2024 the Pacemaker project contributors
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

#include <crm/common/xml.h>

#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Free an XPath object
 *
 * All elements returned by an XPath query are pointers to elements from the
 * tree, except namespace nodes (which are allocated separately for the XPath
 * object's node set). Accordingly, only namespace nodes and the node set itself
 * are freed when libxml2 frees a node set.
 *
 * This logic requires checking the type of every node in the node set. However,
 * a node may have been freed already (for example, by \c xmlNodeSetContent()),
 * so this check may constitute a use-after-free error.
 *
 * To avoid this, we remove references from the node set by setting them to
 * \c NULL when we access them.
 *
 * This approach is adapted from \c xpath2.c in libxml2's examples. That file
 * also describes a way to reproduce the use-after-free error.
 *
 * \param[in,out] xpath_obj  XPath object to free
 */
void
pcmk__xpath_free_object(xmlXPathObject *xpath_obj)
{
    /* @TODO The "set node set members to NULL" logic here and in
     * pcmk__xpath_result_element() helps, but there are still edge cases.
     *
     * For example, suppose our XPath expression matches both a parent node and
     * a child node. Index 0 of the node set is a pointer to the parent, and
     * index 1 is a pointer to the child.
     *
     * Suppose that while processing the parent, we free the child. In general,
     * we can't know while processing the parent that we should set the child's
     * reference to NULL. So when we later reach the child in the node set, it's
     * a use-after-free error.
     *
     * It may be better to document limitations and use caution when processing
     * XPath matches, rather than relying on a false sense of security.
     */
    int num_nodes = pcmk__xpath_num_nodes(xpath_obj);

    for (int i = 0; i < num_nodes; i++) {
        xmlNode **node_tab = xpath_obj->nodesetval->nodeTab;

        if ((node_tab[i] != NULL)
            && (node_tab[i]->type != XML_NAMESPACE_DECL)) {

            node_tab[i] = NULL;
        }
    }

    xmlXPathFreeObject(xpath_obj);
}

/*!
 * \internal
 * \brief Get an element node from the result of evaluating an XPath expression
 *
 * Evaluating an XPath expression stores the list of matching nodes in an
 * \c xmlXPathObject. This function gets the node at a particular index within
 * that list.
 *
 * Each matching node may be of an arbitrary type. This function is guaranteed
 * to return an element node (or \c NULL).
 * * If a match is an element, return it.
 * * If a match is a document, return the document's root element.
 * * If the match has an element as its parent, return the match's parent.
 * * Otherwise, return \c NULL.
 *
 * \param[in,out] xpath_obj  XPath object containing result nodes
 * \param[in]     index      Index of result node to get
 *
 * \return Element node based on result node at the given index if possible, or
 *         \c NULL otherwise
 *
 * \note This has a side effect: it sets the result node at \p index to NULL
 *       within \p xpath_obj, so the result at a given index can be retrieved
 *       only once. This is a workaround to prevent a use-after-free error. See
 *       \c pcmk__xpath_free_object() for details.
 */
xmlNode *
pcmk__xpath_result_element(xmlXPathObject *xpath_obj, int index)
{
    xmlNode *match = NULL;

    CRM_CHECK((xpath_obj != NULL) && (index >= 0), return NULL);

    match = xmlXPathNodeSetItem(xpath_obj->nodesetval, index);
    if (match == NULL) {
        // Previously requested or out of range
        return NULL;
    }

    if (match->type != XML_NAMESPACE_DECL) {
        // See the comment for pcmk__xpath_free_object()
        xpath_obj->nodesetval->nodeTab[index] = NULL;
    }

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
            crm_err("Cannot get element from XPath expression match of type %s",
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
    pcmkXmlStr xpath_expr = (pcmkXmlStr) path;
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
 * \param[in]     fn         Function to call for the XML node of each result
 * \param[in,out] user_data  Data to pass to \p fn
 *
 * \note Results for which an element node cannot be obtained are ignored. See
 *       \c pcmk__xpath_result_element() for details.
 */
void
pcmk__xpath_foreach_result(xmlDoc *doc, const char *path,
                           void (*fn)(xmlNode *, void *), void *user_data)
{
    xmlXPathObject *xpath_obj = pcmk__xpath_search(doc, path);
    int num_nodes = pcmk__xpath_num_nodes(xpath_obj);

    for (int i = 0; i < num_nodes; i++) {
        xmlNode *result = pcmk__xpath_result_element(xpath_obj, i);

        if (result != NULL) {
            (*fn)(result, user_data);
        }
    }
    pcmk__xpath_free_object(xpath_obj);
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
    int num_nodes = 0;
    xmlNode *result = NULL;
    xmlXPathObject *xpath_obj = NULL;

    CRM_CHECK((doc != NULL) && (path != NULL), return NULL);

    xpath_obj = pcmk__xpath_search(doc, path);
    num_nodes = pcmk__xpath_num_nodes(xpath_obj);

    if (num_nodes == 1) {
        result = pcmk__xpath_result_element(xpath_obj, 0);

    } else if (level < LOG_NEVER) {
        const xmlNode *root = xmlDocGetRootElement(doc);
        const char *root_name = NULL;

        if (root != NULL) {
            root_name = (const char *) root->name;
        }

        if (num_nodes > 1) {
            do_crm_log(level, "Multiple matches for %s in <%s>",
                       path, pcmk__s(root_name, "(unknown)"));

            for (int i = 0; i < num_nodes; i++) {
                xmlNode *match = pcmk__xpath_result_element(xpath_obj, i);

                if (match != NULL) {
                    xmlChar *match_path = xmlGetNodePath(match);

                    do_crm_log(level, "%s[%d] = %s",
                               path, i,
                               pcmk__s((const char *) match_path, "(unknown)"));
                    free(match_path);

                } else {
                    do_crm_log(level, "%s[%d] = %s",
                               path, i, "(non-element match)");
                }
            }

            if (root != NULL) {
                crm_log_xml_explicit(root, "multiple-matches");
            }

        } else {
            do_crm_log(level, "No match for %s in <%s>",
                       path, pcmk__s(root_name, "(unknown)"));

            if (root != NULL) {
                crm_log_xml_explicit(root, "no-match");
            }
        }
    }

    pcmk__xpath_free_object(xpath_obj);
    return result;
}

xmlNode *
get_xpath_object(const char *xpath, xmlNode * xml_obj, int error_level)
{
    int max;
    xmlNode *result = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    char *nodePath = NULL;
    char *matchNodePath = NULL;

    if (xpath == NULL) {
        return xml_obj;         /* or return NULL? */
    }

    CRM_CHECK(xml_obj != NULL, return NULL);

    xpathObj = pcmk__xpath_search(xml_obj->doc, xpath);
    nodePath = (char *)xmlGetNodePath(xml_obj);
    max = pcmk__xpath_num_nodes(xpathObj);

    if (max < 1) {
        if (error_level < LOG_NEVER) {
            do_crm_log(error_level, "No match for %s in %s",
                       xpath, pcmk__s(nodePath, "unknown path"));
            crm_log_xml_explicit(xml_obj, "Unexpected Input");
        }

    } else if (max > 1) {
        if (error_level < LOG_NEVER) {
            int lpc = 0;

            do_crm_log(error_level, "Too many matches for %s in %s",
                       xpath, pcmk__s(nodePath, "unknown path"));

            for (lpc = 0; lpc < max; lpc++) {
                xmlNode *match = pcmk__xpath_result_element(xpathObj, lpc);

                CRM_LOG_ASSERT(match != NULL);
                if (match != NULL) {
                    matchNodePath = (char *) xmlGetNodePath(match);
                    do_crm_log(error_level, "%s[%d] = %s",
                               xpath, lpc,
                               pcmk__s(matchNodePath, "unrecognizable match"));
                    free(matchNodePath);
                }
            }
            crm_log_xml_explicit(xml_obj, "Bad Input");
        }

    } else {
        result = pcmk__xpath_result_element(xpathObj, 0);
    }

    pcmk__xpath_free_object(xpathObj);
    free(nodePath);

    return result;
}

/*!
 * \internal
 * \brief Get an XPath string that matches an XML element as closely as possible
 *
 * \param[in] xml  The XML element for which to build an XPath string
 *
 * \return A \p GString that matches \p xml, or \p NULL if \p xml is \p NULL.
 *
 * \note The caller is responsible for freeing the string using
 *       \p g_string_free().
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
    char *start = NULL;
    char *end = NULL;

    if (node == NULL || xpath == NULL) {
        return retval;
    }

    patt = crm_strdup_printf("/%s[@" PCMK_XA_ID "=", node);
    start = strstr(xpath, patt);

    if (!start) {
        free(patt);
        return retval;
    }

    start += strlen(patt);
    start++;

    end = strstr(start, "\'");
    CRM_ASSERT(end);
    retval = strndup(start, end-start);

    free(patt);
    return retval;
}

static int
output_attr_child(xmlNode *child, void *userdata)
{
    pcmk__output_t *out = userdata;

    out->info(out, "  Value: %s \t(id=%s)",
              crm_element_value(child, PCMK_XA_VALUE),
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

/*!
 * \deprecated This function will be removed in a future release
 * \brief Get an XPath string that matches an XML element as closely as possible
 *
 * \param[in] xml  The XML element for which to build an XPath string
 *
 * \return A string that matches \p xml, or \p NULL if \p xml is \p NULL.
 *
 * \note The caller is responsible for freeing the string using free().
 */
char *
xml_get_path(const xmlNode *xml)
{
    char *path = NULL;
    GString *g_path = pcmk__element_xpath(xml);

    if (g_path == NULL) {
        return NULL;
    }
    path = pcmk__str_copy(g_path->str);
    g_string_free(g_path, TRUE);
    return path;
}

xmlNode *
get_xpath_object_relative(const char *xpath, xmlNode *xml_obj, int error_level)
{
    xmlNode *result = NULL;
    char *xpath_full = NULL;
    char *xpath_prefix = NULL;

    if (xml_obj == NULL || xpath == NULL) {
        return NULL;
    }

    xpath_prefix = (char *)xmlGetNodePath(xml_obj);

    xpath_full = crm_strdup_printf("%s%s", xpath_prefix, xpath);

    result = get_xpath_object(xpath_full, xml_obj, error_level);

    free(xpath_prefix);
    free(xpath_full);
    return result;
}

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
    int max = pcmk__xpath_num_nodes(xpathObj);

    CRM_CHECK(index >= 0, return NULL);
    CRM_CHECK(xpathObj != NULL, return NULL);

    if (index >= max) {
        crm_err("Requested index %d of only %d items", index, max);
        return NULL;

    } else if(xpathObj->nodesetval->nodeTab[index] == NULL) {
        /* Previously requested */
        return NULL;
    }

    match = xpathObj->nodesetval->nodeTab[index];
    CRM_CHECK(match != NULL, return NULL);

    if (xpathObj->nodesetval->nodeTab[index]->type != XML_NAMESPACE_DECL) {
        /* See the comment for pcmk__xpath_free_object() */
        xpathObj->nodesetval->nodeTab[index] = NULL;
    }

    if (match->type == XML_DOCUMENT_NODE) {
        /* Will happen if section = '/' */
        // Bug? match->children is not guaranteed to be an element node
        match = match->children;

    } else if (match->type != XML_ELEMENT_NODE
               && match->parent && match->parent->type == XML_ELEMENT_NODE) {
        /* Return the parent instead */
        match = match->parent;

    } else if (match->type != XML_ELEMENT_NODE) {
        /* We only support searching nodes */
        crm_err("We only support %d not %d", XML_ELEMENT_NODE, match->type);
        match = NULL;
    }
    return match;
}

void
freeXpathObject(xmlXPathObjectPtr xpathObj)
{
    int lpc, max = pcmk__xpath_num_nodes(xpathObj);

    if (xpathObj == NULL) {
        return;
    }

    for (lpc = 0; lpc < max; lpc++) {
        if (xpathObj->nodesetval->nodeTab[lpc] && xpathObj->nodesetval->nodeTab[lpc]->type != XML_NAMESPACE_DECL) {
            xpathObj->nodesetval->nodeTab[lpc] = NULL;
        }
    }

    xmlXPathFreeObject(xpathObj);
}

void
dedupXpathResults(xmlXPathObjectPtr xpathObj)
{
    int lpc, max = pcmk__xpath_num_nodes(xpathObj);

    if (xpathObj == NULL) {
        return;
    }

    for (lpc = 0; lpc < max; lpc++) {
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
    CRM_CHECK(xml != NULL, return);
    pcmk__xpath_foreach_result(xml->doc, xpath, helper, user_data);
}

// LCOV_EXCL_STOP
// End deprecated API
