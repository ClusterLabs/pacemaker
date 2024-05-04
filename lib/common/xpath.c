/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdio.h>
#include <string.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include "crmcommon_private.h"

/*
 * From xpath2.c
 *
 * All the elements returned by an XPath query are pointers to
 * elements from the tree *except* namespace nodes where the XPath
 * semantic is different from the implementation in libxml2 tree.
 * As a result when a returned node set is freed when
 * xmlXPathFreeObject() is called, that routine must check the
 * element type. But node from the returned set may have been removed
 * by xmlNodeSetContent() resulting in access to freed data.
 *
 * This can be exercised by running
 *       valgrind xpath2 test3.xml '//discarded' discarded
 *
 * There is 2 ways around it:
 *   - make a copy of the pointers to the nodes from the result set
 *     then call xmlXPathFreeObject() and then modify the nodes
 * or
 * - remove the references from the node set, if they are not
       namespace nodes, before calling xmlXPathFreeObject().
 */
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

    /* _Now_ it's safe to free it */
    xmlXPathFreeObject(xpathObj);
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
        /* See the comment for freeXpathObject() */
        xpathObj->nodesetval->nodeTab[index] = NULL;
    }

    if (match->type == XML_DOCUMENT_NODE) {
        /* Will happen if section = '/' */
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
 * \brief Run a supplied function for each result of an xpath search
 *
 * \param[in,out] xml        XML to search
 * \param[in]     xpath      XPath search string
 * \param[in]     helper     Function to call for each result
 * \param[in,out] user_data  Data to pass to supplied function
 *
 * \note The helper function will be passed the XML node of the result,
 *       and the supplied user_data. This function does not otherwise
 *       use user_data.
 */
void
crm_foreach_xpath_result(xmlNode *xml, const char *xpath,
                         void (*helper)(xmlNode*, void*), void *user_data)
{
    xmlXPathObjectPtr xpathObj = NULL;
    int nresults = 0;

    CRM_CHECK(xml != NULL, return);

    xpathObj = pcmk__xpath_search(xml->doc, xpath);
    nresults = pcmk__xpath_num_nodes(xpathObj);

    for (int i = 0; i < nresults; i++) {
        xmlNode *result = getXpathResult(xpathObj, i);

        CRM_LOG_ASSERT(result != NULL);
        if (result) {
            (*helper)(result, user_data);
        }
    }
    freeXpathObject(xpathObj);
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
                xmlNode *match = getXpathResult(xpathObj, lpc);

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
        result = getXpathResult(xpathObj, 0);
    }

    freeXpathObject(xpathObj);
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

// LCOV_EXCL_STOP
// End deprecated API
