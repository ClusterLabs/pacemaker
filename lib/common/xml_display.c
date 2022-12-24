/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  // PCMK__XML_LOG_BASE, etc.
#include "crmcommon_private.h"

static void log_xml_node(GString *buffer, int log_level, const char *prefix,
                         const xmlNode *data, int depth, int options);

// Log an XML library error
void
pcmk__log_xmllib_err(void *ctx, const char *fmt, ...)
{
    va_list ap;
    static struct qb_log_callsite *xml_error_cs = NULL;

    if (xml_error_cs == NULL) {
        xml_error_cs = qb_log_callsite_get(__func__, __FILE__,
                                           "xml library error", LOG_TRACE,
                                           __LINE__, crm_trace_nonlog);
    }

    va_start(ap, fmt);
    if ((xml_error_cs != NULL) && (xml_error_cs->targets != 0)) {
        PCMK__XML_LOG_BASE(LOG_ERR, TRUE,
                           crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__,
                                     "xml library error", TRUE, TRUE),
                           "XML Error: ", fmt, ap);
    } else {
        PCMK__XML_LOG_BASE(LOG_ERR, TRUE, 0, "XML Error: ", fmt, ap);
    }
    va_end(ap);
}

/*!
 * \internal
 * \brief Log an XML comment with depth-based indentation
 *
 * Depending on the value of \p log_level, the output may be written to
 * \p stdout or to a log file.
 *
 * \param[in]     log_level  Priority at which to log the message
 * \param[in]     data       XML node to log
 * \param[in]     depth      Current indentation level
 * \param[in]     options    Group of \p pcmk__xml_fmt_options flags
 */
static void
log_xml_comment(int log_level, const xmlNode *data, int depth, int options)
{
    if (pcmk_is_set(options, pcmk__xml_fmt_open)) {
        do_crm_log(log_level, "%*s<!--%s-->",
                   pcmk_is_set(options, pcmk__xml_fmt_pretty)? (2 * depth) : 0,
                   "", (const char *) data->content);
    }
}

/*!
 * \internal
 * \brief Log an XML element in a formatted way
 *
 * Depending on the value of \p log_level, the output may be written to
 * \p stdout or to a log file.
 *
 * \param[in,out] buffer     Where to build output strings
 * \param[in]     log_level  Priority at which to log the messages
 * \param[in]     prefix     String to prepend to every line of output
 * \param[in]     data       XML node to log
 * \param[in]     depth      Current indentation level
 * \param[in]     options    Group of \p pcmk__xml_fmt_options flags
 *
 * \note This is a recursive helper function for \p log_xml_node().
 * \note \p buffer may be overwritten many times. The caller is responsible for
 *       freeing it using \p g_string_free() but should not rely on its
 *       contents.
 */
static void
log_xml_element(GString *buffer, int log_level, const char *prefix,
                const xmlNode *data, int depth, int options)
{
    const char *name = crm_element_name(data);
    int spaces = pcmk_is_set(options, pcmk__xml_fmt_pretty)? (2 * depth) : 0;

    if (pcmk_is_set(options, pcmk__xml_fmt_open)) {
        const char *hidden = crm_element_value(data, "hidden");

        g_string_truncate(buffer, 0);

        for (int lpc = 0; lpc < spaces; lpc++) {
            g_string_append_c(buffer, ' ');
        }
        pcmk__g_strcat(buffer, "<", name, NULL);

        for (const xmlAttr *attr = pcmk__xe_first_attr(data); attr != NULL;
             attr = attr->next) {
            xml_node_private_t *nodepriv = attr->_private;
            const char *p_name = (const char *) attr->name;
            const char *p_value = pcmk__xml_attr_value(attr);
            char *p_copy = NULL;

            if (pcmk_is_set(nodepriv->flags, pcmk__xf_deleted)) {
                continue;
            }

            // @COMPAT Remove when v1 patchsets are removed
            if (pcmk_any_flags_set(options,
                                   pcmk__xml_fmt_diff_plus
                                   |pcmk__xml_fmt_diff_minus)
                && (strcmp(XML_DIFF_MARKER, p_name) == 0)) {
                continue;
            }

            if ((hidden != NULL) && (p_name[0] != '\0')
                && (strstr(hidden, p_name) != NULL)) {
                pcmk__str_update(&p_copy, "*****");

            } else {
                p_copy = crm_xml_escape(p_value);
            }

            pcmk__g_strcat(buffer, " ", p_name, "=\"",
                           pcmk__s(p_copy, "<null>"), "\"", NULL);
            free(p_copy);
        }

        if (xml_has_children(data)
            && pcmk_is_set(options, pcmk__xml_fmt_children)) {
            g_string_append_c(buffer, '>');

        } else {
            g_string_append(buffer, "/>");
        }

        do_crm_log(log_level, "%s%s%s",
                   pcmk__s(prefix, ""), pcmk__str_empty(prefix)? "" : " ",
                   buffer->str);
    }

    if (!xml_has_children(data)) {
        return;
    }

    if (pcmk_is_set(options, pcmk__xml_fmt_children)) {
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {

            log_xml_node(buffer, log_level, prefix, child, depth + 1,
                         options|pcmk__xml_fmt_open|pcmk__xml_fmt_close);
        }
    }

    if (pcmk_is_set(options, pcmk__xml_fmt_close)) {
        do_crm_log(log_level, "%s%s%*s</%s>",
                   pcmk__s(prefix, ""), pcmk__str_empty(prefix)? "" : " ",
                   spaces, "", name);
    }
}

/*!
 * \internal
 * \brief Log an XML element or comment in a formatted way
 *
 * Depending on the value of \p log_level, the output may be written to
 * \p stdout or to a log file.
 *
 * \param[in,out] buffer     Where to build output strings
 * \param[in]     log_level  Priority at which to log the messages
 * \param[in]     prefix     String to prepend to every line of output
 * \param[in]     data       XML node to log
 * \param[in]     depth      Current indentation level
 * \param[in]     options    Group of \p pcmk__xml_fmt_options flags
 *
 * \note This is a recursive helper function for \p pcmk__xml_log().
 * \note \p buffer may be overwritten many times. The caller is responsible for
 *       freeing it using \p g_string_free() but should not rely on its
 *       contents.
 */
static void
log_xml_node(GString *buffer, int log_level, const char *prefix,
             const xmlNode *data, int depth, int options)
{
    if ((data == NULL) || (log_level == LOG_NEVER)) {
        return;
    }

    switch (data->type) {
        case XML_COMMENT_NODE:
            log_xml_comment(log_level, data, depth, options);
            break;
        case XML_ELEMENT_NODE:
            log_xml_element(buffer, log_level, prefix, data, depth, options);
            break;
        default:
            break;
    }
}

/*!
 * \internal
 * \brief Log an XML element or comment in a formatted way
 *
 * Depending on the value of \p log_level, the output may be written to
 * \p stdout or to a log file.
 *
 * \param[in] log_level  Priority at which to log the messages
 * \param[in] prefix     String to prepend to every line of output
 * \param[in] data       XML node to log
 * \param[in] depth      Current indentation level
 * \param[in] options    Group of \p pcmk__xml_fmt_options flags
 */
void
pcmk__xml_log(int log_level, const char *prefix, const xmlNode *data, int depth,
              int options)
{
    /* Allocate a buffer once, for log_xml_node() to truncate and reuse in
     * recursive calls
     */
    GString *buffer = g_string_sized_new(1024);

    CRM_CHECK(depth >= 0, depth = 0);

    log_xml_node(buffer, log_level, prefix, data, depth, options);
    g_string_free(buffer, TRUE);
}

/*!
 * \internal
 * \brief Log XML portions that have been marked as changed
 *
 * \param[in] log_level  Priority at which to log the messages
 * \param[in] data       XML node to log
 * \param[in] depth      Current indentation level
 * \param[in] options    Group of \p pcmk__xml_fmt_options flags
 *
 * \note This is a recursive helper for \p pcmk__xml_log_changes(), logging
 *       changes to \p data and its children.
 */
static void
log_xml_changes_recursive(int log_level, const xmlNode *data, int depth,
                          int options)
{
    /* @COMPAT: When log_data_element() is removed, we can remove the options
     * argument here and instead hard-code pcmk__xml_log_pretty.
     */
    xml_node_private_t *nodepriv = NULL;

    if ((data == NULL) || (log_level == LOG_NEVER)) {
        return;
    }

    nodepriv = data->_private;

    if (pcmk_all_flags_set(nodepriv->flags, pcmk__xf_dirty|pcmk__xf_created)) {
        // Newly created
        pcmk__xml_log(log_level, PCMK__XML_PREFIX_CREATED, data, depth,
                      options
                      |pcmk__xml_fmt_open
                      |pcmk__xml_fmt_children
                      |pcmk__xml_fmt_close);
        return;
    }

    if (pcmk_is_set(nodepriv->flags, pcmk__xf_dirty)) {
        // Modified or moved
        bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
        int spaces = pretty? (2 * depth) : 0;
        const char *prefix = PCMK__XML_PREFIX_MODIFIED;

        if (pcmk_is_set(nodepriv->flags, pcmk__xf_moved)) {
            prefix = PCMK__XML_PREFIX_MOVED;
        }

        // Log opening tag
        pcmk__xml_log(log_level, prefix, data, depth,
                      options|pcmk__xml_fmt_open);

        // Log changes to attributes
        for (const xmlAttr *attr = pcmk__xe_first_attr(data); attr != NULL;
             attr = attr->next) {
            const char *name = (const char *) attr->name;

            nodepriv = attr->_private;

            if (pcmk_is_set(nodepriv->flags, pcmk__xf_deleted)) {
                const char *value = crm_element_value(data, name);

                do_crm_log(log_level, "%s %*s @%s=%s",
                           PCMK__XML_PREFIX_DELETED, spaces, "", name, value);

            } else if (pcmk_is_set(nodepriv->flags, pcmk__xf_dirty)) {
                const char *value = crm_element_value(data, name);

                if (pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {
                    prefix = PCMK__XML_PREFIX_CREATED;

                } else if (pcmk_is_set(nodepriv->flags, pcmk__xf_modified)) {
                    prefix = PCMK__XML_PREFIX_MODIFIED;

                } else if (pcmk_is_set(nodepriv->flags, pcmk__xf_moved)) {
                    prefix = PCMK__XML_PREFIX_MOVED;

                } else {
                    prefix = PCMK__XML_PREFIX_MODIFIED;
                }
                do_crm_log(log_level, "%s %*s @%s=%s",
                           prefix, spaces, "", name, value);
            }
        }

        // Log changes to children
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {
            log_xml_changes_recursive(log_level, child, depth + 1, options);
        }

        // Log closing tag
        pcmk__xml_log(log_level, PCMK__XML_PREFIX_MODIFIED, data, depth,
                      options|pcmk__xml_fmt_close);

    } else {
        // This node hasn't changed, but check its children
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {
            log_xml_changes_recursive(log_level, child, depth + 1, options);
        }
    }
}

/*!
 * \internal
 * \brief Log changes to an XML node and any children
 *
 * \param[in] log_level  Priority at which to log the message
 * \param[in] xml        XML node to log
 */
void
pcmk__xml_log_changes(uint8_t log_level, const xmlNode *xml)
{
    xml_doc_private_t *docpriv = NULL;

    if (log_level == LOG_NEVER) {
        return;
    }

    CRM_ASSERT(xml != NULL);
    CRM_ASSERT(xml->doc != NULL);

    docpriv = xml->doc->_private;
    if (!pcmk_is_set(docpriv->flags, pcmk__xf_dirty)) {
        return;
    }

    for (const GList *iter = docpriv->deleted_objs; iter != NULL;
         iter = iter->next) {
        const pcmk__deleted_xml_t *deleted_obj = iter->data;

        if (deleted_obj->position >= 0) {
            do_crm_log(log_level, PCMK__XML_PREFIX_DELETED " %s (%d)",
                       deleted_obj->path, deleted_obj->position);

        } else {
            do_crm_log(log_level, PCMK__XML_PREFIX_DELETED " %s",
                       deleted_obj->path);
        }
    }

    log_xml_changes_recursive(log_level, xml, 0, pcmk__xml_fmt_pretty);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/logging_compat.h>
#include <crm/common/xml_compat.h>

void
log_data_element(int log_level, const char *file, const char *function,
                 int line, const char *prefix, const xmlNode *data, int depth,
                 int legacy_options)
{
    int options = 0;

    if (log_level == LOG_NEVER) {
        return;
    }

    if (data == NULL) {
        do_crm_log(log_level, "%s%sNo data to dump as XML",
                   pcmk__s(prefix, ""), pcmk__str_empty(prefix)? "" : " ");
        return;
    }

    /* Map xml_log_options to pcmk__xml_fmt_options so that we can go ahead and
     * start using the pcmk__xml_fmt_options in all the internal functions.
     *
     * xml_log_option_dirty_add and xml_log_option_diff_all are ignored by
     * internal code and only used here, so they don't need to be addressed.
     */
    if (pcmk_is_set(legacy_options, xml_log_option_filtered)) {
        options |= pcmk__xml_fmt_filtered;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_formatted)) {
        options |= pcmk__xml_fmt_pretty;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_full_fledged)) {
        options |= pcmk__xml_fmt_full;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_open)) {
        options |= pcmk__xml_fmt_open;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_children)) {
        options |= pcmk__xml_fmt_children;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_close)) {
        options |= pcmk__xml_fmt_close;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_text)) {
        options |= pcmk__xml_fmt_text;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_diff_plus)) {
        options |= pcmk__xml_fmt_diff_plus;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_diff_minus)) {
        options |= pcmk__xml_fmt_diff_minus;
    }
    if (pcmk_is_set(legacy_options, xml_log_option_diff_short)) {
        options |= pcmk__xml_fmt_diff_short;
    }

    if (pcmk_is_set(legacy_options, xml_log_option_dirty_add)) {
        CRM_CHECK(depth >= 0, depth = 0);
        log_xml_changes_recursive(log_level, data, depth, options);
        return;
    }

    if (pcmk_is_set(options, pcmk__xml_fmt_pretty)
        && (!xml_has_children(data)
            || (crm_element_value(data, XML_DIFF_MARKER) != NULL))) {

        if (pcmk_is_set(options, pcmk__xml_fmt_diff_plus)) {
            legacy_options |= xml_log_option_diff_all;
            prefix = PCMK__XML_PREFIX_CREATED;

        } else if (pcmk_is_set(options, pcmk__xml_fmt_diff_minus)) {
            legacy_options |= xml_log_option_diff_all;
            prefix = PCMK__XML_PREFIX_DELETED;
        }
    }

    if (pcmk_is_set(options, pcmk__xml_fmt_diff_short)
        && !pcmk_is_set(legacy_options, xml_log_option_diff_all)) {

        if (!pcmk_any_flags_set(options,
                                pcmk__xml_fmt_diff_plus
                                |pcmk__xml_fmt_diff_minus)) {
            // Nothing will ever be logged
            return;
        }

        // Keep looking for the actual change
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {
            log_data_element(log_level, file, function, line, prefix, child,
                             depth + 1, options);
        }

    } else {
        pcmk__xml_log(log_level, prefix, data, depth,
                      options
                      |pcmk__xml_fmt_open
                      |pcmk__xml_fmt_children
                      |pcmk__xml_fmt_close);
    }
}

void
xml_log_changes(uint8_t log_level, const char *function, const xmlNode *xml)
{
    pcmk__xml_log_changes(log_level, xml);
}

// LCOV_EXCL_STOP
// End deprecated API
