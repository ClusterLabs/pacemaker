/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

static int show_xml_node(pcmk__output_t *out, GString *buffer,
                         const char *prefix, const xmlNode *data, int depth,
                         uint32_t options);

// Log an XML library error
void
pcmk__log_xmllib_err(void *ctx, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    pcmk__if_tracing(
        {
            PCMK__XML_LOG_BASE(LOG_ERR, TRUE,
                               crm_abort(__FILE__, __PRETTY_FUNCTION__,
                                         __LINE__, "xml library error", TRUE,
                                         TRUE),
                               "XML Error: ", fmt, ap);
        },
        {
            PCMK__XML_LOG_BASE(LOG_ERR, TRUE, 0, "XML Error: ", fmt, ap);
        }
    );
    va_end(ap);
}

/*!
 * \internal
 * \brief Output an XML comment with depth-based indentation
 *
 * \param[in,out] out      Output object
 * \param[in]     data     XML node to output
 * \param[in]     depth    Current indentation level
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 *
 * \return Standard Pacemaker return code
 *
 * \note This currently produces output only for text-like output objects.
 */
static int
show_xml_comment(pcmk__output_t *out, const xmlNode *data, int depth,
                 uint32_t options)
{
    if (pcmk__is_set(options, pcmk__xml_fmt_open)) {
        int width =
            pcmk__is_set(options, pcmk__xml_fmt_pretty)? (2 * depth) : 0;

        return out->info(out, "%*s<!--%s-->",
                         width, "", (const char *) data->content);
    }
    return pcmk_rc_no_output;
}

/*!
 * \internal
 * \brief Output an XML element in a formatted way
 *
 * \param[in,out] out      Output object
 * \param[in,out] buffer   Where to build output strings
 * \param[in]     prefix   String to prepend to every line of output
 * \param[in]     data     XML node to output
 * \param[in]     depth    Current indentation level
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 *
 * \return Standard Pacemaker return code
 *
 * \note This is a recursive helper function for \p show_xml_node().
 * \note This currently produces output only for text-like output objects.
 * \note \p buffer may be overwritten many times. The caller is responsible for
 *       freeing it using \p g_string_free() but should not rely on its
 *       contents.
 */
static int
show_xml_element(pcmk__output_t *out, GString *buffer, const char *prefix,
                 const xmlNode *data, int depth, uint32_t options)
{
    int spaces = pcmk__is_set(options, pcmk__xml_fmt_pretty)? (2 * depth) : 0;
    int rc = pcmk_rc_no_output;

    if (pcmk__is_set(options, pcmk__xml_fmt_open)) {
        const char *hidden = pcmk__xe_get(data, PCMK__XA_HIDDEN);

        g_string_truncate(buffer, 0);

        for (int lpc = 0; lpc < spaces; lpc++) {
            g_string_append_c(buffer, ' ');
        }
        pcmk__g_strcat(buffer, "<", data->name, NULL);

        for (const xmlAttr *attr = pcmk__xe_first_attr(data); attr != NULL;
             attr = attr->next) {
            xml_node_private_t *nodepriv = attr->_private;
            const char *p_name = (const char *) attr->name;
            const char *p_value = pcmk__xml_attr_value(attr);
            gchar *p_value_disp = NULL;

            if ((nodepriv == NULL)
                || pcmk__is_set(nodepriv->flags, pcmk__xf_deleted)) {
                continue;
            }

            if (p_value == NULL) {
                continue;
            }

            if ((hidden != NULL) && !pcmk__str_empty(p_name)) {
                gchar **hidden_names = g_strsplit(hidden, ",", 0);

                if (pcmk__g_strv_contains(hidden_names, p_name)) {
                    p_value = "*****";
                }
                g_strfreev(hidden_names);
            }

            p_value_disp = pcmk__xml_escape(p_value, pcmk__xml_escape_attr);

            pcmk__g_strcat(buffer, " ", p_name, "=\"", p_value_disp, "\"", NULL);
            g_free(p_value_disp);
        }

        if ((data->children != NULL)
            && pcmk__is_set(options, pcmk__xml_fmt_children)) {
            g_string_append_c(buffer, '>');

        } else {
            g_string_append(buffer, "/>");
        }

        rc = out->info(out, "%s%s%s",
                       pcmk__s(prefix, ""), pcmk__str_empty(prefix)? "" : " ",
                       buffer->str);
    }

    if (data->children == NULL) {
        return rc;
    }

    if (pcmk__is_set(options, pcmk__xml_fmt_children)) {
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {

            int temp_rc = show_xml_node(out, buffer, prefix, child, depth + 1,
                                        options
                                        |pcmk__xml_fmt_open
                                        |pcmk__xml_fmt_close);
            rc = pcmk__output_select_rc(rc, temp_rc);
        }
    }

    if (pcmk__is_set(options, pcmk__xml_fmt_close)) {
        int temp_rc = out->info(out, "%s%s%*s</%s>",
                                pcmk__s(prefix, ""),
                                pcmk__str_empty(prefix)? "" : " ",
                                spaces, "", data->name);
        rc = pcmk__output_select_rc(rc, temp_rc);
    }

    return rc;
}

/*!
 * \internal
 * \brief Output an XML element or comment in a formatted way
 *
 * \param[in,out] out      Output object
 * \param[in,out] buffer   Where to build output strings
 * \param[in]     prefix   String to prepend to every line of output
 * \param[in]     data     XML node to log
 * \param[in]     depth    Current indentation level
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 *
 * \return Standard Pacemaker return code
 *
 * \note This is a recursive helper function for \p pcmk__xml_show().
 * \note This currently produces output only for text-like output objects.
 * \note \p buffer may be overwritten many times. The caller is responsible for
 *       freeing it using \p g_string_free() but should not rely on its
 *       contents.
 */
static int
show_xml_node(pcmk__output_t *out, GString *buffer, const char *prefix,
              const xmlNode *data, int depth, uint32_t options)
{
    switch (data->type) {
        case XML_COMMENT_NODE:
            return show_xml_comment(out, data, depth, options);
        case XML_ELEMENT_NODE:
            return show_xml_element(out, buffer, prefix, data, depth, options);
        default:
            return pcmk_rc_no_output;
    }
}

/*!
 * \internal
 * \brief Output an XML element or comment in a formatted way
 *
 * \param[in,out] out        Output object
 * \param[in]     prefix     String to prepend to every line of output
 * \param[in]     data       XML node to output
 * \param[in]     depth      Current nesting level
 * \param[in]     options    Group of \p pcmk__xml_fmt_options flags
 *
 * \return Standard Pacemaker return code
 *
 * \note This currently produces output only for text-like output objects.
 */
int
pcmk__xml_show(pcmk__output_t *out, const char *prefix, const xmlNode *data,
               int depth, uint32_t options)
{
    int rc = pcmk_rc_no_output;
    GString *buffer = NULL;

    pcmk__assert(out != NULL);
    CRM_CHECK(depth >= 0, depth = 0);

    if (data == NULL) {
        return rc;
    }

    /* Allocate a buffer once, for show_xml_node() to truncate and reuse in
     * recursive calls
     */
    buffer = g_string_sized_new(1024);
    rc = show_xml_node(out, buffer, prefix, data, depth, options);
    g_string_free(buffer, TRUE);

    return rc;
}

/*!
 * \internal
 * \brief Output XML portions that have been marked as changed
 *
 * \param[in,out] out      Output object
 * \param[in]     data     XML node to output
 * \param[in]     depth    Current indentation level
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 *
 * \note This is a recursive helper for \p pcmk__xml_show_changes(), showing
 *       changes to \p data and its children.
 * \note This currently produces output only for text-like output objects.
 */
static int
show_xml_changes_recursive(pcmk__output_t *out, const xmlNode *data, int depth,
                           uint32_t options)
{
    /* @COMPAT: When log_data_element() is removed, we can remove the options
     * argument here and instead hard-code pcmk__xml_log_pretty.
     */
    xml_node_private_t *nodepriv = (xml_node_private_t *) data->_private;
    int rc = pcmk_rc_no_output;
    int temp_rc = pcmk_rc_no_output;

    if (nodepriv == NULL) {
        return pcmk_rc_no_output;
    }

    if (pcmk__all_flags_set(nodepriv->flags, pcmk__xf_dirty|pcmk__xf_created)) {
        // Newly created
        return pcmk__xml_show(out, PCMK__XML_PREFIX_CREATED, data, depth,
                              options
                              |pcmk__xml_fmt_open
                              |pcmk__xml_fmt_children
                              |pcmk__xml_fmt_close);
    }

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_dirty)) {
        // Modified or moved
        bool pretty = pcmk__is_set(options, pcmk__xml_fmt_pretty);
        int spaces = pretty? (2 * depth) : 0;
        const char *prefix = PCMK__XML_PREFIX_MODIFIED;

        if (pcmk__is_set(nodepriv->flags, pcmk__xf_moved)) {
            prefix = PCMK__XML_PREFIX_MOVED;
        }

        // Log opening tag
        rc = pcmk__xml_show(out, prefix, data, depth,
                            options|pcmk__xml_fmt_open);

        // Log changes to attributes
        for (const xmlAttr *attr = pcmk__xe_first_attr(data); attr != NULL;
             attr = attr->next) {
            const char *name = (const char *) attr->name;

            nodepriv = attr->_private;

            if (pcmk__is_set(nodepriv->flags, pcmk__xf_deleted)) {
                const char *value = pcmk__xml_attr_value(attr);

                temp_rc = out->info(out, "%s %*s @%s=%s",
                                    PCMK__XML_PREFIX_DELETED, spaces, "", name,
                                    value);

            } else if (pcmk__is_set(nodepriv->flags, pcmk__xf_dirty)) {
                const char *value = pcmk__xml_attr_value(attr);

                if (pcmk__is_set(nodepriv->flags, pcmk__xf_created)) {
                    prefix = PCMK__XML_PREFIX_CREATED;

                } else if (pcmk__is_set(nodepriv->flags, pcmk__xf_modified)) {
                    prefix = PCMK__XML_PREFIX_MODIFIED;

                } else if (pcmk__is_set(nodepriv->flags, pcmk__xf_moved)) {
                    prefix = PCMK__XML_PREFIX_MOVED;

                } else {
                    prefix = PCMK__XML_PREFIX_MODIFIED;
                }

                temp_rc = out->info(out, "%s %*s @%s=%s",
                                    prefix, spaces, "", name, value);
            }
            rc = pcmk__output_select_rc(rc, temp_rc);
        }

        // Log changes to children
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {
            temp_rc = show_xml_changes_recursive(out, child, depth + 1,
                                                 options);
            rc = pcmk__output_select_rc(rc, temp_rc);
        }

        // Log closing tag
        temp_rc = pcmk__xml_show(out, PCMK__XML_PREFIX_MODIFIED, data, depth,
                                 options|pcmk__xml_fmt_close);
        return pcmk__output_select_rc(rc, temp_rc);
    }

    // This node hasn't changed, but check its children
    for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
         child = pcmk__xml_next(child)) {
        temp_rc = show_xml_changes_recursive(out, child, depth + 1, options);
        rc = pcmk__output_select_rc(rc, temp_rc);
    }
    return rc;
}

/*!
 * \internal
 * \brief Output changes to an XML node and any children
 *
 * \param[in,out] out  Output object
 * \param[in]     xml  XML node to output
 *
 * \return Standard Pacemaker return code
 *
 * \note This currently produces output only for text-like output objects.
 */
int
pcmk__xml_show_changes(pcmk__output_t *out, const xmlNode *xml)
{
    xml_doc_private_t *docpriv = NULL;
    int rc = pcmk_rc_no_output;
    int temp_rc = pcmk_rc_no_output;

    pcmk__assert((out != NULL) && (xml != NULL) && (xml->doc != NULL));

    docpriv = xml->doc->_private;
    if (!pcmk__is_set(docpriv->flags, pcmk__xf_dirty)) {
        return rc;
    }

    for (const GList *iter = docpriv->deleted_objs; iter != NULL;
         iter = iter->next) {
        const pcmk__deleted_xml_t *deleted_obj = iter->data;

        if (deleted_obj->position >= 0) {
            temp_rc = out->info(out, PCMK__XML_PREFIX_DELETED " %s (%d)",
                                deleted_obj->path, deleted_obj->position);
        } else {
            temp_rc = out->info(out, PCMK__XML_PREFIX_DELETED " %s",
                                deleted_obj->path);
        }
        rc = pcmk__output_select_rc(rc, temp_rc);
    }

    temp_rc = show_xml_changes_recursive(out, xml, 0, pcmk__xml_fmt_pretty);
    return pcmk__output_select_rc(rc, temp_rc);
}
