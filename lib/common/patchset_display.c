/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>

#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Output an XML patchset header
 *
 * This function parses a header from an XML patchset (an \p XML_ATTR_DIFF
 * element and its children).
 *
 * All header lines contain three integers separated by dots, of the form
 * <tt>{0}.{1}.{2}</tt>:
 * * \p {0}: \p XML_ATTR_GENERATION_ADMIN
 * * \p {1}: \p XML_ATTR_GENERATION
 * * \p {2}: \p XML_ATTR_NUMUPDATES
 *
 * Lines containing \p "---" describe removals and end with the patch format
 * number. Lines containing \p "+++" describe additions and end with the patch
 * digest.
 *
 * \param[in,out] out       Output object
 * \param[in]     patchset  XML patchset to output
 *
 * \return Standard Pacemaker return code
 *
 * \note This function produces output only for text-like formats.
 */
static int
xml_show_patchset_header(pcmk__output_t *out, const xmlNode *patchset)
{
    int rc = pcmk_rc_no_output;
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    xml_patch_versions(patchset, add, del);

    if ((add[0] != del[0]) || (add[1] != del[1]) || (add[2] != del[2])) {
        const char *fmt = crm_element_value(patchset, "format");
        const char *digest = crm_element_value(patchset, XML_ATTR_DIGEST);

        out->info(out, "Diff: --- %d.%d.%d %s", del[0], del[1], del[2], fmt);
        rc = out->info(out, "Diff: +++ %d.%d.%d %s",
                       add[0], add[1], add[2], digest);

    } else if ((add[0] != 0) || (add[1] != 0) || (add[2] != 0)) {
        rc = out->info(out, "Local-only Change: %d.%d.%d",
                       add[0], add[1], add[2]);
    }

    return rc;
}

/*!
 * \internal
 * \brief Output a user-friendly form of XML additions or removals
 *
 * \param[in,out] out      Output object
 * \param[in]     prefix   String to prepend to every line of output
 * \param[in]     data     XML node to output
 * \param[in]     depth    Current indentation level
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 *
 * \return Standard Pacemaker return code
 *
 * \note This function produces output only for text-like formats.
 */
static int
xml_show_patchset_v1_recursive(pcmk__output_t *out, const char *prefix,
                               const xmlNode *data, int depth, uint32_t options)
{
    if (!xml_has_children(data)
        || (crm_element_value(data, XML_DIFF_MARKER) != NULL)) {

        // Found a change; clear the pcmk__xml_fmt_diff_short option if set
        options &= ~pcmk__xml_fmt_diff_short;

        if (pcmk_is_set(options, pcmk__xml_fmt_diff_plus)) {
            prefix = PCMK__XML_PREFIX_CREATED;
        } else {    // pcmk_is_set(options, pcmk__xml_fmt_diff_minus)
            prefix = PCMK__XML_PREFIX_DELETED;
        }
    }

    if (pcmk_is_set(options, pcmk__xml_fmt_diff_short)) {
        int rc = pcmk_rc_no_output;

        // Keep looking for the actual change
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {
            int temp_rc = xml_show_patchset_v1_recursive(out, prefix, child,
                                                         depth + 1, options);
            rc = pcmk__output_select_rc(rc, temp_rc);
        }
        return rc;
    }

    return pcmk__xml_show(out, prefix, data, depth,
                          options
                          |pcmk__xml_fmt_open
                          |pcmk__xml_fmt_children
                          |pcmk__xml_fmt_close);
}

/*!
 * \internal
 * \brief Output a user-friendly form of an XML patchset (format 1)
 *
 * This function parses an XML patchset (an \p XML_ATTR_DIFF element and its
 * children) into a user-friendly combined diff output.
 *
 * \param[in,out] out       Output object
 * \param[in]     patchset  XML patchset to output
 * \param[in]     options   Group of \p pcmk__xml_fmt_options flags
 *
 * \return Standard Pacemaker return code
 *
 * \note This function produces output only for text-like formats.
 */
static int
xml_show_patchset_v1(pcmk__output_t *out, const xmlNode *patchset,
                     uint32_t options)
{
    const xmlNode *removed = NULL;
    const xmlNode *added = NULL;
    const xmlNode *child = NULL;
    bool is_first = true;
    int rc = xml_show_patchset_header(out, patchset);

    /* It's not clear whether "- " or "+ " ever does *not* get overridden by
     * PCMK__XML_PREFIX_DELETED or PCMK__XML_PREFIX_CREATED in practice.
     * However, v1 patchsets can only exist during rolling upgrades from
     * Pacemaker 1.1.11, so not worth worrying about.
     */
    removed = find_xml_node(patchset, "diff-removed", FALSE);
    for (child = pcmk__xml_first_child(removed); child != NULL;
         child = pcmk__xml_next(child)) {
        int temp_rc = xml_show_patchset_v1_recursive(out, "- ", child, 0,
                                                     options
                                                     |pcmk__xml_fmt_diff_minus);
        rc = pcmk__output_select_rc(rc, temp_rc);

        if (is_first) {
            is_first = false;
        } else {
            rc = pcmk__output_select_rc(rc, out->info(out, " --- "));
        }
    }

    is_first = true;
    added = find_xml_node(patchset, "diff-added", FALSE);
    for (child = pcmk__xml_first_child(added); child != NULL;
         child = pcmk__xml_next(child)) {
        int temp_rc = xml_show_patchset_v1_recursive(out, "+ ", child, 0,
                                                     options
                                                     |pcmk__xml_fmt_diff_plus);
        rc = pcmk__output_select_rc(rc, temp_rc);

        if (is_first) {
            is_first = false;
        } else {
            rc = pcmk__output_select_rc(rc, out->info(out, " +++ "));
        }
    }

    return rc;
}

/*!
 * \internal
 * \brief Output a user-friendly form of an XML patchset (format 2)
 *
 * This function parses an XML patchset (an \p XML_ATTR_DIFF element and its
 * children) into a user-friendly combined diff output.
 *
 * \param[in,out] out       Output object
 * \param[in]     patchset  XML patchset to output
 *
 * \return Standard Pacemaker return code
 *
 * \note This function produces output only for text-like formats.
 */
static int
xml_show_patchset_v2(pcmk__output_t *out, const xmlNode *patchset)
{
    int rc = xml_show_patchset_header(out, patchset);
    int temp_rc = pcmk_rc_no_output;

    for (const xmlNode *change = pcmk__xml_first_child(patchset);
         change != NULL; change = pcmk__xml_next(change)) {
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);

        if (op == NULL) {
            continue;
        }

        if (strcmp(op, "create") == 0) {
            char *prefix = crm_strdup_printf(PCMK__XML_PREFIX_CREATED " %s: ",
                                             xpath);

            temp_rc = pcmk__xml_show(out, prefix, change->children, 0,
                                     pcmk__xml_fmt_pretty|pcmk__xml_fmt_open);
            rc = pcmk__output_select_rc(rc, temp_rc);

            // Overwrite all except the first two characters with spaces
            for (char *ch = prefix + 2; *ch != '\0'; ch++) {
                *ch = ' ';
            }

            temp_rc = pcmk__xml_show(out, prefix, change->children, 0,
                                     pcmk__xml_fmt_pretty
                                     |pcmk__xml_fmt_children
                                     |pcmk__xml_fmt_close);
            rc = pcmk__output_select_rc(rc, temp_rc);
            free(prefix);

        } else if (strcmp(op, "move") == 0) {
            const char *position = crm_element_value(change, XML_DIFF_POSITION);

            temp_rc = out->info(out,
                                PCMK__XML_PREFIX_MOVED " %s moved to offset %s",
                                xpath, position);
            rc = pcmk__output_select_rc(rc, temp_rc);

        } else if (strcmp(op, "modify") == 0) {
            xmlNode *clist = first_named_child(change, XML_DIFF_LIST);
            GString *buffer_set = NULL;
            GString *buffer_unset = NULL;

            for (const xmlNode *child = pcmk__xml_first_child(clist);
                 child != NULL; child = pcmk__xml_next(child)) {
                const char *name = crm_element_value(child, "name");

                op = crm_element_value(child, XML_DIFF_OP);
                if (op == NULL) {
                    continue;
                }

                if (strcmp(op, "set") == 0) {
                    const char *value = crm_element_value(child, "value");

                    pcmk__add_separated_word(&buffer_set, 256, "@", ", ");
                    pcmk__g_strcat(buffer_set, name, "=", value, NULL);

                } else if (strcmp(op, "unset") == 0) {
                    pcmk__add_separated_word(&buffer_unset, 256, "@", ", ");
                    g_string_append(buffer_unset, name);
                }
            }

            if (buffer_set != NULL) {
                temp_rc = out->info(out, "+  %s:  %s", xpath, buffer_set->str);
                rc = pcmk__output_select_rc(rc, temp_rc);
                g_string_free(buffer_set, TRUE);
            }

            if (buffer_unset != NULL) {
                temp_rc = out->info(out, "-- %s:  %s",
                                    xpath, buffer_unset->str);
                rc = pcmk__output_select_rc(rc, temp_rc);
                g_string_free(buffer_unset, TRUE);
            }

        } else if (strcmp(op, "delete") == 0) {
            int position = -1;

            crm_element_value_int(change, XML_DIFF_POSITION, &position);
            if (position >= 0) {
                temp_rc = out->info(out, "-- %s (%d)", xpath, position);
            } else {
                temp_rc = out->info(out, "-- %s", xpath);
            }
            rc = pcmk__output_select_rc(rc, temp_rc);
        }
    }

    return rc;
}

/*!
 * \internal
 * \brief Output a user-friendly form of an XML patchset
 *
 * This function parses an XML patchset (an \p XML_ATTR_DIFF element and its
 * children) into a user-friendly combined diff output.
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain only the XML patchset
 */
PCMK__OUTPUT_ARGS("xml-patchset", "xmlNodePtr")
static int
xml_patchset_default(pcmk__output_t *out, va_list args)
{
    xmlNodePtr patchset = va_arg(args, xmlNodePtr);

    int format = 1;

    if (patchset == NULL) {
        crm_trace("Empty patch");
        return pcmk_rc_no_output;
    }

    crm_element_value_int(patchset, "format", &format);
    switch (format) {
        case 1:
            return xml_show_patchset_v1(out, patchset, pcmk__xml_fmt_pretty);
        case 2:
            return xml_show_patchset_v2(out, patchset);
        default:
            crm_err("Unknown patch format: %d", format);
            return pcmk_rc_unknown_format;
    }
}

/*!
 * \internal
 * \brief Output a user-friendly form of an XML patchset
 *
 * This function parses an XML patchset (an \p XML_ATTR_DIFF element and its
 * children) into a user-friendly combined diff output.
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain only the XML patchset
 */
PCMK__OUTPUT_ARGS("xml-patchset", "xmlNodePtr")
static int
xml_patchset_log(pcmk__output_t *out, va_list args)
{
    static struct qb_log_callsite *patchset_cs = NULL;

    xmlNodePtr patchset = va_arg(args, xmlNodePtr);

    uint8_t log_level = pcmk__output_get_log_level(out);
    int format = 1;

    if (log_level == LOG_NEVER) {
        return pcmk_rc_no_output;
    }

    if (patchset == NULL) {
        crm_trace("Empty patch");
        return pcmk_rc_no_output;
    }

    if (patchset_cs == NULL) {
        patchset_cs = qb_log_callsite_get(__func__, __FILE__, "xml-patchset",
                                          log_level, __LINE__,
                                          crm_trace_nonlog);
    }

    if (!crm_is_callsite_active(patchset_cs, log_level, crm_trace_nonlog)) {
        // Nothing would be logged, so skip all the work
        return pcmk_rc_no_output;
    }

    crm_element_value_int(patchset, "format", &format);
    switch (format) {
        case 1:
            if (log_level < LOG_DEBUG) {
                return xml_show_patchset_v1(out, patchset,
                                            pcmk__xml_fmt_pretty
                                            |pcmk__xml_fmt_diff_short);
            }
            return xml_show_patchset_v1(out, patchset, pcmk__xml_fmt_pretty);
        case 2:
            return xml_show_patchset_v2(out, patchset);
        default:
            crm_err("Unknown patch format: %d", format);
            return pcmk_rc_unknown_format;
    }
}

/*!
 * \internal
 * \brief Output an XML patchset
 *
 * This function outputs an XML patchset (an \p XML_ATTR_DIFF element and its
 * children) without modification, as a CDATA block.
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain only the XML patchset
 */
PCMK__OUTPUT_ARGS("xml-patchset", "xmlNodePtr")
static int
xml_patchset_xml(pcmk__output_t *out, va_list args)
{
    xmlNodePtr patchset = va_arg(args, xmlNodePtr);

    if (patchset != NULL) {
        char *buf = dump_xml_formatted_with_text(patchset);

        out->output_xml(out, "xml-patchset", buf);
        free(buf);
        return pcmk_rc_ok;
    }
    crm_trace("Empty patch");
    return pcmk_rc_no_output;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "xml-patchset", "default", xml_patchset_default },
    { "xml-patchset", "log", xml_patchset_log },
    { "xml-patchset", "xml", xml_patchset_xml },

    { NULL, NULL, NULL }
};

/*!
 * \internal
 * \brief Register the formatting functions for XML patchsets
 *
 * \param[in,out] out  Output object
 */
void
pcmk__register_patchset_messages(pcmk__output_t *out) {
    pcmk__register_messages(out, fmt_functions);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

void
xml_log_patchset(uint8_t log_level, const char *function,
                 const xmlNode *patchset)
{
    /* This function has some duplication relative to the message functions.
     * This way, we can maintain the const xmlNode * in the signature. The
     * message functions must be non-const. They have to support XML output
     * objects, which must make a copy of a the patchset, requiring a non-const
     * function call.
     *
     * In contrast, this legacy function doesn't need to support XML output.
     */
    static struct qb_log_callsite *patchset_cs = NULL;

    pcmk__output_t *out = NULL;
    int format = 1;
    int rc = pcmk_rc_no_output;

    switch (log_level) {
        case LOG_NEVER:
            return;
        case LOG_STDOUT:
            CRM_CHECK(pcmk__text_output_new(&out, NULL) == pcmk_rc_ok, return);
            break;
        default:
            if (patchset_cs == NULL) {
                patchset_cs = qb_log_callsite_get(__func__, __FILE__,
                                                  "xml-patchset", log_level,
                                                  __LINE__, crm_trace_nonlog);
            }
            if (!crm_is_callsite_active(patchset_cs, log_level,
                                        crm_trace_nonlog)) {
                return;
            }
            CRM_CHECK(pcmk__log_output_new(&out) == pcmk_rc_ok, return);
            pcmk__output_set_log_level(out, log_level);
            break;
    }

    if (patchset == NULL) {
        // Should come after the LOG_NEVER check
        crm_trace("Empty patch");
        goto done;
    }

    crm_element_value_int(patchset, "format", &format);
    switch (format) {
        case 1:
            if (log_level < LOG_DEBUG) {
                rc = xml_show_patchset_v1(out, patchset,
                                          pcmk__xml_fmt_pretty
                                          |pcmk__xml_fmt_diff_short);
            } else {    // Note: LOG_STDOUT > LOG_DEBUG
                rc = xml_show_patchset_v1(out, patchset, pcmk__xml_fmt_pretty);
            }
            break;
        case 2:
            rc = xml_show_patchset_v2(out, patchset);
            break;
        default:
            crm_err("Unknown patch format: %d", format);
            rc = pcmk_rc_unknown_format;
            break;
    }

done:
    out->finish(out, pcmk_rc2exitc(rc), true, NULL);
    pcmk__output_free(out);
}

// LCOV_EXCL_STOP
// End deprecated API
