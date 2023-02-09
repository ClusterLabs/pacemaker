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
 */
static void
xml_show_patchset_header(pcmk__output_t *out, const xmlNode *patchset)
{
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    xml_patch_versions(patchset, add, del);

    if ((add[0] != del[0]) || (add[1] != del[1]) || (add[2] != del[2])) {
        const char *fmt = crm_element_value(patchset, "format");
        const char *digest = crm_element_value(patchset, XML_ATTR_DIGEST);

        out->info(out, "Diff: --- %d.%d.%d %s", del[0], del[1], del[2], fmt);
        out->info(out, "Diff: +++ %d.%d.%d %s", add[0], add[1], add[2], digest);

    } else if ((add[0] != 0) || (add[1] != 0) || (add[2] != 0)) {
        out->info(out, "Local-only Change: %d.%d.%d", add[0], add[1], add[2]);
    }
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
 */
static void
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
        // Keep looking for the actual change
        for (const xmlNode *child = pcmk__xml_first_child(data); child != NULL;
             child = pcmk__xml_next(child)) {
            xml_show_patchset_v1_recursive(out, prefix, child, depth + 1,
                                           options);
        }

    } else {
        pcmk__xml_show(out, prefix, data, depth,
                       options
                       |pcmk__xml_fmt_open
                       |pcmk__xml_fmt_children
                       |pcmk__xml_fmt_close);
    }
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
 */
static void
xml_show_patchset_v1(pcmk__output_t *out, const xmlNode *patchset)
{
    uint32_t options = pcmk__xml_fmt_pretty;
    const xmlNode *removed = NULL;
    const xmlNode *added = NULL;
    const xmlNode *child = NULL;
    bool is_first = true;

    // @FIXME: Use message functions to get rid of explicit fmt_name check
    if (pcmk__str_eq(out->fmt_name, "log", pcmk__str_none)
        && (pcmk__output_get_log_level(out) < LOG_DEBUG)) {
        options |= pcmk__xml_fmt_diff_short;
    }

    xml_show_patchset_header(out, patchset);

    /* It's not clear whether "- " or "+ " ever does *not* get overridden by
     * PCMK__XML_PREFIX_DELETED or PCMK__XML_PREFIX_CREATED in practice.
     * However, v1 patchsets can only exist during rolling upgrades from
     * Pacemaker 1.1.11, so not worth worrying about.
     */
    removed = find_xml_node(patchset, "diff-removed", FALSE);
    for (child = pcmk__xml_first_child(removed); child != NULL;
         child = pcmk__xml_next(child)) {
        xml_show_patchset_v1_recursive(out, "- ", child, 0,
                                       options|pcmk__xml_fmt_diff_minus);
        if (is_first) {
            is_first = false;
        } else {
            out->info(out, " --- ");
        }
    }

    is_first = true;
    added = find_xml_node(patchset, "diff-added", FALSE);
    for (child = pcmk__xml_first_child(added); child != NULL;
         child = pcmk__xml_next(child)) {
        xml_show_patchset_v1_recursive(out, "+ ", child, 0,
                                       options|pcmk__xml_fmt_diff_plus);
        if (is_first) {
            is_first = false;
        } else {
            out->info(out, " +++ ");
        }
    }
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
 */
static void
xml_show_patchset_v2(pcmk__output_t *out, const xmlNode *patchset)
{
    xml_show_patchset_header(out, patchset);

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

            pcmk__xml_show(out, prefix, change->children, 0,
                           pcmk__xml_fmt_pretty|pcmk__xml_fmt_open);

            // Overwrite all except the first two characters with spaces
            for (char *ch = prefix + 2; *ch != '\0'; ch++) {
                *ch = ' ';
            }

            pcmk__xml_show(out, prefix, change->children, 0,
                           pcmk__xml_fmt_pretty
                           |pcmk__xml_fmt_children
                           |pcmk__xml_fmt_close);
            free(prefix);

        } else if (strcmp(op, "move") == 0) {
            const char *position = crm_element_value(change, XML_DIFF_POSITION);

            out->info(out, PCMK__XML_PREFIX_MOVED " %s moved to offset %s",
                      xpath, position);

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
                out->info(out, "+  %s:  %s", xpath, buffer_set->str);
                g_string_free(buffer_set, TRUE);
            }

            if (buffer_unset != NULL) {
                out->info(out, "-- %s:  %s", xpath, buffer_unset->str);
                g_string_free(buffer_unset, TRUE);
            }

        } else if (strcmp(op, "delete") == 0) {
            int position = -1;

            crm_element_value_int(change, XML_DIFF_POSITION, &position);
            if (position >= 0) {
                out->info(out, "-- %s (%d)", xpath, position);
            } else {
                out->info(out, "-- %s", xpath);
            }
        }
    }
}

/*!
 * \internal
 * \brief Log a user-friendly form of an XML patchset
 *
 * This function parses an XML patchset (an \p XML_ATTR_DIFF element and its
 * children) into a user-friendly combined diff output. Depending on the value
 * of \p log_level, the output may be written to \p stdout or to a log file.
 *
 * \param[in] log_level  Priority at which to log the messages
 * \param[in] patchset   XML patchset to log
 */
void
pcmk__xml_log_patchset(uint8_t log_level, const xmlNode *patchset)
{
    int format = 1;
    pcmk__output_t *out = NULL;

    static struct qb_log_callsite *patchset_cs = NULL;

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
            xml_show_patchset_v1(out, patchset);
            break;
        case 2:
            xml_show_patchset_v2(out, patchset);
            break;
        default:
            crm_err("Unknown patch format: %d", format);
            break;
    }

done:
    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

void
xml_log_patchset(uint8_t log_level, const char *function,
                 const xmlNode *patchset)
{
    pcmk__xml_log_patchset(log_level, patchset);
}

// LCOV_EXCL_STOP
// End deprecated API
