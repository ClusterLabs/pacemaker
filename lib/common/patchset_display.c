/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>

#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Output an XML patchset header
 *
 * This function parses a header from an XML patchset (a \c PCMK_XE_DIFF element
 * and its children).
 *
 * All header lines contain three integers separated by dots, of the form
 * <tt>{0}.{1}.{2}</tt>:
 * * \p {0}: \c PCMK_XA_ADMIN_EPOCH
 * * \p {1}: \c PCMK_XA_EPOCH
 * * \p {2}: \c PCMK_XA_NUM_UPDATES
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

    pcmk__xml_patchset_versions(patchset, del, add);

    if ((add[0] != del[0]) || (add[1] != del[1]) || (add[2] != del[2])) {
        const char *fmt = pcmk__xe_get(patchset, PCMK_XA_FORMAT);
        const char *digest = pcmk__xe_get(patchset, PCMK_XA_DIGEST);

        out->info(out, "Diff: --- %d.%d.%d %s", del[0], del[1], del[2],
                  pcmk__s(fmt, "(no format)"));
        rc = out->info(out, "Diff: +++ %d.%d.%d %s",
                       add[0], add[1], add[2], pcmk__s(digest, "(no digest)"));

    } else if ((add[0] != 0) || (add[1] != 0) || (add[2] != 0)) {
        rc = out->info(out, "Local-only Change: %d.%d.%d",
                       add[0], add[1], add[2]);
    }

    return rc;
}

/*!
 * \internal
 * \brief Output a user-friendly form of an XML patchset
 *
 * This function parses an XML patchset (a \c PCMK_XE_DIFF element and its
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
xml_show_patchset(pcmk__output_t *out, const xmlNode *patchset)
{
    int rc = xml_show_patchset_header(out, patchset);
    int temp_rc = pcmk_rc_no_output;

    for (const xmlNode *change = pcmk__xe_first_child(patchset, NULL, NULL,
                                                      NULL);
         change != NULL; change = pcmk__xe_next(change, NULL)) {

        const char *op = pcmk__xe_get(change, PCMK_XA_OPERATION);
        const char *xpath = pcmk__xe_get(change, PCMK_XA_PATH);

        if (op == NULL) {
            continue;
        }

        if (strcmp(op, PCMK_VALUE_CREATE) == 0) {
            char *prefix = pcmk__assert_asprintf(PCMK__XML_PREFIX_CREATED
                                                 " %s: ",
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

        } else if (strcmp(op, PCMK_VALUE_MOVE) == 0) {
            const char *position = pcmk__xe_get(change, PCMK_XE_POSITION);

            temp_rc = out->info(out,
                                PCMK__XML_PREFIX_MOVED " %s moved to offset %s",
                                xpath, position);
            rc = pcmk__output_select_rc(rc, temp_rc);

        } else if (strcmp(op, PCMK_VALUE_MODIFY) == 0) {
            xmlNode *clist = pcmk__xe_first_child(change, PCMK_XE_CHANGE_LIST,
                                                  NULL, NULL);
            GString *buffer_set = NULL;
            GString *buffer_unset = NULL;

            for (const xmlNode *child = pcmk__xe_first_child(clist, NULL, NULL,
                                                             NULL);
                 child != NULL; child = pcmk__xe_next(child, NULL)) {

                const char *name = pcmk__xe_get(child, PCMK_XA_NAME);

                op = pcmk__xe_get(child, PCMK_XA_OPERATION);
                if (op == NULL) {
                    continue;
                }

                if (strcmp(op, "set") == 0) {
                    const char *value = pcmk__xe_get(child, PCMK_XA_VALUE);

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

        } else if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
            int position = -1;

            pcmk__xe_get_int(change, PCMK_XE_POSITION, &position);
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
 * This function parses an XML patchset (a \c PCMK_XE_DIFF element and its
 * children) into a user-friendly combined diff output.
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# XML patchset
 */
PCMK__OUTPUT_ARGS("xml-patchset", "const xmlNode *")
static int
xml_patchset_default(pcmk__output_t *out, va_list args)
{
    const xmlNode *patchset = va_arg(args, const xmlNode *);

    int format = 1;

    if (patchset == NULL) {
        pcmk__trace("Empty patch");
        return pcmk_rc_no_output;
    }

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        pcmk__err("Unknown patch format: %d", format);
        return pcmk_rc_bad_xml_patch;
    }

    return xml_show_patchset(out, patchset);
}

/*!
 * \internal
 * \brief Output a user-friendly form of an XML patchset
 *
 * This function parses an XML patchset (a \c PCMK_XE_DIFF element and its
 * children) into a user-friendly combined diff output.
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# XML patchset
 */
PCMK__OUTPUT_ARGS("xml-patchset", "const xmlNode *")
static int
xml_patchset_log(pcmk__output_t *out, va_list args)
{
    static struct qb_log_callsite *patchset_cs = NULL;

    const xmlNode *patchset = va_arg(args, const xmlNode *);

    uint8_t log_level = pcmk__output_get_log_level(out);
    int format = 1;

    if (log_level == PCMK__LOG_NEVER) {
        return pcmk_rc_no_output;
    }

    if (patchset == NULL) {
        pcmk__trace("Empty patch");
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

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        pcmk__err("Unknown patch format: %d", format);
        return pcmk_rc_bad_xml_patch;
    }

    return xml_show_patchset(out, patchset);
}

/*!
 * \internal
 * \brief Output an XML patchset
 *
 * This function outputs an XML patchset (a \c PCMK_XE_DIFF element and its
 * children) without modification, as a CDATA block.
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# XML patchset
 */
PCMK__OUTPUT_ARGS("xml-patchset", "const xmlNode *")
static int
xml_patchset_xml(pcmk__output_t *out, va_list args)
{
    const xmlNode *patchset = va_arg(args, const xmlNode *);

    if (patchset != NULL) {
        GString *buf = g_string_sized_new(1024);

        pcmk__xml_string(patchset, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text, buf,
                         0);

        out->output_xml(out, PCMK_XE_XML_PATCHSET, buf->str);
        g_string_free(buf, TRUE);
        return pcmk_rc_ok;
    }
    pcmk__trace("Empty patch");
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
