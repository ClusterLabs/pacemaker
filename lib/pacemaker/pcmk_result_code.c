/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/cib/internal.h>
#include <crm/crm.h>

#include <pacemaker.h>
#include <pacemaker-internal.h>

#include <inttypes.h>   // PRIx32
#include <stdint.h>     // uint32_t

/*!
 * \internal
 * \brief Display the name and/or description of a result code
 *
 * \param[in,out] out    Output object
 * \param[in]     code   The result code
 * \param[in]     type   Interpret \c code as this type of result code.
 *                       Supported values: \c pcmk_result_legacy,
 *                       \c pcmk_result_rc, \c pcmk_result_exitcode.
 * \param[in]     flags  Group of \c pcmk_rc_disp_flags
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__show_result_code(pcmk__output_t *out, int code,
                       enum pcmk_result_type type, uint32_t flags)
{
    int rc = pcmk_rc_ok;
    bool quiet_orig = out->quiet;
    const char *name = NULL;
    const char *desc = NULL;

    rc = pcmk_result_get_strings(code, type, &name, &desc);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Error looking up result code %d", code);
        return rc;
    }

    // out->quiet controls whether the code is shown (if quiet is supported)
    out->quiet = !pcmk_is_set(flags, pcmk_rc_disp_code);

    out->message(out, "result-code", code,
                 pcmk_is_set(flags, pcmk_rc_disp_name)? name : NULL,
                 pcmk_is_set(flags, pcmk_rc_disp_desc)? desc : NULL);
    out->quiet = quiet_orig;

    return rc;
}

// Documented in header
int
pcmk_show_result_code(xmlNodePtr *xml, int code, enum pcmk_result_type type,
                      uint32_t flags)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__show_result_code(out, code, type, flags);
    pcmk__xml_output_finish(out, xml);
    return rc;
}

/*!
 * \internal
 * \brief List all valid result codes in a particular family
 *
 * \param[in,out] out    Output object
 * \param[in]     type   The family of result codes to list. Supported
 *                       values: \c pcmk_result_legacy, \c pcmk_result_rc,
 *                       \c pcmk_result_exitcode.
 * \param[in]     flags  Group of \c pcmk_rc_disp_flags
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__list_result_codes(pcmk__output_t *out, enum pcmk_result_type type,
                        uint32_t flags)
{
    int rc = pcmk_rc_ok;
    int start = 0;
    int end = 0;
    int code = 0;

    bool quiet_orig = out->quiet;
    const char *name = NULL;
    const char *desc = NULL;

    rc = pcmk__result_bounds(type, &start, &end);
    if (rc != pcmk_rc_ok) {
        out->err(out,
                "Failed to get result code bounds for result code type "
                 "%#010x" PRIx32, (uint32_t) type);
        return rc;
    }

    code = start;
    while (code <= end) {
        int local_rc = pcmk_rc_ok;

        if (code == (pcmk_rc_error + 1)) {
            /* Values between pcmk_rc_error and pcmk_rc_ok are reserved for
             * callers, so skip them
             */
            code = pcmk_rc_ok;
            continue;
        }

        // Shouldn't affect the return code of the whole list operation
        local_rc = pcmk_result_get_strings(code, type, &name, &desc);

        if ((local_rc != pcmk_rc_ok) || (name == NULL)
            || pcmk__str_any_of(name, "Unknown", "CRM_EX_UNKNOWN", NULL)) {

            code++;
            continue;
        }

        // out->quiet controls whether the code is shown (if quiet is supported)
        out->quiet = !pcmk_is_set(flags, pcmk_rc_disp_code);

        out->message(out, "result-code", code,
                     pcmk_is_set(flags, pcmk_rc_disp_name)? name : NULL,
                     pcmk_is_set(flags, pcmk_rc_disp_desc)? desc : NULL);
        out->quiet = quiet_orig;

        code++;
    }

    return rc;
}

// Documented in header
int
pcmk_list_result_codes(xmlNodePtr *xml, enum pcmk_result_type type,
                       uint32_t flags)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pcmk__register_lib_messages(out);

    rc = pcmk__list_result_codes(out, type, flags);
    pcmk__xml_output_finish(out, xml);
    return rc;
}
