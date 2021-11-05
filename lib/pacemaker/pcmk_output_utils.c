/*
 * Copyright 2019-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/results.h>
#include <crm/common/output_internal.h>
#include <libxml/tree.h>
#include <pacemaker-internal.h>

pcmk__supported_format_t pcmk__out_formats[] = {
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

int
pcmk__out_prologue(pcmk__output_t **out, xmlNodePtr *xml) {
    int rc = pcmk_rc_ok;

    if (*xml != NULL) {
        xmlFreeNode(*xml);
    }

    pcmk__register_formats(NULL, pcmk__out_formats);
    rc = pcmk__output_new(out, "xml", NULL, NULL);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    return rc;
}

void
pcmk__out_epilogue(pcmk__output_t *out, xmlNodePtr *xml, int retval) {
    if (retval == pcmk_rc_ok) {
        out->finish(out, 0, FALSE, (void **) xml);
    }

    pcmk__output_free(out);
}

/*!
 * \internal
 * \brief Create a new output object using the "log" format
 *
 * Create a new output object using the "log" format, and register the
 * libpe_status and libpacemaker messages.
 *
 * \return Newly created output object, or NULL on error
 */
pcmk__output_t *
pcmk__new_logger(void)
{
    int rc = pcmk_rc_ok;
    pcmk__output_t *out = NULL;
    const char* argv[] = { "", NULL };
    pcmk__supported_format_t formats[] = {
        PCMK__SUPPORTED_FORMAT_LOG,
        { NULL, NULL, NULL }
    };

    pcmk__register_formats(NULL, formats);
    rc = pcmk__output_new(&out, "log", NULL, (char**)argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        crm_err("Can't log resource details due to internal error: %s\n",
                pcmk_rc_str(rc));
        return NULL;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);
    return out;
}

