/*
 * Copyright 2023-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/cib/internal.h>
#include <crm/common/output.h>
#include <crm/common/results.h>
#include <crm/common/scheduler.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libpacemaker_private.h"

int
pcmk__parse_cib(pcmk__output_t *out, const char *cib_source, xmlNodePtr *cib_object)
{
    // @COMPAT Take an enum for cib_source instead of trying to figure it out?
    const char *first = cib_source;

    if (cib_source == NULL) {
        return cib__signon_query(out, NULL, cib_object);
    }

    while (isspace(*first)) {
        first++;
    }

    if (*first == '<') {
        *cib_object = pcmk__xml_parse(cib_source);
    } else {
        *cib_object = pcmk__xml_read(cib_source);
    }

    return (*cib_object == NULL)? pcmk_rc_unpack_error : pcmk_rc_ok;
}

int
pcmk__verify(pcmk_scheduler_t *scheduler, pcmk__output_t *out,
             xmlNode **cib_object)
{
    /* @TODO The scheduler argument is needed only for pcmk__config_has_error
     * and pcmk__config_has_warning. When we reset the scheduler, we reset those
     * global variables. Otherwise, we could drop the argument and create our
     * own scheduler object locally. Then we could be confident that it has no
     * relevant state.
     *
     * We should improve this, possibly with an "enum pcmk__fail_type" pointer
     * argument or similar.
     */
    int rc = pcmk_rc_ok;
    xmlNode *status = NULL;

    pcmk__assert((cib_object != NULL) && (*cib_object != NULL));

    /* Without the CIB element, we can't get a schema to validate against, so
     * report that separately from validation
     */
    if (!pcmk__xe_is(*cib_object, PCMK_XE_CIB)) {
        out->err(out,
                 "Input is not a CIB (outermost element is %s not "
                 PCMK_XE_CIB ")",
                 pcmk__s((const char *) (*cib_object)->name, "unrecognizable"));
        rc = pcmk_rc_schema_validation;
        goto verify_done;
    }

    status = pcmk_find_cib_element(*cib_object, PCMK_XE_STATUS);
    if (status == NULL) {
        pcmk__xe_create(*cib_object, PCMK_XE_STATUS);
    }

    if (!pcmk__validate_xml(*cib_object, (xmlRelaxNGValidityErrorFunc) out->err,
                            out)) {
        pcmk__config_has_error = true;
        rc = pcmk_rc_schema_validation;
        goto verify_done;
    }

    rc = pcmk__update_configured_schema(cib_object, false);
    if (rc != pcmk_rc_ok) {
        pcmk__config_has_error = true;
        out->err(out, "The cluster will NOT be able to use this configuration.\n"
                 "Please manually update the configuration to conform to the %s syntax.",
                 pcmk__highest_schema_name());
        goto verify_done;
    }

    /* Process the configuration to set pcmk__config_has_error and
     * pcmk__config_has_warning.
     *
     * @TODO Some parts of the configuration are unpacked only when needed (for
     * example, action configuration), so we aren't necessarily checking those.
     */
    if (*cib_object != NULL) {
        scheduler->input = *cib_object;

        pcmk__set_scheduler_flags(scheduler, pcmk__sched_no_counts);
        if (status == NULL) {
            // No status available, so do minimal checks
            pcmk__set_scheduler_flags(scheduler, pcmk__sched_validate_only);
        }
        pcmk__schedule_actions(scheduler);

        scheduler->input = NULL;
    }

verify_done:
    if (pcmk__config_has_error) {
        rc = pcmk_rc_schema_validation;
        pcmk__config_err("CIB did not pass schema validation");
    } else if (pcmk__config_has_warning) {
        rc = pcmk_rc_schema_validation;
    }
    return rc;
}

int
pcmk_verify(xmlNodePtr *xml, const char *cib_source)
{
    pcmk_scheduler_t *scheduler = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    xmlNode *cib_object = NULL;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    rc = pcmk__parse_cib(out, cib_source, &cib_object);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Verification failed: %s", pcmk_rc_str(rc));
        goto done;
    }

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        rc = errno;
        out->err(out, "Couldn't allocate scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }

    scheduler->priv->out = out;
    rc = pcmk__verify(scheduler, out, &cib_object);

done:
    pcmk_free_scheduler(scheduler);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    pcmk__xml_free(cib_object);
    return rc;
}
