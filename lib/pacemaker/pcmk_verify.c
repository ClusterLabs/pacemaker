/*
 * Copyright 2023-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
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
    int rc = pcmk_rc_ok;

    if (cib_source == NULL) {
        crm_info("Reading XML from: live cluster");
        rc = cib__signon_query(out, NULL, cib_object);

    }  else if (cib_source[0] == '<') {
        *cib_object = string2xml(cib_source);
        if (*cib_object == NULL) {
            rc = ENODATA;
        }

    } else if (strcmp(cib_source, "-") == 0) {
        *cib_object = stdin2xml();
        if (*cib_object == NULL) {
            rc = ENODATA;
        }

    } else {
        *cib_object = filename2xml(cib_source);
        if (*cib_object == NULL) {
            rc = ENODATA;
        }
    }

    return rc;
}

int
pcmk__verify(pcmk_scheduler_t *scheduler, pcmk__output_t *out, xmlNode *cib_object)
{
    int rc = pcmk_rc_ok;
    xmlNode *status = NULL;
    xmlNode *cib_object_copy = NULL;

    if (!pcmk__xe_is(cib_object, PCMK_XE_CIB)) {
        rc = EBADMSG;
        out->err(out, "This tool can only check complete configurations (i.e. those starting with <cib>).");
        goto verify_done;
    }

    status = pcmk_find_cib_element(cib_object, XML_CIB_TAG_STATUS);
    if (status == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (pcmk__validate_xml(cib_object, NULL, (xmlRelaxNGValidityErrorFunc) out->err, out) == FALSE) {
        crm_config_error = TRUE;
        rc = pcmk_rc_schema_validation;
        goto verify_done;

    } else if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        crm_config_error = TRUE;
        out->err(out, "The cluster will NOT be able to use this configuration.\n"
                 "Please manually update the configuration to conform to the %s syntax.",
                 xml_latest_schema());
        rc = pcmk_rc_schema_validation;
        goto verify_done;
    }

    /* Process the configuration to set crm_config_error/crm_config_warning.
     *
     * @TODO Some parts of the configuration are unpacked only when needed (for
     * example, action configuration), so we aren't necessarily checking those.
     */
    if (cib_object != NULL) {
        unsigned long long flags = pcmk_sched_no_counts|pcmk_sched_no_compat;

        if (status == NULL) {
            // No status available, so do minimal checks
            flags |= pcmk_sched_validate_only;
        }
        cib_object_copy = copy_xml(cib_object);

        /* The scheduler takes ownership of the XML object and potentially
         * frees it later. We want the caller of pcmk__verify to retain
         * ownership of the passed-in XML object, hence we pass in a copy
         * to the scheduler.
         */ 
        pcmk__schedule_actions(cib_object_copy, flags, scheduler);
    }

verify_done:
    if (crm_config_error) {
        rc = pcmk_rc_schema_validation;
        pcmk__config_err("CIB did not pass schema validation");
    } else if (crm_config_warning) {
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
        out->err(out, "Couldn't parse input");
        goto done;
    }

    scheduler = pe_new_working_set();

    if (scheduler == NULL) {
        rc = errno;
        out->err(out, "Could not allocate scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }
    
    scheduler->priv = out;

    rc = pcmk__verify(scheduler, out, cib_object);
    
    pe_free_working_set(scheduler);

done:
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    if (cib_object != NULL) {
        free_xml(cib_object);      
    }

    return rc;
}