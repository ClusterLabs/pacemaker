/*
 * Copyright 2024-2025 the Pacemaker project contributors
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
#include <crm/fencing/internal.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>

#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Set up a pcmk__output_t, (optionally) cib_t, and
 *        (optionally) pcmk_scheduler_t for use in implementing
 *        public/private API function pairs
 *
 * \param[in,out] out       Where to store a \c pcmk__output_t object
 * \param[in,out] cib       Where to store a \c cib_t object
 *                          (may be \c NULL if a CIB is not needed)
 * \param[in,out] scheduler Where to store a \c pcmk_scheduler_t object
 *                          (may be \c NULL if a scheduler is not needed)
 * \param[in,out] xml       Where to write any result XML
 *
 * \note The \p cib and \p scheduler arguments will only be valid if there
 *       are no errors in this function.  However, \p out will always be
 *       valid unless there are errors setting it up so that other errors
 *       may still be reported.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__setup_output_cib_sched(pcmk__output_t **out, cib_t **cib,
                             pcmk_scheduler_t **scheduler, xmlNode **xml)
{
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if (cib != NULL) {
        *cib = cib_new();
        if (*cib == NULL) {
            return pcmk_rc_cib_corrupt;
        }

        rc = (*cib)->cmds->signon(*cib, crm_system_name, cib_command);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            cib__clean_up_connection(cib);
            return rc;
        }
    }

    if (scheduler != NULL) {
        rc = pcmk__init_scheduler(*out, NULL, NULL, scheduler);
        if (rc != pcmk_rc_ok && cib != NULL) {
            cib__clean_up_connection(cib);
            return rc;
        }

        pcmk__unpack_constraints(*scheduler);
    }

    pcmk__register_lib_messages(*out);
    return rc;
}

/*!
 * \internal
 * \brief Set up a pcmk__output_t and stonith_t for use in implementing
 *        public/private API function pairs
 *
 * \param[in,out] out       Where to store a \c pcmk__output_t object
 * \param[in,out] st        Where to store a \c stonith_t object
 * \param[in,out] xml       Where to write any result XML
 *
 * \note The \p st argument will only be valid if there are no errors in this
 *       function.  However, \p out will always be valid unless there are
 *       errors setting it up so that other errors may still be reported.
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__setup_output_fencing(pcmk__output_t **out, stonith_t **st, xmlNode **xml)
{
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    *st = stonith__api_new();
    if (*st == NULL) {
        return ENOMEM;
    }

    rc = (*st)->cmds->connect(*st, crm_system_name, NULL);
    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        stonith__api_free(*st);
        return rc;
    }

    pcmk__register_lib_messages(*out);
    stonith__register_messages(*out);
    return rc;
}
