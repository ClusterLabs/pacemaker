/*
 * Copyright 2009-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
*/

#include <crm_internal.h>

#include <stdio.h>
#include <errno.h>

#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>

#include <pacemaker-internal.h>
#include <pacemaker-fenced.h>

pcmk_scheduler_t *fenced_data_set = NULL;

/*!
 * \internal
 * \brief Initialize scheduler data for fencer purposes
 *
 * \return Standard Pacemaker return code
 */
int
fenced_scheduler_init(void)
{
    pcmk__output_t *logger = NULL;
    int rc = pcmk__log_output_new(&logger);

    if (rc != pcmk_rc_ok) {
        return rc;
    }

    fenced_data_set = pe_new_working_set();
    if (fenced_data_set == NULL) {
        pcmk__output_free(logger);
        return ENOMEM;
    }

    pe__register_messages(logger);
    pcmk__register_lib_messages(logger);
    pcmk__output_set_log_level(logger, LOG_TRACE);
    fenced_data_set->priv = logger;

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Free all scheduler-related resources
 */
void
fenced_scheduler_cleanup(void)
{
    if (fenced_data_set != NULL) {
        pcmk__output_t *logger = fenced_data_set->priv;

        if (logger != NULL) {
            logger->finish(logger, CRM_EX_OK, true, NULL);
            pcmk__output_free(logger);
            fenced_data_set->priv = NULL;
        }
        pe_free_working_set(fenced_data_set);
        fenced_data_set = NULL;
    }
}

/*!
 * \internal
 * \brief Run the scheduler for fencer purposes
 *
 * \param[in] cib  Cluster's current CIB
 */
void
fenced_scheduler_run(xmlNode *cib)
{
    CRM_CHECK((cib != NULL) && (fenced_data_set != NULL), return);

    if (fenced_data_set->now != NULL) {
        crm_time_free(fenced_data_set->now);
        fenced_data_set->now = NULL;
    }
    fenced_data_set->localhost = stonith_our_uname;
    pcmk__schedule_actions(cib, pcmk_sched_location_only
                                |pcmk_sched_no_compat
                                |pcmk_sched_no_counts, fenced_data_set);
}
