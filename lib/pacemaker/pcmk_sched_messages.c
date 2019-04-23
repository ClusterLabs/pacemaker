/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include <crm/common/ipcs.h>

gboolean show_scores = FALSE;
int scores_log_level = LOG_TRACE;
gboolean show_utilization = FALSE;
int utilization_log_level = LOG_TRACE;

/*!
 * \internal
 * \brief Run the scheduler for a given CIB
 *
 * \param[in,out] data_set  Cluster working set
 * \param[in]     xml_input CIB XML to use as scheduler input
 * \param[in]     now       Time to use for rule evaluation (or NULL for now)
 */
xmlNode *
pcmk__schedule_actions(pe_working_set_t *data_set, xmlNode *xml_input,
                       crm_time_t *now)
{
    GListPtr gIter = NULL;
    int rsc_log_level = LOG_INFO;

/*	pe_debug_on(); */

    CRM_ASSERT(xml_input || is_set(data_set->flags, pe_flag_have_status));

    if (is_set(data_set->flags, pe_flag_have_status) == FALSE) {
        set_working_set_defaults(data_set);
        data_set->input = xml_input;
        data_set->now = now;

    } else {
        crm_trace("Already have status - reusing");
    }

    if (data_set->now == NULL) {
        data_set->now = crm_time_new(NULL);
    }

    crm_trace("Calculate cluster status");
    stage0(data_set);

    if(is_not_set(data_set->flags, pe_flag_quick_location)) {
        gIter = data_set->resources;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;

            if (is_set(rsc->flags, pe_rsc_orphan) && rsc->role == RSC_ROLE_STOPPED) {
                continue;
            }
            rsc->fns->print(rsc, NULL, pe_print_log, &rsc_log_level);
        }
    }

    crm_trace("Applying placement constraints");
    stage2(data_set);

    if(is_set(data_set->flags, pe_flag_quick_location)){
        return NULL;
    }

    crm_trace("Create internal constraints");
    stage3(data_set);

    crm_trace("Check actions");
    stage4(data_set);

    crm_trace("Allocate resources");
    stage5(data_set);

    crm_trace("Processing fencing and shutdown cases");
    stage6(data_set);

    crm_trace("Applying ordering constraints");
    stage7(data_set);

    crm_trace("Create transition graph");
    stage8(data_set);

    crm_trace("=#=#=#=#= Summary =#=#=#=#=");
    crm_trace("\t========= Set %d (Un-runnable) =========", -1);
    if (get_crm_log_level() >= LOG_TRACE) {
        gIter = data_set->actions;
        for (; gIter != NULL; gIter = gIter->next) {
            action_t *action = (action_t *) gIter->data;

            if (is_set(action->flags, pe_action_optional) == FALSE
                && is_set(action->flags, pe_action_runnable) == FALSE
                && is_set(action->flags, pe_action_pseudo) == FALSE) {
                log_action(LOG_TRACE, "\t", action, TRUE);
            }
        }
    }

    return data_set->graph;
}
