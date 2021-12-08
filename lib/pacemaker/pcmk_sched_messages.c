/*
 * Copyright 2004-2021 the Pacemaker project contributors
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
#include <crm/common/ipc_internal.h>
#include "libpacemaker_private.h"

extern bool pcmk__is_daemon;

static void
log_resource_details(pe_working_set_t *data_set)
{
    pcmk__output_t *out = data_set->priv;
    GList *all = NULL;

    /* We need a list of nodes that we are allowed to output information for.
     * This is necessary because out->message for all the resource-related
     * messages expects such a list, due to the `crm_mon --node=` feature.  Here,
     * we just make it a list of all the nodes.
     */
    all = g_list_prepend(all, (gpointer) "*");

    for (GList *item = data_set->resources; item != NULL; item = item->next) {
        pe_resource_t *rsc = (pe_resource_t *) item->data;

        // Log all resources except inactive orphans
        if (!pcmk_is_set(rsc->flags, pe_rsc_orphan)
            || (rsc->role != RSC_ROLE_STOPPED)) {
            out->message(out, crm_map_element_name(rsc->xml), 0, rsc, all, all);
        }
    }

    g_list_free(all);
}

static void
log_all_actions(pe_working_set_t *data_set)
{
    /* This only ever outputs to the log, so ignore whatever output object was
     * previously set and just log instead.
     */
    pcmk__output_t *prev_out = data_set->priv;
    pcmk__output_t *out = pcmk__new_logger();

    if (out == NULL) {
        return;
    }

    pcmk__output_set_log_level(out, LOG_NOTICE);
    data_set->priv = out;

    out->begin_list(out, NULL, NULL, "Actions");
    LogNodeActions(data_set);

    for (GList *iter = data_set->resources; iter != NULL; iter = iter->next) {
        pe_resource_t *rsc = (pe_resource_t *) iter->data;

        rsc->cmds->output_actions(rsc);
    }

    out->end_list(out);
    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);

    data_set->priv = prev_out;
}

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
    GList *gIter = NULL;

    CRM_ASSERT(xml_input || pcmk_is_set(data_set->flags, pe_flag_have_status));

    if (!pcmk_is_set(data_set->flags, pe_flag_have_status)) {
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
    if (!pcmk_is_set(data_set->flags, pe_flag_quick_location) &&
         pcmk__is_daemon) {
        log_resource_details(data_set);
    }

    crm_trace("Applying location constraints");
    stage2(data_set);

    if (pcmk_is_set(data_set->flags, pe_flag_quick_location)) {
        return NULL;
    }

    pcmk__create_internal_constraints(data_set);

    crm_trace("Check actions");
    stage4(data_set);

    crm_trace("Allocate resources");
    stage5(data_set);

    crm_trace("Processing fencing and shutdown cases");
    stage6(data_set);

    pcmk__apply_orderings(data_set);
    log_all_actions(data_set);

    crm_trace("Create transition graph");
    stage8(data_set);

    crm_trace("=#=#=#=#= Summary =#=#=#=#=");
    crm_trace("\t========= Set %d (Un-runnable) =========", -1);
    if (get_crm_log_level() == LOG_TRACE) {
        gIter = data_set->actions;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_action_t *action = (pe_action_t *) gIter->data;

            if (!pcmk_any_flags_set(action->flags,
                                    pe_action_optional
                                    |pe_action_runnable
                                    |pe_action_pseudo)) {
                pcmk__log_action("\t", action, true);
            }
        }
    }

    return data_set->graph;
}
