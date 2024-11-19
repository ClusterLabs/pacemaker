/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <crm/cib/internal.h>
#include <crm/common/output.h>
#include <crm/common/results.h>
#include <crm/fencing/internal.h>
#include <crm/pengine/internal.h>
#include <crm/stonith-ng.h> // stonith__register_messages()
#include <pacemaker.h>
#include <pacemaker-internal.h>

static stonith_t *
fencing_connect(void)
{
    stonith_t *st = stonith_api_new();
    int rc = pcmk_rc_ok;

    if (st == NULL) {
        return NULL;
    }

    rc = st->cmds->connect(st, crm_system_name, NULL);
    if (rc == pcmk_rc_ok) {
        return st;
    } else {
        stonith_api_delete(st);
        return NULL;
    }
}

/*!
 * \internal
 * \brief Output the cluster status given a fencer and CIB connection
 *
 * \param[in,out] scheduler            Scheduler object (will be reset)
 * \param[in,out] stonith              Fencer connection
 * \param[in,out] cib                  CIB connection
 * \param[in]     current_cib          Current CIB XML
 * \param[in]     pcmkd_state          \p pacemakerd state
 * \param[in]     fence_history        How much of the fencing history to output
 * \param[in]     show                 Group of \p pcmk_section_e flags
 * \param[in]     show_opts            Group of \p pcmk_show_opt_e flags
 * \param[in]     only_node            If a node name or tag, include only the
 *                                     matching node(s) (if any) in the output.
 *                                     If \p "*" or \p NULL, include all nodes
 *                                     in the output.
 * \param[in]     only_rsc             If a resource ID or tag, include only the
 *                                     matching resource(s) (if any) in the
 *                                     output. If \p "*" or \p NULL, include all
 *                                     resources in the output.
 * \param[in]     neg_location_prefix  Prefix denoting a ban in a constraint ID
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__output_cluster_status(pcmk_scheduler_t *scheduler, stonith_t *stonith,
                            cib_t *cib, xmlNode *current_cib,
                            enum pcmk_pacemakerd_state pcmkd_state,
                            enum pcmk__fence_history fence_history,
                            uint32_t show, uint32_t show_opts,
                            const char *only_node, const char *only_rsc,
                            const char *neg_location_prefix)
{
    xmlNode *cib_copy = pcmk__xml_copy(NULL, current_cib);
    stonith_history_t *stonith_history = NULL;
    int history_rc = 0;
    GList *unames = NULL;
    GList *resources = NULL;
    pcmk__output_t *out = NULL;

    int rc = pcmk_rc_ok;

    if ((scheduler == NULL) || (scheduler->priv->out == NULL)) {
        return EINVAL;
    }
    out = scheduler->priv->out;

    rc = pcmk__update_configured_schema(&cib_copy, false);
    if (rc != pcmk_rc_ok) {
        cib__clean_up_connection(&cib);
        pcmk__xml_free(cib_copy);
        out->err(out, "Upgrade failed: %s", pcmk_rc_str(rc));
        return rc;
    }

    /* get the stonith-history if there is evidence we need it */
    if (fence_history != pcmk__fence_history_none) {
        history_rc = pcmk__get_fencing_history(stonith, &stonith_history,
                                               fence_history);
    }

    pe_reset_working_set(scheduler);
    scheduler->input = cib_copy;
    rc = pcmk_unpack_scheduler_input(scheduler);

    if (rc != pcmk_rc_ok) {
        /* Now that we've set up the scheduler, it's up to the caller to clean up.
         * Doing cleanup here can result in double frees of XML or CIB data.
         */
        return rc;
    }

    /* Unpack constraints if any section will need them
     * (tickets may be referenced in constraints but not granted yet,
     * and bans need negative location constraints) */
    if (pcmk_is_set(show, pcmk_section_bans)
        || pcmk_is_set(show, pcmk_section_tickets)) {
        pcmk__unpack_constraints(scheduler);
    }

    unames = pe__build_node_name_list(scheduler, only_node);
    resources = pe__build_rsc_list(scheduler, only_rsc);

    /* Always print DC if NULL. */
    if (scheduler->dc_node == NULL) {
        show |= pcmk_section_dc;
    }

    out->message(out, "cluster-status",
                 scheduler, pcmkd_state, pcmk_rc2exitc(history_rc),
                 stonith_history, fence_history, show, show_opts,
                 neg_location_prefix, unames, resources);

    g_list_free_full(unames, free);
    g_list_free_full(resources, free);

    stonith_history_free(stonith_history);
    stonith_history = NULL;
    return rc;
}

int
pcmk_status(xmlNodePtr *xml)
{
    cib_t *cib = NULL;
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    uint32_t show_opts = pcmk_show_pending
                         |pcmk_show_inactive_rscs
                         |pcmk_show_timing;

    cib = cib_new();

    if (cib == NULL) {
        return pcmk_rc_cib_corrupt;
    }

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        cib_delete(cib);
        return rc;
    }

    pcmk__register_lib_messages(out);
    pe__register_messages(out);
    stonith__register_messages(out);

    rc = pcmk__status(out, cib, pcmk__fence_history_full, pcmk_section_all,
                      show_opts, NULL, NULL, NULL, 0);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);

    cib_delete(cib);
    return rc;
}

/*!
 * \internal
 * \brief Query and output the cluster status
 *
 * The operation is considered a success if we're able to get the \p pacemakerd
 * state. If possible, we'll also try to connect to the fencer and CIB and
 * output their respective status information.
 *
 * \param[in,out] out                  Output object
 * \param[in,out] cib                  CIB connection
 * \param[in]     fence_history        How much of the fencing history to output
 * \param[in]     show                 Group of \p pcmk_section_e flags
 * \param[in]     show_opts            Group of \p pcmk_show_opt_e flags
 * \param[in]     only_node            If a node name or tag, include only the
 *                                     matching node(s) (if any) in the output.
 *                                     If \p "*" or \p NULL, include all nodes
 *                                     in the output.
 * \param[in]     only_rsc             If a resource ID or tag, include only the
 *                                     matching resource(s) (if any) in the
 *                                     output. If \p "*" or \p NULL, include all
 *                                     resources in the output.
 * \param[in]     neg_location_prefix  Prefix denoting a ban in a constraint ID
 * \param[in]     timeout_ms           How long to wait for a reply from the
 *                                     \p pacemakerd API. If 0,
 *                                     \p pcmk_ipc_dispatch_sync will be used.
 *                                     If positive, \p pcmk_ipc_dispatch_main
 *                                     will be used, and a new mainloop will be
 *                                     created for this purpose (freed before
 *                                     return).
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__status(pcmk__output_t *out, cib_t *cib,
             enum pcmk__fence_history fence_history, uint32_t show,
             uint32_t show_opts, const char *only_node, const char *only_rsc,
             const char *neg_location_prefix, unsigned int timeout_ms)
{
    xmlNode *current_cib = NULL;
    int rc = pcmk_rc_ok;
    stonith_t *stonith = NULL;
    enum pcmk_pacemakerd_state pcmkd_state = pcmk_pacemakerd_state_invalid;
    time_t last_updated = 0;
    pcmk_scheduler_t *scheduler = NULL;

    if (cib == NULL) {
        return ENOTCONN;
    }

    if (cib->variant == cib_native) {
        rc = pcmk__pacemakerd_status(out, crm_system_name, timeout_ms, false,
                                     &pcmkd_state);
        if (rc != pcmk_rc_ok) {
            return rc;
        }

        last_updated = time(NULL);

        switch (pcmkd_state) {
            case pcmk_pacemakerd_state_running:
            case pcmk_pacemakerd_state_shutting_down:
            case pcmk_pacemakerd_state_remote:
                /* Fencer and CIB may still be available while shutting down or
                 * running on a Pacemaker Remote node
                 */
                break;
            default:
                // Fencer and CIB are definitely unavailable
                out->message(out, "pacemakerd-health",
                             NULL, pcmkd_state, NULL, last_updated);
                return rc;
        }

        if (fence_history != pcmk__fence_history_none) {
            stonith = fencing_connect();
        }
    }

    rc = cib__signon_query(out, &cib, &current_cib);
    if (rc != pcmk_rc_ok) {
        if (pcmkd_state != pcmk_pacemakerd_state_invalid) {
            // Invalid at this point means we didn't query the pcmkd state
            out->message(out, "pacemakerd-health",
                         NULL, pcmkd_state, NULL, last_updated);
        }
        goto done;
    }

    scheduler = pe_new_working_set();
    pcmk__mem_assert(scheduler);
    scheduler->priv->out = out;

    if ((cib->variant == cib_native) && pcmk_is_set(show, pcmk_section_times)) {
        // Currently used only in the times section
        pcmk__query_node_name(out, 0, &(scheduler->priv->local_node_name), 0);
    }

    rc = pcmk__output_cluster_status(scheduler, stonith, cib, current_cib,
                                     pcmkd_state, fence_history, show,
                                     show_opts, only_node, only_rsc,
                                     neg_location_prefix);
    if (rc != pcmk_rc_ok) {
        out->err(out, "Error outputting status info from the fencer or CIB");
    }

done:
    pe_free_working_set(scheduler);
    stonith_api_delete(stonith);
    pcmk__xml_free(current_cib);
    return pcmk_rc_ok;
}
