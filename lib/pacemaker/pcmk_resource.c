/*
 * Copyright 2021-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <glib.h>
#include <libxml/tree.h>

#include <crm/cib/internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/results.h>
#include <crm/common/output_internal.h>
#include <crm/pengine/internal.h>

#include <pacemaker.h>
#include <pacemaker-internal.h>

// Search path for resource operation history (takes node name and resource ID)
#define XPATH_OP_HISTORY "//" PCMK_XE_STATUS                            \
                         "/" PCMK__XE_NODE_STATE                        \
                         "[@" PCMK_XA_UNAME "='%s']"                    \
                         "/" PCMK__XE_LRM "/" PCMK__XE_LRM_RESOURCES    \
                         "/" PCMK__XE_LRM_RESOURCE "[@" PCMK_XA_ID "='%s']"

static xmlNode *
best_op(const pcmk_resource_t *rsc, const pcmk_node_t *node)
{
    char *xpath = NULL;
    xmlNode *history = NULL;
    xmlNode *best = NULL;
    bool best_effective_op = false;
    guint best_interval = 0;
    bool best_failure = false;
    const char *best_digest = NULL;

    // Find node's resource history
    xpath = crm_strdup_printf(XPATH_OP_HISTORY, node->details->uname, rsc->id);
    history = get_xpath_object(xpath, rsc->cluster->input, LOG_NEVER);
    free(xpath);

    // Examine each history entry
    for (xmlNode *lrm_rsc_op = pcmk__xe_first_child(history,
                                                    PCMK__XE_LRM_RSC_OP, NULL,
                                                    NULL);
         lrm_rsc_op != NULL; lrm_rsc_op = pcmk__xe_next_same(lrm_rsc_op)) {

        const char *digest = crm_element_value(lrm_rsc_op,
                                               PCMK__XA_OP_RESTART_DIGEST);
        guint interval_ms = 0;
        const char *task = crm_element_value(lrm_rsc_op, PCMK_XA_OPERATION);
        bool effective_op = false;
        bool failure = pcmk__ends_with(pcmk__xe_id(lrm_rsc_op),
                                       "_last_failure_0");


        crm_element_value_ms(lrm_rsc_op, PCMK_META_INTERVAL, &interval_ms);
        effective_op = interval_ms == 0
                       && pcmk__strcase_any_of(task, PCMK_ACTION_MONITOR,
                                               PCMK_ACTION_START,
                                               PCMK_ACTION_PROMOTE,
                                               PCMK_ACTION_MIGRATE_FROM, NULL);

        if (best == NULL) {
            goto is_best;
        }

        if (best_effective_op) {
            // Do not use an ineffective op if there's an effective one.
            if (!effective_op) {
                continue;
            }
        // Do not use an ineffective non-recurring op if there's a recurring one
        } else if (best_interval != 0
                   && !effective_op
                   && interval_ms == 0) {
            continue;
        }

        // Do not use last failure if there's a successful one.
        if (!best_failure && failure) {
            continue;
        }

        // Do not use an op without a restart digest if there's one with.
        if (best_digest != NULL && digest == NULL) {
            continue;
        }

        // Do not use an older op if there's a newer one.
        if (pe__is_newer_op(best, lrm_rsc_op, true) > 0) {
            continue;
        }

is_best:
         best = lrm_rsc_op;
         best_effective_op = effective_op;
         best_interval = interval_ms;
         best_failure = failure;
         best_digest = digest;
    }
    return best;
}

/*!
 * \internal
 * \brief Remove a resource
 *
 * \param[in,out] cib       An open connection to the CIB
 * \param[in]     cib_opts  Options to use in the CIB operation call
 * \param[in]     rsc_id    Resource to remove
 * \param[in]     rsc_type  Type of the resource ("primitive", "group", etc.)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__resource_delete(cib_t *cib, uint32_t cib_opts, const char *rsc_id,
                      const char *rsc_type)
{
    int rc = pcmk_rc_ok;
    xmlNode *msg_data = NULL;

    if (cib == NULL) {
        return ENOTCONN;
    }

    if (rsc_id == NULL || rsc_type == NULL) {
        return EINVAL;
    }

    msg_data = pcmk__xe_create(NULL, rsc_type);
    crm_xml_add(msg_data, PCMK_XA_ID, rsc_id);

    rc = cib->cmds->remove(cib, PCMK_XE_RESOURCES, msg_data, cib_opts);
    rc = pcmk_legacy2rc(rc);

    pcmk__xml_free(msg_data);
    return rc;
}

int
pcmk_resource_delete(xmlNodePtr *xml, const char *rsc_id, const char *rsc_type)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;
    uint32_t cib_opts = cib_sync_call;
    cib_t *cib = NULL;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    cib = cib_new();
    if (cib == NULL) {
        rc = pcmk_rc_cib_corrupt;
        goto done;
    }

    rc = cib->cmds->signon(cib, crm_system_name, cib_command);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = pcmk__resource_delete(cib, cib_opts, rsc_id, rsc_type);

done:
    if (cib != NULL) {
        cib__clean_up_connection(&cib);
    }

    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}

/*!
 * \internal
 * \brief Calculate and output resource operation digests
 *
 * \param[in,out] out        Output object
 * \param[in,out] rsc        Resource to calculate digests for
 * \param[in]     node       Node whose operation history should be used
 * \param[in]     overrides  Hash table of configuration parameters to override
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__resource_digests(pcmk__output_t *out, pcmk_resource_t *rsc,
                       const pcmk_node_t *node, GHashTable *overrides)
{
    const char *task = NULL;
    xmlNode *xml_op = NULL;
    pcmk__op_digest_t *digests = NULL;
    guint interval_ms = 0;
    int rc = pcmk_rc_ok;

    if ((out == NULL) || (rsc == NULL) || (node == NULL)) {
        return EINVAL;
    }
    if (rsc->variant != pcmk_rsc_variant_primitive) {
        // Only primitives get operation digests
        return EOPNOTSUPP;
    }

    // Find XML of operation history to use
    xml_op = best_op(rsc, node);

    // Generate an operation key
    if (xml_op != NULL) {
        task = crm_element_value(xml_op, PCMK_XA_OPERATION);
        crm_element_value_ms(xml_op, PCMK_META_INTERVAL, &interval_ms);
    }
    if (task == NULL) { // Assume start if no history is available
        task = PCMK_ACTION_START;
        interval_ms = 0;
    }

    // Calculate and show digests
    digests = pe__calculate_digests(rsc, task, &interval_ms, node, xml_op,
                                    overrides, true, rsc->cluster);
    rc = out->message(out, "digests", rsc, node, task, interval_ms, digests);

    pe__free_digests(digests);
    return rc;
}

// @COMPAT The scheduler parameter is unused and can be removed at the next break
int
pcmk_resource_digests(xmlNodePtr *xml, pcmk_resource_t *rsc,
                      const pcmk_node_t *node, GHashTable *overrides,
                      pcmk_scheduler_t *scheduler)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }
    pcmk__register_lib_messages(out);
    rc = pcmk__resource_digests(out, rsc, node, overrides);
    pcmk__xml_output_finish(out, pcmk_rc2exitc(rc), xml);
    return rc;
}
