/*
 * Copyright 2021-2023 the Pacemaker project contributors
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

#include <crm/common/mainloop.h>
#include <crm/common/results.h>
#include <crm/common/output_internal.h>
#include <crm/pengine/internal.h>

#include <pacemaker.h>
#include <pacemaker-internal.h>

// Search path for resource operation history (takes node name and resource ID)
#define XPATH_OP_HISTORY "//" XML_CIB_TAG_STATUS                            \
                         "/" XML_CIB_TAG_STATE "[@" XML_ATTR_UNAME "='%s']" \
                         "/" XML_CIB_TAG_LRM "/" XML_LRM_TAG_RESOURCES      \
                         "/" XML_LRM_TAG_RESOURCE "[@" XML_ATTR_ID "='%s']"

static xmlNode *
best_op(const pe_resource_t *rsc, const pe_node_t *node)
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
    for (xmlNode *lrm_rsc_op = first_named_child(history, XML_LRM_TAG_RSC_OP);
         lrm_rsc_op != NULL; lrm_rsc_op = crm_next_same_xml(lrm_rsc_op)) {

        const char *digest = crm_element_value(lrm_rsc_op,
                                               XML_LRM_ATTR_RESTART_DIGEST);
        guint interval_ms = 0;
        const char *task = crm_element_value(lrm_rsc_op, XML_LRM_ATTR_TASK);
        bool effective_op = false;
        bool failure = pcmk__ends_with(ID(lrm_rsc_op), "_last_failure_0");


        crm_element_value_ms(lrm_rsc_op, XML_LRM_ATTR_INTERVAL, &interval_ms);
        effective_op = interval_ms == 0
                       && pcmk__strcase_any_of(task, PCMK_ACTION_MONITOR,
                                               PCMK_ACTION_START, RSC_PROMOTE,
                                               RSC_MIGRATED, NULL);

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
pcmk__resource_digests(pcmk__output_t *out, pe_resource_t *rsc,
                       const pe_node_t *node, GHashTable *overrides)
{
    const char *task = NULL;
    xmlNode *xml_op = NULL;
    op_digest_cache_t *digests = NULL;
    guint interval_ms = 0;
    int rc = pcmk_rc_ok;

    if ((out == NULL) || (rsc == NULL) || (node == NULL)) {
        return EINVAL;
    }
    if (rsc->variant != pe_native) {
        // Only primitives get operation digests
        return EOPNOTSUPP;
    }

    // Find XML of operation history to use
    xml_op = best_op(rsc, node);

    // Generate an operation key
    if (xml_op != NULL) {
        task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
        crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);
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

int
pcmk_resource_digests(xmlNodePtr *xml, pe_resource_t *rsc,
                      const pe_node_t *node, GHashTable *overrides,
                      pe_working_set_t *data_set)
{
    pcmk__output_t *out = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk__xml_output_new(&out, xml);
    if (rc != pcmk_rc_ok) {
        return rc;
    }
    pcmk__register_lib_messages(out);
    rc = pcmk__resource_digests(out, rsc, node, overrides);
    pcmk__xml_output_finish(out, xml);
    return rc;
}
