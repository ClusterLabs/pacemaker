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
#include <glib.h>

#include <crm/pengine/status.h>
#include <crm/pengine/internal.h>

#include <pacemaker-internal.h>
#include <pacemaker-fenced.h>

static pcmk_scheduler_t *scheduler = NULL;

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

    scheduler = pe_new_working_set();
    if (scheduler == NULL) {
        pcmk__output_free(logger);
        return ENOMEM;
    }

    pe__register_messages(logger);
    pcmk__register_lib_messages(logger);
    pcmk__output_set_log_level(logger, LOG_TRACE);
    scheduler->priv = logger;

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Free all scheduler-related resources
 */
void
fenced_scheduler_cleanup(void)
{
    if (scheduler != NULL) {
        pcmk__output_t *logger = scheduler->priv;

        if (logger != NULL) {
            logger->finish(logger, CRM_EX_OK, true, NULL);
            pcmk__output_free(logger);
            scheduler->priv = NULL;
        }
        pe_free_working_set(scheduler);
        scheduler = NULL;
    }
}

/*!
 * \internal
 * \brief Check whether the local node is in a resource's allowed node list
 *
 * \param[in] rsc  Resource to check
 *
 * \return Pointer to node if found, otherwise NULL
 */
static pcmk_node_t *
local_node_allowed_for(const pcmk_resource_t *rsc)
{
    if ((rsc != NULL) && (stonith_our_uname != NULL)) {
        GHashTableIter iter;
        pcmk_node_t *node = NULL;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &node)) {
            if (pcmk__str_eq(node->details->uname, stonith_our_uname,
                             pcmk__str_casei)) {
                return node;
            }
        }
    }
    return NULL;
}

/*!
 * \internal
 * \brief If a given resource or any of its children are fencing devices,
 *        register the devices
 *
 * \param[in,out] data       Resource to check
 * \param[in,out] user_data  Ignored
 */
static void
register_if_fencing_device(gpointer data, gpointer user_data)
{
    pcmk_resource_t *rsc = data;

    xmlNode *xml = NULL;
    GHashTableIter hash_iter;
    pcmk_node_t *node = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *rclass = NULL;
    const char *agent = NULL;
    const char *rsc_provides = NULL;
    stonith_key_value_t *params = NULL;

    // If this is a collective resource, check children instead
    if (rsc->children != NULL) {
        for (GList *iter = rsc->children; iter != NULL; iter = iter->next) {
            register_if_fencing_device(iter->data, NULL);
            if (pe_rsc_is_clone(rsc)) {
                return; // Only one instance needs to be checked for clones
            }
        }
        return;
    }

    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    if (!pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        return; // Not a fencing device
    }

    if (pe__resource_is_disabled(rsc)) {
        crm_info("Ignoring fencing device %s because it is disabled", rsc->id);
        return;
    }

    if ((stonith_watchdog_timeout_ms <= 0) &&
        pcmk__str_eq(rsc->id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
        crm_info("Ignoring fencing device %s "
                 "because watchdog fencing is disabled", rsc->id);
        return;
    }

    // Check whether local node is allowed to run resource
    node = local_node_allowed_for(rsc);
    if (node == NULL) {
        crm_info("Ignoring fencing device %s "
                 "because local node is not allowed to run it", rsc->id);
        return;
    }
    if (node->weight < 0) {
        crm_info("Ignoring fencing device %s "
                 "because local node has preference %s for it",
                 rsc->id, pcmk_readable_score(node->weight));
        return;
    }

    // If device is in a group, check whether local node is allowed for group
    if ((rsc->parent != NULL)
        && (rsc->parent->variant == pcmk_rsc_variant_group)) {
        pcmk_node_t *group_node = local_node_allowed_for(rsc->parent);

        if ((group_node != NULL) && (group_node->weight < 0)) {
            crm_info("Ignoring fencing device %s "
                     "because local node has preference %s for its group",
                     rsc->id, pcmk_readable_score(group_node->weight));
            return;
        }
    }

    crm_debug("Reloading configuration of fencing device %s", rsc->id);

    agent = crm_element_value(rsc->xml, XML_ATTR_TYPE);

    get_meta_attributes(rsc->meta, rsc, node, scheduler);
    rsc_provides = g_hash_table_lookup(rsc->meta, PCMK_STONITH_PROVIDES);

    g_hash_table_iter_init(&hash_iter, pe_rsc_params(rsc, node, scheduler));
    while (g_hash_table_iter_next(&hash_iter, (gpointer *) &name,
                                  (gpointer *) &value)) {
        if ((name == NULL) || (value == NULL)) {
            continue;
        }
        params = stonith_key_value_add(params, name, value);
    }

    xml = create_device_registration_xml(pcmk__s(rsc->clone_name, rsc->id),
                                         st_namespace_any, agent, params,
                                         rsc_provides);
    stonith_key_value_freeall(params, 1, 1);
    CRM_ASSERT(stonith_device_register(xml, TRUE) == pcmk_ok);
    free_xml(xml);
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
    CRM_CHECK((cib != NULL) && (scheduler != NULL), return);

    if (scheduler->now != NULL) {
        crm_time_free(scheduler->now);
        scheduler->now = NULL;
    }
    scheduler->localhost = stonith_our_uname;
    pcmk__schedule_actions(cib, pcmk_sched_location_only
                                |pcmk_sched_no_compat
                                |pcmk_sched_no_counts, scheduler);
    g_list_foreach(scheduler->resources, register_if_fencing_device, NULL);

    scheduler->input = NULL; // Wasn't a copy, so don't let API free it
    pe_reset_working_set(scheduler);
}
