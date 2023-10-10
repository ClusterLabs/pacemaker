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

static pcmk_scheduler_t *fenced_data_set = NULL;

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
 * \brief Check whether our uname is in a resource's allowed node list
 *
 * \param[in] rsc  Resource to check
 *
 * \return Pointer to node object if found, NULL otherwise
 */
static pcmk_node_t *
our_node_allowed_for(const pcmk_resource_t *rsc)
{
    GHashTableIter iter;
    pcmk_node_t *node = NULL;

    if (rsc && stonith_our_uname) {
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if (node && strcmp(node->details->uname, stonith_our_uname) == 0) {
                break;
            }
            node = NULL;
        }
    }
    return node;
}

#define rsc_name(x) x->clone_name?x->clone_name:x->id

/*!
 * \internal
 * \brief If a resource or any of its children are STONITH devices, update their
 *        definitions given a cluster working set.
 *
 * \param[in,out] data       Resource to check
 * \param[in,out] user_data  Cluster working set with device information
 */
static void
cib_device_update(pcmk_resource_t *rsc, pcmk_scheduler_t *data_set)
{
    pcmk_node_t *node = NULL;
    const char *value = NULL;
    const char *rclass = NULL;
    pcmk_node_t *parent = NULL;

    /* If this is a complex resource, check children rather than this resource itself. */
    if(rsc->children) {
        GList *gIter = NULL;
        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            cib_device_update(gIter->data, data_set);
            if(pe_rsc_is_clone(rsc)) {
                crm_trace("Only processing one copy of the clone %s", rsc->id);
                break;
            }
        }
        return;
    }

    /* We only care about STONITH resources. */
    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    if (!pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        return;
    }

    /* If this STONITH resource is disabled, remove it. */
    if (pe__resource_is_disabled(rsc)) {
        crm_info("Device %s has been disabled", rsc->id);
        return;
    }

    /* if watchdog-fencing is disabled handle any watchdog-fence
       resource as if it was disabled
     */
    if ((stonith_watchdog_timeout_ms <= 0) &&
        pcmk__str_eq(rsc->id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
        crm_info("Watchdog-fencing disabled thus handling "
                 "device %s as disabled", rsc->id);
        return;
    }

    /* Check whether our node is allowed for this resource (and its parent if in a group) */
    node = our_node_allowed_for(rsc);
    if (rsc->parent && (rsc->parent->variant == pcmk_rsc_variant_group)) {
        parent = our_node_allowed_for(rsc->parent);
    }

    if(node == NULL) {
        /* Our node is disallowed, so remove the device */
        GHashTableIter iter;

        crm_info("Device %s has been disabled on %s: unknown", rsc->id, stonith_our_uname);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            crm_trace("Available: %s = %d", pe__node_name(node), node->weight);
        }

        return;

    } else if(node->weight < 0 || (parent && parent->weight < 0)) {
        /* Our node (or its group) is disallowed by score, so remove the device */
        int score = (node->weight < 0)? node->weight : parent->weight;

        crm_info("Device %s has been disabled on %s: score=%s",
                 rsc->id, stonith_our_uname, pcmk_readable_score(score));
        return;

    } else {
        /* Our node is allowed, so update the device information */
        int rc;
        xmlNode *data;
        GHashTable *rsc_params = NULL;
        GHashTableIter gIter;
        stonith_key_value_t *params = NULL;

        const char *name = NULL;
        const char *agent = crm_element_value(rsc->xml, XML_EXPR_ATTR_TYPE);
        const char *rsc_provides = NULL;

        crm_debug("Device %s is allowed on %s: score=%d", rsc->id, stonith_our_uname, node->weight);
        rsc_params = pe_rsc_params(rsc, node, data_set);
        get_meta_attributes(rsc->meta, rsc, node, data_set);

        rsc_provides = g_hash_table_lookup(rsc->meta, PCMK_STONITH_PROVIDES);

        g_hash_table_iter_init(&gIter, rsc_params);
        while (g_hash_table_iter_next(&gIter, (gpointer *) & name, (gpointer *) & value)) {
            if (!name || !value) {
                continue;
            }
            params = stonith_key_value_add(params, name, value);
            crm_trace(" %s=%s", name, value);
        }

        data = create_device_registration_xml(rsc_name(rsc), st_namespace_any,
                                              agent, params, rsc_provides);
        stonith_key_value_freeall(params, 1, 1);
        rc = stonith_device_register(data, TRUE);
        CRM_ASSERT(rc == pcmk_ok);
        free_xml(data);
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
    g_list_foreach(fenced_data_set->resources, (GFunc) cib_device_update,
                   fenced_data_set);

    fenced_data_set->input = NULL; // Wasn't a copy, so don't let API free it
    pe_reset_working_set(fenced_data_set);
}
