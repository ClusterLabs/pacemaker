/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/cib_internal.h>

#include <glib.h>

#include <crm/pengine/internal.h>
#include <pe_status_private.h>

/*!
 * \brief Create a new object to hold scheduler data
 *
 * \return New, initialized scheduler data on success, else NULL (and set errno)
 * \note Only pcmk_scheduler_t objects created with this function (as opposed
 *       to statically declared or directly allocated) should be used with the
 *       functions in this library, to allow for future extensions to the
 *       data type. The caller is responsible for freeing the memory with
 *       pe_free_working_set() when the instance is no longer needed.
 */
pcmk_scheduler_t *
pe_new_working_set(void)
{
    pcmk_scheduler_t *scheduler = calloc(1, sizeof(pcmk_scheduler_t));

    if (scheduler != NULL) {
        set_working_set_defaults(scheduler);
    }
    return scheduler;
}

/*!
 * \brief Free scheduler data
 *
 * \param[in,out] scheduler  Scheduler data to free
 */
void
pe_free_working_set(pcmk_scheduler_t *scheduler)
{
    if (scheduler != NULL) {
        pe_reset_working_set(scheduler);
        scheduler->priv = NULL;
        free(scheduler);
    }
}

/*
 * Unpack everything
 * At the end you'll have:
 *  - A list of nodes
 *  - A list of resources (each with any dependencies on other resources)
 *  - A list of constraints between resources and nodes
 *  - A list of constraints between start/stop actions
 *  - A list of nodes that need to be stonith'd
 *  - A list of nodes that need to be shutdown
 *  - A list of the possible stop/start actions (without dependencies)
 */
gboolean
cluster_status(pcmk_scheduler_t * scheduler)
{
    const char *new_version = NULL;
    xmlNode *section = NULL;

    if ((scheduler == NULL) || (scheduler->input == NULL)) {
        return FALSE;
    }

    new_version = crm_element_value(scheduler->input, PCMK_XA_CRM_FEATURE_SET);

    if (pcmk__check_feature_set(new_version) != pcmk_rc_ok) {
        pcmk__config_err("Can't process CIB with feature set '%s' greater than our own '%s'",
                         new_version, CRM_FEATURE_SET);
        return FALSE;
    }

    crm_trace("Beginning unpack");

    if (scheduler->failed != NULL) {
        free_xml(scheduler->failed);
    }
    scheduler->failed = create_xml_node(NULL, "failed-ops");

    if (scheduler->now == NULL) {
        scheduler->now = crm_time_new(NULL);
    }

    if (scheduler->dc_uuid == NULL) {
        scheduler->dc_uuid = crm_element_value_copy(scheduler->input,
                                                    PCMK_XA_DC_UUID);
    }

    if (pcmk__xe_attr_is_true(scheduler->input, PCMK_XA_HAVE_QUORUM)) {
        pcmk__set_scheduler_flags(scheduler, pcmk_sched_quorate);
    } else {
        pcmk__clear_scheduler_flags(scheduler, pcmk_sched_quorate);
    }

    scheduler->op_defaults = get_xpath_object("//" PCMK_XE_OP_DEFAULTS,
                                              scheduler->input, LOG_NEVER);
    scheduler->rsc_defaults = get_xpath_object("//" PCMK_XE_RSC_DEFAULTS,
                                               scheduler->input, LOG_NEVER);

    section = get_xpath_object("//" PCMK_XE_CRM_CONFIG, scheduler->input,
                               LOG_TRACE);
    unpack_config(section, scheduler);

   if (!pcmk_any_flags_set(scheduler->flags,
                           pcmk_sched_location_only|pcmk_sched_quorate)
       && (scheduler->no_quorum_policy != pcmk_no_quorum_ignore)) {
        pcmk__sched_warn("Fencing and resource management disabled "
                         "due to lack of quorum");
    }

    section = get_xpath_object("//" PCMK_XE_NODES, scheduler->input, LOG_TRACE);
    unpack_nodes(section, scheduler);

    section = get_xpath_object("//" PCMK_XE_RESOURCES, scheduler->input,
                               LOG_TRACE);
    if (!pcmk_is_set(scheduler->flags, pcmk_sched_location_only)) {
        unpack_remote_nodes(section, scheduler);
    }
    unpack_resources(section, scheduler);

    section = get_xpath_object("//" PCMK_XE_TAGS, scheduler->input, LOG_NEVER);
    unpack_tags(section, scheduler);

    if (!pcmk_is_set(scheduler->flags, pcmk_sched_location_only)) {
        section = get_xpath_object("//" PCMK_XE_STATUS, scheduler->input,
                                   LOG_TRACE);
        unpack_status(section, scheduler);
    }

    if (!pcmk_is_set(scheduler->flags, pcmk_sched_no_counts)) {
        for (GList *item = scheduler->resources; item != NULL;
             item = item->next) {
            ((pcmk_resource_t *) (item->data))->fns->count(item->data);
        }
        crm_trace("Cluster resource count: %d (%d disabled, %d blocked)",
                  scheduler->ninstances, scheduler->disabled_resources,
                  scheduler->blocked_resources);
    }

    pcmk__set_scheduler_flags(scheduler, pcmk_sched_have_status);
    return TRUE;
}

/*!
 * \internal
 * \brief Free a list of pcmk_resource_t
 *
 * \param[in,out] resources  List to free
 *
 * \note When the scheduler's resource list is freed, that includes the original
 *       storage for the uname and id of any Pacemaker Remote nodes in the
 *       scheduler's node list, so take care not to use those afterward.
 * \todo Refactor pcmk_node_t to strdup() the node name.
 */
static void
pe_free_resources(GList *resources)
{
    pcmk_resource_t *rsc = NULL;
    GList *iterator = resources;

    while (iterator != NULL) {
        rsc = (pcmk_resource_t *) iterator->data;
        iterator = iterator->next;
        rsc->fns->free(rsc);
    }
    if (resources != NULL) {
        g_list_free(resources);
    }
}

static void
pe_free_actions(GList *actions)
{
    GList *iterator = actions;

    while (iterator != NULL) {
        pe_free_action(iterator->data);
        iterator = iterator->next;
    }
    if (actions != NULL) {
        g_list_free(actions);
    }
}

static void
pe_free_nodes(GList *nodes)
{
    for (GList *iterator = nodes; iterator != NULL; iterator = iterator->next) {
        pcmk_node_t *node = (pcmk_node_t *) iterator->data;

        // Shouldn't be possible, but to be safe ...
        if (node == NULL) {
            continue;
        }
        if (node->details == NULL) {
            free(node);
            continue;
        }

        /* This is called after pe_free_resources(), which means that we can't
         * use node->details->uname for Pacemaker Remote nodes.
         */
        crm_trace("Freeing node %s", (pe__is_guest_or_remote_node(node)?
                  "(guest or remote)" : pcmk__node_name(node)));

        if (node->details->attrs != NULL) {
            g_hash_table_destroy(node->details->attrs);
        }
        if (node->details->utilization != NULL) {
            g_hash_table_destroy(node->details->utilization);
        }
        if (node->details->digest_cache != NULL) {
            g_hash_table_destroy(node->details->digest_cache);
        }
        g_list_free(node->details->running_rsc);
        g_list_free(node->details->allocated_rsc);
        free(node->details);
        free(node);
    }
    if (nodes != NULL) {
        g_list_free(nodes);
    }
}

static void
pe__free_ordering(GList *constraints)
{
    GList *iterator = constraints;

    while (iterator != NULL) {
        pcmk__action_relation_t *order = iterator->data;

        iterator = iterator->next;

        free(order->task1);
        free(order->task2);
        free(order);
    }
    if (constraints != NULL) {
        g_list_free(constraints);
    }
}

static void
pe__free_location(GList *constraints)
{
    GList *iterator = constraints;

    while (iterator != NULL) {
        pcmk__location_t *cons = iterator->data;

        iterator = iterator->next;

        g_list_free_full(cons->nodes, free);
        free(cons->id);
        free(cons);
    }
    if (constraints != NULL) {
        g_list_free(constraints);
    }
}

/*!
 * \brief Reset scheduler data to defaults without freeing it or constraints
 *
 * \param[in,out] scheduler  Scheduler data to reset
 *
 * \deprecated This function is deprecated as part of the API;
 *             pe_reset_working_set() should be used instead.
 */
void
cleanup_calculations(pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return;
    }

    pcmk__clear_scheduler_flags(scheduler, pcmk_sched_have_status);
    if (scheduler->config_hash != NULL) {
        g_hash_table_destroy(scheduler->config_hash);
    }

    if (scheduler->singletons != NULL) {
        g_hash_table_destroy(scheduler->singletons);
    }

    if (scheduler->tickets) {
        g_hash_table_destroy(scheduler->tickets);
    }

    if (scheduler->template_rsc_sets) {
        g_hash_table_destroy(scheduler->template_rsc_sets);
    }

    if (scheduler->tags) {
        g_hash_table_destroy(scheduler->tags);
    }

    free(scheduler->dc_uuid);

    crm_trace("deleting resources");
    pe_free_resources(scheduler->resources);

    crm_trace("deleting actions");
    pe_free_actions(scheduler->actions);

    crm_trace("deleting nodes");
    pe_free_nodes(scheduler->nodes);

    pe__free_param_checks(scheduler);
    g_list_free(scheduler->stop_needed);
    free_xml(scheduler->graph);
    crm_time_free(scheduler->now);
    free_xml(scheduler->input);
    free_xml(scheduler->failed);

    set_working_set_defaults(scheduler);

    CRM_CHECK(scheduler->ordering_constraints == NULL,;
        );
    CRM_CHECK(scheduler->placement_constraints == NULL,;
        );
}

/*!
 * \brief Reset scheduler data to default state without freeing it
 *
 * \param[in,out] scheduler  Scheduler data to reset
 */
void
pe_reset_working_set(pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return;
    }

    crm_trace("Deleting %d ordering constraints",
              g_list_length(scheduler->ordering_constraints));
    pe__free_ordering(scheduler->ordering_constraints);
    scheduler->ordering_constraints = NULL;

    crm_trace("Deleting %d location constraints",
              g_list_length(scheduler->placement_constraints));
    pe__free_location(scheduler->placement_constraints);
    scheduler->placement_constraints = NULL;

    crm_trace("Deleting %d colocation constraints",
              g_list_length(scheduler->colocation_constraints));
    g_list_free_full(scheduler->colocation_constraints, free);
    scheduler->colocation_constraints = NULL;

    crm_trace("Deleting %d ticket constraints",
              g_list_length(scheduler->ticket_constraints));
    g_list_free_full(scheduler->ticket_constraints, free);
    scheduler->ticket_constraints = NULL;

    cleanup_calculations(scheduler);
}

void
set_working_set_defaults(pcmk_scheduler_t *scheduler)
{
    void *priv = scheduler->priv;

    memset(scheduler, 0, sizeof(pcmk_scheduler_t));

    scheduler->priv = priv;
    scheduler->order_id = 1;
    scheduler->action_id = 1;
    scheduler->no_quorum_policy = pcmk_no_quorum_stop;

    scheduler->flags = 0x0ULL;

    pcmk__set_scheduler_flags(scheduler,
                              pcmk_sched_symmetric_cluster
                              |pcmk_sched_stop_removed_resources
                              |pcmk_sched_cancel_removed_actions);
    if (!strcmp(PCMK__CONCURRENT_FENCING_DEFAULT, PCMK_VALUE_TRUE)) {
        pcmk__set_scheduler_flags(scheduler, pcmk_sched_concurrent_fencing);
    }
}

pcmk_resource_t *
pe_find_resource(GList *rsc_list, const char *id)
{
    return pe_find_resource_with_flags(rsc_list, id, pcmk_rsc_match_history);
}

pcmk_resource_t *
pe_find_resource_with_flags(GList *rsc_list, const char *id, enum pe_find flags)
{
    GList *rIter = NULL;

    for (rIter = rsc_list; id && rIter; rIter = rIter->next) {
        pcmk_resource_t *parent = rIter->data;

        pcmk_resource_t *match =
            parent->fns->find_rsc(parent, id, NULL, flags);
        if (match != NULL) {
            return match;
        }
    }
    crm_trace("No match for %s", id);
    return NULL;
}

/*!
 * \brief Find a node by name or ID in a list of nodes
 *
 * \param[in] nodes      List of nodes (as pcmk_node_t*)
 * \param[in] id         If not NULL, ID of node to find
 * \param[in] node_name  If not NULL, name of node to find
 *
 * \return Node from \p nodes that matches \p id if any,
 *         otherwise node from \p nodes that matches \p uname if any,
 *         otherwise NULL
 */
pcmk_node_t *
pe_find_node_any(const GList *nodes, const char *id, const char *uname)
{
    pcmk_node_t *match = NULL;

    if (id != NULL) {
        match = pe_find_node_id(nodes, id);
    }
    if ((match == NULL) && (uname != NULL)) {
        match = pe_find_node(nodes, uname);
    }
    return match;
}

/*!
 * \brief Find a node by ID in a list of nodes
 *
 * \param[in] nodes  List of nodes (as pcmk_node_t*)
 * \param[in] id     ID of node to find
 *
 * \return Node from \p nodes that matches \p id if any, otherwise NULL
 */
pcmk_node_t *
pe_find_node_id(const GList *nodes, const char *id)
{
    for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;

        /* @TODO Whether node IDs should be considered case-sensitive should
         * probably depend on the node type, so functionizing the comparison
         * would be worthwhile
         */
        if (pcmk__str_eq(node->details->id, id, pcmk__str_casei)) {
            return node;
        }
    }
    return NULL;
}

/*!
 * \brief Find a node by name in a list of nodes
 *
 * \param[in] nodes      List of nodes (as pcmk_node_t*)
 * \param[in] node_name  Name of node to find
 *
 * \return Node from \p nodes that matches \p node_name if any, otherwise NULL
 */
pcmk_node_t *
pe_find_node(const GList *nodes, const char *node_name)
{
    for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
        pcmk_node_t *node = (pcmk_node_t *) iter->data;

        if (pcmk__str_eq(node->details->uname, node_name, pcmk__str_casei)) {
            return node;
        }
    }
    return NULL;
}
