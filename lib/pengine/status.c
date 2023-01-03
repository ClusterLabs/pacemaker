/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <crm/pengine/internal.h>
#include <pe_status_private.h>

/*!
 * \brief Create a new working set
 *
 * \return New, initialized working set on success, else NULL (and set errno)
 * \note Only pe_working_set_t objects created with this function (as opposed
 *       to statically declared or directly allocated) should be used with the
 *       functions in this library, to allow for future extensions to the
 *       data type. The caller is responsible for freeing the memory with
 *       pe_free_working_set() when the instance is no longer needed.
 */
pe_working_set_t *
pe_new_working_set(void)
{
    pe_working_set_t *data_set = calloc(1, sizeof(pe_working_set_t));

    if (data_set != NULL) {
        set_working_set_defaults(data_set);
    }
    return data_set;
}

/*!
 * \brief Free a working set
 *
 * \param[in,out] data_set  Working set to free
 */
void
pe_free_working_set(pe_working_set_t *data_set)
{
    if (data_set != NULL) {
        pe_reset_working_set(data_set);
        data_set->priv = NULL;
        free(data_set);
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
cluster_status(pe_working_set_t * data_set)
{
    xmlNode *section = NULL;

    if ((data_set == NULL) || (data_set->input == NULL)) {
        return FALSE;
    }

    crm_trace("Beginning unpack");

    if (data_set->failed != NULL) {
        free_xml(data_set->failed);
    }
    data_set->failed = create_xml_node(NULL, "failed-ops");

    if (data_set->now == NULL) {
        data_set->now = crm_time_new(NULL);
    }

    if (data_set->dc_uuid == NULL) {
        data_set->dc_uuid = crm_element_value_copy(data_set->input,
                                                   XML_ATTR_DC_UUID);
    }

    if (pcmk__xe_attr_is_true(data_set->input, XML_ATTR_HAVE_QUORUM)) {
        pe__set_working_set_flags(data_set, pe_flag_have_quorum);
    } else {
        pe__clear_working_set_flags(data_set, pe_flag_have_quorum);
    }

    data_set->op_defaults = get_xpath_object("//" XML_CIB_TAG_OPCONFIG,
                                             data_set->input, LOG_NEVER);
    data_set->rsc_defaults = get_xpath_object("//" XML_CIB_TAG_RSCCONFIG,
                                              data_set->input, LOG_NEVER);

    section = get_xpath_object("//" XML_CIB_TAG_CRMCONFIG, data_set->input,
                               LOG_TRACE);
    unpack_config(section, data_set);

   if (!pcmk_any_flags_set(data_set->flags,
                           pe_flag_quick_location|pe_flag_have_quorum)
       && (data_set->no_quorum_policy != no_quorum_ignore)) {
        crm_warn("Fencing and resource management disabled due to lack of quorum");
    }

    section = get_xpath_object("//" XML_CIB_TAG_NODES, data_set->input,
                               LOG_TRACE);
    unpack_nodes(section, data_set);

    section = get_xpath_object("//" XML_CIB_TAG_RESOURCES, data_set->input,
                               LOG_TRACE);
    if (!pcmk_is_set(data_set->flags, pe_flag_quick_location)) {
        unpack_remote_nodes(section, data_set);
    }
    unpack_resources(section, data_set);

    section = get_xpath_object("//" XML_CIB_TAG_TAGS, data_set->input,
                               LOG_NEVER);
    unpack_tags(section, data_set);

    if (!pcmk_is_set(data_set->flags, pe_flag_quick_location)) {
        section = get_xpath_object("//"XML_CIB_TAG_STATUS, data_set->input,
                                   LOG_TRACE);
        unpack_status(section, data_set);
    }

    if (!pcmk_is_set(data_set->flags, pe_flag_no_counts)) {
        for (GList *item = data_set->resources; item != NULL;
             item = item->next) {
            ((pe_resource_t *) (item->data))->fns->count(item->data);
        }
        crm_trace("Cluster resource count: %d (%d disabled, %d blocked)",
                  data_set->ninstances, data_set->disabled_resources,
                  data_set->blocked_resources);
    }

    pe__set_working_set_flags(data_set, pe_flag_have_status);
    return TRUE;
}

/*!
 * \internal
 * \brief Free a list of pe_resource_t
 *
 * \param[in,out] resources  List to free
 *
 * \note When a working set's resource list is freed, that includes the original
 *       storage for the uname and id of any Pacemaker Remote nodes in the
 *       working set's node list, so take care not to use those afterward.
 * \todo Refactor pe_node_t to strdup() the node name.
 */
static void
pe_free_resources(GList *resources)
{
    pe_resource_t *rsc = NULL;
    GList *iterator = resources;

    while (iterator != NULL) {
        rsc = (pe_resource_t *) iterator->data;
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
        pe_node_t *node = (pe_node_t *) iterator->data;

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
                  "(guest or remote)" : pe__node_name(node)));

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
        pe__ordering_t *order = iterator->data;

        iterator = iterator->next;

        free(order->lh_action_task);
        free(order->rh_action_task);
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
        pe__location_t *cons = iterator->data;

        iterator = iterator->next;

        g_list_free_full(cons->node_list_rh, free);
        free(cons->id);
        free(cons);
    }
    if (constraints != NULL) {
        g_list_free(constraints);
    }
}

/*!
 * \brief Reset working set to default state without freeing it or constraints
 *
 * \param[in,out] data_set  Working set to reset
 *
 * \deprecated This function is deprecated as part of the API;
 *             pe_reset_working_set() should be used instead.
 */
void
cleanup_calculations(pe_working_set_t * data_set)
{
    if (data_set == NULL) {
        return;
    }

    pe__clear_working_set_flags(data_set, pe_flag_have_status);
    if (data_set->config_hash != NULL) {
        g_hash_table_destroy(data_set->config_hash);
    }

    if (data_set->singletons != NULL) {
        g_hash_table_destroy(data_set->singletons);
    }

    if (data_set->tickets) {
        g_hash_table_destroy(data_set->tickets);
    }

    if (data_set->template_rsc_sets) {
        g_hash_table_destroy(data_set->template_rsc_sets);
    }

    if (data_set->tags) {
        g_hash_table_destroy(data_set->tags);
    }

    free(data_set->dc_uuid);

    crm_trace("deleting resources");
    pe_free_resources(data_set->resources);

    crm_trace("deleting actions");
    pe_free_actions(data_set->actions);

    crm_trace("deleting nodes");
    pe_free_nodes(data_set->nodes);

    pe__free_param_checks(data_set);
    g_list_free(data_set->stop_needed);
    free_xml(data_set->graph);
    crm_time_free(data_set->now);
    free_xml(data_set->input);
    free_xml(data_set->failed);

    set_working_set_defaults(data_set);

    CRM_CHECK(data_set->ordering_constraints == NULL,;
        );
    CRM_CHECK(data_set->placement_constraints == NULL,;
        );
}

/*!
 * \brief Reset a working set to default state without freeing it
 *
 * \param[in,out] data_set  Working set to reset
 */
void
pe_reset_working_set(pe_working_set_t *data_set)
{
    if (data_set == NULL) {
        return;
    }

    crm_trace("Deleting %d ordering constraints",
              g_list_length(data_set->ordering_constraints));
    pe__free_ordering(data_set->ordering_constraints);
    data_set->ordering_constraints = NULL;

    crm_trace("Deleting %d location constraints",
              g_list_length(data_set->placement_constraints));
    pe__free_location(data_set->placement_constraints);
    data_set->placement_constraints = NULL;

    crm_trace("Deleting %d colocation constraints",
              g_list_length(data_set->colocation_constraints));
    g_list_free_full(data_set->colocation_constraints, free);
    data_set->colocation_constraints = NULL;

    crm_trace("Deleting %d ticket constraints",
              g_list_length(data_set->ticket_constraints));
    g_list_free_full(data_set->ticket_constraints, free);
    data_set->ticket_constraints = NULL;

    cleanup_calculations(data_set);
}

void
set_working_set_defaults(pe_working_set_t * data_set)
{
    void *priv = data_set->priv;

    memset(data_set, 0, sizeof(pe_working_set_t));

    data_set->priv = priv;
    data_set->order_id = 1;
    data_set->action_id = 1;
    data_set->no_quorum_policy = no_quorum_stop;

    data_set->flags = 0x0ULL;

    pe__set_working_set_flags(data_set,
                              pe_flag_stop_rsc_orphans
                              |pe_flag_symmetric_cluster
                              |pe_flag_stop_action_orphans);
    if (!strcmp(PCMK__CONCURRENT_FENCING_DEFAULT, "true")) {
        pe__set_working_set_flags(data_set, pe_flag_concurrent_fencing);
    }
}

pe_resource_t *
pe_find_resource(GList *rsc_list, const char *id)
{
    return pe_find_resource_with_flags(rsc_list, id, pe_find_renamed);
}

pe_resource_t *
pe_find_resource_with_flags(GList *rsc_list, const char *id, enum pe_find flags)
{
    GList *rIter = NULL;

    for (rIter = rsc_list; id && rIter; rIter = rIter->next) {
        pe_resource_t *parent = rIter->data;

        pe_resource_t *match =
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
 * \param[in] nodes      List of nodes (as pe_node_t*)
 * \param[in] id         If not NULL, ID of node to find
 * \param[in] node_name  If not NULL, name of node to find
 *
 * \return Node from \p nodes that matches \p id if any,
 *         otherwise node from \p nodes that matches \p uname if any,
 *         otherwise NULL
 */
pe_node_t *
pe_find_node_any(const GList *nodes, const char *id, const char *uname)
{
    pe_node_t *match = NULL;

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
 * \param[in] nodes  List of nodes (as pe_node_t*)
 * \param[in] id     ID of node to find
 *
 * \return Node from \p nodes that matches \p id if any, otherwise NULL
 */
pe_node_t *
pe_find_node_id(const GList *nodes, const char *id)
{
    for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;

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
 * \param[in] nodes      List of nodes (as pe_node_t*)
 * \param[in] node_name  Name of node to find
 *
 * \return Node from \p nodes that matches \p node_name if any, otherwise NULL
 */
pe_node_t *
pe_find_node(const GList *nodes, const char *node_name)
{
    for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
        pe_node_t *node = (pe_node_t *) iter->data;

        if (pcmk__str_eq(node->details->uname, node_name, pcmk__str_casei)) {
            return node;
        }
    }
    return NULL;
}
