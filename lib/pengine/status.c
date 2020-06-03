/*
 * Copyright 2004-2020 the Pacemaker project contributors
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
pe_new_working_set()
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
 * \param[in] data_set  Working set to free
 */
void
pe_free_working_set(pe_working_set_t *data_set)
{
    if (data_set != NULL) {
        pe_reset_working_set(data_set);
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
    xmlNode *config = get_xpath_object("//"XML_CIB_TAG_CRMCONFIG, data_set->input, LOG_TRACE);
    xmlNode *cib_nodes = get_xpath_object("//"XML_CIB_TAG_NODES, data_set->input, LOG_TRACE);
    xmlNode *cib_resources = get_xpath_object("//"XML_CIB_TAG_RESOURCES, data_set->input, LOG_TRACE);
    xmlNode *cib_status = get_xpath_object("//"XML_CIB_TAG_STATUS, data_set->input, LOG_TRACE);
    xmlNode *cib_tags = get_xpath_object("//" XML_CIB_TAG_TAGS, data_set->input,
                                         LOG_NEVER);
    const char *value = crm_element_value(data_set->input, XML_ATTR_HAVE_QUORUM);

    crm_trace("Beginning unpack");

    /* reset remaining global variables */
    data_set->failed = create_xml_node(NULL, "failed-ops");

    if (data_set->input == NULL) {
        return FALSE;
    }

    if (data_set->now == NULL) {
        data_set->now = crm_time_new(NULL);
    }

    if (data_set->dc_uuid == NULL) {
        data_set->dc_uuid = crm_element_value_copy(data_set->input,
                                                   XML_ATTR_DC_UUID);
    }

    clear_bit(data_set->flags, pe_flag_have_quorum);
    if (crm_is_true(value)) {
        set_bit(data_set->flags, pe_flag_have_quorum);
    }

    data_set->op_defaults = get_xpath_object("//" XML_CIB_TAG_OPCONFIG,
                                             data_set->input, LOG_NEVER);
    data_set->rsc_defaults = get_xpath_object("//" XML_CIB_TAG_RSCCONFIG,
                                              data_set->input, LOG_NEVER);

    unpack_config(config, data_set);

   if (is_not_set(data_set->flags, pe_flag_quick_location)
       && is_not_set(data_set->flags, pe_flag_have_quorum)
       && data_set->no_quorum_policy != no_quorum_ignore) {
        crm_warn("Fencing and resource management disabled due to lack of quorum");
    }

    unpack_nodes(cib_nodes, data_set);

    if(is_not_set(data_set->flags, pe_flag_quick_location)) {
        unpack_remote_nodes(cib_resources, data_set);
    }

    unpack_resources(cib_resources, data_set);
    unpack_tags(cib_tags, data_set);

    if(is_not_set(data_set->flags, pe_flag_quick_location)) {
        unpack_status(cib_status, data_set);
    }

    if (is_not_set(data_set->flags, pe_flag_no_counts)) {
        for (GList *item = data_set->resources; item != NULL;
             item = item->next) {
            ((pe_resource_t *) (item->data))->fns->count(item->data);
        }
    }

    set_bit(data_set->flags, pe_flag_have_status);
    return TRUE;
}

/*!
 * \internal
 * \brief Free a list of pe_resource_t
 *
 * \param[in] resources  List to free
 *
 * \note When a working set's resource list is freed, that includes the original
 *       storage for the uname and id of any Pacemaker Remote nodes in the
 *       working set's node list, so take care not to use those afterward.
 * \todo Refactor pe_node_t to strdup() the node name.
 */
static void
pe_free_resources(GListPtr resources)
{
    pe_resource_t *rsc = NULL;
    GListPtr iterator = resources;

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
pe_free_actions(GListPtr actions)
{
    GListPtr iterator = actions;

    while (iterator != NULL) {
        pe_free_action(iterator->data);
        iterator = iterator->next;
    }
    if (actions != NULL) {
        g_list_free(actions);
    }
}

static void
pe_free_nodes(GListPtr nodes)
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
                  "(guest or remote)" : node->details->uname));

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
pe__free_ordering(GListPtr constraints)
{
    GListPtr iterator = constraints;

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
pe__free_location(GListPtr constraints)
{
    GListPtr iterator = constraints;

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

    clear_bit(data_set->flags, pe_flag_have_status);
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
    memset(data_set, 0, sizeof(pe_working_set_t));

    data_set->order_id = 1;
    data_set->action_id = 1;
    data_set->no_quorum_policy = no_quorum_stop;

    data_set->flags = 0x0ULL;
    set_bit(data_set->flags, pe_flag_stop_rsc_orphans);
    set_bit(data_set->flags, pe_flag_symmetric_cluster);
    set_bit(data_set->flags, pe_flag_stop_action_orphans);
#ifdef DEFAULT_CONCURRENT_FENCING_TRUE
    set_bit(data_set->flags, pe_flag_concurrent_fencing);
#endif
}

pe_resource_t *
pe_find_resource(GListPtr rsc_list, const char *id)
{
    return pe_find_resource_with_flags(rsc_list, id, pe_find_renamed);
}

pe_resource_t *
pe_find_resource_with_flags(GListPtr rsc_list, const char *id, enum pe_find flags)
{
    GListPtr rIter = NULL;

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

pe_node_t *
pe_find_node_any(GListPtr nodes, const char *id, const char *uname)
{
    pe_node_t *match = pe_find_node_id(nodes, id);

    if (match) {
        return match;
    }
    crm_trace("Looking up %s via its uname instead", uname);
    return pe_find_node(nodes, uname);
}

pe_node_t *
pe_find_node_id(GListPtr nodes, const char *id)
{
    GListPtr gIter = nodes;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (node && safe_str_eq(node->details->id, id)) {
            return node;
        }
    }
    /* error */
    return NULL;
}

pe_node_t *
pe_find_node(GListPtr nodes, const char *uname)
{
    GListPtr gIter = nodes;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (node && safe_str_eq(node->details->uname, uname)) {
            return node;
        }
    }
    /* error */
    return NULL;
}
