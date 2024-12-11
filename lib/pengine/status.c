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

    if (scheduler == NULL) {
        return NULL;
    }
    scheduler->priv = calloc(1, sizeof(pcmk__scheduler_private_t));
    if (scheduler->priv == NULL) {
        free(scheduler);
        return NULL;
    }
    set_working_set_defaults(scheduler);
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
        free(scheduler->priv->local_node_name);
        free(scheduler->priv);
        free(scheduler);
    }
}

#define XPATH_DEPRECATED_RULES                          \
    "//" PCMK_XE_OP_DEFAULTS "//" PCMK_XE_EXPRESSION    \
    "|//" PCMK_XE_OP "//" PCMK_XE_EXPRESSION

/*!
 * \internal
 * \brief Log a warning for deprecated rule syntax in operations
 *
 * \param[in] scheduler  Scheduler data
 */
static void
check_for_deprecated_rules(pcmk_scheduler_t *scheduler)
{
    // @COMPAT Drop this function when support for the syntax is dropped
    xmlNode *deprecated = get_xpath_object(XPATH_DEPRECATED_RULES,
                                           scheduler->input, LOG_NEVER);

    if (deprecated != NULL) {
        pcmk__warn_once(pcmk__wo_op_attr_expr,
                        "Support for rules with node attribute expressions in "
                        PCMK_XE_OP " or " PCMK_XE_OP_DEFAULTS " is deprecated "
                        "and will be dropped in a future release");
    }
}

/*!
 * Unpack scheduler input
 *
 * At the end you'll have:
 *  - A list of nodes
 *  - A list of resources (each with any dependencies on other resources)
 *  - A list of constraints between resources and nodes
 *  - A list of constraints between start/stop actions
 *  - A list of nodes that need to be stonith'd
 *  - A list of nodes that need to be shutdown
 *  - A list of the possible stop/start actions (without dependencies)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_unpack_scheduler_input(pcmk_scheduler_t *scheduler)
{
    const char *new_version = NULL;
    xmlNode *section = NULL;

    if ((scheduler == NULL) || (scheduler->input == NULL)) {
        return EINVAL;
    }

    new_version = crm_element_value(scheduler->input, PCMK_XA_CRM_FEATURE_SET);

    if (pcmk__check_feature_set(new_version) != pcmk_rc_ok) {
        pcmk__config_err("Can't process CIB with feature set '%s' greater than our own '%s'",
                         new_version, CRM_FEATURE_SET);
        return pcmk_rc_schema_validation;
    }

    crm_trace("Beginning unpack");

    if (scheduler->priv->failed != NULL) {
        pcmk__xml_free(scheduler->priv->failed);
    }
    scheduler->priv->failed = pcmk__xe_create(NULL, "failed-ops");

    if (scheduler->priv->now == NULL) {
        scheduler->priv->now = crm_time_new(NULL);
    }

    if (pcmk__xe_attr_is_true(scheduler->input, PCMK_XA_HAVE_QUORUM)) {
        pcmk__set_scheduler_flags(scheduler, pcmk__sched_quorate);
    } else {
        pcmk__clear_scheduler_flags(scheduler, pcmk__sched_quorate);
    }

    scheduler->priv->op_defaults = get_xpath_object("//" PCMK_XE_OP_DEFAULTS,
                                                    scheduler->input,
                                                    LOG_NEVER);
    check_for_deprecated_rules(scheduler);

    scheduler->priv->rsc_defaults = get_xpath_object("//" PCMK_XE_RSC_DEFAULTS,
                                                     scheduler->input,
                                                     LOG_NEVER);

    section = get_xpath_object("//" PCMK_XE_CRM_CONFIG, scheduler->input,
                               LOG_TRACE);
    unpack_config(section, scheduler);

   if (!pcmk_any_flags_set(scheduler->flags,
                           pcmk__sched_location_only|pcmk__sched_quorate)
       && (scheduler->no_quorum_policy != pcmk_no_quorum_ignore)) {
        pcmk__sched_warn(scheduler,
                         "Fencing and resource management disabled "
                         "due to lack of quorum");
    }

    section = get_xpath_object("//" PCMK_XE_NODES, scheduler->input, LOG_TRACE);
    unpack_nodes(section, scheduler);

    section = get_xpath_object("//" PCMK_XE_RESOURCES, scheduler->input,
                               LOG_TRACE);
    if (!pcmk_is_set(scheduler->flags, pcmk__sched_location_only)) {
        unpack_remote_nodes(section, scheduler);
    }
    unpack_resources(section, scheduler);

    section = get_xpath_object("//" PCMK_XE_FENCING_TOPOLOGY, scheduler->input,
                               LOG_TRACE);
    pcmk__validate_fencing_topology(section);

    section = get_xpath_object("//" PCMK_XE_TAGS, scheduler->input, LOG_NEVER);
    unpack_tags(section, scheduler);

    if (!pcmk_is_set(scheduler->flags, pcmk__sched_location_only)) {
        section = get_xpath_object("//" PCMK_XE_STATUS, scheduler->input,
                                   LOG_TRACE);
        unpack_status(section, scheduler);
    }

    if (!pcmk_is_set(scheduler->flags, pcmk__sched_no_counts)) {
        for (GList *item = scheduler->priv->resources;
             item != NULL; item = item->next) {

            pcmk_resource_t *rsc = item->data;

            rsc->priv->fns->count(item->data);
        }
        crm_trace("Cluster resource count: %d (%d disabled, %d blocked)",
                  scheduler->priv->ninstances,
                  scheduler->priv->disabled_resources,
                  scheduler->priv->blocked_resources);
    }

    if ((scheduler->priv->local_node_name != NULL)
        && (pcmk_find_node(scheduler,
                           scheduler->priv->local_node_name) == NULL)) {
        crm_info("Creating a fake local node for %s",
                 scheduler->priv->local_node_name);
        pe_create_node(scheduler->priv->local_node_name,
                       scheduler->priv->local_node_name, NULL, 0, scheduler);
    }

    pcmk__set_scheduler_flags(scheduler, pcmk__sched_have_status);
    return pcmk_rc_ok;
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
        rsc->priv->fns->free(rsc);
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
         * use node->private->name for Pacemaker Remote nodes.
         */
        crm_trace("Freeing node %s", (pcmk__is_pacemaker_remote_node(node)?
                  "(guest or remote)" : pcmk__node_name(node)));

        if (node->priv->attrs != NULL) {
            g_hash_table_destroy(node->priv->attrs);
        }
        if (node->priv->utilization != NULL) {
            g_hash_table_destroy(node->priv->utilization);
        }
        if (node->priv->digest_cache != NULL) {
            g_hash_table_destroy(node->priv->digest_cache);
        }
        g_list_free(node->details->running_rsc);
        g_list_free(node->priv->assigned_resources);
        free(node->priv);
        free(node->details);
        free(node->assign);
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

        g_list_free_full(cons->nodes, pcmk__free_node_copy);
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

    pcmk__clear_scheduler_flags(scheduler, pcmk__sched_have_status);
    if (scheduler->priv->options != NULL) {
        g_hash_table_destroy(scheduler->priv->options);
    }

    if (scheduler->priv->singletons != NULL) {
        g_hash_table_destroy(scheduler->priv->singletons);
    }

    if (scheduler->priv->ticket_constraints != NULL) {
        g_hash_table_destroy(scheduler->priv->ticket_constraints);
    }

    if (scheduler->priv->templates != NULL) {
        g_hash_table_destroy(scheduler->priv->templates);
    }

    if (scheduler->priv->tags != NULL) {
        g_hash_table_destroy(scheduler->priv->tags);
    }

    crm_trace("deleting resources");
    pe_free_resources(scheduler->priv->resources);

    crm_trace("deleting actions");
    pe_free_actions(scheduler->priv->actions);

    crm_trace("deleting nodes");
    pe_free_nodes(scheduler->nodes);

    pe__free_param_checks(scheduler);
    g_list_free(scheduler->priv->stop_needed);
    crm_time_free(scheduler->priv->now);
    pcmk__xml_free(scheduler->input);
    pcmk__xml_free(scheduler->priv->failed);
    pcmk__xml_free(scheduler->priv->graph);

    set_working_set_defaults(scheduler);

    CRM_LOG_ASSERT((scheduler->priv->location_constraints == NULL)
                   && (scheduler->priv->ordering_constraints == NULL));
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
              g_list_length(scheduler->priv->ordering_constraints));
    pe__free_ordering(scheduler->priv->ordering_constraints);
    scheduler->priv->ordering_constraints = NULL;

    crm_trace("Deleting %d location constraints",
              g_list_length(scheduler->priv->location_constraints));
    pe__free_location(scheduler->priv->location_constraints);
    scheduler->priv->location_constraints = NULL;

    crm_trace("Deleting %d colocation constraints",
              g_list_length(scheduler->priv->colocation_constraints));
    g_list_free_full(scheduler->priv->colocation_constraints, free);
    scheduler->priv->colocation_constraints = NULL;

    cleanup_calculations(scheduler);
}

void
set_working_set_defaults(pcmk_scheduler_t *scheduler)
{
    // These members must be preserved
    pcmk__scheduler_private_t *priv = scheduler->priv;
    pcmk__output_t *out = priv->out;
    char *local_node_name = scheduler->priv->local_node_name;

    // Wipe the main structs (any other members must have previously been freed)
    memset(scheduler, 0, sizeof(pcmk_scheduler_t));
    memset(priv, 0, sizeof(pcmk__scheduler_private_t));

    // Restore the members to preserve
    scheduler->priv = priv;
    scheduler->priv->out = out;
    scheduler->priv->local_node_name = local_node_name;

    // Set defaults for everything else
    scheduler->priv->next_ordering_id = 1;
    scheduler->priv->next_action_id = 1;
    scheduler->no_quorum_policy = pcmk_no_quorum_stop;
#if PCMK__CONCURRENT_FENCING_DEFAULT_TRUE
    pcmk__set_scheduler_flags(scheduler,
                              pcmk__sched_symmetric_cluster
                              |pcmk__sched_concurrent_fencing
                              |pcmk__sched_stop_removed_resources
                              |pcmk__sched_cancel_removed_actions);
#else
    pcmk__set_scheduler_flags(scheduler,
                              pcmk__sched_symmetric_cluster
                              |pcmk__sched_stop_removed_resources
                              |pcmk__sched_cancel_removed_actions);
#endif
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
        pcmk_resource_t *match = parent->priv->fns->find_rsc(parent, id, NULL,
                                                             flags);

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
        match = pcmk__find_node_in_list(nodes, uname);
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
        if (pcmk__str_eq(node->priv->id, id, pcmk__str_casei)) {
            return node;
        }
    }
    return NULL;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/pengine/status_compat.h>

gboolean
cluster_status(pcmk_scheduler_t * scheduler)
{
    return pcmk_unpack_scheduler_input(scheduler) == pcmk_rc_ok;
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
    return pcmk__find_node_in_list(nodes, node_name);
}

// LCOV_EXCL_STOP
// End deprecated API
