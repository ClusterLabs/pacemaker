/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
    // @TODO Deprecate, replacing with a safer public alternative if necessary
    const char *new_version = NULL;
    xmlNode *section = NULL;

    if ((scheduler == NULL) || (scheduler->input == NULL)) {
        return FALSE;
    }

    if (pcmk_is_set(scheduler->flags, pcmk__sched_have_status)) {
        /* cluster_status() has already been called since the last time the
         * scheduler was reset. Unpacking the input CIB again would cause
         * duplication within the scheduler object's data structures.
         *
         * The correct return code here is not obvious. Nothing internal checks
         * the code, however.
         */
        return TRUE;
    }

    new_version = crm_element_value(scheduler->input, PCMK_XA_CRM_FEATURE_SET);

    if (pcmk__check_feature_set(new_version) != pcmk_rc_ok) {
        pcmk__config_err("Can't process CIB with feature set '%s' greater than our own '%s'",
                         new_version, CRM_FEATURE_SET);
        return FALSE;
    }

    crm_trace("Beginning unpack");

    pcmk__xml_free(scheduler->priv->failed);
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
    return TRUE;
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

pcmk_scheduler_t *
pe_new_working_set(void)
{
    return pcmk_new_scheduler();
}

void
pe_reset_working_set(pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return;
    }
    pcmk_reset_scheduler(scheduler);
}

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
    g_list_free_full(scheduler->priv->resources, pcmk__free_resource);

    crm_trace("deleting actions");
    g_list_free_full(scheduler->priv->actions, pcmk__free_action);

    crm_trace("deleting nodes");
    g_list_free_full(scheduler->nodes, pcmk__free_node);
    scheduler->nodes = NULL;

    pcmk__free_param_checks(scheduler);
    g_list_free(scheduler->priv->stop_needed);
    crm_time_free(scheduler->priv->now);
    pcmk__xml_free(scheduler->input);
    pcmk__xml_free(scheduler->priv->failed);
    pcmk__xml_free(scheduler->priv->graph);

    set_working_set_defaults(scheduler);

    CRM_LOG_ASSERT((scheduler->priv->location_constraints == NULL)
                   && (scheduler->priv->ordering_constraints == NULL));
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
    pcmk__set_scheduler_defaults(scheduler);
}

void
pe_free_working_set(pcmk_scheduler_t *scheduler)
{
    pcmk_free_scheduler(scheduler);
}

pcmk_node_t *
pe_find_node(const GList *nodes, const char *node_name)
{
    return pcmk__find_node_in_list(nodes, node_name);
}

// LCOV_EXCL_STOP
// End deprecated API
