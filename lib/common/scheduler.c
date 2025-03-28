/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>             // uint32_t
#include <errno.h>              // EINVAL
#include <glib.h>               // gboolean, FALSE, etc.
#include <libxml/tree.h>        // xmlNode

#include <crm/common/scheduler.h>

uint32_t pcmk__warnings = 0;

/*!
 * \brief Create a new object to hold scheduler data
 *
 * \return New, initialized scheduler data, or NULL on memory error
 * \note Only pcmk_scheduler_t objects created with this function (as opposed
 *       to statically declared or directly allocated) should be used with the
 *       functions in this library, to allow for future extensions to the
 *       data type. The caller is responsible for freeing the memory with
 *       pcmk_free_scheduler() when the instance is no longer needed.
 */
pcmk_scheduler_t *
pcmk_new_scheduler(void)
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
    pcmk__set_scheduler_defaults(scheduler);
    return scheduler;
}

/*!
 * \internal
 * \brief Set non-zero default values in scheduler data
 *
 * \param[in,out] scheduler  Scheduler data to modify
 *
 * \note Values that default to NULL or 0 will remain unchanged
 */
void
pcmk__set_scheduler_defaults(pcmk_scheduler_t *scheduler)
{
    pcmk__assert(scheduler != NULL);
    scheduler->flags = 0U;
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
    scheduler->no_quorum_policy = pcmk_no_quorum_stop;
    scheduler->priv->next_action_id = 1;
    scheduler->priv->next_ordering_id = 1;
}

/*!
 * \brief Reset scheduler data to defaults
 *
 * Free scheduler data except the local node name and output object, and reset
 * all other values to defaults, so the data is suitable for rerunning status
 *
 * \param[in,out] scheduler  Scheduler data to reset
 */
void
pcmk_reset_scheduler(pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return;
    }

    /* Be careful about the order of freeing members. Many contain references to
     * other members that will become dangling if those members are freed first.
     * For example, the node name and ID of Pacemaker Remote nodes are pointers
     * into resource objects. Ensure that earlier-freed members are not needed
     * by any of the free functions for later-freed members.
     */

    scheduler->dc_node = NULL;

    g_list_free_full(scheduler->nodes, pcmk__free_node);
    scheduler->nodes = NULL;

    // Do not reset local_node_name or out

    crm_time_free(scheduler->priv->now);
    scheduler->priv->now = NULL;

    if (scheduler->priv->options != NULL) {
        g_hash_table_destroy(scheduler->priv->options);
        scheduler->priv->options = NULL;
    }

    scheduler->priv->fence_action = NULL;
    scheduler->priv->fence_timeout_ms = 0U;
    scheduler->priv->priority_fencing_ms = 0U;
    scheduler->priv->shutdown_lock_ms = 0U;
    scheduler->priv->node_pending_ms = 0U;
    scheduler->priv->placement_strategy = NULL;
    scheduler->priv->rsc_defaults = NULL;
    scheduler->priv->op_defaults = NULL;

    g_list_free_full(scheduler->priv->resources, pcmk__free_resource);
    scheduler->priv->resources = NULL;

    if (scheduler->priv->templates != NULL) {
        g_hash_table_destroy(scheduler->priv->templates);
        scheduler->priv->templates = NULL;
    }
    if (scheduler->priv->tags != NULL) {
        g_hash_table_destroy(scheduler->priv->tags);
        scheduler->priv->tags = NULL;
    }

    g_list_free_full(scheduler->priv->actions, pcmk__free_action);
    scheduler->priv->actions = NULL;

    if (scheduler->priv->singletons != NULL) {
        g_hash_table_destroy(scheduler->priv->singletons);
        scheduler->priv->singletons = NULL;
    }

    pcmk__xml_free(scheduler->priv->failed);
    scheduler->priv->failed = NULL;

    pcmk__free_param_checks(scheduler);

    g_list_free(scheduler->priv->stop_needed);
    scheduler->priv->stop_needed = NULL;

    g_list_free_full(scheduler->priv->location_constraints,
                     pcmk__free_location);
    scheduler->priv->location_constraints = NULL;

    g_list_free_full(scheduler->priv->colocation_constraints, free);
    scheduler->priv->colocation_constraints = NULL;

    g_list_free_full(scheduler->priv->ordering_constraints,
                     pcmk__free_action_relation);
    scheduler->priv->ordering_constraints = NULL;

    if (scheduler->priv->ticket_constraints != NULL) {
        g_hash_table_destroy(scheduler->priv->ticket_constraints);
        scheduler->priv->ticket_constraints = NULL;
    }

    scheduler->priv->ninstances = 0;
    scheduler->priv->blocked_resources = 0;
    scheduler->priv->disabled_resources = 0;
    scheduler->priv->recheck_by = 0;

    pcmk__xml_free(scheduler->priv->graph);
    scheduler->priv->graph = NULL;

    scheduler->priv->synapse_count = 0;

    pcmk__xml_free(scheduler->input);
    scheduler->input = NULL;

    pcmk__set_scheduler_defaults(scheduler);

    pcmk__config_has_error = false;
    pcmk__config_has_warning = false;
}

/*!
 * \brief Free scheduler data
 *
 * \param[in,out] scheduler  Scheduler data to free
 */
void
pcmk_free_scheduler(pcmk_scheduler_t *scheduler)
{
    if (scheduler != NULL) {
        pcmk_reset_scheduler(scheduler);
        free(scheduler->priv->local_node_name);
        free(scheduler->priv);
        free(scheduler);
    }
}

/*!
 * \internal
 * \brief Get the Designated Controller node from scheduler data
 *
 * \param[in] scheduler  Scheduler data
 *
 * \return Designated Controller node from scheduler data, or NULL if none
 */
pcmk_node_t *
pcmk_get_dc(const pcmk_scheduler_t *scheduler)
{
    return (scheduler == NULL)? NULL : scheduler->dc_node;
}

/*!
 * \internal
 * \brief Get the no quorum policy from scheduler data
 *
 * \param[in] scheduler  Scheduler data
 *
 * \return No quorum policy from scheduler data
 */
enum pe_quorum_policy
pcmk_get_no_quorum_policy(const pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return pcmk_no_quorum_stop; // The default
    }
    return scheduler->no_quorum_policy;
}

/*!
 * \internal
 * \brief Set CIB XML as scheduler input in scheduler data
 *
 * \param[out] scheduler  Scheduler data
 * \param[in]  cib        CIB XML to set as scheduler input
 *
 * \return Standard Pacemaker return code (EINVAL if \p scheduler is NULL,
 *         otherwise pcmk_rc_ok)
 * \note This will not free any previously set scheduler CIB.
 */
int
pcmk_set_scheduler_cib(pcmk_scheduler_t *scheduler, xmlNode *cib)
{
    if (scheduler == NULL) {
        return EINVAL;
    }
    scheduler->input = cib;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Check whether cluster has quorum
 *
 * \param[in] scheduler  Scheduler data
 *
 * \return true if cluster has quorum, otherwise false
 */
bool
pcmk_has_quorum(const pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return false;
    }
    return pcmk__is_set(scheduler->flags, pcmk__sched_quorate);
}

/*!
 * \brief Find a node by name in scheduler data
 *
 * \param[in] scheduler  Scheduler data
 * \param[in] node_name  Name of node to find
 *
 * \return Node from scheduler data that matches \p node_name if any,
 *         otherwise NULL
 */
pcmk_node_t *
pcmk_find_node(const pcmk_scheduler_t *scheduler, const char *node_name)
{
    if ((scheduler == NULL) || (node_name == NULL)) {
        return NULL;
    }
    return pcmk__find_node_in_list(scheduler->nodes, node_name);
}

/*!
 * \internal
 * \brief Get scheduler data's "now" in epoch time
 *
 * \param[in,out] scheduler  Scheduler data
 *
 * \return Scheduler data's "now" as seconds since epoch (defaulting to current
 *         time)
 */
time_t
pcmk__scheduler_epoch_time(pcmk_scheduler_t *scheduler)
{
    if (scheduler == NULL) {
        return time(NULL);
    }
    if (scheduler->priv->now == NULL) {
        pcmk__trace("Scheduler 'now' set to current time");
        scheduler->priv->now = crm_time_new(NULL);
    }
    return crm_time_get_seconds_since_epoch(scheduler->priv->now);
}

/*!
 * \internal
 * \brief Update "recheck by" time in scheduler data
 *
 * \param[in]     recheck    Epoch time when recheck should happen
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     reason     What time is being updated for (for logs)
 */
void
pcmk__update_recheck_time(time_t recheck, pcmk_scheduler_t *scheduler,
                          const char *reason)
{
    pcmk__assert(scheduler != NULL);

    if ((recheck > pcmk__scheduler_epoch_time(scheduler))
        && ((scheduler->priv->recheck_by == 0)
            || (scheduler->priv->recheck_by > recheck))) {
        scheduler->priv->recheck_by = recheck;
        pcmk__debug("Updated next scheduler recheck to %s for %s",
                    pcmk__trim(ctime(&recheck)),
                    pcmk__s(reason, "some reason"));
    }
}

/* Fail count clearing for parameter changes normally happens when unpacking
 * history, before resources are unpacked. However, for bundles using the
 * REMOTE_CONTAINER_HACK, we can't check the conditions until after unpacking
 * the bundle, so those parameter checks are deferred using the APIs below.
 */

// History entry to be checked later for fail count clearing
struct param_check {
    const xmlNode *rsc_history; // History entry XML
    pcmk_resource_t *rsc;       // Resource corresponding to history entry
    pcmk_node_t *node;          // Node corresponding to history entry
    enum pcmk__check_parameters check_type; // What needs checking
};

/*!
 * \internal
 * \brief Add a deferred parameter check
 *
 * \param[in]     rsc_history  Resource history XML to check later
 * \param[in,out] rsc          Resource that history is for
 * \param[in]     node         Node that history is for
 * \param[in]     flag         What needs to be checked later
 */
void
pcmk__add_param_check(const xmlNode *rsc_history, pcmk_resource_t *rsc,
                      pcmk_node_t *node, enum pcmk__check_parameters flag)
{
    struct param_check *param_check = NULL;

    CRM_CHECK((rsc_history != NULL) && (rsc != NULL) && (node != NULL), return);

    pcmk__trace("Deferring checks of %s until after assignment",
                pcmk__xe_id(rsc_history));
    param_check = pcmk__assert_alloc(1, sizeof(struct param_check));
    param_check->rsc_history = rsc_history;
    param_check->rsc = rsc;
    param_check->node = node;
    param_check->check_type = flag;

    rsc->priv->scheduler->priv->param_check =
        g_list_prepend(rsc->priv->scheduler->priv->param_check, param_check);
}

/*!
 * \internal
 * \brief Call a function for each deferred parameter check
 *
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     cb         Function to be called
 */
void
pcmk__foreach_param_check(pcmk_scheduler_t *scheduler,
                          void (*cb)(pcmk_resource_t*, pcmk_node_t*,
                                     const xmlNode*,
                                     enum pcmk__check_parameters))
{
    CRM_CHECK((scheduler != NULL) && (cb != NULL), return);

    for (GList *item = scheduler->priv->param_check;
         item != NULL; item = item->next) {
        struct param_check *param_check = item->data;

        cb(param_check->rsc, param_check->node, param_check->rsc_history,
           param_check->check_type);
    }
}

/*!
 * \internal
 * \brief Free all deferred parameter checks
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__free_param_checks(pcmk_scheduler_t *scheduler)
{
    if ((scheduler != NULL) && (scheduler->priv->param_check != NULL)) {
        g_list_free_full(scheduler->priv->param_check, free);
        scheduler->priv->param_check = NULL;
    }
}
