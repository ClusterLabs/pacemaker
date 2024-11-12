/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
    return pcmk_is_set(scheduler->flags, pcmk__sched_quorate);
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
        crm_trace("Scheduler 'now' set to current time");
        scheduler->priv->now = crm_time_new(NULL);
    }
    return crm_time_get_seconds_since_epoch(scheduler->priv->now);
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
 * \param[in]     rsc          Resource that history is for
 * \param[in]     node         Node that history is for
 * \param[in]     flag         What needs to be checked later
 * \param[in,out] scheduler    Scheduler data
 */
void
pcmk__add_param_check(const xmlNode *rsc_history, pcmk_resource_t *rsc,
                      pcmk_node_t *node, enum pcmk__check_parameters flag,
                      pcmk_scheduler_t *scheduler)
{
    struct param_check *param_check = NULL;

    CRM_CHECK((rsc_history != NULL) && (rsc != NULL) && (node != NULL)
              && (scheduler != NULL), return);

    crm_trace("Deferring checks of %s until after assignment",
              pcmk__xe_id(rsc_history));
    param_check = pcmk__assert_alloc(1, sizeof(struct param_check));
    param_check->rsc_history = rsc_history;
    param_check->rsc = rsc;
    param_check->node = node;
    param_check->check_type = flag;
    scheduler->priv->param_check = g_list_prepend(scheduler->priv->param_check,
                                                  param_check);
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
