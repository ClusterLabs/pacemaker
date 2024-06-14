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
#include <glib.h>               // gboolean, FALSE
#include <libxml/tree.h>        // xmlNode

#include <crm/common/scheduler.h>

uint32_t pcmk__warnings = 0;

gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;

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
    return pcmk_is_set(scheduler->flags, pcmk_sched_quorate);
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
