/*
 * Copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef MEMBERSHIP__H
#  define MEMBERSHIP__H

#ifdef __cplusplus
extern "C" {
#endif

#include <crm/cluster/internal.h>

/*!
 * \internal
 * \brief Phases that a node may pass through while joining controller group
 */
enum controld_join_phase {
    controld_join_nack,
    controld_join_none,
    controld_join_welcomed,
    controld_join_integrated,
    controld_join_finalized,
    controld_join_confirmed,
};

//! User data for \c pcmk__node_status_t object
struct controld_node_status_data {
    enum controld_join_phase join_phase;
};

/*!
 * \internal
 * \brief Get the controller group join phase from a node status object
 *
 * \param[in] node  Node status object
 *
 * \return Controller group join phase
 */
static inline enum controld_join_phase
controld_get_join_phase(const pcmk__node_status_t *node)
{
    if ((node != NULL) && (node->user_data != NULL)) {
        struct controld_node_status_data *data = node->user_data;

        return data->join_phase;
    }
    return controld_join_none;
}

void post_cache_update(int instance);

extern gboolean check_join_state(enum crmd_fsa_state cur_state, const char *source);

void controld_destroy_failed_sync_table(void);
void controld_remove_failed_sync_node(const char *node_name);

#ifdef __cplusplus
}
#endif

#endif
