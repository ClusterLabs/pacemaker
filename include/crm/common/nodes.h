/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NODES__H
#define PCMK__CRM_COMMON_NODES__H

#include <stdbool.h>                    // bool
#include <glib.h>                       // gboolean, GList, GHashTable

#include <crm/common/scheduler_types.h> // pcmk_resource_t, pcmk_scheduler_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for nodes
 * \ingroup core
 */

// Special node attributes

#define PCMK_NODE_ATTR_MAINTENANCE          "maintenance"
#define PCMK_NODE_ATTR_STANDBY              "standby"
#define PCMK_NODE_ATTR_TERMINATE            "terminate"


//! \internal Do not use
typedef struct pcmk__node_private pcmk__node_private_t;

// Basic node information (all node objects for the same node share this)
// @COMPAT Drop this struct once all members are moved to pcmk__node_private_t
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pcmk__node_details {
    /* @COMPAT Convert these gbooleans into new enum pcmk__node_flags values
     * when we no longer support versions of sbd that use them
     */

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_node_is_online() instead
    gboolean online;            // Whether online

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_node_is_pending() instead
    gboolean pending;           // Whether controller membership is pending

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call !pcmk_node_is_clean() instead
    gboolean unclean;           // Whether node requires fencing

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_node_is_shutting_down() instead
    gboolean shutdown;          // Whether shutting down

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_node_is_in_maintenance() instead
    gboolean maintenance;       // Whether in maintenance mode

    // NOTE: sbd (as of at least 1.5.2) uses this
    // \deprecated Call pcmk_foreach_active_resource() instead
    GList *running_rsc;             // List of resources active on node
};
//!@}

// Implementation of pcmk_node_t
// @COMPAT Make contents internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pcmk__scored_node {
    struct pcmk__node_assignment *assign;

    // NOTE: sbd (as of at least 1.5.2) uses this
    struct pcmk__node_details *details;   // Basic node information

    //! \internal Do not use
    pcmk__node_private_t *priv;
};
//!@}

bool pcmk_node_is_online(const pcmk_node_t *node);
bool pcmk_node_is_pending(const pcmk_node_t *node);
bool pcmk_node_is_clean(const pcmk_node_t *node);
bool pcmk_node_is_shutting_down(const pcmk_node_t *node);
bool pcmk_node_is_in_maintenance(const pcmk_node_t *node);

bool pcmk_foreach_active_resource(pcmk_node_t *node,
                                  bool (*fn)(pcmk_resource_t *, void *),
                                  void *user_data);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NODES__H
