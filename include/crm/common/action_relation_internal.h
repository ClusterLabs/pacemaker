/*
 * Copyright 2023-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <action_relation_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H
#define PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H

#include <stdbool.h>                        // bool
#include <stdint.h>                         // uint32_t
#include <glib.h>                           // gpointer
#include <crm/common/scheduler_types.h>     // pcmk_resource_t, pcmk_action_t

#ifdef __cplusplus
extern "C" {
#endif

// Flags to indicate the relationship between two actions
enum pcmk__action_relation_flags {
    //! No relation (compare with equality rather than bit set)
    pcmk__ar_none                           = 0U,

    //! Actions are ordered (optionally, if no other flags are set)
    pcmk__ar_ordered                        = (UINT32_C(1) << 0),

    //! Relation applies only if 'first' cannot be part of a live migration
    pcmk__ar_if_first_unmigratable          = (UINT32_C(1) << 1),

    /*!
     * If 'then' is required, 'first' becomes required (and becomes unmigratable
     * if 'then' is); also, if 'first' is a stop of a blocked resource, 'then'
     * becomes unrunnable
     */
    pcmk__ar_then_implies_first             = (UINT32_C(1) << 4),

    /*!
     * If 'first' is required, 'then' becomes required; if 'first' is a stop of
     * a blocked resource, 'then' becomes unrunnable
     */
    pcmk__ar_first_implies_then             = (UINT32_C(1) << 5),

    /*!
     * If 'then' is required and for a promoted instance, 'first' becomes
     * required (and becomes unmigratable if 'then' is)
     */
    pcmk__ar_promoted_then_implies_first    = (UINT32_C(1) << 6),

    /*!
     * 'first' is runnable only if 'then' is both runnable and migratable,
     * and 'first' becomes required if 'then' is
     */
    pcmk__ar_unmigratable_then_blocks       = (UINT32_C(1) << 7),

    //! 'then' is runnable (and migratable) only if 'first' is runnable
    pcmk__ar_unrunnable_first_blocks        = (UINT32_C(1) << 8),

    //! If 'first' is unrunnable, 'then' becomes a real, unmigratable action
    pcmk__ar_first_else_then                = (UINT32_C(1) << 9),

    //! If 'first' is required, 'then' action for instance on same node is
    pcmk__ar_first_implies_same_node_then   = (UINT32_C(1) << 10),

    /*!
     * Disable relation if 'first' is unrunnable and for an active resource,
     * otherwise order actions and make 'then' unrunnable if 'first' is.
     *
     * This is used to order a bundle replica's start of its container before a
     * probe of its remote connection resource, in case the connection uses the
     * REMOTE_CONTAINER_HACK to replace the connection address with where the
     * container is running.
     */
    pcmk__ar_nested_remote_probe            = (UINT32_C(1) << 11),

    /*!
     * If 'first' is for a blocked resource, make 'then' unrunnable.
     *
     * If 'then' is required, make 'first' required, make 'first' unmigratable
     * if 'then' is unmigratable, and make 'then' unrunnable if 'first' is
     * unrunnable.
     *
     * If 'then' is unrunnable and for the same resource as 'first', make
     * 'first' required if it is runnable, and make 'first' unmigratable if
     * 'then' is unmigratable.
     *
     * This is used for "stop then start primitive" (restarts) and
     * "stop group member then stop previous member".
     */
    pcmk__ar_intermediate_stop              = (UINT32_C(1) << 12),

    /*!
     * The actions must be serialized if in the same transition but can be in
     * either order. (In practice, we always arrange them as 'first' then
     * 'then', so they end up being essentially the same as optional orderings.)
     *
     * @TODO Handle more intelligently -- for example, we could schedule the
     * action with the fewest inputs first, so we're more likely to execute at
     * least one if there is a failure during the transition. Or, we could
     * prefer certain action types over others, or base it on resource priority.
     */
    pcmk__ar_serialize                      = (UINT32_C(1) << 14),

    //! Relation applies only if actions are on same node
    pcmk__ar_if_on_same_node                = (UINT32_C(1) << 15),

    //! If 'then' is required, 'first' must be added to the transition graph
    pcmk__ar_then_implies_first_graphed     = (UINT32_C(1) << 16),

    //! If 'first' is required and runnable, 'then' must be in graph
    pcmk__ar_first_implies_then_graphed     = (UINT32_C(1) << 17),

    //! User-configured asymmetric ordering
    pcmk__ar_asymmetric                     = (UINT32_C(1) << 20),

    //! Actions are ordered if on same node (or migration target for migrate_to)
    pcmk__ar_if_on_same_node_or_target      = (UINT32_C(1) << 21),

    //! 'then' action is runnable if certain number of 'first' instances are
    pcmk__ar_min_runnable                   = (UINT32_C(1) << 22),

    //! Ordering applies only if 'first' is required and on same node as 'then'
    pcmk__ar_if_required_on_same_node       = (UINT32_C(1) << 23),

    //! Ordering applies even if 'first' runs on guest node created by 'then'
    pcmk__ar_guest_allowed                  = (UINT32_C(1) << 24),

    //! If 'then' action becomes required, 'first' becomes optional
    pcmk__ar_then_cancels_first             = (UINT32_C(1) << 25),
};

/* Action relation object
 *
 * The most common type of relation is an ordering, in which case action1 etc.
 * refers to the "first" action, and action2 etc. refers to the "then" action.
 */
typedef struct {
    int id;                     // Counter to identify relation
    uint32_t flags;             // Group of enum pcmk__action_relation_flags
    pcmk_resource_t *rsc1;      // Resource for first action, if any
    pcmk_action_t *action1;     // First action in relation
    char *task1;                // Action name or key for first action
    pcmk_resource_t *rsc2;      // Resource for second action, if any
    pcmk_action_t *action2;     // Second action in relation
    char *task2;                // Action name or key for second action
} pcmk__action_relation_t;

// Action sequenced relative to another action
typedef struct {
    pcmk_action_t *action;      // Action to be sequenced
    uint32_t flags;             // Group of enum pcmk__action_relation_flags
    bool graphed;               // Whether action has been added to graph yet
} pcmk__related_action_t;

/*!
 * \internal
 * \brief Set action relation flags
 *
 * \param[in,out] ar_flags      Flag group to modify
 * \param[in]     flags_to_set  enum pcmk__action_relation_flags to set
 */
#define pcmk__set_relation_flags(ar_flags, flags_to_set) do {           \
        ar_flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,    \
                                      "Action relation", "constraint",  \
                                      ar_flags, (flags_to_set),         \
                                      #flags_to_set);                   \
    } while (0)

/*!
 * \internal
 * \brief Clear action relation flags
 *
 * \param[in,out] ar_flags        Flag group to modify
 * \param[in]     flags_to_clear  enum pcmk__action_relation_flags to clear
 */
#define pcmk__clear_relation_flags(ar_flags, flags_to_clear) do {           \
        ar_flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,      \
                                        "Action relation", "constraint",    \
                                        ar_flags, (flags_to_clear),         \
                                        #flags_to_clear);                   \
    } while (0)

void pcmk__free_action_relation(gpointer user_data);

#ifdef __cplusplus
}
#endif

#endif      // PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H
