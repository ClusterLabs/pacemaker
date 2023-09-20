/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H
#  define PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H

/*!
 * Flags to indicate the relationship between two actions
 *
 * @COMPAT The values and semantics of these flags should not be changed until
 * the deprecated enum pe_ordering is dropped from the public API.
 */
enum pcmk__action_relation_flags {
    //! No relation (compare with equality rather than bit set)
    pcmk__ar_none                           = 0U,

    //! Actions are ordered (optionally, if no other flags are set)
    pcmk__ar_ordered                        = (1U << 0),

    //! Relation applies only if 'first' cannot be part of a live migration
    pcmk__ar_if_first_unmigratable          = (1U << 1),

    /*!
     * If 'then' is required, 'first' becomes required (and becomes unmigratable
     * if 'then' is); also, if 'first' is a stop of a blocked resource, 'then'
     * becomes unrunnable
     */
    pcmk__ar_then_implies_first             = (1U << 4),

    /*!
     * If 'first' is required, 'then' becomes required; if 'first' is a stop of
     * a blocked resource, 'then' becomes unrunnable
     */
    pcmk__ar_first_implies_then             = (1U << 5),

    /*!
     * If 'then' is required and for a promoted instance, 'first' becomes
     * required (and becomes unmigratable if 'then' is)
     */
    pcmk__ar_promoted_then_implies_first    = (1U << 6),

    /*!
     * 'first' is runnable only if 'then' is both runnable and migratable,
     * and 'first' becomes required if 'then' is
     */
    pcmk__ar_unmigratable_then_blocks       = (1U << 7),

    //! 'then' is runnable (and migratable) only if 'first' is runnable
    pcmk__ar_unrunnable_first_blocks        = (1U << 8),

    //! If 'first' is unrunnable, 'then' becomes a real, unmigratable action
    pcmk__ar_first_else_then                = (1U << 9),

    //! If 'first' is required, 'then' action for instance on same node is
    pcmk__ar_first_implies_same_node_then   = (1U << 10),

    /*!
     * Disable relation if 'first' is unrunnable and for an active resource,
     * otherwise order actions and make 'then' unrunnable if 'first' is.
     *
     * This is used to order a bundle replica's start of its container before a
     * probe of its remote connection resource, in case the connection uses the
     * REMOTE_CONTAINER_HACK to replace the connection address with where the
     * container is running.
     */
    pcmk__ar_nested_remote_probe            = (1U << 11),

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
    pcmk__ar_intermediate_stop              = (1U << 12),

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
    pcmk__ar_serialize                      = (1U << 14),
};

#endif      // PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H
