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
};

#endif      // PCMK__CRM_COMMON_ACTION_RELATION_INTERNAL__H
