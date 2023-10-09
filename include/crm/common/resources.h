/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES__H
#  define PCMK__CRM_COMMON_RESOURCES__H

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for resources
 * \ingroup core
 */

//! Resource variants supported by Pacemaker
enum pe_obj_types {
    // Order matters: some code compares greater or lesser than
    pcmk_rsc_variant_unknown    = -1,   //!< Unknown resource variant
    pcmk_rsc_variant_primitive  = 0,    //!< Primitive resource
    pcmk_rsc_variant_group      = 1,    //!< Group resource
    pcmk_rsc_variant_clone      = 2,    //!< Clone resource
    pcmk_rsc_variant_bundle     = 3,    //!< Bundle resource

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_rsc_variant_unknown instead
    pe_unknown      = pcmk_rsc_variant_unknown,

    //! \deprecated Use pcmk_rsc_variant_primitive instead
    pe_native       = pcmk_rsc_variant_primitive,

    //! \deprecated Use pcmk_rsc_variant_group instead
    pe_group        = pcmk_rsc_variant_group,

    //! \deprecated Use pcmk_rsc_variant_clone instead
    pe_clone        = pcmk_rsc_variant_clone,

    //! \deprecated Use pcmk_rsc_variant_bundle instead
    pe_container    = pcmk_rsc_variant_bundle,
#endif
};

//! What resource needs before it can be recovered from a failed node
enum rsc_start_requirement {
    pcmk_requires_nothing   = 0,    //!< Resource can be recovered immediately
    pcmk_requires_quorum    = 1,    //!< Resource can be recovered if quorate
    pcmk_requires_fencing   = 2,    //!< Resource can be recovered after fencing

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_requires_nothing instead
    rsc_req_nothing         = pcmk_requires_nothing,

    //! \deprecated Use pcmk_requires_quorum instead
    rsc_req_quorum          = pcmk_requires_quorum,

    //! \deprecated Use pcmk_requires_fencing instead
    rsc_req_stonith         = pcmk_requires_fencing,
#endif
};

//! How to recover a resource that is incorrectly active on multiple nodes
enum rsc_recovery_type {
    pcmk_multiply_active_restart    = 0,    //!< Stop on all, start on desired
    pcmk_multiply_active_stop       = 1,    //!< Stop on all and leave stopped
    pcmk_multiply_active_block      = 2,    //!< Do nothing to resource
    pcmk_multiply_active_unexpected = 3,    //!< Stop unexpected instances

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_multiply_active_restart instead
    recovery_stop_start             = pcmk_multiply_active_restart,

    //! \deprecated Use pcmk_multiply_active_stop instead
    recovery_stop_only              = pcmk_multiply_active_stop,

    //! \deprecated Use pcmk_multiply_active_block instead
    recovery_block                  = pcmk_multiply_active_block,

    //! \deprecated Use pcmk_multiply_active_unexpected instead
    recovery_stop_unexpected        = pcmk_multiply_active_unexpected,
#endif
};

//! Resource scheduling flags
enum pcmk_rsc_flags {
    //! No resource flags set (compare with equality rather than bit set)
    pcmk_no_rsc_flags               = 0ULL,

    //! Whether resource has been removed from the configuration
    pcmk_rsc_removed                = (1ULL << 0),

    //! Whether resource is managed
    pcmk_rsc_managed                = (1ULL << 1),

    //! Whether resource is blocked from further action
    pcmk_rsc_blocked                = (1ULL << 2),

    //! Whether resource has been removed but has a container
    pcmk_rsc_removed_filler         = (1ULL << 3),

    //! Whether resource has clone notifications enabled
    pcmk_rsc_notify                 = (1ULL << 4),

    //! Whether resource is not an anonymous clone instance
    pcmk_rsc_unique                 = (1ULL << 5),

    //! Whether resource's class is "stonith"
    pcmk_rsc_fence_device           = (1ULL << 6),

    //! Whether resource can be promoted and demoted
    pcmk_rsc_promotable             = (1ULL << 7),

    //! Whether resource has not yet been assigned to a node
    pcmk_rsc_unassigned             = (1ULL << 8),

    //! Whether resource is in the process of being assigned to a node
    pcmk_rsc_assigning              = (1ULL << 9),

    //! Whether resource is in the process of modifying allowed node scores
    pcmk_rsc_updating_nodes         = (1ULL << 10),

    //! Whether resource is in the process of scheduling actions to restart
    pcmk_rsc_restarting             = (1ULL << 11),

    //! Whether resource must be stopped (instead of demoted) if it is failed
    pcmk_rsc_stop_if_failed         = (1ULL << 12),

    //! Whether a reload action has been scheduled for resource
    pcmk_rsc_reload                 = (1ULL << 13),

    //! Whether resource is a remote connection allowed to run on a remote node
    pcmk_rsc_remote_nesting_allowed = (1ULL << 14),

    //! Whether resource has "critical" meta-attribute enabled
    pcmk_rsc_critical               = (1ULL << 15),

    //! Whether resource is considered failed
    pcmk_rsc_failed                 = (1ULL << 16),

    //! Flag for non-scheduler code to use to detect recursion loops
    pcmk_rsc_detect_loop            = (1ULL << 17),

    //! \deprecated Do not use
    pcmk_rsc_runnable               = (1ULL << 18),

    //! Whether resource has pending start action in history
    pcmk_rsc_start_pending          = (1ULL << 19),

    //! \deprecated Do not use
    pcmk_rsc_starting               = (1ULL << 20),

    //! \deprecated Do not use
    pcmk_rsc_stopping               = (1ULL << 21),

    //! Whether resource is multiply active with recovery set to stop_unexpected
    pcmk_rsc_stop_unexpected        = (1ULL << 22),

    //! Whether resource is allowed to live-migrate
    pcmk_rsc_migratable             = (1ULL << 23),

    //! Whether resource has an ignorable failure
    pcmk_rsc_ignore_failure         = (1ULL << 24),

    //! Whether resource is an implicit container resource for a bundle replica
    pcmk_rsc_replica_container      = (1ULL << 25),

    //! Whether resource, its node, or entire cluster is in maintenance mode
    pcmk_rsc_maintenance            = (1ULL << 26),

    //! \deprecated Do not use
    pcmk_rsc_has_filler             = (1ULL << 27),

    //! Whether resource can be started or promoted only on quorate nodes
    pcmk_rsc_needs_quorum           = (1ULL << 28),

    //! Whether resource requires fencing before recovery if on unclean node
    pcmk_rsc_needs_fencing          = (1ULL << 29),

    //! Whether resource can be started or promoted only on unfenced nodes
    pcmk_rsc_needs_unfencing        = (1ULL << 30),
};

//! Search options for resources (exact resource ID always matches)
enum pe_find {
    //! Also match clone instance ID from resource history
    pcmk_rsc_match_history          = (1 << 0),

    //! Also match anonymous clone instances by base name
    pcmk_rsc_match_anon_basename    = (1 << 1),

    //! Match only clones and their instances, by either clone or instance ID
    pcmk_rsc_match_clone_only       = (1 << 2),

    //! If matching by node, compare current node instead of assigned node
    pcmk_rsc_match_current_node     = (1 << 3),

    //! \deprecated Do not use
    pe_find_inactive                = (1 << 4),

    //! Match clone instances (even unique) by base name as well as exact ID
    pcmk_rsc_match_basename         = (1 << 5),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_rsc_match_history instead
    pe_find_renamed     = pcmk_rsc_match_history,

    //! \deprecated Use pcmk_rsc_match_anon_basename instead
    pe_find_anon        = pcmk_rsc_match_anon_basename,

    //! \deprecated Use pcmk_rsc_match_clone_only instead
    pe_find_clone       = pcmk_rsc_match_clone_only,

    //! \deprecated Use pcmk_rsc_match_current_node instead
    pe_find_current     = pcmk_rsc_match_current_node,

    //! \deprecated Use pcmk_rsc_match_basename instead
    pe_find_any         = pcmk_rsc_match_basename,
#endif
};

//!@{
//! \deprecated Do not use
enum pe_restart {
    pe_restart_restart,
    pe_restart_ignore,
};

enum pe_print_options {
    pe_print_log            = (1 << 0),
    pe_print_html           = (1 << 1),
    pe_print_ncurses        = (1 << 2),
    pe_print_printf         = (1 << 3),
    pe_print_dev            = (1 << 4),  // Ignored
    pe_print_details        = (1 << 5),  // Ignored
    pe_print_max_details    = (1 << 6),  // Ignored
    pe_print_rsconly        = (1 << 7),
    pe_print_ops            = (1 << 8),
    pe_print_suppres_nl     = (1 << 9),
    pe_print_xml            = (1 << 10),
    pe_print_brief          = (1 << 11),
    pe_print_pending        = (1 << 12),
    pe_print_clone_details  = (1 << 13),
    pe_print_clone_active   = (1 << 14), // Print clone instances only if active
    pe_print_implicit       = (1 << 15)  // Print implicitly created resources
};
//!@}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES__H
