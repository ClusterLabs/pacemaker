/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES__H
#  define PCMK__CRM_PENGINE_PE_TYPES__H


#  include <stdbool.h>              // bool
#  include <sys/types.h>            // time_t
#  include <libxml/tree.h>          // xmlNode
#  include <glib.h>                 // gboolean, guint, GList, GHashTable
#  include <crm/common/iso8601.h>
#  include <crm/pengine/common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Data types for cluster status
 * \ingroup pengine
 */

typedef struct pe_node_s pe_node_t;
typedef struct pe_action_s pe_action_t;
typedef struct pe_resource_s pe_resource_t;
typedef struct pe_working_set_s pe_working_set_t;

enum pe_obj_types {
    pe_unknown = -1,
    pe_native = 0,
    pe_group = 1,
    pe_clone = 2,
    pe_container = 3,
};

typedef struct resource_object_functions_s {
    gboolean (*unpack) (pe_resource_t*, pe_working_set_t*);
    pe_resource_t *(*find_rsc) (pe_resource_t *parent, const char *search,
                                const pe_node_t *node, int flags);
    /* parameter result must be free'd */
    char *(*parameter) (pe_resource_t*, pe_node_t*, gboolean, const char*,
                        pe_working_set_t*);
    //! \deprecated will be removed in a future release
    void (*print) (pe_resource_t*, const char*, long, void*);
    gboolean (*active) (pe_resource_t*, gboolean);
    enum rsc_role_e (*state) (const pe_resource_t*, gboolean);
    pe_node_t *(*location) (const pe_resource_t*, GList**, int);
    void (*free) (pe_resource_t*);
    void (*count) (pe_resource_t*);
    gboolean (*is_filtered) (const pe_resource_t*, GList *, gboolean);
} resource_object_functions_t;

typedef struct resource_alloc_functions_s resource_alloc_functions_t;

enum pe_quorum_policy {
    no_quorum_freeze,
    no_quorum_stop,
    no_quorum_ignore,
    no_quorum_suicide,
    no_quorum_demote
};

enum node_type {
    node_ping,      //! \deprecated Do not use
    node_member,
    node_remote
};

//! \deprecated will be removed in a future release
enum pe_restart {
    pe_restart_restart, //! \deprecated will be removed in a future release
    pe_restart_ignore   //! \deprecated will be removed in a future release
};

//! Determine behavior of pe_find_resource_with_flags()
enum pe_find {
    pe_find_renamed  = 0x001, //!< match resource ID or LRM history ID
    pe_find_anon     = 0x002, //!< match base name of anonymous clone instances
    pe_find_clone    = 0x004, //!< match only clone instances
    pe_find_current  = 0x008, //!< match resource active on specified node
    pe_find_inactive = 0x010, //!< match resource not running anywhere
    pe_find_any      = 0x020, //!< match base name of any clone instance
};

// @TODO Make these an enum

#  define pe_flag_have_quorum           0x00000001ULL
#  define pe_flag_symmetric_cluster     0x00000002ULL
#  define pe_flag_maintenance_mode      0x00000008ULL

#  define pe_flag_stonith_enabled       0x00000010ULL
#  define pe_flag_have_stonith_resource 0x00000020ULL
#  define pe_flag_enable_unfencing      0x00000040ULL
#  define pe_flag_concurrent_fencing    0x00000080ULL

#  define pe_flag_stop_rsc_orphans      0x00000100ULL
#  define pe_flag_stop_action_orphans   0x00000200ULL
#  define pe_flag_stop_everything       0x00000400ULL

#  define pe_flag_start_failure_fatal   0x00001000ULL

//! \deprecated
#  define pe_flag_remove_after_stop     0x00002000ULL

#  define pe_flag_startup_fencing       0x00004000ULL
#  define pe_flag_shutdown_lock         0x00008000ULL

#  define pe_flag_startup_probes        0x00010000ULL
#  define pe_flag_have_status           0x00020000ULL
#  define pe_flag_have_remote_nodes     0x00040000ULL

#  define pe_flag_quick_location        0x00100000ULL
#  define pe_flag_sanitized             0x00200000ULL

//! \deprecated
#  define pe_flag_stdout                0x00400000ULL

//! Don't count total, disabled and blocked resource instances
#  define pe_flag_no_counts             0x00800000ULL

/*! Skip deprecated code that is kept solely for backward API compatibility.
 * (Internal code should always set this.)
 */
#  define pe_flag_no_compat             0x01000000ULL

#  define pe_flag_show_scores           0x02000000ULL
#  define pe_flag_show_utilization      0x04000000ULL

/*!
 * When scheduling, only unpack the CIB (including constraints), calculate
 * as much cluster status as possible, and apply node health.
 */
#  define pe_flag_check_config          0x08000000ULL

struct pe_working_set_s {
    xmlNode *input;
    crm_time_t *now;

    /* options extracted from the input */
    char *dc_uuid;
    pe_node_t *dc_node;
    const char *stonith_action;
    const char *placement_strategy;

    unsigned long long flags;

    int stonith_timeout;
    enum pe_quorum_policy no_quorum_policy;

    GHashTable *config_hash;
    GHashTable *tickets;

    // Actions for which there can be only one (e.g. fence nodeX)
    GHashTable *singletons;

    GList *nodes;
    GList *resources;
    GList *placement_constraints;
    GList *ordering_constraints;
    GList *colocation_constraints;
    GList *ticket_constraints;

    GList *actions;
    xmlNode *failed;
    xmlNode *op_defaults;
    xmlNode *rsc_defaults;

    /* stats */
    int num_synapse;
    int max_valid_nodes;    //! Deprecated (will be removed in a future release)
    int order_id;
    int action_id;

    /* final output */
    xmlNode *graph;

    GHashTable *template_rsc_sets;
    const char *localhost;
    GHashTable *tags;

    int blocked_resources;
    int disabled_resources;

    GList *param_check; // History entries that need to be checked
    GList *stop_needed; // Containers that need stop actions
    time_t recheck_by;  // Hint to controller to re-run scheduler by this time
    int ninstances;     // Total number of resource instances
    guint shutdown_lock;// How long (seconds) to lock resources to shutdown node
    int priority_fencing_delay; // Priority fencing delay

    void *priv;
};

enum pe_check_parameters {
    /* Clear fail count if parameters changed for un-expired start or monitor
     * last_failure.
     */
    pe_check_last_failure,

    /* Clear fail count if parameters changed for start, monitor, promote, or
     * migrate_from actions for active resources.
     */
    pe_check_active,
};

struct pe_node_shared_s {
    const char *id;
    const char *uname;
    enum node_type type;

    /* @TODO convert these flags into a bitfield */
    gboolean online;
    gboolean standby;
    gboolean standby_onfail;
    gboolean pending;
    gboolean unclean;
    gboolean unseen;
    gboolean shutdown;
    gboolean expected_up;
    gboolean is_dc;
    gboolean maintenance;
    gboolean rsc_discovery_enabled;
    gboolean remote_requires_reset;
    gboolean remote_was_fenced;
    gboolean remote_maintenance; /* what the remote-rsc is thinking */
    gboolean unpacked;

    int num_resources;
    pe_resource_t *remote_rsc;
    GList *running_rsc;       /* pe_resource_t* */
    GList *allocated_rsc;     /* pe_resource_t* */

    GHashTable *attrs;          /* char* => char* */
    GHashTable *utilization;
    GHashTable *digest_cache;   //!< cache of calculated resource digests
    int priority; // calculated based on the priority of resources running on the node
    pe_working_set_t *data_set; //!< Cluster that this node is part of
};

struct pe_node_s {
    int weight;
    gboolean fixed; //!< \deprecated Will be removed in a future release
    int count;
    struct pe_node_shared_s *details;
    int rsc_discover_mode;
};

#  define pe_rsc_orphan                     0x00000001ULL
#  define pe_rsc_managed                    0x00000002ULL
#  define pe_rsc_block                      0x00000004ULL
#  define pe_rsc_orphan_container_filler    0x00000008ULL

#  define pe_rsc_notify                     0x00000010ULL
#  define pe_rsc_unique                     0x00000020ULL
#  define pe_rsc_fence_device               0x00000040ULL
#  define pe_rsc_promotable                 0x00000080ULL

#  define pe_rsc_provisional                0x00000100ULL
#  define pe_rsc_allocating                 0x00000200ULL
#  define pe_rsc_merging                    0x00000400ULL
#  define pe_rsc_restarting                 0x00000800ULL

#  define pe_rsc_stop                       0x00001000ULL
#  define pe_rsc_reload                     0x00002000ULL
#  define pe_rsc_allow_remote_remotes       0x00004000ULL
#  define pe_rsc_critical                   0x00008000ULL

#  define pe_rsc_failed                     0x00010000ULL
#  define pe_rsc_detect_loop                0x00020000ULL
#  define pe_rsc_runnable                   0x00040000ULL
#  define pe_rsc_start_pending              0x00080000ULL

//!< \deprecated Do not use
#  define pe_rsc_starting                   0x00100000ULL

//!< \deprecated Do not use
#  define pe_rsc_stopping                   0x00200000ULL

#  define pe_rsc_stop_unexpected            0x00400000ULL
#  define pe_rsc_allow_migrate              0x00800000ULL

#  define pe_rsc_failure_ignored            0x01000000ULL
#  define pe_rsc_maintenance                0x04000000ULL
#  define pe_rsc_is_container               0x08000000ULL

#  define pe_rsc_needs_quorum               0x10000000ULL
#  define pe_rsc_needs_fencing              0x20000000ULL
#  define pe_rsc_needs_unfencing            0x40000000ULL

/* *INDENT-OFF* */
enum pe_action_flags {
    pe_action_pseudo = 0x00001,
    pe_action_runnable = 0x00002,
    pe_action_optional = 0x00004,
    pe_action_print_always = 0x00008,

    pe_action_have_node_attrs = 0x00010,
    pe_action_implied_by_stonith = 0x00040,
    pe_action_migrate_runnable =   0x00080,

    pe_action_dumped = 0x00100,
    pe_action_processed = 0x00200,
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    pe_action_clear = 0x00400, //! \deprecated Unused
#endif
    pe_action_dangle = 0x00800,

    /* This action requires one or more of its dependencies to be runnable.
     * We use this to clear the runnable flag before checking dependencies.
     */
    pe_action_requires_any = 0x01000,

    pe_action_reschedule = 0x02000,
    pe_action_tracking = 0x04000,
    pe_action_dedup = 0x08000, //! Internal state tracking when creating graph

    pe_action_dc = 0x10000,         //! Action may run on DC instead of target
};
/* *INDENT-ON* */

struct pe_resource_s {
    char *id;
    char *clone_name;
    xmlNode *xml;
    xmlNode *orig_xml;
    xmlNode *ops_xml;

    pe_working_set_t *cluster;
    pe_resource_t *parent;

    enum pe_obj_types variant;
    void *variant_opaque;
    resource_object_functions_t *fns;
    resource_alloc_functions_t *cmds;

    enum rsc_recovery_type recovery_type;

    enum pe_restart restart_type; //!< \deprecated will be removed in future release

    int priority;
    int stickiness;
    int sort_index;
    int failure_timeout;
    int migration_threshold;
    guint remote_reconnect_ms;
    char *pending_task;

    unsigned long long flags;

    // @TODO merge these into flags
    gboolean is_remote_node;
    gboolean exclusive_discover;

    //!@{
    //! This field should be treated as internal to Pacemaker
    GList *rsc_cons_lhs;      // List of pcmk__colocation_t*
    GList *rsc_cons;          // List of pcmk__colocation_t*
    GList *rsc_location;      // List of pe__location_t*
    GList *actions;           // List of pe_action_t*
    GList *rsc_tickets;       // List of rsc_ticket*
    //!@}

    pe_node_t *allocated_to;
    pe_node_t *partial_migration_target;
    pe_node_t *partial_migration_source;
    GList *running_on;        /* pe_node_t*   */
    GHashTable *known_on;       /* pe_node_t*   */
    GHashTable *allowed_nodes;  /* pe_node_t*   */

    enum rsc_role_e role;
    enum rsc_role_e next_role;

    GHashTable *meta;
    GHashTable *parameters; //! \deprecated Use pe_rsc_params() instead
    GHashTable *utilization;

    GList *children;          /* pe_resource_t*   */
    GList *dangling_migrations;       /* pe_node_t*       */

    pe_resource_t *container;
    GList *fillers;

    // @COMPAT These should be made const at next API compatibility break
    pe_node_t *pending_node;    // Node on which pending_task is happening
    pe_node_t *lock_node;       // Resource is shutdown-locked to this node

    time_t lock_time;           // When shutdown lock started

    /* Resource parameters may have node-attribute-based rules, which means the
     * values can vary by node. This table is a cache of parameter name/value
     * tables for each node (as needed). Use pe_rsc_params() to get the table
     * for a given node.
     */
    GHashTable *parameter_cache; // Key = node name, value = parameters table
};

struct pe_action_s {
    int id;
    int priority;

    pe_resource_t *rsc;
    pe_node_t *node;
    xmlNode *op_entry;

    char *task;
    char *uuid;
    char *cancel_task;
    char *reason;

    enum pe_action_flags flags;
    enum rsc_start_requirement needs;
    enum action_fail_response on_fail;
    enum rsc_role_e fail_role;

    GHashTable *meta;
    GHashTable *extra;

    /* 
     * These two varables are associated with the constraint logic
     * that involves first having one or more actions runnable before
     * then allowing this action to execute.
     *
     * These varables are used with features such as 'clone-min' which
     * requires at minimum X number of cloned instances to be running
     * before an order dependency can run. Another option that uses
     * this is 'require-all=false' in ordering constrants. This option
     * says "only require one instance of a resource to start before
     * allowing dependencies to start" -- basically, require-all=false is
     * the same as clone-min=1.
     */

    /* current number of known runnable actions in the before list. */
    int runnable_before;
    /* the number of "before" runnable actions required for this action
     * to be considered runnable */ 
    int required_runnable_before;

    GList *actions_before;    /* pe_action_wrapper_t* */
    GList *actions_after;     /* pe_action_wrapper_t* */

    /* Some of the above fields could be moved to the details,
     * except for API backward compatibility.
     */
    void *action_details; // varies by type of action
};

typedef struct pe_ticket_s {
    char *id;
    gboolean granted;
    time_t last_granted;
    gboolean standby;
    GHashTable *state;
} pe_ticket_t;

typedef struct pe_tag_s {
    char *id;
    GList *refs;
} pe_tag_t;

//! Internal tracking for transition graph creation
enum pe_link_state {
    pe_link_not_dumped, //! Internal tracking for transition graph creation
    pe_link_dumped,     //! Internal tracking for transition graph creation
    pe_link_dup,        //! \deprecated No longer used by Pacemaker
};

enum pe_discover_e {
    pe_discover_always = 0,
    pe_discover_never,
    pe_discover_exclusive,
};

/* *INDENT-OFF* */
enum pe_ordering {
    pe_order_none                  = 0x0,       /* deleted */
    pe_order_optional              = 0x1,       /* pure ordering, nothing implied */
    pe_order_apply_first_non_migratable = 0x2,  /* Only apply this constraint's ordering if first is not migratable. */

    pe_order_implies_first         = 0x10,      /* If 'then' is required, ensure 'first' is too */
    pe_order_implies_then          = 0x20,      /* If 'first' is required, ensure 'then' is too */
    pe_order_promoted_implies_first = 0x40,     /* If 'then' is required and then's rsc is promoted, ensure 'first' becomes required too */

    /* first requires then to be both runnable and migrate runnable. */
    pe_order_implies_first_migratable  = 0x80,

    pe_order_runnable_left         = 0x100,     /* 'then' requires 'first' to be runnable */

    pe_order_pseudo_left           = 0x200,     /* 'then' can only be pseudo if 'first' is runnable */
    pe_order_implies_then_on_node  = 0x400,     /* If 'first' is required on 'nodeX',
                                                 * ensure instances of 'then' on 'nodeX' are too.
                                                 * Only really useful if 'then' is a clone and 'first' is not
                                                 */
    pe_order_probe                 = 0x800,     /* If 'first->rsc' is
                                                 *  - running but about to stop, ignore the constraint
                                                 *  - otherwise, behave as runnable_left
                                                 */

    pe_order_restart               = 0x1000,    /* 'then' is runnable if 'first' is optional or runnable */
    pe_order_stonith_stop          = 0x2000,    //<! \deprecated Will be removed in future release
    pe_order_serialize_only        = 0x4000,    /* serialize */
    pe_order_same_node             = 0x8000,    /* applies only if 'first' and 'then' are on same node */

    pe_order_implies_first_printed = 0x10000,   /* Like ..implies_first but only ensures 'first' is printed, not mandatory */
    pe_order_implies_then_printed  = 0x20000,   /* Like ..implies_then but only ensures 'then' is printed, not mandatory */

    pe_order_asymmetrical          = 0x100000,  /* Indicates asymmetrical one way ordering constraint. */
    pe_order_load                  = 0x200000,  /* Only relevant if... */
    pe_order_one_or_more           = 0x400000,  /* 'then' is runnable only if one or more of its dependencies are too */
    pe_order_anti_colocation       = 0x800000,

    pe_order_preserve              = 0x1000000, /* Hack for breaking user ordering constraints with container resources */
    pe_order_then_cancels_first    = 0x2000000, // if 'then' becomes required, 'first' becomes optional
    pe_order_trace                 = 0x4000000, /* test marker */

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    // \deprecated Use pe_order_promoted_implies_first instead
    pe_order_implies_first_master  = pe_order_promoted_implies_first,
#endif
};
/* *INDENT-ON* */

typedef struct pe_action_wrapper_s {
    enum pe_ordering type;
    enum pe_link_state state;
    pe_action_t *action;
} pe_action_wrapper_t;

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/pengine/pe_types_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES__H
