/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACTIONS__H
#define PCMK__CRM_COMMON_ACTIONS__H

#include <stdbool.h>                    // bool
#include <strings.h>                    // strcasecmp()
#include <glib.h>                       // gboolean, guint
#include <libxml/tree.h>                // xmlNode

#include <crm/lrmd_events.h>            // lrmd_event_data_t

#include <glib.h>                       // GList, GHashTable
#include <libxml/tree.h>                // xmlNode

#include <crm/common/nodes.h>
#include <crm/common/resources.h>       // enum rsc_start_requirement, etc.
#include <crm/common/scheduler_types.h> // pcmk_resource_t, pcmk_node_t

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief APIs related to actions
 * \ingroup core
 */

//! Default timeout (in milliseconds) for non-metadata actions
#define PCMK_DEFAULT_ACTION_TIMEOUT_MS      20000

// @COMPAT We don't need a separate timeout for metadata, much less a longer one
//! \deprecated Default timeout (in milliseconds) for metadata actions
#define PCMK_DEFAULT_METADATA_TIMEOUT_MS    30000

// Action names as strings
#define PCMK_ACTION_CANCEL              "cancel"
#define PCMK_ACTION_CLEAR_FAILCOUNT     "clear_failcount"
#define PCMK_ACTION_CLONE_ONE_OR_MORE   "clone-one-or-more"
#define PCMK_ACTION_DELETE              "delete"
#define PCMK_ACTION_DEMOTE              "demote"
#define PCMK_ACTION_DEMOTED             "demoted"
#define PCMK_ACTION_DO_SHUTDOWN         "do_shutdown"
#define PCMK_ACTION_LIST                "list"
#define PCMK_ACTION_LRM_DELETE          "lrm_delete"
#define PCMK_ACTION_LOAD_STOPPED        "load_stopped"
#define PCMK_ACTION_MAINTENANCE_NODES   "maintenance_nodes"
#define PCMK_ACTION_META_DATA           "meta-data"
#define PCMK_ACTION_METADATA            "metadata"
#define PCMK_ACTION_MIGRATE_FROM        "migrate_from"
#define PCMK_ACTION_MIGRATE_TO          "migrate_to"
#define PCMK_ACTION_MONITOR             "monitor"
#define PCMK_ACTION_NOTIFIED            "notified"
#define PCMK_ACTION_NOTIFY              "notify"
#define PCMK_ACTION_OFF                 "off"
#define PCMK_ACTION_ON                  "on"
#define PCMK_ACTION_ONE_OR_MORE         "one-or-more"
#define PCMK_ACTION_PROMOTE             "promote"
#define PCMK_ACTION_PROMOTED            "promoted"
#define PCMK_ACTION_REBOOT              "reboot"
#define PCMK_ACTION_RELOAD              "reload"
#define PCMK_ACTION_RELOAD_AGENT        "reload-agent"
#define PCMK_ACTION_RUNNING             "running"
#define PCMK_ACTION_START               "start"
#define PCMK_ACTION_STATUS              "status"
#define PCMK_ACTION_STONITH             "stonith"
#define PCMK_ACTION_STOP                "stop"
#define PCMK_ACTION_STOPPED             "stopped"
#define PCMK_ACTION_VALIDATE_ALL        "validate-all"

// Possible actions (including some pseudo-actions)
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum action_tasks {
    pcmk_action_unspecified = 0,    // Unspecified or unknown action
    pcmk_action_monitor,            // Monitor

    // Each "completed" action must be the regular action plus 1

    pcmk_action_stop,               // Stop
    pcmk_action_stopped,            // Stop completed

    pcmk_action_start,              // Start
    pcmk_action_started,            // Start completed

    pcmk_action_notify,             // Notify
    pcmk_action_notified,           // Notify completed

    pcmk_action_promote,            // Promote
    pcmk_action_promoted,           // Promoted

    pcmk_action_demote,             // Demote
    pcmk_action_demoted,            // Demoted

    pcmk_action_shutdown,           // Shut down node
    pcmk_action_fence,              // Fence node

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    no_action               = pcmk_action_unspecified,
    monitor_rsc             = pcmk_action_monitor,
    stop_rsc                = pcmk_action_stop,
    stopped_rsc             = pcmk_action_stopped,
    start_rsc               = pcmk_action_start,
    started_rsc             = pcmk_action_started,
    action_notify           = pcmk_action_notify,
    action_notified         = pcmk_action_notified,
    action_promote          = pcmk_action_promote,
    action_promoted         = pcmk_action_promoted,
    action_demote           = pcmk_action_demote,
    action_demoted          = pcmk_action_demoted,
    shutdown_crm            = pcmk_action_shutdown,
    stonith_node            = pcmk_action_fence,
#endif
};
//!@}

// Possible responses to a resource action failure
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum action_fail_response {
    /* The order is (partially) significant here; the values from
     * pcmk_on_fail_ignore through pcmk_on_fail_fence_node are in order of
     * increasing severity.
     *
     * @COMPAT The values should be ordered and numbered per the "TODO" comments
     *         below, so all values are in order of severity and there is room for
     *         future additions, but that would break API compatibility.
     * @TODO   For now, we just use a function to compare the values specially, but
     *         at the next compatibility break, we should arrange things
     *         properly so we can compare with less than and greater than.
     */

    // @TODO Define as 10
    pcmk_on_fail_ignore             = 0,    // Act as if failure didn't happen

    // @TODO Define as 30
    pcmk_on_fail_restart            = 1,    // Restart resource

    // @TODO Define as 60
    pcmk_on_fail_ban                = 2,    // Ban resource from current node

    // @TODO Define as 70
    pcmk_on_fail_block              = 3,    // Treat resource as unmanaged

    // @TODO Define as 80
    pcmk_on_fail_stop               = 4,    // Stop resource and leave stopped

    // @TODO Define as 90
    pcmk_on_fail_standby_node       = 5,    // Put resource's node in standby

    // @TODO Define as 100
    pcmk_on_fail_fence_node         = 6,    // Fence resource's node

    // @COMPAT Values below here are out of desired order for API compatibility

    // @TODO Define as 50
    pcmk_on_fail_restart_container  = 7,    // Restart resource's container

    // @TODO Define as 40
    /*
     * Fence the remote node created by the resource if fencing is enabled,
     * otherwise attempt to restart the resource (used internally for some
     * remote connection failures).
     */
    pcmk_on_fail_reset_remote       = 8,

    // @TODO Define as 20
    pcmk_on_fail_demote             = 9,    // Demote if promotable, else stop

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    action_fail_ignore              = pcmk_on_fail_ignore,
    action_fail_recover             = pcmk_on_fail_restart,
    action_fail_migrate             = pcmk_on_fail_ban,
    action_fail_block               = pcmk_on_fail_block,
    action_fail_stop                = pcmk_on_fail_stop,
    action_fail_standby             = pcmk_on_fail_standby_node,
    action_fail_fence               = pcmk_on_fail_fence_node,
    action_fail_restart_container   = pcmk_on_fail_restart_container,
    action_fail_reset_remote        = pcmk_on_fail_reset_remote,
    action_fail_demote              = pcmk_on_fail_demote,
#endif
};
//!@}

// Action scheduling flags
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
enum pe_action_flags {
    // No action flags set (compare with equality rather than bit set)
    pcmk_no_action_flags            = 0,

    // Whether action does not require invoking an agent
    pcmk_action_pseudo              = (1 << 0),

    // Whether action is runnable
    pcmk_action_runnable            = (1 << 1),

    // Whether action should not be executed
    pcmk_action_optional            = (1 << 2),

    // Whether action should be added to transition graph even if optional
    pcmk_action_always_in_graph     = (1 << 3),

    // Whether operation-specific instance attributes have been unpacked yet
    pcmk_action_attrs_evaluated     = (1 << 4),

    // Whether action is allowed to be part of a live migration
    pcmk_action_migratable           = (1 << 7),

    // Whether action has been added to transition graph
    pcmk_action_added_to_graph       = (1 << 8),

    // Whether action is a stop to abort a dangling migration
    pcmk_action_migration_abort      = (1 << 11),

    /*
     * Whether action is an ordering point for minimum required instances
     * (used to implement ordering after clones with \c PCMK_META_CLONE_MIN
     * configured, and ordered sets with \c PCMK_XA_REQUIRE_ALL set to
     * \c PCMK_VALUE_FALSE).
     */
    pcmk_action_min_runnable         = (1 << 12),

    // Whether action is recurring monitor that must be rescheduled if active
    pcmk_action_reschedule           = (1 << 13),

    // Whether action has already been processed by a recursive procedure
    pcmk_action_detect_loop          = (1 << 14),

    // Whether action's inputs have been de-duplicated yet
    pcmk_action_inputs_deduplicated  = (1 << 15),

    // Whether action can be executed on DC rather than own node
    pcmk_action_on_dc                = (1 << 16),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    pe_action_pseudo                = pcmk_action_pseudo,
    pe_action_runnable              = pcmk_action_runnable,
    pe_action_optional              = pcmk_action_optional,
    pe_action_print_always          = pcmk_action_always_in_graph,
    pe_action_have_node_attrs       = pcmk_action_attrs_evaluated,
    pe_action_implied_by_stonith    = (1 << 6),
    pe_action_migrate_runnable      = pcmk_action_migratable,
    pe_action_dumped                = pcmk_action_added_to_graph,
    pe_action_processed             = (1 << 9),
    pe_action_clear                 = (1 << 10),
    pe_action_dangle                = pcmk_action_migration_abort,
    pe_action_requires_any          = pcmk_action_min_runnable,
    pe_action_reschedule            = pcmk_action_reschedule,
    pe_action_tracking              = pcmk_action_detect_loop,
    pe_action_dedup                 = pcmk_action_inputs_deduplicated,
    pe_action_dc                    = pcmk_action_on_dc,
#endif
};
//!@}

/* @COMPAT enum pe_link_state and enum pe_ordering are currently needed for
 * struct pe_action_wrapper_s (which is public) but should be removed at an
 * API compatibility break when that can be refactored and made internal
 */

//!@{
//! \deprecated Do not use
enum pe_link_state {
    pe_link_not_dumped  = 0,
    pe_link_dumped      = 1,
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    pe_link_dup         = 2,
#endif
};

enum pe_ordering {
    pe_order_none                  = 0x0,
#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    pe_order_optional              = 0x1,
    pe_order_apply_first_non_migratable = 0x2,
    pe_order_implies_first         = 0x10,
    pe_order_implies_then          = 0x20,
    pe_order_promoted_implies_first = 0x40,
    pe_order_implies_first_migratable  = 0x80,
    pe_order_runnable_left         = 0x100,
    pe_order_pseudo_left           = 0x200,
    pe_order_implies_then_on_node  = 0x400,
    pe_order_probe                 = 0x800,
    pe_order_restart               = 0x1000,
    pe_order_stonith_stop          = 0x2000,
    pe_order_serialize_only        = 0x4000,
    pe_order_same_node             = 0x8000,
    pe_order_implies_first_printed = 0x10000,
    pe_order_implies_then_printed  = 0x20000,
    pe_order_asymmetrical          = 0x100000,
    pe_order_load                  = 0x200000,
    pe_order_one_or_more           = 0x400000,
    pe_order_anti_colocation       = 0x800000,
    pe_order_preserve              = 0x1000000,
    pe_order_then_cancels_first    = 0x2000000,
    pe_order_trace                 = 0x4000000,
    pe_order_implies_first_master  = pe_order_promoted_implies_first,
#endif
};

// Action sequenced relative to another action
// @COMPAT This should be internal
struct pe_action_wrapper_s {
    // @COMPAT This should be uint32_t
    enum pe_ordering type;      // Group of enum pcmk__action_relation_flags

    // @COMPAT This should be a bool
    enum pe_link_state state;   // Whether action has been added to graph yet

    pcmk_action_t *action;      // Action to be sequenced
};
//!@}

// Implementation of pcmk_action_t
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pe_action_s {
    int id;                 // Counter to identify action

    /*
     * When the controller aborts a transition graph, it sets an abort priority.
     * If this priority is higher, the action will still be executed anyway.
     * Pseudo-actions are always allowed, so this is irrelevant for them.
     */
    int priority;

    pcmk_resource_t *rsc;   // Resource to apply action to, if any
    pcmk_node_t *node;      // Node to execute action on, if any
    xmlNode *op_entry;      // Action XML configuration, if any
    char *task;             // Action name
    char *uuid;             // Action key
    char *cancel_task;      // If task is "cancel", the action being cancelled
    char *reason;           // Readable description of why action is needed

    //@ COMPAT Change to uint32_t at a compatibility break
    enum pe_action_flags flags;         // Group of enum pe_action_flags

    enum rsc_start_requirement needs;   // Prerequisite for recovery
    enum action_fail_response on_fail;  // Response to failure
    enum rsc_role_e fail_role;          // Resource role if action fails
    GHashTable *meta;                   // Meta-attributes relevant to action
    GHashTable *extra;                  // Action-specific instance attributes

    /* Current count of runnable instance actions for "first" action in an
     * ordering dependency with pcmk__ar_min_runnable set.
     */
    int runnable_before;                // For Pacemaker use only

    /*
     * Number of instance actions for "first" action in an ordering dependency
     * with pcmk__ar_min_runnable set that must be runnable before this action
     * can be runnable.
     */
    int required_runnable_before;

    // Actions in a relation with this one (as pcmk__related_action_t *)
    GList *actions_before;
    GList *actions_after;

    /* This is intended to hold data that varies by the type of action, but is
     * not currently used. Some of the above fields could be moved here except
     * for API backward compatibility.
     */
    void *action_details;
};
//!@}

const char *pcmk_action_text(enum action_tasks action);
enum action_tasks pcmk_parse_action(const char *action_name);

// @COMPAT Make this internal when we can break API backward compatibility
//! \deprecated Do not use (public access will be removed in a future release)
const char *pcmk_on_fail_text(enum action_fail_response on_fail);

// For parsing various action-related string specifications
gboolean parse_op_key(const char *key, char **rsc_id, char **op_type,
                      guint *interval_ms);
gboolean decode_transition_key(const char *key, char **uuid, int *transition_id,
                               int *action_id, int *target_rc);
gboolean decode_transition_magic(const char *magic, char **uuid,
                                 int *transition_id, int *action_id,
                                 int *op_status, int *op_rc, int *target_rc);

// @COMPAT Either these shouldn't be in libcrmcommon or lrmd_event_data_t should
int rsc_op_expected_rc(const lrmd_event_data_t *event);
gboolean did_rsc_op_fail(lrmd_event_data_t *event, int target_rc);

bool crm_op_needs_metadata(const char *rsc_class, const char *op);

xmlNode *crm_create_op_xml(xmlNode *parent, const char *prefix,
                           const char *task, const char *interval_spec,
                           const char *timeout);

bool pcmk_is_probe(const char *task, guint interval);
bool pcmk_xe_is_probe(const xmlNode *xml_op);
bool pcmk_xe_mask_probe_failure(const xmlNode *xml_op);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ACTIONS__H
