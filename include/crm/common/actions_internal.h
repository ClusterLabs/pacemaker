/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ACTIONS_INTERNAL__H
#define PCMK__CRM_COMMON_ACTIONS_INTERNAL__H

#include <stdbool.h>                        // bool
#include <stdint.h>                         // uint32_t, UINT32_C()
#include <glib.h>                           // guint, GList, GHashTable
#include <libxml/tree.h>                    // xmlNode

#include <crm/common/actions.h>             // PCMK_ACTION_MONITOR
#include <crm/common/roles.h>               // enum rsc_role_e
#include <crm/common/scheduler_types.h>     // pcmk_resource_t, pcmk_node_t
#include <crm/common/strings_internal.h>    // pcmk__str_eq()

#include <crm/common/strings_internal.h>    // pcmk__str_any_of()

#ifdef __cplusplus
extern "C" {
#endif

//! printf-style format to create operation key from resource, action, interval
#define PCMK__OP_FMT "%s_%s_%u"

/*!
 * \internal
 * \brief Set action flags for an action
 *
 * \param[in,out] action        Action to set flags for
 * \param[in]     flags_to_set  Group of enum pcmk__action_flags to set
 */
#define pcmk__set_action_flags(action, flags_to_set) do {               \
        (action)->flags = pcmk__set_flags_as(__func__, __LINE__,        \
                                             LOG_TRACE,                 \
                                             "Action", (action)->uuid,  \
                                             (action)->flags,           \
                                             (flags_to_set),            \
                                             #flags_to_set);            \
    } while (0)

/*!
 * \internal
 * \brief Clear action flags for an action
 *
 * \param[in,out] action          Action to clear flags for
 * \param[in]     flags_to_clear  Group of enum pcmk__action_flags to clear
 */
#define pcmk__clear_action_flags(action, flags_to_clear) do {               \
        (action)->flags = pcmk__clear_flags_as(__func__, __LINE__,          \
                                               LOG_TRACE,                   \
                                               "Action", (action)->uuid,    \
                                               (action)->flags,             \
                                               (flags_to_clear),            \
                                               #flags_to_clear);            \
    } while (0)

/*!
 * \internal
 * \brief Set action flags for a flag group
 *
 * \param[in,out] action_flags  Flag group to set flags for
 * \param[in]     action_name   Name of action being modified (for logging)
 * \param[in]     to_set        Group of enum pcmk__action_flags to set
 */
#define pcmk__set_raw_action_flags(action_flags, action_name, to_set) do {  \
        action_flags = pcmk__set_flags_as(__func__, __LINE__,               \
                                          LOG_TRACE, "Action", action_name, \
                                          (action_flags),                   \
                                          (to_set), #to_set);               \
    } while (0)

/*!
 * \internal
 * \brief Clear action flags for a flag group
 *
 * \param[in,out] action_flags  Flag group to clear flags for
 * \param[in]     action_name   Name of action being modified (for logging)
 * \param[in]     to_clear      Group of enum pcmk__action_flags to clear
 */
#define pcmk__clear_raw_action_flags(action_flags, action_name, to_clear)   \
    do {                                                                    \
        action_flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,  \
                                            "Action", action_name,          \
                                            (action_flags),                 \
                                            (to_clear), #to_clear);         \
    } while (0)

// Possible actions (including some pseudo-actions)
enum pcmk__action_type {
    pcmk__action_unspecified = 0,   // Unspecified or unknown action
    pcmk__action_monitor,           // Monitor

    // Each "completed" action must be the regular action plus 1

    pcmk__action_stop,              // Stop
    pcmk__action_stopped,           // Stop completed

    pcmk__action_start,             // Start
    pcmk__action_started,           // Start completed

    pcmk__action_notify,            // Notify
    pcmk__action_notified,          // Notify completed

    pcmk__action_promote,           // Promote
    pcmk__action_promoted,          // Promoted

    pcmk__action_demote,            // Demote
    pcmk__action_demoted,           // Demoted

    pcmk__action_shutdown,          // Shut down node
    pcmk__action_fence,             // Fence node
};

// Action scheduling flags
enum pcmk__action_flags {
    // No action flags set (compare with equality rather than bit set)
    pcmk__no_action_flags               = 0,

    // Whether action does not require invoking an agent
    pcmk__action_pseudo                 = (UINT32_C(1) << 0),

    // Whether action is runnable
    pcmk__action_runnable               = (UINT32_C(1) << 1),

    // Whether action should not be executed
    pcmk__action_optional               = (UINT32_C(1) << 2),

    // Whether action should be added to transition graph even if optional
    pcmk__action_always_in_graph        = (UINT32_C(1) << 3),

    // Whether operation-specific instance attributes have been unpacked yet
    pcmk__action_attrs_evaluated        = (UINT32_C(1) << 4),

    // Whether action is allowed to be part of a live migration
    pcmk__action_migratable             = (UINT32_C(1) << 7),

    // Whether action has been added to transition graph
    pcmk__action_added_to_graph         = (UINT32_C(1) << 8),

    // Whether action is a stop to abort a dangling migration
    pcmk__action_migration_abort        = (UINT32_C(1) << 11),

    // Whether action is recurring monitor that must be rescheduled if active
    pcmk__action_reschedule             = (UINT32_C(1) << 13),

    // Whether action has already been processed by a recursive procedure
    pcmk__action_detect_loop            = (UINT32_C(1) << 14),

    // Whether action's inputs have been de-duplicated yet
    pcmk__action_inputs_deduplicated    = (UINT32_C(1) << 15),

    // Whether action can be executed on DC rather than own node
    pcmk__action_on_dc                  = (UINT32_C(1) << 16),
};

/* Possible responses to a resource action failure
 *
 * The order is significant; the values are in order of increasing severity so
 * that they can be compared with less than and greater than.
 */
enum pcmk__on_fail {
    pcmk__on_fail_ignore,               // Act as if failure didn't happen
    pcmk__on_fail_demote,               // Demote if promotable, else stop
    pcmk__on_fail_restart,              // Restart resource

    /* Fence the remote node created by the resource if fencing is enabled,
     * otherwise attempt to restart the resource (used internally for some
     * remote connection failures).
     */
    pcmk__on_fail_reset_remote,

    pcmk__on_fail_restart_container,    // Restart resource's container
    pcmk__on_fail_ban,                  // Ban resource from current node
    pcmk__on_fail_block,                // Treat resource as unmanaged
    pcmk__on_fail_stop,                 // Stop resource and leave stopped
    pcmk__on_fail_standby_node,         // Put resource's node in standby
    pcmk__on_fail_fence_node,           // Fence resource's node
};

// What resource needs before it can be recovered from a failed node
enum pcmk__requires {
    pcmk__requires_nothing   = 0,   // Resource can be recovered immediately
    pcmk__requires_quorum    = 1,   // Resource can be recovered if quorate
    pcmk__requires_fencing   = 2,   // Resource can be recovered after fencing
};

// Implementation of pcmk_action_t
struct pcmk__action {
    int id;                 // Counter to identify action

    /*
     * When the controller aborts a transition graph, it sets an abort priority.
     * If this priority is higher, the action will still be executed anyway.
     * Pseudo-actions are always allowed, so this is irrelevant for them.
     */
    int priority;

    pcmk_resource_t *rsc;   // Resource to apply action to, if any
    pcmk_node_t *node;      // Copy of node to execute action on, if any
    xmlNode *op_entry;      // Action XML configuration, if any
    char *task;             // Action name
    char *uuid;             // Action key
    char *cancel_task;      // If task is "cancel", the action being cancelled
    char *reason;           // Readable description of why action is needed
    uint32_t flags;         // Group of enum pcmk__action_flags
    enum pcmk__requires needs;          // Prerequisite for recovery
    enum pcmk__on_fail on_fail;         // Response to failure
    enum rsc_role_e fail_role;          // Resource role if action fails
    GHashTable *meta;                   // Meta-attributes relevant to action
    GHashTable *extra;                  // Action-specific instance attributes
    pcmk_scheduler_t *scheduler;        // Scheduler data this action is part of

    /* Current count of runnable instance actions for "first" action in an
     * ordering dependency with pcmk__ar_min_runnable set.
     */
    int runnable_before;

    /*
     * Number of instance actions for "first" action in an ordering dependency
     * with pcmk__ar_min_runnable set that must be runnable before this action
     * can be runnable.
     */
    int required_runnable_before;

    // Actions in a relation with this one (as pcmk__related_action_t *)
    GList *actions_before;
    GList *actions_after;
};

void pcmk__free_action(gpointer user_data);
char *pcmk__op_key(const char *rsc_id, const char *op_type, guint interval_ms);
char *pcmk__notify_key(const char *rsc_id, const char *notify_type,
                       const char *op_type);
char *pcmk__transition_key(int transition_id, int action_id, int target_rc,
                           const char *node);
void pcmk__filter_op_for_digest(xmlNode *param_set);
bool pcmk__is_fencing_action(const char *action);
enum pcmk__action_type pcmk__parse_action(const char *action_name);
const char *pcmk__action_text(enum pcmk__action_type action);
const char *pcmk__on_fail_text(enum pcmk__on_fail on_fail);


/*!
 * \internal
 * \brief Get a human-friendly action name
 *
 * \param[in] action_name  Actual action name
 * \param[in] interval_ms  Action interval (in milliseconds)
 *
 * \return Action name suitable for display
 */
static inline const char *
pcmk__readable_action(const char *action_name, guint interval_ms) {
    if ((interval_ms == 0)
        && pcmk__str_eq(action_name, PCMK_ACTION_MONITOR, pcmk__str_none)) {
        return "probe";
    }
    return action_name;
}

/*!
 * \internal
 * \brief Check whether an action raises a resource's role
 *
 * \param[in] action  Action to check
 *
 * \return \c true if \p action is "start", "promote", or "migrate_from"
 */
static inline bool
pcmk__is_up_action(const char *action)
{
    return pcmk__str_any_of(action, PCMK_ACTION_START, PCMK_ACTION_PROMOTE,
                            PCMK_ACTION_MIGRATE_FROM, NULL);
}

/*!
 * \internal
 * \brief Check whether an action lowers a resource's role
 *
 * \param[in] action  Action to check
 *
 * \return \c true if \p action is "stop", "demote", or "migrate_to"
 */
static inline bool
pcmk__is_down_action(const char *action)
{
    return pcmk__str_any_of(action, PCMK_ACTION_STOP, PCMK_ACTION_DEMOTE,
                            PCMK_ACTION_MIGRATE_TO, NULL);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ACTIONS_INTERNAL__H
