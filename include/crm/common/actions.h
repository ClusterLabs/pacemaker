/*
 * Copyright 2004-2023 the Pacemaker project contributors
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

//! Possible actions (including some pseudo-actions)
enum action_tasks {
    pcmk_action_unspecified = 0,    //!< Unspecified or unknown action
    pcmk_action_monitor,            //!< Monitor

    // Each "completed" action must be the regular action plus 1

    pcmk_action_stop,               //!< Stop
    pcmk_action_stopped,            //!< Stop completed

    pcmk_action_start,              //!< Start
    pcmk_action_started,            //!< Start completed

    pcmk_action_notify,             //!< Notify
    pcmk_action_notified,           //!< Notify completed

    pcmk_action_promote,            //!< Promote
    pcmk_action_promoted,           //!< Promoted

    pcmk_action_demote,             //!< Demote
    pcmk_action_demoted,            //!< Demoted

    pcmk_action_shutdown,           //!< Shut down node
    pcmk_action_fence,              //!< Fence node

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_action_unspecified instead
    no_action               = pcmk_action_unspecified,

    //! \deprecated Use pcmk_action_monitor instead
    monitor_rsc             = pcmk_action_monitor,

    //! \deprecated Use pcmk_action_stop instead
    stop_rsc                = pcmk_action_stop,

    //! \deprecated Use pcmk_action_stopped instead
    stopped_rsc             = pcmk_action_stopped,

    //! \deprecated Use pcmk_action_start instead
    start_rsc               = pcmk_action_start,

    //! \deprecated Use pcmk_action_started instead
    started_rsc             = pcmk_action_started,

    //! \deprecated Use pcmk_action_notify instead
    action_notify           = pcmk_action_notify,

    //! \deprecated Use pcmk_action_notified instead
    action_notified         = pcmk_action_notified,

    //! \deprecated Use pcmk_action_promote instead
    action_promote          = pcmk_action_promote,

    //! \deprecated Use pcmk_action_promoted instead
    action_promoted         = pcmk_action_promoted,

    //! \deprecated Use pcmk_action_demote instead
    action_demote           = pcmk_action_demote,

    //! \deprecated Use pcmk_action_demoted instead
    action_demoted          = pcmk_action_demoted,

    //! \deprecated Use pcmk_action_shutdown instead
    shutdown_crm            = pcmk_action_shutdown,

    //! \deprecated Use pcmk_action_fence instead
    stonith_node            = pcmk_action_fence,
#endif
};

//! Possible responses to a resource action failure
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
    pcmk_on_fail_ignore             = 0,    //!< Act as if failure didn't happen

    // @TODO Define as 30
    pcmk_on_fail_restart            = 1,    //!< Restart resource

    // @TODO Define as 60
    pcmk_on_fail_ban                = 2,    //!< Ban resource from current node

    // @TODO Define as 70
    pcmk_on_fail_block              = 3,    //!< Treat resource as unmanaged

    // @TODO Define as 80
    pcmk_on_fail_stop               = 4,    //!< Stop resource and leave stopped

    // @TODO Define as 90
    pcmk_on_fail_standby_node       = 5,    //!< Put resource's node in standby

    // @TODO Define as 100
    pcmk_on_fail_fence_node         = 6,    //!< Fence resource's node

    // @COMPAT Values below here are out of desired order for API compatibility

    // @TODO Define as 50
    pcmk_on_fail_restart_container  = 7,    //!< Restart resource's container

    // @TODO Define as 40
    /*!
     * Fence the remote node created by the resource if fencing is enabled,
     * otherwise attempt to restart the resource (used internally for some
     * remote connection failures).
     */
    pcmk_on_fail_reset_remote       = 8,

    // @TODO Define as 20
    pcmk_on_fail_demote             = 9,    //!< Demote if promotable, else stop

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_on_fail_ignore instead
    action_fail_ignore              = pcmk_on_fail_ignore,

    //! \deprecated Use pcmk_on_fail_restart instead
    action_fail_recover             = pcmk_on_fail_restart,

    //! \deprecated Use pcmk_on_fail_ban instead
    action_fail_migrate             = pcmk_on_fail_ban,

    //! \deprecated Use pcmk_on_fail_block instead
    action_fail_block               = pcmk_on_fail_block,

    //! \deprecated Use pcmk_on_fail_stop instead
    action_fail_stop                = pcmk_on_fail_stop,

    //! \deprecated Use pcmk_on_fail_standby_node instead
    action_fail_standby             = pcmk_on_fail_standby_node,

    //! \deprecated Use pcmk_on_fail_fence_node instead
    action_fail_fence               = pcmk_on_fail_fence_node,

    //! \deprecated Use pcmk_on_fail_restart_container instead
    action_fail_restart_container   = pcmk_on_fail_restart_container,

    //! \deprecated Use pcmk_on_fail_reset_remote instead
    action_fail_reset_remote        = pcmk_on_fail_reset_remote,

    //! \deprecated Use pcmk_on_fail_demote instead
    action_fail_demote              = pcmk_on_fail_demote,
#endif
};

//! Action scheduling flags
enum pe_action_flags {
    //! No action flags set (compare with equality rather than bit set)
    pcmk_no_action_flags            = 0,

    //! Whether action does not require invoking an agent
    pcmk_action_pseudo              = (1 << 0),

    //! Whether action is runnable
    pcmk_action_runnable            = (1 << 1),

    //! Whether action should not be executed
    pcmk_action_optional            = (1 << 2),

    //! Whether action should be added to transition graph even if optional
    pcmk_action_always_in_graph     = (1 << 3),

    //! Whether operation-specific instance attributes have been unpacked yet
    pcmk_action_attrs_evaluated     = (1 << 4),

    //! Whether action can be related to a live migration
    pcmk_action_migratable           = (1 << 7),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_action_pseudo instead
    pe_action_pseudo                = pcmk_action_pseudo,

    //! \deprecated Use pcmk_action_runnable instead
    pe_action_runnable              = pcmk_action_runnable,

    //! \deprecated Use pcmk_action_optional instead
    pe_action_optional              = pcmk_action_optional,

    //! \deprecated Use pcmk_action_always_in_graph instead
    pe_action_print_always          = pcmk_action_always_in_graph,

    //! \deprecated Use pcmk_action_attrs_evaluated instead
    pe_action_have_node_attrs       = pcmk_action_attrs_evaluated,

    //! \deprecated Do not use
    pe_action_implied_by_stonith    = (1 << 6),
#endif

    pe_action_migrate_runnable      = pcmk_action_migratable,

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
