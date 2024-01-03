/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_OPTIONS__H
#  define PCMK__CRM_COMMON_OPTIONS__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief API related to options
 * \ingroup core
 */

/*
 * Cluster options
 */

#define PCMK_OPT_BATCH_LIMIT                "batch-limit"
#define PCMK_OPT_CLUSTER_DELAY              "cluster-delay"
#define PCMK_OPT_CLUSTER_INFRASTRUCTURE     "cluster-infrastructure"
#define PCMK_OPT_CLUSTER_IPC_LIMIT          "cluster-ipc-limit"
#define PCMK_OPT_CLUSTER_NAME               "cluster-name"
#define PCMK_OPT_CLUSTER_RECHECK_INTERVAL   "cluster-recheck-interval"
#define PCMK_OPT_CONCURRENT_FENCING         "concurrent-fencing"
#define PCMK_OPT_DC_DEADTIME                "dc-deadtime"
#define PCMK_OPT_DC_VERSION                 "dc-version"
#define PCMK_OPT_ELECTION_TIMEOUT           "election-timeout"
#define PCMK_OPT_ENABLE_ACL                 "enable-acl"
#define PCMK_OPT_ENABLE_STARTUP_PROBES      "enable-startup-probes"
#define PCMK_OPT_FENCE_REACTION             "fence-reaction"
#define PCMK_OPT_HAVE_WATCHDOG              "have-watchdog"
#define PCMK_OPT_JOIN_FINALIZATION_TIMEOUT  "join-finalization-timeout"
#define PCMK_OPT_JOIN_INTEGRATION_TIMEOUT   "join-integration-timeout"
#define PCMK_OPT_LOAD_THRESHOLD             "load-threshold"
#define PCMK_OPT_MAINTENANCE_MODE           "maintenance-mode"
#define PCMK_OPT_MIGRATION_LIMIT            "migration-limit"
#define PCMK_OPT_NO_QUORUM_POLICY           "no-quorum-policy"
#define PCMK_OPT_NODE_ACTION_LIMIT          "node-action-limit"
#define PCMK_OPT_NODE_HEALTH_BASE           "node-health-base"
#define PCMK_OPT_NODE_HEALTH_GREEN          "node-health-green"
#define PCMK_OPT_NODE_HEALTH_RED            "node-health-red"
#define PCMK_OPT_NODE_HEALTH_STRATEGY       "node-health-strategy"
#define PCMK_OPT_NODE_HEALTH_YELLOW         "node-health-yellow"
#define PCMK_OPT_NODE_PENDING_TIMEOUT       "node-pending-timeout"
#define PCMK_OPT_PE_ERROR_SERIES_MAX        "pe-error-series-max"
#define PCMK_OPT_PE_INPUT_SERIES_MAX        "pe-input-series-max"
#define PCMK_OPT_PE_WARN_SERIES_MAX         "pe-warn-series-max"
#define PCMK_OPT_PLACEMENT_STRATEGY         "placement-strategy"
#define PCMK_OPT_PRIORITY_FENCING_DELAY     "priority-fencing-delay"
#define PCMK_OPT_SHUTDOWN_ESCALATION        "shutdown-escalation"
#define PCMK_OPT_SHUTDOWN_LOCK              "shutdown-lock"
#define PCMK_OPT_SHUTDOWN_LOCK_LIMIT        "shutdown-lock-limit"
#define PCMK_OPT_START_FAILURE_IS_FATAL     "start-failure-is-fatal"
#define PCMK_OPT_STARTUP_FENCING            "startup-fencing"
#define PCMK_OPT_STONITH_ACTION             "stonith-action"
#define PCMK_OPT_STONITH_ENABLED            "stonith-enabled"
#define PCMK_OPT_STONITH_MAX_ATTEMPTS       "stonith-max-attempts"
#define PCMK_OPT_STONITH_TIMEOUT            "stonith-timeout"
#define PCMK_OPT_STONITH_WATCHDOG_TIMEOUT   "stonith-watchdog-timeout"
#define PCMK_OPT_STOP_ALL_RESOURCES         "stop-all-resources"
#define PCMK_OPT_STOP_ORPHAN_ACTIONS        "stop-orphan-actions"
#define PCMK_OPT_STOP_ORPHAN_RESOURCES      "stop-orphan-resources"
#define PCMK_OPT_SYMMETRIC_CLUSTER          "symmetric-cluster"
#define PCMK_OPT_TRANSITION_DELAY           "transition-delay"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_OPTIONS__H
