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
extern     "C" {
#endif

/**
 * \file
 * \brief API related to options
 * \ingroup core
 */

/*
 * Cluster options
 */

#define PCMK_OPT_BATCH_LIMIT                    "batch-limit"
#define PCMK_OPT_CLUSTER_DELAY                  "cluster-delay"
#define PCMK_OPT_CLUSTER_INFRASTRUCTURE         "cluster-infrastructure"
#define PCMK_OPT_CLUSTER_IPC_LIMIT              "cluster-ipc-limit"
#define PCMK_OPT_CLUSTER_NAME                   "cluster-name"
#define PCMK_OPT_CLUSTER_RECHECK_INTERVAL       "cluster-recheck-interval"
#define PCMK_OPT_CONCURRENT_FENCING             "concurrent-fencing"
#define PCMK_OPT_DC_DEADTIME                    "dc-deadtime"
#define PCMK_OPT_DC_VERSION                     "dc-version"
#define PCMK_OPT_ELECTION_TIMEOUT               "election-timeout"
#define PCMK_OPT_ENABLE_ACL                     "enable-acl"
#define PCMK_OPT_ENABLE_STARTUP_PROBES          "enable-startup-probes"
#define PCMK_OPT_FENCE_REACTION                 "fence-reaction"
#define PCMK_OPT_HAVE_WATCHDOG                  "have-watchdog"
#define PCMK_OPT_JOIN_FINALIZATION_TIMEOUT      "join-finalization-timeout"
#define PCMK_OPT_JOIN_INTEGRATION_TIMEOUT       "join-integration-timeout"
#define PCMK_OPT_LOAD_THRESHOLD                 "load-threshold"
#define PCMK_OPT_MAINTENANCE_MODE               "maintenance-mode"
#define PCMK_OPT_MIGRATION_LIMIT                "migration-limit"
#define PCMK_OPT_NO_QUORUM_POLICY               "no-quorum-policy"
#define PCMK_OPT_NODE_ACTION_LIMIT              "node-action-limit"
#define PCMK_OPT_NODE_HEALTH_BASE               "node-health-base"
#define PCMK_OPT_NODE_HEALTH_GREEN              "node-health-green"
#define PCMK_OPT_NODE_HEALTH_RED                "node-health-red"
#define PCMK_OPT_NODE_HEALTH_STRATEGY           "node-health-strategy"
#define PCMK_OPT_NODE_HEALTH_YELLOW             "node-health-yellow"
#define PCMK_OPT_NODE_PENDING_TIMEOUT           "node-pending-timeout"
#define PCMK_OPT_PE_ERROR_SERIES_MAX            "pe-error-series-max"
#define PCMK_OPT_PE_INPUT_SERIES_MAX            "pe-input-series-max"
#define PCMK_OPT_PE_WARN_SERIES_MAX             "pe-warn-series-max"
#define PCMK_OPT_PLACEMENT_STRATEGY             "placement-strategy"
#define PCMK_OPT_PRIORITY_FENCING_DELAY         "priority-fencing-delay"
#define PCMK_OPT_SHUTDOWN_ESCALATION            "shutdown-escalation"
#define PCMK_OPT_SHUTDOWN_LOCK                  "shutdown-lock"
#define PCMK_OPT_SHUTDOWN_LOCK_LIMIT            "shutdown-lock-limit"
#define PCMK_OPT_START_FAILURE_IS_FATAL         "start-failure-is-fatal"
#define PCMK_OPT_STARTUP_FENCING                "startup-fencing"
#define PCMK_OPT_STONITH_ACTION                 "stonith-action"
#define PCMK_OPT_STONITH_ENABLED                "stonith-enabled"
#define PCMK_OPT_STONITH_MAX_ATTEMPTS           "stonith-max-attempts"
#define PCMK_OPT_STONITH_TIMEOUT                "stonith-timeout"
#define PCMK_OPT_STONITH_WATCHDOG_TIMEOUT       "stonith-watchdog-timeout"
#define PCMK_OPT_STOP_ALL_RESOURCES             "stop-all-resources"
#define PCMK_OPT_STOP_ORPHAN_ACTIONS            "stop-orphan-actions"
#define PCMK_OPT_STOP_ORPHAN_RESOURCES          "stop-orphan-resources"
#define PCMK_OPT_SYMMETRIC_CLUSTER              "symmetric-cluster"
#define PCMK_OPT_TRANSITION_DELAY               "transition-delay"


/*
 * Meta-attributes
 */

#define PCMK_META_ALLOW_MIGRATE                 "allow-migrate"
#define PCMK_META_ALLOW_UNHEALTHY_NODES         "allow-unhealthy-nodes"
#define PCMK_META_CLONE_MAX                     "clone-max"
#define PCMK_META_CLONE_MIN                     "clone-min"
#define PCMK_META_CLONE_NODE_MAX                "clone-node-max"
#define PCMK_META_CONTAINER_ATTRIBUTE_TARGET    "container-attribute-target"
#define PCMK_META_CRITICAL                      "critical"
#define PCMK_META_ENABLED                       "enabled"
#define PCMK_META_FAILURE_TIMEOUT               "failure-timeout"
#define PCMK_META_GLOBALLY_UNIQUE               "globally-unique"
#define PCMK_META_INTERLEAVE                    "interleave"
#define PCMK_META_INTERVAL                      "interval"
#define PCMK_META_IS_MANAGED                    "is-managed"
#define PCMK_META_INTERVAL_ORIGIN               "interval-origin"
#define PCMK_META_MAINTENANCE                   "maintenance"
#define PCMK_META_MIGRATION_THRESHOLD           "migration-threshold"
#define PCMK_META_MULTIPLE_ACTIVE               "multiple-active"
#define PCMK_META_NOTIFY                        "notify"
#define PCMK_META_ON_FAIL                       "on-fail"
#define PCMK_META_ORDERED                       "ordered"
#define PCMK_META_PRIORITY                      "priority"
#define PCMK_META_PROMOTABLE                    "promotable"
#define PCMK_META_PROMOTED_MAX                  "promoted-max"
#define PCMK_META_PROMOTED_NODE_MAX             "promoted-node-max"
#define PCMK_META_RECORD_PENDING                "record-pending"
#define PCMK_META_REMOTE_ADDR                   "remote-addr"
#define PCMK_META_REMOTE_ALLOW_MIGRATE          "remote-allow-migrate"
#define PCMK_META_REMOTE_CONNECT_TIMEOUT        "remote-connect-timeout"
#define PCMK_META_REMOTE_NODE                   "remote-node"
#define PCMK_META_REMOTE_PORT                   "remote-port"
#define PCMK_META_REQUIRES                      "requires"
#define PCMK_META_RESOURCE_STICKINESS           "resource-stickiness"
#define PCMK_META_START_DELAY                   "start-delay"
#define PCMK_META_TARGET_ROLE                   "target-role"
#define PCMK_META_TIMEOUT                       "timeout"
#define PCMK_META_TIMESTAMP_FORMAT              "timestamp-format"


/*
 * Remote resource instance attributes
 */

#define PCMK_REMOTE_RA_ADDR                     "addr"
#define PCMK_REMOTE_RA_PORT                     "port"
#define PCMK_REMOTE_RA_RECONNECT_INTERVAL       "reconnect_interval"
#define PCMK_REMOTE_RA_SERVER                   "server"


/*
 * Enumerated values
 */

#define PCMK_VALUE_ALWAYS                       "always"
#define PCMK_VALUE_AND                          "and"
#define PCMK_VALUE_BALANCED                     "balanced"
#define PCMK_VALUE_BLOCK                        "block"
#define PCMK_VALUE_BOOLEAN                      "boolean"
#define PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS        "cib-bootstrap-options"
#define PCMK_VALUE_CREATE                       "create"
#define PCMK_VALUE_CUSTOM                       "custom"
#define PCMK_VALUE_DATE_SPEC                    "date_spec"
#define PCMK_VALUE_DEFAULT                      "default"
#define PCMK_VALUE_DEFINED                      "defined"
#define PCMK_VALUE_DELETE                       "delete"
#define PCMK_VALUE_DEMOTE                       "demote"
#define PCMK_VALUE_DENY                         "deny"
#define PCMK_VALUE_DURATION                     "duration"
#define PCMK_VALUE_DYNAMIC_LIST                 "dynamic-list"
#define PCMK_VALUE_EQ                           "eq"
#define PCMK_VALUE_EXCLUSIVE                    "exclusive"
#define PCMK_VALUE_FAILED                       "failed"
#define PCMK_VALUE_FALSE                        "false"
#define PCMK_VALUE_FENCE                        "fence"
#define PCMK_VALUE_FENCING                      "fencing"
#define PCMK_VALUE_FREEZE                       "freeze"
#define PCMK_VALUE_GRANTED                      "granted"
#define PCMK_VALUE_GREEN                        "green"
#define PCMK_VALUE_GT                           "gt"
#define PCMK_VALUE_GTE                          "gte"
#define PCMK_VALUE_HOST                         "host"
#define PCMK_VALUE_IGNORE                       "ignore"
#define PCMK_VALUE_IN_RANGE                     "in_range"
#define PCMK_VALUE_INFINITY                     "INFINITY"
#define PCMK_VALUE_INTEGER                      "integer"
#define PCMK_VALUE_LITERAL                      "literal"
#define PCMK_VALUE_LT                           "lt"
#define PCMK_VALUE_LTE                          "lte"
#define PCMK_VALUE_MANDATORY                    "Mandatory"
#define PCMK_VALUE_MEMBER                       "member"
#define PCMK_VALUE_META                         "meta"
#define PCMK_VALUE_MIGRATE_ON_RED               "migrate-on-red"
#define PCMK_VALUE_MINIMAL                      "minimal"
#define PCMK_VALUE_MINUS_INFINITY               "-" PCMK_VALUE_INFINITY
#define PCMK_VALUE_MODIFY                       "modify"
#define PCMK_VALUE_MOVE                         "move"
#define PCMK_VALUE_NE                           "ne"
#define PCMK_VALUE_NEVER                        "never"
#define PCMK_VALUE_NONE                         "none"
#define PCMK_VALUE_NONNEGATIVE_INTEGER          "nonnegative_integer"
#define PCMK_VALUE_NOT_DEFINED                  "not_defined"
#define PCMK_VALUE_NOTHING                      "nothing"
#define PCMK_VALUE_NUMBER                       "number"
#define PCMK_VALUE_OFFLINE                      "offline"
#define PCMK_VALUE_ONLINE                       "online"
#define PCMK_VALUE_ONLY_GREEN                   "only-green"
#define PCMK_VALUE_OPTIONAL                     "Optional"
#define PCMK_VALUE_OR                           "or"
#define PCMK_VALUE_PANIC                        "panic"
#define PCMK_VALUE_PARAM                        "param"
#define PCMK_VALUE_PENDING                      "pending"
#define PCMK_VALUE_PERCENTAGE                   "percentage"
#define PCMK_VALUE_PLUS_INFINITY                "+" PCMK_VALUE_INFINITY
#define PCMK_VALUE_PROGRESSIVE                  "progressive"
#define PCMK_VALUE_QUORUM                       "quorum"
#define PCMK_VALUE_READ                         "read"
#define PCMK_VALUE_RED                          "red"
#define PCMK_VALUE_REMOTE                       "remote"
#define PCMK_VALUE_RESTART                      "restart"
#define PCMK_VALUE_RESTART_CONTAINER            "restart-container"
#define PCMK_VALUE_REVOKED                      "revoked"
#define PCMK_VALUE_SCORE                        "score"
#define PCMK_VALUE_SELECT                       "select"
#define PCMK_VALUE_SERIALIZE                    "Serialize"
#define PCMK_VALUE_STANDBY                      "standby"
#define PCMK_VALUE_STRING                       "string"
#define PCMK_VALUE_STOP                         "stop"
#define PCMK_VALUE_SUCCESS                      "success"
#define PCMK_VALUE_TIMEOUT                      "timeout"
#define PCMK_VALUE_TRUE                         "true"
#define PCMK_VALUE_UNFENCING                    "unfencing"
#define PCMK_VALUE_UNKNOWN                      "unknown"
#define PCMK_VALUE_UTILIZATION                  "utilization"
#define PCMK_VALUE_VERSION                      "version"
#define PCMK_VALUE_WRITE                        "write"
#define PCMK_VALUE_YELLOW                       "yellow"

// @COMPAT This will become a deprecated alias for PCMK_VALUE_FENCE (see T279)
#define PCMK_VALUE_FENCE_LEGACY                 "suicide"


#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_OPTIONS__H
