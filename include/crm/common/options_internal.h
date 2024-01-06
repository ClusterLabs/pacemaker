/*
 * Copyright 2006-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__OPTIONS_INTERNAL__H
#  define PCMK__OPTIONS_INTERNAL__H

#  ifndef PCMK__CONFIG_H
#    define PCMK__CONFIG_H
#    include <config.h>   // _Noreturn
#  endif

#  include <glib.h>     // GHashTable
#  include <stdbool.h>  // bool

#include <crm/common/util.h>    // pcmk_parse_interval_spec()

_Noreturn void pcmk__cli_help(char cmd);


/*
 * Environment variable option handling
 */

const char *pcmk__env_option(const char *option);
void pcmk__set_env_option(const char *option, const char *value, bool compat);
bool pcmk__env_option_enabled(const char *daemon, const char *option);


/*
 * Cluster option handling
 */

typedef struct pcmk__cluster_option_s {
    const char *name;
    const char *alt_name;
    const char *type;
    const char *values;
    const char *default_value;

    bool (*is_valid)(const char *);

    const char *description_short;
    const char *description_long;

} pcmk__cluster_option_t;

const char *pcmk__cluster_option(GHashTable *options,
                                 const pcmk__cluster_option_t *option_list,
                                 int len, const char *name);

gchar *pcmk__format_option_metadata(const char *name, const char *desc_short,
                                    const char *desc_long,
                                    pcmk__cluster_option_t *option_list,
                                    int len);

void pcmk__validate_cluster_options(GHashTable *options,
                                    pcmk__cluster_option_t *option_list,
                                    int len);

bool pcmk__valid_interval_spec(const char *value);
bool pcmk__valid_boolean(const char *value);
bool pcmk__valid_int(const char *value);
bool pcmk__valid_positive_int(const char *value);
bool pcmk__valid_no_quorum_policy(const char *value);
bool pcmk__valid_percentage(const char *value);
bool pcmk__valid_script(const char *value);

// from watchdog.c
long pcmk__get_sbd_watchdog_timeout(void);
bool pcmk__get_sbd_sync_resource_startup(void);
long pcmk__auto_stonith_watchdog_timeout(void);
bool pcmk__valid_stonith_watchdog_timeout(const char *value);

// Constants for environment variable names
#define PCMK__ENV_AUTHKEY_LOCATION          "authkey_location"
#define PCMK__ENV_BLACKBOX                  "blackbox"
#define PCMK__ENV_CALLGRIND_ENABLED         "callgrind_enabled"
#define PCMK__ENV_CLUSTER_TYPE              "cluster_type"
#define PCMK__ENV_DEBUG                     "debug"
#define PCMK__ENV_DH_MAX_BITS               "dh_max_bits"
#define PCMK__ENV_DH_MIN_BITS               "dh_min_bits"
#define PCMK__ENV_FAIL_FAST                 "fail_fast"
#define PCMK__ENV_IPC_BUFFER                "ipc_buffer"
#define PCMK__ENV_IPC_TYPE                  "ipc_type"
#define PCMK__ENV_LOGFACILITY               "logfacility"
#define PCMK__ENV_LOGFILE                   "logfile"
#define PCMK__ENV_LOGFILE_MODE              "logfile_mode"
#define PCMK__ENV_LOGPRIORITY               "logpriority"
#define PCMK__ENV_NODE_ACTION_LIMIT         "node_action_limit"
#define PCMK__ENV_NODE_START_STATE          "node_start_state"
#define PCMK__ENV_PANIC_ACTION              "panic_action"
#define PCMK__ENV_REMOTE_ADDRESS            "remote_address"
#define PCMK__ENV_REMOTE_SCHEMA_DIR         "remote_schema_directory"
#define PCMK__ENV_REMOTE_PID1               "remote_pid1"
#define PCMK__ENV_REMOTE_PORT               "remote_port"
#define PCMK__ENV_RESPAWNED                 "respawned"
#define PCMK__ENV_SCHEMA_DIRECTORY          "schema_directory"
#define PCMK__ENV_SERVICE                   "service"
#define PCMK__ENV_STDERR                    "stderr"
#define PCMK__ENV_TLS_PRIORITIES            "tls_priorities"
#define PCMK__ENV_TRACE_BLACKBOX            "trace_blackbox"
#define PCMK__ENV_TRACE_FILES               "trace_files"
#define PCMK__ENV_TRACE_FORMATS             "trace_formats"
#define PCMK__ENV_TRACE_FUNCTIONS           "trace_functions"
#define PCMK__ENV_TRACE_TAGS                "trace_tags"
#define PCMK__ENV_VALGRIND_ENABLED          "valgrind_enabled"

// @COMPAT Drop at 3.0.0; default is plenty
#define PCMK__ENV_CIB_TIMEOUT               "cib_timeout"

// @COMPAT Drop at 3.0.0; likely last used in 1.1.24
#define PCMK__ENV_MCP                       "mcp"

// @COMPAT Drop at 3.0.0; added unused in 1.1.9
#define PCMK__ENV_QUORUM_TYPE               "quorum_type"

/* @COMPAT Drop at 3.0.0; added to debug shutdown issues when Pacemaker is
 * managed by systemd, but no longer useful.
 */
#define PCMK__ENV_SHUTDOWN_DELAY            "shutdown_delay"

// @COMPAT Deprecated since 2.1.0
#define PCMK__OPT_REMOVE_AFTER_STOP         "remove-after-stop"

// Constants for meta-attribute names
#define PCMK__META_CLONE                    "clone"
#define PCMK__META_CONTAINER                "container"
#define PCMK__META_DIGESTS_ALL              "digests-all"
#define PCMK__META_DIGESTS_SECURE           "digests-secure"
#define PCMK__META_INTERNAL_RSC             "internal_rsc"
#define PCMK__META_MIGRATE_SOURCE           "migrate_source"
#define PCMK__META_MIGRATE_TARGET           "migrate_target"
#define PCMK__META_ON_NODE                  "on_node"
#define PCMK__META_ON_NODE_UUID             "on_node_uuid"
#define PCMK__META_OP_NO_WAIT               "op_no_wait"
#define PCMK__META_OP_TARGET_RC             "op_target_rc"
#define PCMK__META_PHYSICAL_HOST            "physical-host"

/* @TODO Plug these in. Currently, they're never set. These are op attrs for use
 * with https://projects.clusterlabs.org/T382.
 */
#define PCMK__META_CLEAR_FAILURE_OP         "clear_failure_op"
#define PCMK__META_CLEAR_FAILURE_INTERVAL   "clear_failure_interval"

// @COMPAT Deprecated meta-attribute since 2.1.0
#define PCMK__META_CAN_FAIL                 "can_fail"

// @COMPAT Deprecated alias for PCMK__META_PROMOTED_MAX since 2.0.0
#define PCMK__META_PROMOTED_MAX_LEGACY      "master-max"

// @COMPAT Deprecated alias for PCMK__META_PROMOTED_NODE_MAX since 2.0.0
#define PCMK__META_PROMOTED_NODE_MAX_LEGACY "master-node-max"

// @COMPAT Deprecated meta-attribute since 2.0.0
#define PCMK__META_RESTART_TYPE             "restart-type"

// @COMPAT Deprecated meta-attribute since 2.0.0
#define PCMK__META_ROLE_AFTER_FAILURE       "role_after_failure"

// Constants for enumerated values for various options
#define PCMK__VALUE_CIB                     "cib"
#define PCMK__VALUE_CLUSTER                 "cluster"
#define PCMK__VALUE_CRMD                    "crmd"
#define PCMK__VALUE_CUSTOM                  "custom"
#define PCMK__VALUE_EN                      "en"
#define PCMK__VALUE_FENCING                 "fencing"
#define PCMK__VALUE_GREEN                   "green"
#define PCMK__VALUE_INIT                    "init"
#define PCMK__VALUE_LOCAL                   "local"
#define PCMK__VALUE_MIGRATE_ON_RED          "migrate-on-red"
#define PCMK__VALUE_NONE                    "none"
#define PCMK__VALUE_NOTHING                 "nothing"
#define PCMK__VALUE_ONLY_GREEN              "only-green"
#define PCMK__VALUE_PROGRESSIVE             "progressive"
#define PCMK__VALUE_QUORUM                  "quorum"
#define PCMK__VALUE_RED                     "red"
#define PCMK__VALUE_REMOTE                  "remote"
#define PCMK__VALUE_REQUEST                 "request"
#define PCMK__VALUE_RESPONSE                "response"
#define PCMK__VALUE_RUNNING                 "running"
#define PCMK__VALUE_SHUTDOWN_COMPLETE       "shutdown_complete"
#define PCMK__VALUE_SHUTTING_DOWN           "shutting_down"
#define PCMK__VALUE_STARTING_DAEMONS        "starting_daemons"
#define PCMK__VALUE_UNFENCING               "unfencing"
#define PCMK__VALUE_WAIT_FOR_PING           "wait_for_ping"
#define PCMK__VALUE_YELLOW                  "yellow"

#endif // PCMK__OPTIONS_INTERNAL__H
