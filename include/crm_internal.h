/*
 * Copyright 2006-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_INTERNAL__H
#  define CRM_INTERNAL__H

#  ifndef PCMK__CONFIG_H
#    define PCMK__CONFIG_H
#    include <config.h>
#  endif

#  include <portability.h>

/* Our minimum glib dependency is 2.42. Define that as both the minimum and
 * maximum glib APIs that are allowed (i.e. APIs that were already deprecated
 * in 2.42, and APIs introduced after 2.42, cannot be used by Pacemaker code).
 */
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_42
#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_42

#  include <glib.h>
#  include <stdbool.h>
#  include <libxml/tree.h>

/* Public API headers can guard including deprecated API headers with this
 * symbol, thus preventing internal code (which includes this header) from using
 * deprecated APIs, while still allowing external code to use them by default.
 */
#define PCMK_ALLOW_DEPRECATED 0

#  include <crm/lrmd.h>
#  include <crm/common/logging.h>
#  include <crm/common/logging_internal.h>
#  include <crm/common/ipc_internal.h>
#  include <crm/common/options_internal.h>
#  include <crm/common/output_internal.h>
#  include <crm/common/xml_internal.h>
#  include <crm/common/internal.h>
#  include <locale.h>
#  include <gettext.h>

#define N_(String) (String)

#ifdef ENABLE_NLS
#  define _(String) gettext(String)
#else
#  define _(String) (String)
#endif


/*
 * XML attribute names used only by internal code
 */

#define PCMK__XA_ATTR_DAMPENING         "attr_dampening"
#define PCMK__XA_ATTR_FORCE             "attrd_is_force_write"
#define PCMK__XA_ATTR_INTERVAL          "attr_clear_interval"
#define PCMK__XA_ATTR_IS_PRIVATE        "attr_is_private"
#define PCMK__XA_ATTR_IS_REMOTE         "attr_is_remote"
#define PCMK__XA_ATTR_NAME              "attr_name"
#define PCMK__XA_ATTR_NODE_ID           "attr_host_id"
#define PCMK__XA_ATTR_NODE_NAME         "attr_host"
#define PCMK__XA_ATTR_OPERATION         "attr_clear_operation"
#define PCMK__XA_ATTR_PATTERN           "attr_regex"
#define PCMK__XA_ATTR_RESOURCE          "attr_resource"
#define PCMK__XA_ATTR_SECTION           "attr_section"
#define PCMK__XA_ATTR_SET               "attr_set"
#define PCMK__XA_ATTR_SET_TYPE          "attr_set_type"
#define PCMK__XA_ATTR_SYNC_POINT        "attr_sync_point"
#define PCMK__XA_ATTR_USER              "attr_user"
#define PCMK__XA_ATTR_UUID              "attr_key"
#define PCMK__XA_ATTR_VALUE             "attr_value"
#define PCMK__XA_ATTR_VERSION           "attr_version"
#define PCMK__XA_ATTR_WRITER            "attr_writer"
#define PCMK__XA_CONFIG_ERRORS          "config-errors"
#define PCMK__XA_CONFIG_WARNINGS        "config-warnings"
#define PCMK__XA_CONFIRM                "confirm"
#define PCMK__XA_CONN_HOST              "connection_host"
#define PCMK__XA_CRMD                   "crmd"
#define PCMK__XA_CRMD_STATE             "crmd_state"
#define PCMK__XA_CRM_HOST_TO            "crm_host_to"
#define PCMK__XA_CRM_LIMIT_MAX          "crm-limit-max"
#define PCMK__XA_CRM_LIMIT_MODE         "crm-limit-mode"
#define PCMK__XA_CRM_SUBSYSTEM          "crm_subsystem"
#define PCMK__XA_CRM_SYS_FROM           "crm_sys_from"
#define PCMK__XA_CRM_SYS_TO             "crm_sys_to"
#define PCMK__XA_CRM_TASK               "crm_task"
#define PCMK__XA_CRM_TGRAPH_IN          "crm-tgraph-in"
#define PCMK__XA_CRM_USER               "crm_user"
#define PCMK__XA_DC_LEAVING             "dc-leaving"
#define PCMK__XA_DIGEST                 "digest"
#define PCMK__XA_ELECTION_AGE_SEC       "election-age-sec"
#define PCMK__XA_ELECTION_AGE_NANO_SEC  "election-age-nano-sec"
#define PCMK__XA_ELECTION_ID            "election-id"
#define PCMK__XA_ELECTION_OWNER         "election-owner"
#define PCMK__XA_EXPECTED               "expected"
#define PCMK__XA_FILE                   "file"
#define PCMK__XA_GRAPH_ERRORS           "graph-errors"
#define PCMK__XA_GRAPH_WARNINGS         "graph-warnings"
#define PCMK__XA_IN_CCM                 "in_ccm"
#define PCMK__XA_JOIN                   "join"
#define PCMK__XA_JOIN_ID                "join_id"
#define PCMK__XA_LONG_ID                "long-id"
#define PCMK__XA_MODE                   "mode"
#define PCMK__XA_NODE_START_STATE       "node_start_state"
#define PCMK__XA_OBJECT_TYPE            "object_type"
#define PCMK__XA_PACEMAKERD_STATE       "pacemakerd_state"
#define PCMK__XA_REAP                   "reap"
#define PCMK__XA_SCHEMA                 "schema"
#define PCMK__XA_SCHEMAS                "schemas"
#define PCMK__XA_SRC                    "src"
#define PCMK__XA_SUBT                   "subt"                  // subtype
#define PCMK__XA_T                      "t"                     // type
#define PCMK__XA_TASK                   "task"
#define PCMK__XA_TRANSITION_KEY         "transition-key"
#define PCMK__XA_TRANSITION_MAGIC       "transition-magic"
#define PCMK__XA_UPTIME                 "uptime"

// @COMPAT Deprecated since 2.1.6
#define PCMK__XA_REPLACE                "replace"

/*
 * IPC service names that are only used internally
 */

#  define PCMK__SERVER_BASED_RO		"cib_ro"
#  define PCMK__SERVER_BASED_RW		"cib_rw"
#  define PCMK__SERVER_BASED_SHM		"cib_shm"

/*
 * IPC commands that can be sent to Pacemaker daemons
 */

#define PCMK__ATTRD_CMD_PEER_REMOVE     "peer-remove"
#define PCMK__ATTRD_CMD_UPDATE          "update"
#define PCMK__ATTRD_CMD_UPDATE_BOTH     "update-both"
#define PCMK__ATTRD_CMD_UPDATE_DELAY    "update-delay"
#define PCMK__ATTRD_CMD_QUERY           "query"
#define PCMK__ATTRD_CMD_REFRESH         "refresh"
#define PCMK__ATTRD_CMD_FLUSH           "flush"
#define PCMK__ATTRD_CMD_SYNC            "sync"
#define PCMK__ATTRD_CMD_SYNC_RESPONSE   "sync-response"
#define PCMK__ATTRD_CMD_CLEAR_FAILURE   "clear-failure"
#define PCMK__ATTRD_CMD_CONFIRM         "confirm"

#define PCMK__CONTROLD_CMD_NODES        "list-nodes"

#endif                          /* CRM_INTERNAL__H */
