/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CRM__H
#  define PCMK__CRM_CRM__H

#  include <crm_config.h>
#  include <stdlib.h>
#  include <glib.h>
#  include <stdbool.h>

#  include <string.h>

#  include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief A dumping ground
 * \ingroup core
 */

#ifndef PCMK_ALLOW_DEPRECATED
/*!
 * \brief Allow use of deprecated Pacemaker APIs
 *
 * By default, external code using Pacemaker headers is allowed to use
 * deprecated Pacemaker APIs. If PCMK_ALLOW_DEPRECATED is defined to 0 before
 * including any Pacemaker headers, deprecated APIs will be unusable. It is
 * strongly recommended to leave this unchanged for production and release
 * builds, to avoid breakage when users upgrade to new Pacemaker releases that
 * deprecate more APIs. This should be defined to 0 only for development and
 * testing builds when desiring to check for usage of currently deprecated APIs.
 */
#define PCMK_ALLOW_DEPRECATED 1
#endif

/*!
 * The CRM feature set assists with compatibility in mixed-version clusters.
 * The major version number increases when nodes with different versions
 * would not work (rolling upgrades are not allowed). The minor version
 * number increases when mixed-version clusters are allowed only during
 * rolling upgrades (a node with the oldest feature set will be elected DC). The
 * minor-minor version number is ignored, but allows resource agents to detect
 * cluster support for various features.
 *
 * The feature set also affects the processing of old saved CIBs (such as for
 * many scheduler regression tests).
 *
 * Particular feature points currently tested by Pacemaker code:
 *
 * >2.1:     Operation updates include timing data
 * >=3.0.5:  XML v2 digests are created
 * >=3.0.8:  Peers do not need acks for cancellations
 * >=3.0.9:  DC will send its own shutdown request to all peers
 *           XML v2 patchsets are created by default
 * >=3.0.13: Fail counts include operation name and interval
 * >=3.2.0:  DC supports PCMK_EXEC_INVALID and PCMK_EXEC_NOT_CONNECTED
 */
#  define CRM_FEATURE_SET		"3.18.0"

/* Pacemaker's CPG protocols use fixed-width binary fields for the sender and
 * recipient of a CPG message. This imposes an arbitrary limit on cluster node
 * names.
 */
//! \brief Maximum length of a Corosync cluster node name (in bytes)
#define MAX_NAME	256

#  define CRM_META			"CRM_meta"

extern char *crm_system_name;

/* *INDENT-OFF* */

// How we represent "infinite" scores
#  define CRM_SCORE_INFINITY    1000000
#  define CRM_INFINITY_S        "INFINITY"
#  define CRM_PLUS_INFINITY_S   "+" CRM_INFINITY_S
#  define CRM_MINUS_INFINITY_S  "-" CRM_INFINITY_S

/* @COMPAT API < 2.0.0 Deprecated "infinity" aliases
 *
 * INFINITY might be defined elsewhere (e.g. math.h), so undefine it first.
 * This, of course, complicates any attempt to use the other definition in any
 * code that includes this header.
 */
#  undef INFINITY
#  define INFINITY_S        "INFINITY"
#  define MINUS_INFINITY_S "-INFINITY"
#  define INFINITY        1000000

/* Sub-systems */
#  define CRM_SYSTEM_DC		"dc"
#define CRM_SYSTEM_DCIB         "dcib" // Primary instance of CIB manager
#  define CRM_SYSTEM_CIB		"cib"
#  define CRM_SYSTEM_CRMD		"crmd"
#  define CRM_SYSTEM_LRMD		"lrmd"
#  define CRM_SYSTEM_PENGINE	"pengine"
#  define CRM_SYSTEM_TENGINE	"tengine"
#  define CRM_SYSTEM_STONITHD	"stonithd"
#  define CRM_SYSTEM_MCP	"pacemakerd"

// Names of internally generated node attributes
#  define CRM_ATTR_UNAME            "#uname"
#  define CRM_ATTR_ID               "#id"
#  define CRM_ATTR_KIND             "#kind"
#  define CRM_ATTR_ROLE             "#role"
#  define CRM_ATTR_IS_DC            "#is_dc"
#  define CRM_ATTR_CLUSTER_NAME     "#cluster-name"
#  define CRM_ATTR_SITE_NAME        "#site-name"
#  define CRM_ATTR_UNFENCED         "#node-unfenced"
#  define CRM_ATTR_DIGESTS_ALL      "#digests-all"
#  define CRM_ATTR_DIGESTS_SECURE   "#digests-secure"
#  define CRM_ATTR_PROTOCOL         "#attrd-protocol"
#  define CRM_ATTR_FEATURE_SET      "#feature-set"

/* Valid operations */
#  define CRM_OP_NOOP		"noop"
#  define CRM_OP_JOIN_ANNOUNCE	"join_announce"
#  define CRM_OP_JOIN_OFFER	"join_offer"
#  define CRM_OP_JOIN_REQUEST	"join_request"
#  define CRM_OP_JOIN_ACKNAK	"join_ack_nack"
#  define CRM_OP_JOIN_CONFIRM	"join_confirm"
#  define CRM_OP_PING		"ping"
#  define CRM_OP_NODE_INFO  "node-info"
#  define CRM_OP_THROTTLE	"throttle"
#  define CRM_OP_VOTE		"vote"
#  define CRM_OP_NOVOTE		"no-vote"
#  define CRM_OP_HELLO		"hello"
#  define CRM_OP_PECALC		"pe_calc"
#  define CRM_OP_QUIT		"quit"
#  define CRM_OP_LOCAL_SHUTDOWN 	"start_shutdown"
#  define CRM_OP_SHUTDOWN_REQ	"req_shutdown"
#  define CRM_OP_SHUTDOWN 	"do_shutdown"
#  define CRM_OP_FENCE	 	"stonith"
#  define CRM_OP_REGISTER		"register"
#  define CRM_OP_IPC_FWD		"ipc_fwd"
#  define CRM_OP_INVOKE_LRM	"lrm_invoke"
#  define CRM_OP_LRM_REFRESH "lrm_refresh" //!< Deprecated since 1.1.10
#  define CRM_OP_LRM_DELETE	"lrm_delete"
#  define CRM_OP_LRM_FAIL		"lrm_fail"
#  define CRM_OP_PROBED		"probe_complete"
#  define CRM_OP_REPROBE		"probe_again"
#  define CRM_OP_CLEAR_FAILCOUNT  "clear_failcount"
#  define CRM_OP_REMOTE_STATE     "remote_state"
#  define CRM_OP_RELAXED_SET  "one-or-more"
#  define CRM_OP_RELAXED_CLONE  "clone-one-or-more"
#  define CRM_OP_RM_NODE_CACHE "rm_node_cache"
#  define CRM_OP_MAINTENANCE_NODES "maintenance_nodes"

/* Possible cluster membership states */
#  define CRMD_JOINSTATE_DOWN           "down"
#  define CRMD_JOINSTATE_PENDING        "pending"
#  define CRMD_JOINSTATE_MEMBER         "member"
#  define CRMD_JOINSTATE_NACK           "banned"

#  define CRMD_ACTION_DELETE		"delete"
#  define CRMD_ACTION_CANCEL		"cancel"

#  define CRMD_ACTION_RELOAD		"reload"
#  define CRMD_ACTION_RELOAD_AGENT	"reload-agent"
#  define CRMD_ACTION_MIGRATE		"migrate_to"
#  define CRMD_ACTION_MIGRATED		"migrate_from"

#  define CRMD_ACTION_STARTED		"running"

#  define CRMD_ACTION_STOPPED		"stopped"

#  define CRMD_ACTION_PROMOTE		"promote"
#  define CRMD_ACTION_PROMOTED		"promoted"
#  define CRMD_ACTION_DEMOTE		"demote"
#  define CRMD_ACTION_DEMOTED		"demoted"

#  define CRMD_ACTION_NOTIFY		"notify"
#  define CRMD_ACTION_NOTIFIED		"notified"

#  define CRMD_ACTION_STATUS		PCMK_ACTION_MONITOR
#  define CRMD_ACTION_METADATA		"meta-data"
#  define CRMD_METADATA_CALL_TIMEOUT   30000

/* short names */
#  define RSC_DELETE	CRMD_ACTION_DELETE
#  define RSC_CANCEL	CRMD_ACTION_CANCEL

#  define RSC_MIGRATE	CRMD_ACTION_MIGRATE
#  define RSC_MIGRATED	CRMD_ACTION_MIGRATED

#  define RSC_STARTED	CRMD_ACTION_STARTED

#  define RSC_STOPPED	CRMD_ACTION_STOPPED

#  define RSC_PROMOTE	CRMD_ACTION_PROMOTE
#  define RSC_PROMOTED	CRMD_ACTION_PROMOTED
#  define RSC_DEMOTE	CRMD_ACTION_DEMOTE
#  define RSC_DEMOTED	CRMD_ACTION_DEMOTED

#  define RSC_NOTIFY	CRMD_ACTION_NOTIFY
#  define RSC_NOTIFIED	CRMD_ACTION_NOTIFIED

#  define RSC_STATUS	PCMK_ACTION_MONITOR
#  define RSC_METADATA	CRMD_ACTION_METADATA
/* *INDENT-ON* */

#  include <crm/common/actions.h>
#  include <crm/common/cib.h>
#  include <crm/common/logging.h>
#  include <crm/common/util.h>

static inline const char *
crm_action_str(const char *task, guint interval_ms) {
    if ((task != NULL) && (interval_ms == 0)
        && (strcasecmp(task, PCMK_ACTION_MONITOR) == 0)) {
        return "probe";
    }
    return task;
}

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/crm_compat.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
