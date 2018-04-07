/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM__H
#  define CRM__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief A dumping ground
 * \ingroup core
 */

#  include <crm_config.h>
#  include <stdlib.h>
#  include <glib.h>
#  include <stdbool.h>

#  include <string.h>

#  include <libxml/tree.h>

#  define CRM_FEATURE_SET		"3.1.0"

#  define EOS		'\0'
#  define DIMOF(a)	((int) (sizeof(a)/sizeof(a[0])) )

#  ifndef MAX_NAME
#    define MAX_NAME	256
#  endif

#  ifndef __GNUC__
#    define __builtin_expect(expr, result) (expr)
#  endif

/* Some handy macros used by the Linux kernel */
#  define __likely(expr) __builtin_expect(expr, 1)
#  define __unlikely(expr) __builtin_expect(expr, 0)

#  define CRM_META			"CRM_meta"

extern char *crm_system_name;

/* *INDENT-OFF* */

// Used for some internal IPC timeouts (maybe should be configurable option)
#  define MAX_IPC_DELAY   120

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
#  define CRM_SYSTEM_DCIB		"dcib"
                                        /*  The master CIB */
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
#  define CRM_ATTR_RA_VERSION       "#ra-version"
#  define CRM_ATTR_PROTOCOL         "#attrd-protocol"

/* Valid operations */
#  define CRM_OP_NOOP		"noop"
#  define CRM_OP_JOIN_ANNOUNCE	"join_announce"
#  define CRM_OP_JOIN_OFFER	"join_offer"
#  define CRM_OP_JOIN_REQUEST	"join_request"
#  define CRM_OP_JOIN_ACKNAK	"join_ack_nack"
#  define CRM_OP_JOIN_CONFIRM	"join_confirm"
#  define CRM_OP_PING		"ping"
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
#  define CRM_OP_LRM_REFRESH	"lrm_refresh" /* Deprecated */
#  define CRM_OP_LRM_QUERY	"lrm_query"
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
#  define CRMD_ACTION_MIGRATE		"migrate_to"
#  define CRMD_ACTION_MIGRATED		"migrate_from"

#  define CRMD_ACTION_START		"start"
#  define CRMD_ACTION_STARTED		"running"

#  define CRMD_ACTION_STOP		"stop"
#  define CRMD_ACTION_STOPPED		"stopped"

#  define CRMD_ACTION_PROMOTE		"promote"
#  define CRMD_ACTION_PROMOTED		"promoted"
#  define CRMD_ACTION_DEMOTE		"demote"
#  define CRMD_ACTION_DEMOTED		"demoted"

#  define CRMD_ACTION_NOTIFY		"notify"
#  define CRMD_ACTION_NOTIFIED		"notified"

#  define CRMD_ACTION_STATUS		"monitor"
#  define CRMD_ACTION_METADATA		"meta-data"
#  define CRMD_METADATA_CALL_TIMEOUT   30000

/* short names */
#  define RSC_DELETE	CRMD_ACTION_DELETE
#  define RSC_CANCEL	CRMD_ACTION_CANCEL

#  define RSC_MIGRATE	CRMD_ACTION_MIGRATE
#  define RSC_MIGRATED	CRMD_ACTION_MIGRATED

#  define RSC_START	CRMD_ACTION_START
#  define RSC_STARTED	CRMD_ACTION_STARTED

#  define RSC_STOP	CRMD_ACTION_STOP
#  define RSC_STOPPED	CRMD_ACTION_STOPPED

#  define RSC_PROMOTE	CRMD_ACTION_PROMOTE
#  define RSC_PROMOTED	CRMD_ACTION_PROMOTED
#  define RSC_DEMOTE	CRMD_ACTION_DEMOTE
#  define RSC_DEMOTED	CRMD_ACTION_DEMOTED

#  define RSC_NOTIFY	CRMD_ACTION_NOTIFY
#  define RSC_NOTIFIED	CRMD_ACTION_NOTIFIED

#  define RSC_STATUS	CRMD_ACTION_STATUS
#  define RSC_METADATA	CRMD_ACTION_METADATA
/* *INDENT-ON* */

typedef GList *GListPtr;

#  include <crm/common/logging.h>
#  include <crm/common/util.h>

static inline const char *
crm_action_str(const char *task, guint interval_ms) {
    if(safe_str_eq(task, RSC_STATUS) && !interval_ms) {
        return "probe";
    }
    return task;
}

#ifdef __cplusplus
}
#endif

#endif
