/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM__H
#  define CRM__H

/**
 * \file
 * \brief A dumping ground
 * \ingroup core
 */

#  include <crm_config.h>
#  include <stdlib.h>
#  include <glib.h>
#  include <stdbool.h>

#  undef MIN
#  undef MAX
#  include <string.h>

#  include <libxml/tree.h>

#  define CRM_FEATURE_SET		"3.0.7"
#  define MINIMUM_SCHEMA_VERSION	"pacemaker-1.0"
#  define LATEST_SCHEMA_VERSION         "pacemaker-"CRM_DTD_VERSION

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

/* Clean these up at some point, some probably should be runtime options */
#  define SOCKET_LEN	1024
#  define APPNAME_LEN	256
#  define MAX_IPC_FAIL	5
#  define MAX_IPC_DELAY   120

#  define DAEMON_RESPAWN_STOP 100

#  define MSG_LOG			1
#  define DOT_FSA_ACTIONS		1
#  define DOT_ALL_FSA_INPUTS	1
/* #define FSA_TRACE		1 */

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

/* Valid operations */
#  define CRM_OP_NOOP		"noop"

#  define CRM_OP_JOIN_ANNOUNCE	"join_announce"
#  define CRM_OP_JOIN_OFFER	"join_offer"
#  define CRM_OP_JOIN_REQUEST	"join_request"
#  define CRM_OP_JOIN_ACKNAK	"join_ack_nack"
#  define CRM_OP_JOIN_CONFIRM	"join_confirm"

#  define CRM_OP_DIE		"die_no_respawn"
#  define CRM_OP_RETRIVE_CIB	"retrieve_cib"
#  define CRM_OP_PING		"ping"
#  define CRM_OP_VOTE		"vote"
#  define CRM_OP_NOVOTE		"no-vote"
#  define CRM_OP_HELLO		"hello"
#  define CRM_OP_HBEAT		"dc_beat"
#  define CRM_OP_PECALC		"pe_calc"
#  define CRM_OP_ABORT		"abort"
#  define CRM_OP_QUIT		"quit"
#  define CRM_OP_LOCAL_SHUTDOWN 	"start_shutdown"
#  define CRM_OP_SHUTDOWN_REQ	"req_shutdown"
#  define CRM_OP_SHUTDOWN 	"do_shutdown"
#  define CRM_OP_FENCE	 	"stonith"
#  define CRM_OP_EVENTCC		"event_cc"
#  define CRM_OP_TEABORT		"te_abort"
#  define CRM_OP_TEABORTED	"te_abort_confirmed"    /* we asked */
#  define CRM_OP_TE_HALT		"te_halt"
#  define CRM_OP_TECOMPLETE	"te_complete"
#  define CRM_OP_TETIMEOUT	"te_timeout"
#  define CRM_OP_TRANSITION	"transition"
#  define CRM_OP_REGISTER		"register"
#  define CRM_OP_IPC_FWD		"ipc_fwd"
#  define CRM_OP_DEBUG_UP		"debug_inc"
#  define CRM_OP_DEBUG_DOWN	"debug_dec"
#  define CRM_OP_INVOKE_LRM	"lrm_invoke"
#  define CRM_OP_LRM_REFRESH	"lrm_refresh" /* Deprecated */
#  define CRM_OP_LRM_QUERY	"lrm_query"
#  define CRM_OP_LRM_DELETE	"lrm_delete"
#  define CRM_OP_LRM_FAIL		"lrm_fail"
#  define CRM_OP_PROBED		"probe_complete"
#  define CRM_OP_NODES_PROBED	"probe_nodes_complete"
#  define CRM_OP_REPROBE		"probe_again"
#  define CRM_OP_CLEAR_FAILCOUNT  "clear_failcount"
#  define CRM_OP_RELAXED_SET  "one-or-more"
#  define CRM_OP_RM_NODE_CACHE "rm_node_cache"

#  define CRMD_JOINSTATE_DOWN           "down"
#  define CRMD_JOINSTATE_PENDING        "pending"
#  define CRMD_JOINSTATE_MEMBER         "member"
#  define CRMD_JOINSTATE_NACK           "banned"

#  define CRMD_ACTION_DELETE		"delete"
#  define CRMD_ACTION_CANCEL		"cancel"

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
/* *INDENT-ON* */

typedef GList *GListPtr;

#  include <crm/common/logging.h>
#  include <crm/common/util.h>
#  include <crm/error.h>

#  define crm_str_hash g_str_hash_traditional

guint g_str_hash_traditional(gconstpointer v);

#endif
