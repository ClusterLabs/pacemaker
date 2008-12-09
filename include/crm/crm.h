/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef CRM__H
#define CRM__H

#include <heartbeat/hb_config.h>
#include <crm_config.h>
#include <stdlib.h>
#include <glib.h>

#undef MIN
#undef MAX
#include <string.h>

#include <clplumbing/cl_log.h>

#include <libxml/tree.h> 

#define CRM_FEATURE_SET		"3.0.1"
#define MINIMUM_SCHEMA_VERSION	"pacemaker-1.0"
#define LATEST_SCHEMA_VERSION	"pacemaker-"DTD_VERSION

#define EOS		'\0'
#define DIMOF(a)	((int) (sizeof(a)/sizeof(a[0])) )
#define	HAURL(url)	HA_URLBASE url

#ifndef __GNUC__
#    define __builtin_expect(expr, result) (expr)
#endif

/* Some handy macros used by the Linux kernel */
#define __likely(expr) __builtin_expect(expr, 1)
#define __unlikely(expr) __builtin_expect(expr, 0)

#define CRM_DEPRECATED_SINCE_2_0_1 0
#define CRM_DEPRECATED_SINCE_2_0_2 0
#define CRM_DEPRECATED_SINCE_2_0_3 0
#define CRM_DEPRECATED_SINCE_2_0_4 0
#define CRM_DEPRECATED_SINCE_2_0_5 0
#define CRM_DEPRECATED_SINCE_2_0_6 1
#define CRM_DEPRECATED_SINCE_2_0_7 1
#define CRM_DEPRECATED_SINCE_2_0_8 1
#define CRM_DEPRECATED_SINCE_2_1_0 1

#define CRM_META			"CRM_meta"

#define ipc_call_diff_max_ms 5000
#define action_diff_warn_ms  5000
#define action_diff_max_ms   20000
#define fsa_diff_warn_ms     10000
#define fsa_diff_max_ms      30000

#define CRM_ASSERT(expr) do {						\
	if((expr) == FALSE) {						\
	    crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr, TRUE, FALSE); \
	}								\
    } while(0)

#define CRM_DEV_ASSERT(expr) do {					\
	if((expr) == FALSE) {						\
		crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, #expr, FALSE, TRUE); \
	}								\
    } while(0)

#define CRM_CHECK(expr, failure_action) do {				\
	if((expr) == FALSE) {						\
	    crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, #expr, FALSE, TRUE); \
	    failure_action;						\
	}								\
    } while(0)

#define CRM_CHECK_AND_STORE(expr, failure_action) do {			\
	if((expr) == FALSE) {						\
	    crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, #expr, TRUE, TRUE); \
	    failure_action;						\
	}								\
    } while(0)

extern const char *crm_system_name;

/* Clean these up at some point, some probably should be runtime options */
#define WORKING_DIR	HA_VARLIBDIR"/heartbeat/crm"
#define CRM_SOCK_DIR	HA_VARRUNDIR"/heartbeat/crm"
#define BIN_DIR		HA_LIBDIR"/heartbeat"
#define SOCKET_LEN	1024
#define APPNAME_LEN	256
#define MAX_IPC_FAIL	5
#define CIB_FILENAME	WORKING_DIR"/cib.xml"
#define CIB_BACKUP	WORKING_DIR"/cib_backup.xml"

#define MSG_LOG			1
#define DOT_FSA_ACTIONS		1
#define DOT_ALL_FSA_INPUTS	1
/* #define FSA_TRACE		1 */

#define INFINITY_S        "INFINITY"
#define MINUS_INFINITY_S "-INFINITY"

#define INFINITY        1000000

/* Sub-systems */
#define CRM_SYSTEM_DC		"dc"
#define CRM_SYSTEM_DCIB		"dcib" /*  The master CIB */
#define CRM_SYSTEM_CIB		"cib"
#define CRM_SYSTEM_CRMD		"crmd"
#define CRM_SYSTEM_LRMD		"lrmd"
#define CRM_SYSTEM_PENGINE	"pengine"
#define CRM_SYSTEM_TENGINE	"tengine"
#define CRM_SYSTEM_STONITHD	"stonithd"

/* Valid operations */
#define CRM_OP_NOOP		"noop"

#define CRM_OP_JOIN_ANNOUNCE	"join_announce"
#define CRM_OP_JOIN_OFFER	"join_offer"
#define CRM_OP_JOIN_REQUEST	"join_request"
#define CRM_OP_JOIN_ACKNAK	"join_ack_nack"
#define CRM_OP_JOIN_CONFIRM	"join_confirm"

#define CRM_OP_DIE		"die_no_respawn"
#define CRM_OP_RETRIVE_CIB	"retrieve_cib"
#define CRM_OP_PING		"ping"
#define CRM_OP_VOTE		"vote"
#define CRM_OP_NOVOTE		"no-vote"
#define CRM_OP_HELLO		"hello"
#define CRM_OP_HBEAT		"dc_beat"
#define CRM_OP_PECALC		"pe_calc"
#define CRM_OP_ABORT		"abort"
#define CRM_OP_QUIT		"quit"
#define CRM_OP_LOCAL_SHUTDOWN 	"start_shutdown"
#define CRM_OP_SHUTDOWN_REQ	"req_shutdown"
#define CRM_OP_SHUTDOWN 	"do_shutdown"
#define CRM_OP_FENCE	 	"stonith"
#define CRM_OP_EVENTCC		"event_cc"
#define CRM_OP_TEABORT		"te_abort"
#define CRM_OP_TEABORTED	"te_abort_confirmed" /* we asked */
#define CRM_OP_TE_HALT		"te_halt"
#define CRM_OP_TECOMPLETE	"te_complete"
#define CRM_OP_TETIMEOUT	"te_timeout"
#define CRM_OP_TRANSITION	"transition"
#define CRM_OP_REGISTER		"register"
#define CRM_OP_DEBUG_UP		"debug_inc"
#define CRM_OP_DEBUG_DOWN	"debug_dec"
#define CRM_OP_INVOKE_LRM	"lrm_invoke"
#define CRM_OP_LRM_REFRESH	"lrm_refresh"
#define CRM_OP_LRM_QUERY	"lrm_query"
#define CRM_OP_LRM_DELETE	"lrm_delete"
#define CRM_OP_LRM_FAIL		"lrm_fail"
#define CRM_OP_PROBED		"probe_complete"
#define CRM_OP_REPROBE		"probe_again"

#define CRMD_STATE_ACTIVE	"member"
#define CRMD_STATE_INACTIVE	"down"

#define CRMD_JOINSTATE_DOWN	CRMD_STATE_INACTIVE
#define CRMD_JOINSTATE_PENDING	"pending"
#define CRMD_JOINSTATE_MEMBER	CRMD_STATE_ACTIVE
#define CRMD_JOINSTATE_NACK	"banned"

#define CRMD_ACTION_DELETE		"delete"
#define CRMD_ACTION_CANCEL		"cancel"

#define CRMD_ACTION_MIGRATE		"migrate_to"
#define CRMD_ACTION_MIGRATED		"migrate_from"

#define CRMD_ACTION_START		"start"
#define CRMD_ACTION_STARTED		"running"

#define CRMD_ACTION_STOP		"stop"
#define CRMD_ACTION_STOPPED		"stopped"

#define CRMD_ACTION_PROMOTE		"promote"
#define CRMD_ACTION_PROMOTED		"promoted"
#define CRMD_ACTION_DEMOTE		"demote"
#define CRMD_ACTION_DEMOTED		"demoted"

#define CRMD_ACTION_NOTIFY		"notify"
#define CRMD_ACTION_NOTIFIED		"notified"

#define CRMD_ACTION_STATUS		"monitor"

/* short names */
#define RSC_DELETE	CRMD_ACTION_DELETE
#define RSC_CANCEL	CRMD_ACTION_CANCEL

#define RSC_MIGRATE	CRMD_ACTION_MIGRATE
#define RSC_MIGRATED	CRMD_ACTION_MIGRATED

#define RSC_START	CRMD_ACTION_START
#define RSC_STARTED	CRMD_ACTION_STARTED

#define RSC_STOP	CRMD_ACTION_STOP
#define RSC_STOPPED	CRMD_ACTION_STOPPED

#define RSC_PROMOTE	CRMD_ACTION_PROMOTE
#define RSC_PROMOTED	CRMD_ACTION_PROMOTED
#define RSC_DEMOTE	CRMD_ACTION_DEMOTE
#define RSC_DEMOTED	CRMD_ACTION_DEMOTED

#define RSC_NOTIFY	CRMD_ACTION_NOTIFY
#define RSC_NOTIFIED	CRMD_ACTION_NOTIFIED

#define RSC_STATUS	CRMD_ACTION_STATUS




typedef GList* GListPtr;
#define slist_destroy(child_type, child, parent, a)			\
	{		 						\
		GListPtr __crm_iter_head = parent;			\
		child_type *child = NULL;				\
		while(__crm_iter_head != NULL) {			\
			child = (child_type *) __crm_iter_head->data;	\
			__crm_iter_head = __crm_iter_head->next;	\
			{ a; }						\
		}							\
		g_list_free(parent);					\
	}

#define slist_iter(child, child_type, parent, counter, a)		\
	{		 						\
		GListPtr __crm_iter_head = parent;			\
		child_type *child = NULL;				\
		int counter = 0;					\
		for(; __crm_iter_head != NULL; counter++) {		\
			child = (child_type *) __crm_iter_head->data;	\
			__crm_iter_head = __crm_iter_head->next;	\
			{ a; }						\
		}							\
	}

#define LOG_DEBUG_2  LOG_DEBUG+1
#define LOG_DEBUG_3  LOG_DEBUG+2
#define LOG_DEBUG_4  LOG_DEBUG+3
#define LOG_DEBUG_5  LOG_DEBUG+4
#define LOG_DEBUG_6  LOG_DEBUG+5

#define LOG_MSG  LOG_DEBUG_3

/*
 * Throughout the macros below, note the leading, pre-comma, space in the
 * various ' , ##args' occurences to aid portability across versions of 'gcc'.
 *	http://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html#Variadic-Macros
 */
#define do_crm_log(level, fmt, args...) do {				\
	if(__unlikely(crm_log_level < (level))) {			\
	    continue;							\
	} else if(__likely((level) < LOG_DEBUG_2)) {			\
	    cl_log(level, "%s: " fmt, __PRETTY_FUNCTION__ , ##args);	\
	} else {							\
	    cl_log(LOG_DEBUG, "debug%d: %s: " fmt,			\
		   level-LOG_INFO, __PRETTY_FUNCTION__ , ##args);	\
	}								\
    } while(0)

#define do_crm_log_unlikely(level, fmt, args...) do {			\
	if(__likely(crm_log_level < (level))) {				\
	    continue;							\
	} else if((level) < LOG_DEBUG_2) {				\
	    cl_log(level, "%s: " fmt, __PRETTY_FUNCTION__ , ##args);	\
	} else {							\
	    cl_log(LOG_DEBUG, "debug%d: %s: " fmt,			\
		   level-LOG_INFO, __PRETTY_FUNCTION__ , ##args);	\
	}								\
    } while(0)

#define do_crm_log_always(level, fmt, args...) cl_log(level, "%s: " fmt, __PRETTY_FUNCTION__ , ##args)

#define crm_crit(fmt, args...)    do_crm_log_always(LOG_CRIT,    fmt , ##args)
#define crm_err(fmt, args...)     do_crm_log(LOG_ERR,     fmt , ##args)
#define crm_warn(fmt, args...)    do_crm_log(LOG_WARNING, fmt , ##args)
#define crm_notice(fmt, args...)  do_crm_log(LOG_NOTICE,  fmt , ##args)
#define crm_info(fmt, args...)    do_crm_log(LOG_INFO,    fmt , ##args)
#define crm_debug(fmt, args...)   do_crm_log_unlikely(LOG_DEBUG,   fmt , ##args)
#define crm_debug_2(fmt, args...) do_crm_log_unlikely(LOG_DEBUG_2, fmt , ##args)
#define crm_debug_3(fmt, args...) do_crm_log_unlikely(LOG_DEBUG_3, fmt , ##args)
#define crm_debug_4(fmt, args...) do_crm_log_unlikely(LOG_DEBUG_4, fmt , ##args)
#define crm_debug_5(fmt, args...) do_crm_log_unlikely(LOG_DEBUG_5, fmt , ##args)
#define crm_debug_6(fmt, args...) do_crm_log_unlikely(LOG_DEBUG_6, fmt , ##args)
#define crm_perror(level, fmt, args...) do {				\
	const char *err = strerror(errno);				\
	do_crm_log_always(level, fmt ": %s", ##args, err);		\
    } while(0)

#include <crm/common/util.h>

#define crm_log_xml(level, text, xml)   if(crm_log_level >= (level)) {	\
		print_xml_formatted(level,  __PRETTY_FUNCTION__, xml, text); \
	}
#define crm_log_xml_crit(xml, text)    crm_log_xml(LOG_CRIT,    text, xml)
#define crm_log_xml_err(xml, text)     crm_log_xml(LOG_ERR,     text, xml)
#define crm_log_xml_warn(xml, text)    crm_log_xml(LOG_WARNING, text, xml)
#define crm_log_xml_notice(xml, text)  crm_log_xml(LOG_NOTICE,  text, xml)
#define crm_log_xml_info(xml, text)    crm_log_xml(LOG_INFO,    text, xml)
#define crm_log_xml_debug(xml, text)   crm_log_xml(LOG_DEBUG,   text, xml)
#define crm_log_xml_debug_2(xml, text) crm_log_xml(LOG_DEBUG_2, text, xml)
#define crm_log_xml_debug_3(xml, text) crm_log_xml(LOG_DEBUG_3, text, xml)
#define crm_log_xml_debug_4(xml, text) crm_log_xml(LOG_DEBUG_4, text, xml)
#define crm_log_xml_debug_5(xml, text) crm_log_xml(LOG_DEBUG_5, text, xml)

#define crm_str(x)    (const char*)(x?x:"<null>")

#define crm_malloc0(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    crm_err("Failed allocation of %lu bytes", (unsigned long)length); \
	    CRM_ASSERT(malloc_obj != NULL);				\
	}								\
	memset(malloc_obj, 0, length);					\
    } while(0)

#define crm_malloc(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    crm_err("Failed allocation of %lu bytes", (unsigned long)length); \
	    CRM_ASSERT(malloc_obj != NULL);				\
	}								\
    } while(0)

#define crm_realloc(realloc_obj, length) do {				\
	realloc_obj = realloc(realloc_obj, length);			\
	CRM_ASSERT(realloc_obj != NULL);				\
    } while(0)
	
#define crm_free(free_obj) do { free(free_obj); free_obj=NULL; } while(0)
#define crm_msg_del(msg) do { if(msg != NULL) { ha_msg_del(msg); msg = NULL; } } while(0)

#define crm_strdup(str) crm_strdup_fn(str, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif
