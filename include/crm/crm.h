/* $Id: crm.h,v 1.98 2006/06/16 10:07:16 andrew Exp $ */
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

#include <stdlib.h>
#include <ha_config.h>
#include <glib.h>
#undef MIN
#undef MAX

#include <string.h>
#include <portability.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_malloc.h>
#ifdef MCHECK
#include <mcheck.h>
#endif

#include <config.h>

#ifndef CRM_DEV_BUILD
#  define CRM_DEV_BUILD 0
#endif

#define CRM_DEPRECATED_SINCE_2_0_1 0
#define CRM_DEPRECATED_SINCE_2_0_2 0
#define CRM_DEPRECATED_SINCE_2_0_3 0
#define CRM_DEPRECATED_SINCE_2_0_4 1
#define CRM_DEPRECATED_SINCE_2_0_5 1
#define CRM_DEPRECATED_SINCE_2_0_6 1
#define CRM_DEPRECATED_SINCE_2_0_7 1
#define CRM_DEPRECATED_SINCE_2_0_8 1
#define CRM_DEPRECATED_SINCE_2_1_0 1

#define CRM_META			"CRM_meta"
#if 1
#  define crm_meta_name(field) CRM_META"_"field
#else
#  define crm_meta_name(field) field
#endif

#define ipc_call_diff_max_ms 5000
#define action_diff_warn_ms  5000
#define action_diff_max_ms   20000
#define fsa_diff_warn_ms     10000
#define fsa_diff_max_ms      30000

#include <crm/common/util.h>

#define CRM_ASSERT(expr) if((expr) == FALSE) {				\
	crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, #expr, FALSE); \
}

extern gboolean crm_assert_failed;

#define CRM_DEV_ASSERT(expr)						\
	crm_assert_failed = FALSE;					\
	if((expr) == FALSE) {						\
		crm_assert_failed = TRUE;				\
		crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, #expr, TRUE); \
	}

#define CRM_CHECK(expr, failure_action) if((expr) == FALSE) {		\
		crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, #expr, TRUE); \
		failure_action;						\
	}

/* Clean these up at some point, some probably should be runtime options */
#define WORKING_DIR	HA_VARLIBDIR"/heartbeat/crm"
#define CRM_SOCK_DIR	HA_VARRUNDIR"/heartbeat/crm"
#define BIN_DIR		HA_LIBDIR"/heartbeat"
#define SOCKET_LEN	1024
#define APPNAME_LEN	256
#define MAX_IPC_FAIL	5
#define CIB_FILENAME	WORKING_DIR"/cib.xml"
#define CIB_BACKUP	WORKING_DIR"/cib_backup.xml"

#define CRM_FEATURE_SET	"1.0.7"

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
#define CRM_OP_PROBED		"probe_complete"
#define CRM_OP_REPROBE		"probe_again"

#define CRMD_STATE_ACTIVE	"member"
#define CRMD_STATE_INACTIVE	"down"

#define CRMD_JOINSTATE_DOWN	CRMD_STATE_INACTIVE
#define CRMD_JOINSTATE_PENDING	"pending"
#define CRMD_JOINSTATE_MEMBER	CRMD_STATE_ACTIVE

#define CRMD_ACTION_DELETE		"delete"
#define CRMD_ACTION_CANCEL		"cancel"

#define CRMD_ACTION_START		"start"
#define CRMD_ACTION_STARTED		"running"
#define CRMD_ACTION_START_FAIL		"start_failed"
#define CRMD_ACTION_START_PENDING	"starting"

#define CRMD_ACTION_STOP		"stop"
#define CRMD_ACTION_STOPPED		"stopped"
#define CRMD_ACTION_STOP_FAIL		"stop_failed"
#define CRMD_ACTION_STOP_PENDING	"stopping"

#define CRMD_ACTION_PROMOTE		"promote"
#define CRMD_ACTION_PROMOTED		"promoted"
#define CRMD_ACTION_DEMOTE		"demote"
#define CRMD_ACTION_DEMOTED		"demoted"

#define CRMD_ACTION_NOTIFY		"notify"
#define CRMD_ACTION_NOTIFIED		"notified"

#define CRMD_ACTION_STATUS		"monitor"
#define CRMD_ACTION_MON			"monitor"
#define CRMD_ACTION_MON_PENDING		CRMD_ACTION_STARTED
#define CRMD_ACTION_MON_OK		CRMD_ACTION_STARTED
#define CRMD_ACTION_MON_FAIL		"monitor_failed"
/* #define CRMD_ACTION_GENERIC		"pending" */
#define CRMD_ACTION_GENERIC_PENDING	"pending"
#define CRMD_ACTION_GENERIC_OK		"complete"
#define CRMD_ACTION_GENERIC_FAIL	"pending_failed"

typedef GList* GListPtr;

#define slist_iter(child, child_type, parent, counter, a)		\
	{								\
		GListPtr __crm_iter_head = parent;			\
		child_type *child = NULL;				\
		int counter = 0;					\
		for(; __crm_iter_head != NULL; counter++) {		\
			child = __crm_iter_head->data;			\
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

#define do_crm_log(level, fmt, args...) do {				\
		if(level > 1) {						\
			cl_log(level, "debug%d: %s: " fmt,		\
			       level, __PRETTY_FUNCTION__, ##args);	\
		} else {						\
			cl_log(level, "%s: " fmt,			\
			       __PRETTY_FUNCTION__, ##args);		\
		}							\
	} while(0)
		

#define crm_crit(fmt, args...)    do_crm_log(LOG_CRIT,    fmt, ##args)
#define crm_err(fmt, args...)     do_crm_log(LOG_ERR,     fmt, ##args)
#define crm_warn(fmt, args...)    do_crm_log(LOG_WARNING, fmt, ##args)
#define crm_notice(fmt, args...)  do_crm_log(LOG_NOTICE,  fmt, ##args)
#define crm_info(fmt, args...)    do_crm_log(LOG_INFO,    fmt, ##args)
#define crm_log_maybe(level, fmt, args...) if(crm_log_level >= (level)) { \
		do_crm_log((level), fmt, ##args);			\
	}

#define crm_debug(fmt, args...)   crm_log_maybe(LOG_DEBUG,   fmt, ##args)
#define crm_debug_2(fmt, args...) crm_log_maybe(LOG_DEBUG_2, fmt, ##args)
#define crm_debug_3(fmt, args...) crm_log_maybe(LOG_DEBUG_3, fmt, ##args)

/* If this is not a developmental build, give the compiler every chance to
 * optimize these away
 */
#if CRM_DEV_BUILD
#  define crm_debug_4(fmt, args...) crm_log_maybe(LOG_DEBUG_4, fmt, ##args)
#  define crm_debug_5(fmt, args...) crm_log_maybe(LOG_DEBUG_5, fmt, ##args)
#  define crm_debug_6(fmt, args...) crm_log_maybe(LOG_DEBUG_6, fmt, ##args)
#else
#  define crm_debug_4(fmt, args...) if(0) { do_crm_log(LOG_DEBUG, fmt, ##args); }
#  define crm_debug_5(fmt, args...) if(0) { do_crm_log(LOG_DEBUG, fmt, ##args); }
#  define crm_debug_6(fmt, args...) if(0) { do_crm_log(LOG_DEBUG, fmt, ##args); }
#endif

extern void crm_log_message_adv(
	int level, const char *alt_debugfile, const HA_Message *msg);

#define crm_log_message(level, msg) if(crm_log_level >= level) {	\
		crm_log_message_adv(level, NULL, msg);			\
	}

#define crm_do_action(level, actions) if(crm_log_level >= level) {	\
		actions;						\
	}
#define crm_action_info(x)    crm_do_action(LOG_INFO,    x)
#define crm_action_debug(x)   crm_do_action(LOG_DEBUG,   x)
#define crm_action_debug_2(x) crm_do_action(LOG_DEBUG_2, x)
#define crm_action_debug_3(x) crm_do_action(LOG_DEBUG_3, x)
#define crm_action_debug_4(x) crm_do_action(LOG_DEBUG_4, x)

#define crm_log_xml(level, text, xml)   if(crm_log_level >= level) {  \
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

#if CRM_USE_MALLOC
#  define crm_malloc0(new_obj,length)					\
	{								\
		new_obj = malloc(length);				\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			cl_flush_logs();				\
			exit(1);					\
		}							\
		memset(new_obj, 0, length);				\
	}
#  define crm_realloc(new_obj,length)					\
	{								\
		new_obj = realloc(new_obj, length);			\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			cl_flush_logs();				\
			exit(1);					\
		}							\
	}
#  define crm_free(x) if(x) { free(x); x=NULL; }
#else
#  if CRM_DEV_BUILD
#    define crm_malloc0(new_obj,length)					\
	{								\
		if(new_obj) {						\
			crm_err("Potential memory leak:"		\
				" %s at %s:%d not NULL before alloc.",	\
				#new_obj, __FILE__, __LINE__);		\
			cl_flush_logs();				\
			abort();					\
		}							\
		new_obj = cl_malloc(length);				\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			cl_flush_logs();				\
			abort();					\
		}							\
		memset(new_obj, 0, length);				\
	}
/* it's not a memory leak to already have an object to realloc, that's
 * the usual case, however if it does have a value, it must have been
 * allocated by the same allocator! */ 
#    define crm_realloc(new_obj,length)					\
	{								\
		if (new_obj != NULL) {					\
			CRM_ASSERT(cl_is_allocated(new_obj) == 1);	\
		}							\
		new_obj = cl_realloc(new_obj, length);			\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			cl_flush_logs();				\
			abort();					\
		}							\
	}
#    define crm_free(x) if(x) {				\
		CRM_ASSERT(cl_is_allocated(x) == 1);	\
		cl_free(x);				\
		x=NULL;				\
	}
#  else
#    define crm_malloc0(new_obj,length)					\
	{								\
		new_obj = cl_malloc(length);				\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			cl_flush_logs();				\
			abort();					\
		}							\
		memset(new_obj, 0, length);				\
	}
#    define crm_realloc(new_obj,length)					\
	{								\
		new_obj = cl_realloc(new_obj, length);			\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			cl_flush_logs();				\
			abort();					\
		}							\
	}
#    define crm_free(x) if(x) {				\
		cl_free(x);				\
		x=NULL;				\
	}
#  endif
#endif

#define crm_msg_del(msg) if(msg != NULL) { ha_msg_del(msg); msg = NULL; }

#endif
