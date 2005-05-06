/* $Id: crm.h,v 1.57 2005/05/06 16:01:05 gshi Exp $ */
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

#include <string.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_malloc.h>
#ifdef MCHECK
#include <mcheck.h>
#endif

#include <config.h>

#ifndef CRM_DEV_BUILD
#  define CRM_DEV_BUILD 0
#endif

#define ipc_call_diff_max_ms 1000
#define action_diff_max_ms   1000
#define fsa_diff_max_ms      2000

#include <crm/common/util.h>

#define CRM_ASSERT(expr) if((expr) == FALSE) {				\
		do_crm_log(LOG_CRIT, __FILE__, __PRETTY_FUNCTION__,	\
			   "Triggered dev assert at %s:%d : %s",	\
			   __FILE__, __LINE__, #expr);			\
		abort();						\
	}

extern gboolean crm_assert_failed;

#define CRM_DEV_ASSERT(expr) crm_assert_failed = FALSE;			\
	if((expr) == FALSE) {						\
		crm_assert_failed = TRUE;				\
		do_crm_log(CRM_DEV_BUILD?LOG_CRIT:LOG_ERR,		\
			   __FILE__, __PRETTY_FUNCTION__,		\
			   "Triggered dev assert at %s:%d : %s",	\
			   __FILE__, __LINE__, #expr);			\
		if(CRM_DEV_BUILD) {					\
			abort();					\
		}							\
	}

/* Clean these up at some point, some probably should be runtime options */
#define WORKING_DIR	HA_VARLIBDIR"/heartbeat/crm"
#define BIN_DIR		HA_LIBDIR"/heartbeat"
#define SOCKET_LEN	1024
#define APPNAME_LEN	256
#define LOG_DIR		"/var/log"
#define MAX_IPC_FAIL	5
#define CIB_FILENAME	WORKING_DIR"/cib.xml"
#define CIB_BACKUP	WORKING_DIR"/cib_backup.xml"

#define DEVEL_CIB_COPY   1
#define DEVEL_DIR	"/tmp/crm"

#define CRM_VERSION	"0.7"

#define MSG_LOG			1
#define DOT_FSA_ACTIONS		1
#define DOT_ALL_FSA_INPUTS	1
#define FSA_TRACE		1
/* #define USE_FAKE_LRM		1 */

#define INFINITY_S        "INFINITY"
#define MINUS_INFINITY_S "-INFINITY"

#define INFINITY        1000000.0

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

/* soon to be moved to cib.h */
#define CRM_OP_CIB_SLAVE	"cib_slave"
#define CRM_OP_CIB_SLAVEALL	"cib_slave_all"
#define CRM_OP_CIB_MASTER	"cib_master"
#define CRM_OP_CIB_SYNC		"cib_sync"
#define CRM_OP_CIB_ISMASTER	"cib_ismaster"
#define CRM_OP_CIB_BUMP		"cib_bump"
#define CRM_OP_CIB_QUERY	"cib_query"
#define CRM_OP_CIB_CREATE	"cib_create"
#define CRM_OP_CIB_UPDATE	"cib_update"
#define CRM_OP_CIB_DELETE	"cib_delete"
#define CRM_OP_CIB_ERASE	"cib_erase"
#define CRM_OP_CIB_REPLACE	"cib_replace"
#define CRM_OP_CIB_NOTIFY	"cib_notify"

#define CRM_OP_JOIN_ANNOUNCE	"join_announce"
#define CRM_OP_JOIN_OFFER	"join_offer"
#define CRM_OP_JOIN_REQUEST	"join_request"
#define CRM_OP_JOIN_ACKNAK	"join_ack_nack"
#define CRM_OP_JOIN_CONFIRM	"join_confirm"

#define CRM_OP_DIE		"die_no_respawn"
#define CRM_OP_RETRIVE_CIB	"retrieve_cib"
#define CRM_OP_PING		"ping"
#define CRM_OP_VOTE		"vote"
#define CRM_OP_HELLO		"hello"
#define CRM_OP_HBEAT		"dc_beat"
#define CRM_OP_PECALC		"pe_calc"
#define CRM_OP_ABORT		"abort"
#define CRM_OP_QUIT		"quit"
#define CRM_OP_LOCAL_SHUTDOWN 	"start_shutdown"
#define CRM_OP_SHUTDOWN_REQ	"req_shutdown"
#define CRM_OP_SHUTDOWN 	"do_shutdown"
#define CRM_OP_EVENTCC		"event_cc"
#define CRM_OP_TEABORT		"te_abort"
#define CRM_OP_TRANSITION	"transition"
#define CRM_OP_TECOMPLETE	"te_complete"
#define CRM_OP_TETIMEOUT	"te_timeout"
#define CRM_OP_REGISTER		"register"
#define CRM_OP_DEBUG_UP		"debug_inc"
#define CRM_OP_DEBUG_DOWN	"debug_dec"

#define CRMD_STATE_ACTIVE	"member"
#define CRMD_STATE_INACTIVE	"down"

#define CRMD_JOINSTATE_DOWN	"down"
#define CRMD_JOINSTATE_PENDING	"pending"
#define CRMD_JOINSTATE_MEMBER	"member"

#define CRMD_RSCSTATE_START		"start"
#define CRMD_RSCSTATE_START_PENDING	"starting"
#define CRMD_RSCSTATE_START_OK		"running"
#define CRMD_RSCSTATE_START_FAIL	"start_failed"
#define CRMD_RSCSTATE_STOP		"stop"
#define CRMD_RSCSTATE_STOP_PENDING	"stopping"
#define CRMD_RSCSTATE_STOP_OK		"stopped"
#define CRMD_RSCSTATE_STOP_FAIL		"stop_failed"
#define CRMD_RSCSTATE_MON		"monitor"
#define CRMD_RSCSTATE_MON_PENDING	CRMD_RSCSTATE_START_OK
#define CRMD_RSCSTATE_MON_OK		CRMD_RSCSTATE_START_OK
#define CRMD_RSCSTATE_MON_FAIL		"monitor_failed"
/* #define CRMD_RSCSTATE_GENERIC		"pending" */
#define CRMD_RSCSTATE_GENERIC_PENDING	"pending"
#define CRMD_RSCSTATE_GENERIC_OK	"complete"
#define CRMD_RSCSTATE_GENERIC_FAIL	"pending_failed"

typedef GList* GListPtr;

#define crm_atoi(text, default) atoi(text?text:default)

extern gboolean safe_str_eq(const char *a, const char *b);
extern gboolean safe_str_neq(const char *a, const char *b);

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

#define safe_val3(def, t,u,v)       (t?t->u?t->u->v:def:def)

/* Developmental debug stuff */

#define LOG_VERBOSE  LOG_DEBUG+1
#define LOG_DEV      LOG_DEBUG+2
#define LOG_TRACE    LOG_DEBUG+3
#define LOG_INSANE   LOG_DEBUG+5
#define LOG_MSG      LOG_DEV

#  define crm_crit(w...)    do_crm_log(LOG_CRIT,    __FILE__, __FUNCTION__, w)
#  define crm_err(w...)     do_crm_log(LOG_ERR,     __FILE__, __FUNCTION__, w)
#  define crm_warn(w...)    do_crm_log(LOG_WARNING, __FILE__, __FUNCTION__, w)
#  define crm_notice(w...)  do_crm_log(LOG_NOTICE,  __FILE__, __FUNCTION__, w)
#  define crm_info(w...)    do_crm_log(LOG_INFO,    __FILE__, __FUNCTION__, w)
#if 1
#  define crm_debug(w...)   do_crm_log(LOG_DEBUG,   __FILE__, __FUNCTION__, w)
#  define crm_devel(w...)   do_crm_log(LOG_DEV,     __FILE__, __FUNCTION__, w)
#  define crm_verbose(w...) do_crm_log(LOG_VERBOSE, __FILE__, __FUNCTION__, w)
#  define crm_trace(w...)   do_crm_log(LOG_TRACE,   __FILE__, __FUNCTION__, w)
#  define crm_insane(w...)  do_crm_log(LOG_INSANE,  __FILE__, __FUNCTION__, w)
#else
#  define crm_debug(w...)   if(0) { do_crm_log(LOG_DEBUG,   NULL, NULL, w); }
#  define crm_devel(w...)   if(0) { do_crm_log(LOG_DEV,     NULL, NULL, w); }
#  define crm_verbose(w...) if(0) { do_crm_log(LOG_VERBOSE, NULL, NULL, w); }
#  define crm_trace(w...)   if(0) { do_crm_log(LOG_TRACE,   NULL, NULL, w); }
#  define crm_insane(w...)  if(0) { do_crm_log(LOG_INSANE,  NULL, NULL, w); }
#endif

extern void crm_log_message_adv(int level, const char *alt_debugfile, const HA_Message *msg);
#define crm_log_message(level, msg) crm_log_message_adv(level, NULL, msg)

#define crm_do_action(level, actions) if(crm_log_level >= level) {	\
		actions;						\
	}

#define crm_info_action(x)    crm_do_action(LOG_INFO, x)
#define crm_debug_action(x)   crm_do_action(LOG_DEBUG, x)
#define crm_verbose_action(x) crm_do_action(LOG_VERBOSE, x)
#define crm_devel_action(x)   crm_do_action(LOG_DEV, x)

#define crm_log_xml(level, text, xml)   if(crm_log_level >= level) {  \
		print_xml_formatted(level,  __FUNCTION__, xml, text); \
	}
#define crm_xml_crit(xml, text)    crm_log_xml(LOG_CRIT,    text, xml)
#define crm_xml_err(xml, text)     crm_log_xml(LOG_ERR,     text, xml)
#define crm_xml_warn(xml, text)    crm_log_xml(LOG_WARNING, text, xml)
#define crm_xml_notice(xml, text)  crm_log_xml(LOG_NOTICE,  text, xml)
#define crm_xml_info(xml, text)    crm_log_xml(LOG_INFO,    text, xml)
#define crm_xml_debug(xml, text)   crm_log_xml(LOG_DEBUG,   text, xml)
#define crm_xml_devel(xml, text)   crm_log_xml(LOG_DEV,     text, xml)
#define crm_xml_verbose(xml, text) crm_log_xml(LOG_VERBOSE, text, xml)
#define crm_xml_trace(xml, text)   crm_log_xml(LOG_TRACE,   text, xml)
#define crm_xml_insane(xml, text)  crm_log_xml(LOG_INSANE,  text, xml)

#define crm_malloc0(new_obj,length)					\
	{								\
		if(new_obj) {						\
			crm_err("Potential memory leak:"		\
				" %s at %s:%d not NULL before alloc.",	\
				#new_obj, __FILE__, __LINE__);		\
			if(CRM_DEV_BUILD) { abort(); }			\
		}							\
		new_obj = cl_malloc(length);				\
		if(new_obj == NULL) {					\
			crm_crit("Out of memory... exiting");		\
			exit(1);					\
		} else {						\
			memset(new_obj, 0, length);			\
		}							\
	}	

/* for temporary backwards compatibility */
#define crm_malloc(new_obj,length) crm_malloc0(new_obj,length) 

#if 1
#  define crm_free(x)   if(x) {				\
		CRM_ASSERT(cl_is_allocated(x) == 1);	\
		cl_free(x);				\
		x=NULL;					\
	}
#else
#  define crm_free(x)   x=NULL
#endif
#define crm_str(x)    (const char*)(x?x:"<null>")

#if 1
#  define crm_msg_del(msg) if(msg != NULL) { ha_msg_del(msg); }
#else
#  define crm_msg_del(msg) msg = NULL
#endif

#endif
