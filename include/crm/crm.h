/* $Id: crm.h,v 1.27 2004/09/21 19:11:22 andrew Exp $ */
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
#include <crm/common/util.h>

/* Clean these up at some point, some probably should be runtime options */
#define WORKING_DIR	HA_VARLIBDIR"/heartbeat/crm"
#define BIN_DIR		"/usr/lib/heartbeat"
#define MAXDATASIZE	65535 /* ipc comms */
#define SOCKET_LEN	1024
#define APPNAME_LEN	256
#define LOG_DIR		"/var/log"
#define MAX_IPC_FAIL	5
#define CIB_FILENAME	WORKING_DIR"/cib.xml"
#define CIB_BACKUP	WORKING_DIR"/cib_backup.xml"

#define DEVEL_CIB_COPY   1
#define DEVEL_DIR	"/tmp/crm"

#define CRM_VERSION	"0.6"

#define MSG_LOG			1
#define DOT_FSA_ACTIONS		1
#define DOT_ALL_FSA_INPUTS	1
#define FSA_TRACE		1
/* #define USE_FAKE_LRM		1 */

/* Sub-systems */
#define CRM_SYSTEM_DC		"dc"
#define CRM_SYSTEM_DCIB		"dcib" /*  The master CIB */
#define CRM_SYSTEM_CIB		"cib"
#define CRM_SYSTEM_CRMD		"crmd"
#define CRM_SYSTEM_LRMD		"lrmd"
#define CRM_SYSTEM_PENGINE	"pengine"
#define CRM_SYSTEM_TENGINE	"tengine"

/* Valid operations */
#define CRM_OP_BUMP		"bump"
#define CRM_OP_QUERY		"query"
#define CRM_OP_CREATE		"create"
#define CRM_OP_UPDATE		"update"
#define CRM_OP_DELETE		"delete"
#define CRM_OP_ERASE		"erase"
#define CRM_OP_STORE		"store"
#define CRM_OP_REPLACE		"replace"
#define CRM_OP_FORWARD		"forward"
#define CRM_OP_JOINACK		"join_ack_nack"
#define CRM_OP_WELCOME		"welcome"
#define CRM_OP_PING		"ping"
#define CRM_OP_VOTE		"vote"
#define CRM_OP_HELLO		"hello"
#define CRM_OP_ANNOUNCE		"announce"
#define CRM_OP_HBEAT		"dc_beat"
#define CRM_OP_PECALC		"pe_calc"
#define CRM_OP_ABORT		"abort"
#define CRM_OP_QUIT		"quit"
#define CRM_OP_SHUTDOWN 	"shutdown_crm"
#define CRM_OP_EVENTCC		"event_cc"
#define CRM_OP_TEABORT		"te_abort"
#define CRM_OP_TRANSITION	"transition"
#define CRM_OP_TECOMPLETE	"te_complete"
#define CRM_OP_SHUTDOWN_REQ	"req_shutdown"

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
#define CRMD_RSCSTATE_MON		"status"
#define CRMD_RSCSTATE_MON_PENDING	CRMD_RSCSTATE_START_OK
#define CRMD_RSCSTATE_MON_OK		CRMD_RSCSTATE_START_OK
#define CRMD_RSCSTATE_MON_FAIL		"status_failed"
/* #define CRMD_RSCSTATE_GENERIC		"pending" */
#define CRMD_RSCSTATE_GENERIC_PENDING	"pending"
#define CRMD_RSCSTATE_GENERIC_OK	"complete"
#define CRMD_RSCSTATE_GENERIC_FAIL	"pending_failed"

typedef GList* GListPtr;

#define safe_str_eq(x, y)  (x!=NULL && y!=NULL && strcmp(x,y) == 0)
#define safe_str_neq(x, y) (x != y && (x==NULL || y==NULL || strcmp(x,y) != 0))

#define slist_iter(w, x, y, z, a)					\
	{								\
		z = 0;							\
		GListPtr __crm_iter_head = y;				\
		x *w = NULL;						\
		while(__crm_iter_head != NULL) {			\
			z++;						\
			w = __crm_iter_head->data;			\
			__crm_iter_head = __crm_iter_head->next;	\
			a;						\
		}							\
	}								\

/* Developmental debug stuff */

#define LOG_VERBOSE  LOG_DEBUG+1
#define LOG_DEV      LOG_DEBUG+2
#define LOG_TRACE    LOG_DEBUG+3

#if 1
#  define crm_crit(w...)    do_crm_log(LOG_CRIT,    __FUNCTION__, w)
#  define crm_err(w...)     do_crm_log(LOG_ERR,     __FUNCTION__, w)
#  define crm_warn(w...)    do_crm_log(LOG_WARNING, __FUNCTION__, w)
#  define crm_notice(w...)  do_crm_log(LOG_NOTICE,  __FUNCTION__, w)
#  define crm_info(w...)    do_crm_log(LOG_INFO,    __FUNCTION__, w)
#  define crm_debug(w...)   do_crm_log(LOG_DEBUG,   __FUNCTION__, w)
#  define crm_devel(w...)   do_crm_log(LOG_DEV,     __FUNCTION__, w)
#  define crm_verbose(w...) do_crm_log(LOG_VERBOSE, __FUNCTION__, w)
#  define crm_trace(w...)   do_crm_log(LOG_TRACE,   __FUNCTION__, w)
#else
#  define crm_crit(w...)    cl_log(LOG_CRIT,    w)
#  define crm_err(w...)     cl_log(LOG_ERR,     w)
#  define crm_warn(w...)    cl_log(LOG_WARNING, w)
#  define crm_notice(w...)  cl_log(LOG_NOTICE,  w)
#  define crm_info(w...)    cl_log(LOG_INFO,    w)
#  define crm_debug(w...)   cl_log(LOG_DEBUG,   w)
#  define crm_devel(w...)   cl_log(LOG_DEV,     w)
#  define crm_verbose(w...) cl_log(LOG_VERBOSE, w)
#  define crm_trace(w...)   cl_log(LOG_TRACE,   w)
#endif

#define crm_debug_action(x) if(crm_log_level >= LOG_DEBUG) {	\
		x;						\
	}

#define crm_info_action(x) if(crm_log_level >= LOG_INFO) {	\
		x;						\
	}

#define crm_xml_crit(x,y)    print_xml_formatted(LOG_CRIT,   __FUNCTION__, x,y)
#define crm_xml_err(x,y)     print_xml_formatted(LOG_ERR,    __FUNCTION__, x,y)
#define crm_xml_warn(x,y)    print_xml_formatted(LOG_WARNING,__FUNCTION__, x,y)
#define crm_xml_notice(x,y)  print_xml_formatted(LOG_NOTICE, __FUNCTION__, x,y)
#define crm_xml_info(x,y)    print_xml_formatted(LOG_INFO,   __FUNCTION__, x,y)
#define crm_xml_debug(x,y)   print_xml_formatted(LOG_DEBUG,  __FUNCTION__, x,y)
#define crm_xml_devel(x,y)   print_xml_formatted(LOG_DEV,    __FUNCTION__, x,y)
#define crm_xml_verbose(x,y) print_xml_formatted(LOG_VERBOSE,__FUNCTION__, x,y)
#define crm_xml_trace(x,y)   print_xml_formatted(LOG_TRACE,  __FUNCTION__, x,y)

#define crm_malloc(x,y)						\
	{							\
		x = cl_malloc(y);				\
		if(x == NULL) {				\
			crm_crit("Out of memory... exiting");	\
			exit(1);				\
		}						\
	}							\
	
#define crm_strdup(x) cl_strdup(x)
#define crm_free(x)   if(x) { cl_free(x); x=NULL; }
#define crm_str(x)    (const char*)(x?x:"<null>")
#endif
