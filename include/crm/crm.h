/* $Id: crm.h,v 1.8 2004/06/01 11:45:39 andrew Exp $ */
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
#include <mcheck.h>

/* Clean these up at some point, some probably should be runtime options */
#define WORKING_DIR HA_VARLIBDIR"/heartbeat/crm"
#define BIN_DIR "/usr/lib/heartbeat"
#define MAXDATASIZE 65535 // ipc comms
#define SOCKET_LEN    1024
#define APPNAME_LEN 256
#define LOG_DIR     "/var/log"
#define MAX_IPC_FAIL 5
#define CIB_FILENAME WORKING_DIR"/cib.xml"
#define CIB_BACKUP   WORKING_DIR"/cib_backup.xml"


#define MSG_LOG 1
#define INTEGRATED_CIB 1
#define DOT_FSA_ACTIONS 1
#define DOT_ALL_FSA_INPUTS 1
//#define FSA_TRACE 1
#define USE_FAKE_LRM 1
/* Throttle announce messages to work around what appears to be a bug in
 * the send_ordered_*_message() code.  node messages are taking approx 15s
 * longer to be sent than their cluster counterparts
 */
#define THROTTLE_ANNOUNCE 1


/* Sub-systems */
#define CRM_SYSTEM_DC		"dc"
#define CRM_SYSTEM_DCIB		"dcib" // The master CIB
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
#define CRM_OP_JOINACK		"join_ack"
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

#define CRMD_STATE_ACTIVE	"active"
#define CRMD_STATE_INACTIVE	"inactive"

#define CRMD_JOINSTATE_DOWN	"down"
#define CRMD_JOINSTATE_PENDING	"pending"
#define CRMD_JOINSTATE_MEMBER	"member"

typedef GSList* GSListPtr;

#define safe_str_eq(x, y)  x!=NULL && y!=NULL && strcmp(x,y) == 0
#define safe_str_neq(x, y) x != y && (x==NULL || y==NULL || strcmp(x,y) != 0)

#define slist_iter(w, x, y, z, a) for(z = 0; z < g_slist_length(y);  z++) { \
				         x *w = (x*)g_slist_nth_data(y, z); \
					 a;				    \
				  }

/* Developmental debug stuff */
#define CRM_DEBUG(w...) cl_log(LOG_DEBUG, w)

extern gboolean crm_debug_state;
#define crm_debug(w...)  if(crm_debug_state) {	\
		cl_log(LOG_DEBUG, w);		\
	}

#define crm_debug_action(x) if(crm_debug_state) {	\
		x;					\
	}

/* Seriously detailed debug stuff */
#if 0
#   define FNIN()     cl_log(LOG_DEBUG, "#---#---# Entering %s...", __FUNCTION__)
#   define FNOUT()  { cl_log(LOG_DEBUG, "#---#---# Leaving %s...",  __FUNCTION__); return;   }
#   define FNRET(x) { cl_log(LOG_DEBUG, "#---#---# Leaving %s...",  __FUNCTION__); return x; }
#else
#   define FNIN()   ;
#   define FNOUT()  return;
#   define FNRET(x) return x; 
#endif

#define crm_malloc(x) malloc(x)
#define crm_free(x)   if(x) { free(x); x=NULL; }
#define crm_strdup(x) strdup(x)

#endif
