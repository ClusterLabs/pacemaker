/* $Id: crm.h,v 1.7 2004/05/23 18:13:09 andrew Exp $ */
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

#include <clplumbing/cl_log.h>
#include <clplumbing/cl_malloc.h>
#include <string.h>

#define safe_str_eq(x, y)  x!=NULL && y!=NULL && strcmp(x,y) == 0
#define safe_str_neq(x, y) x != y && (x==NULL || y==NULL || strcmp(x,y) != 0)

/* Developmental debug stuff */
#if 1
#   define CRM_DEBUG(w...)        cl_log(LOG_DEBUG, w)
#else
/* these wont work yet, need to cast to void */
#   define CRM_DEBUG(w...)		if(0) { cl_log(LOG_DEBUG, w); }
#endif

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

/* Sub-systems */
#define CRM_SYSTEM_DC       "dc"
#define CRM_SYSTEM_DCIB     "dcib" // The master CIB
#define CRM_SYSTEM_CIB      "cib"
#define CRM_SYSTEM_CRMD     "crmd"
#define CRM_SYSTEM_LRMD     "lrmd"
#define CRM_SYSTEM_PENGINE  "pengine"
#define CRM_SYSTEM_TENGINE  "tengine"

/* Valid operations */
#define CRM_OPERATION_BUMP	"bump"
#define CRM_OPERATION_QUERY	"query"
#define CRM_OPERATION_CREATE	"create"
#define CRM_OPERATION_UPDATE	"update"
#define CRM_OPERATION_DELETE	"delete"
#define CRM_OPERATION_ERASE	"erase"
#define CRM_OPERATION_STORE	"store"
#define CRM_OPERATION_REPLACE	"replace"
#define CRM_OPERATION_FORWARD	"forward"
#define CRM_OPERATION_JOINACK	"join_ack"
#define CRM_OPERATION_WELCOME	"welcome"
#define CRM_OPERATION_PING	"ping"
#define CRM_OPERATION_VOTE	"vote"
#define CRM_OPERATION_ANNOUNCE	"announce"
#define CRM_OPERATION_HBEAT	"dc_beat"
#define CRM_OPERATION_SHUTDOWN	"shutdown"
#define CRM_OPERATION_SHUTDOWN_REQ	"req_shutdown"


typedef GSList* GSListPtr;

#define slist_iter(w, x, y, z, a) for(z = 0; z < g_slist_length(y);  z++) { \
				         x *w = (x*)g_slist_nth_data(y, z); \
					 a;				    \
				  }

#define crm_malloc(x) cl_malloc(x)
#define crm_free(x)   if(x) { cl_free(x); x=NULL; }
#define crm_strdup(x) cl_strdup(x)
#include <mcheck.h>

#endif
