/* $Id: crm.h,v 1.13 2004/03/22 14:22:11 andrew Exp $ */
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

#include <clplumbing/cl_log.h>

#if 1
#   define CRM_DEBUG(w)        cl_log(LOG_DEBUG, w)
#   define CRM_DEBUG2(w,x)     cl_log(LOG_DEBUG, w, x)
#   define CRM_DEBUG3(w,x,y)   cl_log(LOG_DEBUG, w, x, y)
#   define CRM_DEBUG4(w,x,y,z) cl_log(LOG_DEBUG, w, x, y, z)
#else
/* these wont work yet, need to cast to void */
#   define CRM_DEBUG(w)		{ (void)w; }
#   define CRM_DEBUG2(w,x)     	{ (void)w; (void)x; }
#   define CRM_DEBUG3(w,x,y)  	{ (void)w; (void)x; (void)y; }
#   define CRM_DEBUG4(w,x,y,z)	{ (void)w; (void)x; (void)y; (void)z; }
#endif

#if 0
#   define FNIN()     cl_log(LOG_DEBUG, "#---#---# Entering function %s...", __FUNCTION__)
#   define FNOUT()  { cl_log(LOG_DEBUG, "#---#---# Leaving function %s...",  __FUNCTION__); return;   }
#   define FNRET(x) { cl_log(LOG_DEBUG, "#---#---# Leaving function %s...",  __FUNCTION__); return x; }
#else
#   define FNIN()   ;
#   define FNOUT()  return;
#   define FNRET(x) return x; 
#endif


extern char *ha_strdup(const char *s);
extern void *ha_malloc(size_t size);
extern void  ha_free(void *mem);

#endif
