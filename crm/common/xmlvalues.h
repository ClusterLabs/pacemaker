/* $Id: xmlvalues.h,v 1.8 2004/03/24 09:59:05 andrew Exp $ */
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
#define CIB_VAL_RESSTATUS_STOPED     "stopped"
#define CIB_VAL_RESSTATUS_STARTING   "starting"
#define CIB_VAL_RESSTATUS_RUNNING    "running"
#define CIB_VAL_RESSTATUS_STOPPING   "stopping"
#define CIB_VAL_RESSTATUS_FAILED     "failed"
#define CIB_VAL_RESSTATUS_DEFAULT    CIB_VAL_RESSTATUS_STOPED 

#define CIB_VAL_SOURCE_DEFAULT  "unknown"

#define CRM_SYSTEM_DC       "dc"
#define CRM_SYSTEM_DCIB     "dcib" // The master CIB
#define CRM_SYSTEM_CIB      "cib"
#define CRM_SYSTEM_CRMD     "crmd"
#define CRM_SYSTEM_LRMD     "lrmd"
#define CRM_SYSTEM_PENGINE  "pengine"
#define CRM_SYSTEM_TENGINE  "tengine"

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

