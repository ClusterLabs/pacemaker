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
#define MAXDATASIZE 65535 // ipc comms
#define FIFO_LEN    1024
#define APPNAME_LEN 256

#define CRM_DEBUG(w)        cl_log(LOG_DEBUG, w)
#define CRM_DEBUG2(w,x)     cl_log(LOG_DEBUG, w, x)
#define CRM_DEBUG3(w,x,y)   cl_log(LOG_DEBUG, w, x, y)
#define CRM_DEBUG4(w,x,y,z) cl_log(LOG_DEBUG, w, x, y, z)

#define FNIN()   cl_log(LOG_DEBUG, "#---#---# Entering function %s...", __FUNCTION__)
#define FNOUT()  cl_log(LOG_DEBUG, "#---#---# Leaving function %s...",  __FUNCTION__)
#define FNRET(x) { cl_log(LOG_DEBUG, "#---#---# Leaving function %s...",  __FUNCTION__); return x; }
//#define FNRET(x) return x;

#define _CRM_DEBUG(w)       
#define _CRM_DEBUG2(w,x)    
#define _CRM_DEBUG3(w,x,y)  
#define _CRM_DEBUG4(w,x,y,z)

extern char *ha_strdup(const char *s);
extern void *ha_malloc(size_t size);
extern void  ha_free(void *mem);

extern char* getNow(void);

#endif
