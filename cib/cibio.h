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

#ifndef CIB_IO__H
#define CIB_IO__H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 
#include <crm/common/xml.h>

extern gboolean initialized;
extern gboolean per_action_cib;
extern crm_data_t *the_cib;
extern crm_data_t *node_search;
extern crm_data_t *resource_search;
extern crm_data_t *constraint_search;
extern crm_data_t *status_search;
    
extern crm_data_t *get_the_CIB(void);

extern int initializeCib(crm_data_t *cib);
extern gboolean uninitializeCib(void);
extern crm_data_t *createEmptyCib(void);
extern gboolean verifyCibXml(crm_data_t *cib);
extern crm_data_t *readCibXml(char *buffer);
extern crm_data_t *readCibXmlFile(
	const char *dir, const char *file, gboolean discard_status);
extern int activateCibBuffer(char *buffer, const char *filename);
extern int activateCibXml(crm_data_t *doc, gboolean to_disk);

extern gboolean update_quorum(crm_data_t *xml_obj);
extern gboolean set_connected_peers(crm_data_t *xml_obj);
extern gboolean update_counters(
	const char *file, const char *fn, crm_data_t *xml_obj);

/* extern crm_data_t *server_get_cib_copy(void); */

#endif
