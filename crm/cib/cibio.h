/* $Id: cibio.h,v 1.5 2004/02/17 22:11:56 lars Exp $ */
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

#ifndef CRMIO_H
#define CRMIO_H

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 
#include <libxml/tree.h> 

#define CIB_FILENAME "cib.xml"
#define CIB_BACKUP   "cib_backup.xml"

extern gboolean initialized;
extern xmlNodePtr the_cib;
extern xmlNodePtr node_search;
extern xmlNodePtr resource_search;
extern xmlNodePtr constraint_search;
extern xmlNodePtr status_search;

extern xmlNodePtr get_the_CIB(void);
extern xmlNodePtr getCibSection(const char *section);
extern xmlNodePtr get_object_root(const char *object_type,
				  xmlNodePtr the_root);

extern int initializeCib(xmlNodePtr cib);
extern gboolean uninitializeCib(void);
extern xmlNodePtr createEmptyCib(void);
extern gboolean verifyCibXml(xmlNodePtr cib);
extern xmlNodePtr readCibXml(char *buffer);
extern xmlNodePtr readCibXmlFile(const char *filename);
extern int activateCibBuffer(char *buffer);
extern int activateCibXml(xmlNodePtr doc);

extern int moveFile(const char *oldname,
		    const char *newname,
		    gboolean backup,
		    char *ext);


#endif
