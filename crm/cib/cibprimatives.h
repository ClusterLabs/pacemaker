/* $Id: cibprimatives.h,v 1.8 2004/03/25 17:11:23 andrew Exp $ */
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

#ifndef CRMINTERNAL_H
#define CRMINTERNAL_H

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

#define IS_DAEMON
#define IPC_COMMS

typedef xmlNode cibStatus;
typedef xmlNode cibResource;
typedef xmlNode cibConstraint;
typedef xmlNode cibHaNode;


/* extern gboolean initialized; */
/* extern xmlNodePtr the_cib; */
/* extern xmlNodePtr node_search; */
/* extern xmlNodePtr resource_search; */
/* extern xmlNodePtr constraint_search; */
/* extern xmlNodePtr status_search; */
/* extern const char* crm_system_name; */

extern xmlNodePtr get_the_CIB(void);

extern int addResource  (xmlNodePtr cib, xmlNodePtr anXmlNode);
extern int addConstraint(xmlNodePtr cib, xmlNodePtr anXmlNode);
extern int addHaNode    (xmlNodePtr cib, xmlNodePtr anXmlNode);
extern int addStatus    (xmlNodePtr cib, xmlNodePtr anXmlNode);

extern xmlNodePtr findResource  (xmlNodePtr cib, const char *id);
extern xmlNodePtr findConstraint(xmlNodePtr cib, const char *id);
extern xmlNodePtr findHaNode    (xmlNodePtr cib, const char *id);
extern xmlNodePtr findStatus    (xmlNodePtr cib, const char *id);

extern int updateResource  (xmlNodePtr cib, xmlNodePtr anXmlNode);
extern int updateConstraint(xmlNodePtr cib, xmlNodePtr anXmlNode);
extern int updateHaNode    (xmlNodePtr cib, xmlNodePtr anXmlNode);
extern int updateStatus    (xmlNodePtr cib, xmlNodePtr anXmlNode);

extern int delResource  (xmlNodePtr cib, xmlNodePtr delete_spec);
extern int delConstraint(xmlNodePtr cib, xmlNodePtr delete_spec);
extern int delHaNode    (xmlNodePtr cib, xmlNodePtr delete_spec);
extern int delStatus    (xmlNodePtr cib, xmlNodePtr delete_spec);

extern int add_cib_object   (xmlNodePtr parent, xmlNodePtr new_obj);
extern int delete_cib_object(xmlNodePtr parent, xmlNodePtr delete_spec);
extern int update_cib_object(xmlNodePtr parent, xmlNodePtr new_obj,
			     gboolean force);


#endif
