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

#ifndef CIB_PRIMATIVES__H
#define CIB_PRIMATIVES__H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h> 
#include <crm/common/xml.h>

#define IS_DAEMON
#define IPC_COMMS

typedef xmlNode cibStatus;
typedef xmlNode cibResource;
typedef xmlNode cibConstraint;
typedef xmlNode cibHaNode;


/* extern gboolean initialized; */
/* extern xmlNode *the_cib; */
/* extern xmlNode *node_search; */
/* extern xmlNode *resource_search; */
/* extern xmlNode *constraint_search; */
/* extern xmlNode *status_search; */
/* extern const char* crm_system_name; */

extern xmlNode *get_the_CIB(void);

extern int addResource  (xmlNode *cib, xmlNode *anXmlNode);
extern int addConstraint(xmlNode *cib, xmlNode *anXmlNode);
extern int addHaNode    (xmlNode *cib, xmlNode *anXmlNode);
extern int addStatus    (xmlNode *cib, xmlNode *anXmlNode);

extern xmlNode *findResource  (xmlNode *cib, const char *id);
extern xmlNode *findConstraint(xmlNode *cib, const char *id);
extern xmlNode *findHaNode    (xmlNode *cib, const char *id);
extern xmlNode *findStatus    (xmlNode *cib, const char *id);

extern int updateResource  (xmlNode *cib, xmlNode *anXmlNode);
extern int updateConstraint(xmlNode *cib, xmlNode *anXmlNode);
extern int updateHaNode    (xmlNode *cib, xmlNode *anXmlNode);
extern int updateStatus    (xmlNode *cib, xmlNode *anXmlNode);

extern int delResource  (xmlNode *cib, xmlNode *delete_spec);
extern int delConstraint(xmlNode *cib, xmlNode *delete_spec);
extern int delHaNode    (xmlNode *cib, xmlNode *delete_spec);
extern int delStatus    (xmlNode *cib, xmlNode *delete_spec);

extern int add_cib_object   (xmlNode *parent, xmlNode *new_obj);
extern int delete_cib_object(xmlNode *parent, xmlNode *delete_spec);
extern int update_cib_object(xmlNode *parent, xmlNode *new_obj);

#endif
