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
/* extern const char* daemon_name; */

extern void* ha_malloc(size_t size);

xmlNodePtr theCib(void);
xmlNodePtr getCibSection(const char *section);

cibResource   *newResource  (const char *id, const char *type, const char *name, const char *max_instances);
cibStatus     *newStatus    (const char *res_id, const char *node_id, const char *instance);
cibConstraint *newConstraint(const char *id);
cibHaNode     *newHaNode    (const char *id, const char *type);

int addResource  (xmlNodePtr cib, cibResource   *xml_node);
int addStatus    (xmlNodePtr cib, cibStatus     *xml_node);
int addConstraint(xmlNodePtr cib, cibConstraint *xml_node);
int addHaNode    (xmlNodePtr cib, cibHaNode     *xml_node);

xmlNodePtr findResource  (xmlNodePtr cib, const char *id);
xmlNodePtr findStatus    (xmlNodePtr cib, const char *id, const char *instanceNum);
xmlNodePtr findConstraint(xmlNodePtr cib, const char *id);
xmlNodePtr findHaNode    (xmlNodePtr cib, const char *id);

int updateResource  (xmlNodePtr cib, cibResource   *resource);
int updateStatus    (xmlNodePtr cib, cibStatus     *resource);
int updateConstraint(xmlNodePtr cib, cibConstraint *resource);
int updateHaNode    (xmlNodePtr cib, cibHaNode     *resource);

int delResource  (xmlNodePtr cib, const char *id);
int delStatus    (xmlNodePtr cib, const char *id, const char *instanceNum);
int delConstraint(xmlNodePtr cib, const char *id);
int delHaNode    (xmlNodePtr cib, const char *id);

int test(void);
xmlDocPtr createTree(void);

#endif
