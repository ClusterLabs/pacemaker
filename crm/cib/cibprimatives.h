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

typedef crm_data_t cibStatus;
typedef crm_data_t cibResource;
typedef crm_data_t cibConstraint;
typedef crm_data_t cibHaNode;


/* extern gboolean initialized; */
/* extern crm_data_t *the_cib; */
/* extern crm_data_t *node_search; */
/* extern crm_data_t *resource_search; */
/* extern crm_data_t *constraint_search; */
/* extern crm_data_t *status_search; */
/* extern const char* crm_system_name; */

extern crm_data_t *get_the_CIB(void);

extern int addResource  (crm_data_t *cib, crm_data_t *anXmlNode);
extern int addConstraint(crm_data_t *cib, crm_data_t *anXmlNode);
extern int addHaNode    (crm_data_t *cib, crm_data_t *anXmlNode);
extern int addStatus    (crm_data_t *cib, crm_data_t *anXmlNode);

extern crm_data_t *findResource  (crm_data_t *cib, const char *id);
extern crm_data_t *findConstraint(crm_data_t *cib, const char *id);
extern crm_data_t *findHaNode    (crm_data_t *cib, const char *id);
extern crm_data_t *findStatus    (crm_data_t *cib, const char *id);

extern int updateResource  (crm_data_t *cib, crm_data_t *anXmlNode);
extern int updateConstraint(crm_data_t *cib, crm_data_t *anXmlNode);
extern int updateHaNode    (crm_data_t *cib, crm_data_t *anXmlNode);
extern int updateStatus    (crm_data_t *cib, crm_data_t *anXmlNode);

extern int delResource  (crm_data_t *cib, crm_data_t *delete_spec);
extern int delConstraint(crm_data_t *cib, crm_data_t *delete_spec);
extern int delHaNode    (crm_data_t *cib, crm_data_t *delete_spec);
extern int delStatus    (crm_data_t *cib, crm_data_t *delete_spec);

extern int add_cib_object   (crm_data_t *parent, crm_data_t *new_obj);
extern int delete_cib_object(crm_data_t *parent, crm_data_t *delete_spec);
extern int update_cib_object(crm_data_t *parent, crm_data_t *new_obj);

#endif
