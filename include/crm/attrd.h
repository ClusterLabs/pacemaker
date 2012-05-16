/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_ATTRD__H
#  define CRM_ATTRD__H
#  include <crm/common/ipc.h>

#define attrd_channel		T_ATTRD
#define F_ATTRD_KEY		"attr_key"
#define F_ATTRD_ATTRIBUTE	"attr_name"
#define F_ATTRD_TASK		"task"
#define F_ATTRD_VALUE		"attr_value"
#define F_ATTRD_SET		"attr_set"
#define F_ATTRD_SECTION		"attr_section"
#define F_ATTRD_DAMPEN		"attr_dampening"
#define F_ATTRD_IGNORE_LOCALLY	"attr_ignore_locally"
#define F_ATTRD_HOST		"attr_host"
#define F_ATTRD_USER		"attr_user"

extern gboolean attrd_update_delegate(crm_ipc_t *ipc, char command, const char *host,
                                      const char *name, const char *value, const char *section,
                                      const char *set, const char *dampen, const char *user_name);

/* API compatability functions */
gboolean attrd_update(crm_ipc_t *cluster, char command, const char *host, const char *name,
                      const char *value, const char *section, const char *set, const char *dampen) QB_GNUC_DEPRECATED;

gboolean attrd_lazy_update(char command, const char *host, const char *name,
                           const char *value, const char *section, const char *set,
                           const char *dampen) QB_GNUC_DEPRECATED;

gboolean attrd_update_no_mainloop(int *connection, char command, const char *host,
                                  const char *name, const char *value, const char *section,
                                  const char *set, const char *dampen) QB_GNUC_DEPRECATED;

#endif
