/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef ALERT_INTERNAL_H
#define ALERT_INTERNAL_H
/* Default-Timeout to use before killing a notification script (in milliseconds) */
#  define CRMD_NOTIFY_DEFAULT_TIMEOUT_MS (30000)

/* Default-Format-String used to pass timestamps to the notification scripts */
#  define CRMD_NOTIFY_DEFAULT_TSTAMP_FORMAT "%H:%M:%S.%06N"

typedef struct {
    char *name;
    char *value;
} envvar_t;

typedef struct {
    char *id;
    char *path;
    int timeout;
    char *tstamp_format;
    char *recipient;
    GListPtr envvars;
} notify_entry_t;

enum notify_keys_e{
    CRM_notify_recipient = 0,
    CRM_notify_node,
    CRM_notify_nodeid,
    CRM_notify_rsc,
    CRM_notify_task,
    CRM_notify_interval,
    CRM_notify_desc,
    CRM_notify_status,
    CRM_notify_target_rc,
    CRM_notify_rc,
    CRM_notify_kind,
    CRM_notify_version,
    CRM_notify_node_sequence,
    CRM_notify_timestamp
};

extern char *notify_script;
extern char *notify_target;
extern GListPtr notify_list;
extern guint max_alert_timeout;
extern const char *notify_keys[14][3];

void free_notify_list(void);
GListPtr add_dup_envvar(GListPtr envvar_list, envvar_t *entry);
GListPtr drop_envvars(GListPtr envvar_list, int count);
GListPtr get_envvars_from_cib(xmlNode *basenode, GListPtr list, int *count);
void add_dup_notify_list_entry(notify_entry_t *entry);
#endif
