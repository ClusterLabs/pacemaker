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
#  define CRM_ALERT_DEFAULT_TIMEOUT_MS (30000)

/* Default-Format-String used to pass timestamps to the notification scripts */
#  define CRM_ALERT_DEFAULT_TSTAMP_FORMAT "%H:%M:%S.%06N"

typedef struct {
    char *id;
    char *path;
    int timeout;
    char *tstamp_format;
    char *recipient;
    GListPtr envvars;
} crm_alert_entry_t;

enum crm_alert_keys_e {
    CRM_alert_recipient = 0,
    CRM_alert_node,
    CRM_alert_nodeid,
    CRM_alert_rsc,
    CRM_alert_task,
    CRM_alert_interval,
    CRM_alert_desc,
    CRM_alert_status,
    CRM_alert_target_rc,
    CRM_alert_rc,
    CRM_alert_kind,
    CRM_alert_version,
    CRM_alert_node_sequence,
    CRM_alert_timestamp
};

extern GListPtr crm_alert_list;
extern guint crm_alert_max_alert_timeout;
extern const char *crm_alert_keys[14][3];

void crm_free_notify_list(void);
GListPtr crm_drop_envvars(crm_alert_entry_t *entry, int count);
void crm_add_dup_notify_list_entry(crm_alert_entry_t *entry);
GListPtr crm_get_envvars_from_cib(xmlNode *basenode, crm_alert_entry_t *entry, int *count);
void crm_set_alert_key(enum crm_alert_keys_e name, const char *value);
void crm_set_alert_key_int(enum crm_alert_keys_e name, int value);
void crm_unset_alert_keys(void);
void crm_set_envvar_list(crm_alert_entry_t *entry);
void crm_unset_envvar_list(crm_alert_entry_t *entry);
#endif
