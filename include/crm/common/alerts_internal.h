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

#include <glib.h>
#include <stdbool.h>

/* Default-Timeout to use before killing a alerts script (in milliseconds) */
#  define CRM_ALERT_DEFAULT_TIMEOUT_MS (30000)

/* Default-Format-String used to pass timestamps to the alerts scripts */
#  define CRM_ALERT_DEFAULT_TSTAMP_FORMAT "%H:%M:%S.%06N"

typedef struct {
    char *name;
    char *value;
}  crm_alert_envvar_t;

enum crm_alert_flags {
    crm_alert_none         = 0x0000,
    crm_alert_node         = 0x0001,
    crm_alert_fencing      = 0x0002,
    crm_alert_resource     = 0x0004,
    crm_alert_attribute    = 0x0008,
    crm_alert_default      = crm_alert_node|crm_alert_fencing|crm_alert_resource
};

typedef struct {
    char *id;
    char *path;
    char *tstamp_format;
    char *recipient;
    char **select_attribute_name;
    GHashTable *envvars;
    int timeout;
    uint32_t flags;
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
    CRM_alert_timestamp,
    CRM_alert_attribute_name,
    CRM_alert_attribute_value,
    CRM_alert_timestamp_epoch,
    CRM_alert_timestamp_usec,
    CRM_alert_exec_time,
    CRM_alert_select_kind,
    CRM_alert_select_attribute_name
};

#define CRM_ALERT_INTERNAL_KEY_MAX 19
#define CRM_ALERT_NODE_SEQUENCE "CRM_alert_node_sequence"

extern const char *crm_alert_keys[CRM_ALERT_INTERNAL_KEY_MAX][3];

crm_alert_entry_t *crm_dup_alert_entry(crm_alert_entry_t *entry);
crm_alert_envvar_t *crm_dup_alert_envvar(crm_alert_envvar_t *src);
crm_alert_entry_t *crm_alert_entry_new(const char *id, const char *path);
void crm_free_alert_entry(crm_alert_entry_t *entry);
void crm_free_alert_envvar(crm_alert_envvar_t *entry);
void crm_insert_alert_key(GHashTable *table, enum crm_alert_keys_e name,
                          const char *value);
void crm_insert_alert_key_int(GHashTable *table, enum crm_alert_keys_e name,
                              int value);
void crm_unset_alert_keys(void);
void crm_set_envvar_list(crm_alert_entry_t *entry);
void crm_unset_envvar_list(crm_alert_entry_t *entry);
bool crm_patchset_contains_alert(xmlNode *msg, bool config);

static inline const char *
crm_alert_flag2text(enum crm_alert_flags flag)
{
    switch (flag) {
        case crm_alert_node:
            return "node";
        case crm_alert_fencing:
            return "fencing";
        case crm_alert_resource:
            return "resource";
        case crm_alert_attribute:
            return "attribute";
        default:
            return "unknown";
    }
}
#endif
