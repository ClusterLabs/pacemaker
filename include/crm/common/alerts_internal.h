/*
 * Copyright 2015-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__ALERT_INTERNAL__H
#define PCMK__ALERT_INTERNAL__H

#include <glib.h>
#include <stdbool.h>

/* Default-Timeout to use before killing a alerts script (in milliseconds) */
#  define PCMK__ALERT_DEFAULT_TIMEOUT_MS (30000)

/* Default-Format-String used to pass timestamps to the alerts scripts */
#  define PCMK__ALERT_DEFAULT_TSTAMP_FORMAT "%H:%M:%S.%06N"

enum pcmk__alert_flags {
    pcmk__alert_none         = 0,
    pcmk__alert_node         = (1 << 0),
    pcmk__alert_fencing      = (1 << 1),
    pcmk__alert_resource     = (1 << 2),
    pcmk__alert_attribute    = (1 << 3),
    pcmk__alert_default      = pcmk__alert_node|pcmk__alert_fencing|
                               pcmk__alert_resource,
};

typedef struct {
    char *id;
    char *path;
    char *tstamp_format;
    char *recipient;
    char *alert_log_level;
    char **select_attribute_name;
    GHashTable *envvars;
    int timeout;
    uint32_t flags;
} pcmk__alert_t;

enum pcmk__alert_keys_e {
    PCMK__alert_key_recipient = 0,
    PCMK__alert_key_node,
    PCMK__alert_key_nodeid,
    PCMK__alert_key_rsc,
    PCMK__alert_key_task,
    PCMK__alert_key_interval,
    PCMK__alert_key_desc,
    PCMK__alert_key_status,
    PCMK__alert_key_target_rc,
    PCMK__alert_key_rc,
    PCMK__alert_key_kind,
    PCMK__alert_key_version,
    PCMK__alert_key_node_sequence,
    PCMK__alert_key_timestamp,
    PCMK__alert_key_attribute_name,
    PCMK__alert_key_attribute_value,
    PCMK__alert_key_timestamp_epoch,
    PCMK__alert_key_timestamp_usec,
    PCMK__alert_key_exec_time,
    PCMK__alert_key_select_kind,
    PCMK__alert_key_select_attribute_name,
    PCMK__alert_log_level
};

#define PCMK__ALERT_INTERNAL_KEY_MAX 23
#define PCMK__ALERT_NODE_SEQUENCE "CRM_alert_node_sequence"

extern const char *pcmk__alert_keys[PCMK__ALERT_INTERNAL_KEY_MAX][3];

pcmk__alert_t *pcmk__dup_alert(pcmk__alert_t *entry);
pcmk__alert_t *pcmk__alert_new(const char *id, const char *path);
void pcmk__free_alert(pcmk__alert_t *entry);
void pcmk__add_alert_key(GHashTable *table, enum pcmk__alert_keys_e name,
                         const char *value);
void pcmk__add_alert_key_int(GHashTable *table, enum pcmk__alert_keys_e name,
                             int value);
bool pcmk__alert_in_patchset(xmlNode *msg, bool config);

static inline const char *
pcmk__alert_flag2text(enum pcmk__alert_flags flag)
{
    switch (flag) {
        case pcmk__alert_node:      return "node";
        case pcmk__alert_fencing:   return "fencing";
        case pcmk__alert_resource:  return "resource";
        case pcmk__alert_attribute: return "attribute";
        default:                    return "unknown";
    }
}
#endif
