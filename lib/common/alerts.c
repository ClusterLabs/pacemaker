/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/msg_xml.h>
#include <crm/common/alerts_internal.h>
#include <crm/cib/internal.h> /* for F_CIB_UPDATE_RESULT */

/*		
 * to allow script compatibility we can have more than one		
 * set of environment variables		
 */
const char *crm_alert_keys[CRM_ALERT_INTERNAL_KEY_MAX][3] =		
{		
    [CRM_alert_recipient]     = {"CRM_notify_recipient",     "CRM_alert_recipient",     NULL},		
    [CRM_alert_node]          = {"CRM_notify_node",          "CRM_alert_node",          NULL},		
    [CRM_alert_nodeid]        = {"CRM_notify_nodeid",        "CRM_alert_nodeid",        NULL},		
    [CRM_alert_rsc]           = {"CRM_notify_rsc",           "CRM_alert_rsc",           NULL},		
    [CRM_alert_task]          = {"CRM_notify_task",          "CRM_alert_task",          NULL},		
    [CRM_alert_interval]      = {"CRM_notify_interval",      "CRM_alert_interval",      NULL},		
    [CRM_alert_desc]          = {"CRM_notify_desc",          "CRM_alert_desc",          NULL},		
    [CRM_alert_status]        = {"CRM_notify_status",        "CRM_alert_status",        NULL},		
    [CRM_alert_target_rc]     = {"CRM_notify_target_rc",     "CRM_alert_target_rc",     NULL},		
    [CRM_alert_rc]            = {"CRM_notify_rc",            "CRM_alert_rc",            NULL},		
    [CRM_alert_kind]          = {"CRM_notify_kind",          "CRM_alert_kind",          NULL},		
    [CRM_alert_version]       = {"CRM_notify_version",       "CRM_alert_version",       NULL},		
    [CRM_alert_node_sequence] = {"CRM_notify_node_sequence", CRM_ALERT_NODE_SEQUENCE, NULL},		
    [CRM_alert_timestamp]     = {"CRM_notify_timestamp",     "CRM_alert_timestamp",     NULL},
    [CRM_alert_attribute_name]     = {"CRM_notify_attribute_name",     "CRM_alert_attribute_name",     NULL},
    [CRM_alert_attribute_value]     = {"CRM_notify_attribute_value",     "CRM_alert_attribute_value",     NULL},
    [CRM_alert_timestamp_snmp]     = {"CRM_notify_timestamp_snmp",     "CRM_alert_timestamp_snmp",     NULL}
};

void
crm_free_alert_envvar(crm_alert_envvar_t *entry)
{		
    free(entry->name);		
    free(entry->value);		
    free(entry);		
}		

/*!
 * \brief Create a new alert entry structure
 *
 * \param[in] id  ID to use
 * \param[in] path  Path to alert agent executable
 *
 * \return Pointer to newly allocated alert entry
 * \note Non-string fields will be filled in with defaults.
 *       It is the caller's responsibility to free the result,
 *       using crm_free_alert_entry().
 */
crm_alert_entry_t *
crm_alert_entry_new(const char *id, const char *path)
{
    crm_alert_entry_t *entry = calloc(1, sizeof(crm_alert_entry_t));

    CRM_ASSERT(entry && id && path);
    entry->id = strdup(id);
    entry->path = strdup(path);
    entry->timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS;
    entry->flags = crm_alert_default;
    return entry;
}

void
crm_free_alert_entry(crm_alert_entry_t *entry)
{		
    if (entry) {
        free(entry->id);
        free(entry->path);
        free(entry->tstamp_format);
        free(entry->recipient);

        g_strfreev(entry->select_attribute_name);
        if (entry->envvars) {
            g_hash_table_destroy(entry->envvars);
        }
        free(entry);
    }
}		

crm_alert_envvar_t *
crm_dup_alert_envvar(crm_alert_envvar_t *src)
{		
    crm_alert_envvar_t *dst = calloc(1, sizeof(crm_alert_envvar_t));		

    CRM_ASSERT(dst);		
    dst->name = strdup(src->name);		
    dst->value = src->value?strdup(src->value):NULL;		
    return dst;		
}		

/*!
 * \internal
 * \brief Duplicate an alert entry
 *
 * \param[in] entry  Alert entry to duplicate
 *
 * \return Duplicate of alert entry
 */
crm_alert_entry_t *
crm_dup_alert_entry(crm_alert_entry_t *entry)
{
    crm_alert_entry_t *new_entry = crm_alert_entry_new(entry->id, entry->path);

    new_entry->timeout = entry->timeout;
    new_entry->flags = entry->flags;
    new_entry->envvars = crm_str_table_dup(entry->envvars);
    if (entry->tstamp_format) {
        new_entry->tstamp_format = strdup(entry->tstamp_format);
    }
    if (entry->recipient) {
        new_entry->recipient = strdup(entry->recipient);
    }
    if (entry->select_attribute_name) {
        new_entry->select_attribute_name = g_strdupv(entry->select_attribute_name);
    }
    return new_entry;
}

void
crm_unset_alert_keys()
{
    const char **key;
    enum crm_alert_keys_e name;

    for(name = 0; name < DIMOF(crm_alert_keys); name++) {
        for(key = crm_alert_keys[name]; *key; key++) {
            crm_trace("Unsetting alert key %s", *key);
            unsetenv(*key);
        }
    }
}

void
crm_insert_alert_key(GHashTable *table, enum crm_alert_keys_e name,
                     const char *value)
{
    for (const char **key = crm_alert_keys[name]; *key; key++) {
        crm_trace("Inserting alert key %s = '%s'", *key, value);
        if (value) {
            g_hash_table_insert(table, strdup(*key), strdup(value));
        } else {
            g_hash_table_remove(table, *key);
        }
    }
}

void
crm_insert_alert_key_int(GHashTable *table, enum crm_alert_keys_e name,
                         int value)
{
    for (const char **key = crm_alert_keys[name]; *key; key++) {
        crm_trace("Inserting alert key %s = %d", *key, value);
        g_hash_table_insert(table, strdup(*key), crm_itoa(value));
    }
}

static void
set_envvar(gpointer key, gpointer value, gpointer user_data)
{
    gboolean always_unset = GPOINTER_TO_INT(user_data);

    crm_trace("%s environment variable %s='%s'",
              (value? "Setting" : "Unsetting"),
              (char*)key, (value? (char*)value : ""));
    if (value && !always_unset) {
        setenv(key, value, 1);
    } else {
        unsetenv(key);
    }
}

void
crm_set_envvar_list(crm_alert_entry_t *entry)
{
    if (entry->envvars) {
        g_hash_table_foreach(entry->envvars, set_envvar, GINT_TO_POINTER(FALSE));
    }
}

/*
 * \note We have no way of restoring a previous value if one was set.
 */
void
crm_unset_envvar_list(crm_alert_entry_t *entry)
{
    if (entry->envvars) {
        g_hash_table_foreach(entry->envvars, set_envvar, GINT_TO_POINTER(TRUE));
    }
}

#define XPATH_PATCHSET1_DIFF "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED

#define XPATH_PATCHSET1_CRMCONFIG XPATH_PATCHSET1_DIFF "//" XML_CIB_TAG_CRMCONFIG
#define XPATH_PATCHSET1_ALERTS    XPATH_PATCHSET1_DIFF "//" XML_CIB_TAG_ALERTS

#define XPATH_PATCHSET1_EITHER \
    XPATH_PATCHSET1_CRMCONFIG " | " XPATH_PATCHSET1_ALERTS

#define XPATH_CONFIG "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION

#define XPATH_CRMCONFIG XPATH_CONFIG "/" XML_CIB_TAG_CRMCONFIG "/"
#define XPATH_ALERTS    XPATH_CONFIG "/" XML_CIB_TAG_ALERTS

/*!
 * \internal
 * \brief Check whether a CIB update affects alerts
 *
 * \param[in] msg     XML containing CIB update
 * \param[in] config  Whether to check for crmconfig change as well
 *
 * \return TRUE if update affects alerts, FALSE otherwise
 */
bool
crm_patchset_contains_alert(xmlNode *msg, bool config)
{
    int rc = -1;
    int format= 1;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);
    xmlNode *change = NULL;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(msg != NULL, return FALSE);

    crm_element_value_int(msg, F_CIB_RC, &rc);
    if (rc < pcmk_ok) {
        crm_trace("Ignore failed CIB update: %s (%d)", pcmk_strerror(rc), rc);
        return FALSE;
    }

    crm_element_value_int(patchset, "format", &format);
    if (format == 1) {
        const char *diff = (config? XPATH_PATCHSET1_EITHER : XPATH_PATCHSET1_ALERTS);

        if ((xpathObj = xpath_search(msg, diff)) != NULL) {
            freeXpathObject(xpathObj);
            return TRUE;
        }
    } else if (format == 2) {
        for (change = __xml_first_child(patchset); change != NULL; change = __xml_next(change)) {
            const char *xpath = crm_element_value(change, XML_DIFF_PATH);

            if (xpath == NULL) {
                continue;
            }

            if ((!config || !strstr(xpath, XPATH_CRMCONFIG))
                && !strstr(xpath, XPATH_ALERTS)) {

                /* this is not a change to an existing section ... */

                xmlNode *section = NULL;
                const char *name = NULL;

                if ((strcmp(xpath, XPATH_CONFIG) != 0) ||
                    ((section = __xml_first_child(change)) == NULL) ||
                    ((name = crm_element_name(section)) == NULL) ||
                    (strcmp(name, XML_CIB_TAG_ALERTS) != 0)) {

                    /* ... nor is it a newly added alerts section */
                    continue;
                }
            }

            return TRUE;
        }

    } else {
        crm_warn("Unknown patch format: %d", format);
    }
    return FALSE;
}
