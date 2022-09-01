/*
 * Copyright 2015-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/msg_xml.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/cib/internal.h> /* for F_CIB_UPDATE_RESULT */

/*
 * to allow script compatibility we can have more than one
 * set of environment variables
 */
const char *pcmk__alert_keys[PCMK__ALERT_INTERNAL_KEY_MAX][3] =
{
    [PCMK__alert_key_recipient] = {
        "CRM_notify_recipient",         "CRM_alert_recipient",          NULL
    },
    [PCMK__alert_key_node] = {
        "CRM_notify_node",              "CRM_alert_node",               NULL
    },
    [PCMK__alert_key_nodeid] = {
        "CRM_notify_nodeid",            "CRM_alert_nodeid",             NULL
    },
    [PCMK__alert_key_rsc] = {
        "CRM_notify_rsc",               "CRM_alert_rsc",                NULL
    },
    [PCMK__alert_key_task] = {
        "CRM_notify_task",              "CRM_alert_task",               NULL
    },
    [PCMK__alert_key_interval] = {
        "CRM_notify_interval",          "CRM_alert_interval",           NULL
    },
    [PCMK__alert_key_desc] = {
        "CRM_notify_desc",              "CRM_alert_desc",               NULL
    },
    [PCMK__alert_key_status] = {
        "CRM_notify_status",            "CRM_alert_status",             NULL
    },
    [PCMK__alert_key_target_rc] = {
        "CRM_notify_target_rc",         "CRM_alert_target_rc",          NULL
    },
    [PCMK__alert_key_rc] = {
        "CRM_notify_rc",                "CRM_alert_rc",                 NULL
    },
    [PCMK__alert_key_kind] = {
        "CRM_notify_kind",              "CRM_alert_kind",               NULL
    },
    [PCMK__alert_key_version] = {
        "CRM_notify_version",           "CRM_alert_version",            NULL
    },
    [PCMK__alert_key_node_sequence] = {
        "CRM_notify_node_sequence",     PCMK__ALERT_NODE_SEQUENCE,      NULL
    },
    [PCMK__alert_key_timestamp] = {
        "CRM_notify_timestamp",         "CRM_alert_timestamp",          NULL
    },
    [PCMK__alert_key_attribute_name] = {
        "CRM_notify_attribute_name",    "CRM_alert_attribute_name",     NULL
    },
    [PCMK__alert_key_attribute_value] = {
        "CRM_notify_attribute_value",   "CRM_alert_attribute_value",    NULL
    },
    [PCMK__alert_key_timestamp_epoch] = {
        "CRM_notify_timestamp_epoch",   "CRM_alert_timestamp_epoch",    NULL
    },
    [PCMK__alert_key_timestamp_usec] = {
        "CRM_notify_timestamp_usec",    "CRM_alert_timestamp_usec",     NULL
    },
    [PCMK__alert_key_exec_time] = {
        "CRM_notify_exec_time",         "CRM_alert_exec_time",          NULL
    },
    [PCMK__alert_log_level] = {
        "CRM_notify_log_level",         "CRM_alert_log_level",          NULL
    }
};

/*!
 * \brief Create a new alert entry structure
 *
 * \param[in] id  ID to use
 * \param[in] path  Path to alert agent executable
 *
 * \return Pointer to newly allocated alert entry
 * \note Non-string fields will be filled in with defaults.
 *       It is the caller's responsibility to free the result,
 *       using pcmk__free_alert().
 */
pcmk__alert_t *
pcmk__alert_new(const char *id, const char *path)
{
    pcmk__alert_t *entry = calloc(1, sizeof(pcmk__alert_t));

    CRM_ASSERT(entry && id && path);
    entry->id = strdup(id);
    entry->path = strdup(path);
    entry->timeout = PCMK__ALERT_DEFAULT_TIMEOUT_MS;
    entry->flags = pcmk__alert_default;
    return entry;
}

void
pcmk__free_alert(pcmk__alert_t *entry)
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

/*!
 * \internal
 * \brief Duplicate an alert entry
 *
 * \param[in] entry  Alert entry to duplicate
 *
 * \return Duplicate of alert entry
 */
pcmk__alert_t *
pcmk__dup_alert(pcmk__alert_t *entry)
{
    pcmk__alert_t *new_entry = pcmk__alert_new(entry->id, entry->path);

    new_entry->timeout = entry->timeout;
    new_entry->flags = entry->flags;
    new_entry->envvars = pcmk__str_table_dup(entry->envvars);
    pcmk__str_update(&new_entry->tstamp_format, entry->tstamp_format);
    pcmk__str_update(&new_entry->recipient, entry->recipient);
    if (entry->select_attribute_name) {
        new_entry->select_attribute_name = g_strdupv(entry->select_attribute_name);
    }
    return new_entry;
}

void
pcmk__add_alert_key(GHashTable *table, enum pcmk__alert_keys_e name,
                    const char *value)
{
    for (const char **key = pcmk__alert_keys[name]; *key; key++) {
        crm_trace("Inserting alert key %s = '%s'", *key, value);
        if (value) {
            g_hash_table_insert(table, strdup(*key), strdup(value));
        } else {
            g_hash_table_remove(table, *key);
        }
    }
}

void
pcmk__add_alert_key_int(GHashTable *table, enum pcmk__alert_keys_e name,
                        int value)
{
    for (const char **key = pcmk__alert_keys[name]; *key; key++) {
        crm_trace("Inserting alert key %s = %d", *key, value);
        g_hash_table_insert(table, strdup(*key), pcmk__itoa(value));
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
pcmk__alert_in_patchset(xmlNode *msg, bool config)
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
        for (change = pcmk__xml_first_child(patchset); change != NULL;
             change = pcmk__xml_next(change)) {
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
                    ((section = pcmk__xml_first_child(change)) == NULL) ||
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
