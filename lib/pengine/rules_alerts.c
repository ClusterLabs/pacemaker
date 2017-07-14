/*
 * Copyright (C) 2015-2017 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include <crm/common/alerts_internal.h>
#include <crm/pengine/rules_internal.h>

#ifdef RHEL7_COMPAT
/* @COMPAT An early implementation of alerts was backported to RHEL 7,
 * even though it was never in an upstream release.
 */
static char *notify_script = NULL;
static char *notify_target = NULL;

void
pe_enable_legacy_alerts(const char *script, const char *target)
{
    free(notify_script);
    notify_script = (script && strcmp(script, "/dev/null"))?
                    strdup(script) : NULL;

    free(notify_target);
    notify_target = target? strdup(target): NULL;
}
#endif

static void
get_meta_attrs_from_cib(xmlNode *basenode, crm_alert_entry_t *entry,
                        guint *max_timeout)
{
    GHashTable *config_hash = crm_str_table_new();
    crm_time_t *now = crm_time_new(NULL);
    const char *value = NULL;

    unpack_instance_attributes(basenode, basenode, XML_TAG_META_SETS, NULL,
                               config_hash, NULL, FALSE, now);
    crm_time_free(now);

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_TIMEOUT);
    if (value) {
        entry->timeout = crm_get_msec(value);
        if (entry->timeout <= 0) {
            if (entry->timeout == 0) {
                crm_trace("Alert %s uses default timeout of %dmsec",
                          entry->id, CRM_ALERT_DEFAULT_TIMEOUT_MS);
            } else {
                crm_warn("Alert %s has invalid timeout value '%s', using default %dmsec",
                         entry->id, (char*)value, CRM_ALERT_DEFAULT_TIMEOUT_MS);
            }
            entry->timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS;
        } else {
            crm_trace("Alert %s uses timeout of %dmsec",
                      entry->id, entry->timeout);
        }
        if (entry->timeout > *max_timeout) {
            *max_timeout = entry->timeout;
        }
    }
    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_TSTAMP_FORMAT);
    if (value) {
        /* hard to do any checks here as merely anything can
         * can be a valid time-format-string
         */
        entry->tstamp_format = strdup(value);
        crm_trace("Alert %s uses timestamp format '%s'",
                  entry->id, entry->tstamp_format);
    }

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_SELECT_KIND);
    if (value) {
        int n = 0;
        uint32_t flags = crm_alert_none;

        crm_debug("Alert %s has event filter: %s", entry->id, value);
        while (*value != 0) {
            while (*value == ',') {
                ++value;
            }
            n = 0;
            while ((value[n] != ',') && (value[n] != 0)) {
                ++n;
            }
            if (!strncmp(value, "node", n)) {
                flags |= crm_alert_node;
            } else if (!strncmp(value, "fencing", n)) {
                flags |= crm_alert_fencing;
            } else if (!strncmp(value, "resource", n)) {
                flags |= crm_alert_resource;
            } else if (!strncmp(value, "attribute", n)) {
                flags |= crm_alert_attribute;
            } else {
                crm_warn("Unrecognized alert type '%s' for %s", value, entry->id);
            }
            value += n;
        }
        if (flags) {
            entry->flags = flags;
        }
    }

    value = g_hash_table_lookup(config_hash,
                                XML_ALERT_ATTR_SELECT_ATTRIBUTE_NAME);
    if (value) {
        crm_debug("Alert %s has attribute filter: %s", entry->id, value);
        entry->select_attribute_name = g_strsplit(value, ",", 0);
    }

    g_hash_table_destroy(config_hash);
}

static void
get_envvars_from_cib(xmlNode *basenode, crm_alert_entry_t *entry)
{
    xmlNode *child;

    if ((basenode == NULL) || (entry == NULL)) {
        return;
    }

    child = first_named_child(basenode, XML_TAG_ATTR_SETS);
    if (child == NULL) {
        return;
    }

    if (entry->envvars == NULL) {
        entry->envvars = crm_str_table_new();
    }

    for (child = first_named_child(child, XML_CIB_TAG_NVPAIR); child != NULL;
         child = crm_next_same_xml(child)) {

        const char *name = crm_element_value(child, XML_NVPAIR_ATTR_NAME);
        const char *value = crm_element_value(child, XML_NVPAIR_ATTR_VALUE);

        if (value == NULL) {
            value = "";
        }
        g_hash_table_insert(entry->envvars, strdup(name), strdup(value));
        crm_trace("Alert %s: added environment variable %s='%s'",
                  entry->id, name, value);
    }
}

/*!
 * \internal
 * \brief Unpack a CIB alerts section
 *
 * \param[in] alerts  XML of alerts section
 *
 * \return  List of unpacked alert entries
 *
 * \note Unlike most unpack functions, this is not used by the pengine itself,
 *       but is supplied for use by daemons that need to send alerts.
 */
GListPtr
pe_unpack_alerts(xmlNode *alerts)
{
    xmlNode *alert;
    crm_alert_entry_t *entry;
    guint max_timeout = 0;
    GListPtr alert_list = NULL;

    crm_alert_max_alert_timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS;

    if (alerts) {
#ifdef RHEL7_COMPAT
        if (notify_script) {
            crm_warn("Ignoring deprecated notification configuration because alerts available");
        }
#endif
    } else {
#ifdef RHEL7_COMPAT
        if (notify_script) {
            entry = crm_alert_entry_new("legacy_notification", notify_script);
            entry->recipient = strdup(notify_target);
            entry->tstamp_format = strdup(CRM_ALERT_DEFAULT_TSTAMP_FORMAT);
            alert_list = g_list_prepend(alert_list, entry);
            crm_warn("Deprecated notification syntax in use (alerts syntax is preferable)");
        }
#endif
        return alert_list;
    }

    for (alert = first_named_child(alerts, XML_CIB_TAG_ALERT);
         alert != NULL; alert = crm_next_same_xml(alert)) {

        xmlNode *recipient;
        int recipients = 0;
        const char *alert_id = ID(alert);
        const char *alert_path = crm_element_value(alert, XML_ALERT_ATTR_PATH);

        /* The schema should enforce this, but to be safe ... */
        if ((alert_id == NULL) || (alert_path == NULL)) {
            crm_warn("Ignoring invalid alert without id and path");
            continue;
        }

        entry = crm_alert_entry_new(alert_id, alert_path);

        get_envvars_from_cib(alert, entry);
        get_meta_attrs_from_cib(alert, entry, &max_timeout);
        if (entry->tstamp_format == NULL) {
            entry->tstamp_format = strdup(CRM_ALERT_DEFAULT_TSTAMP_FORMAT);
        }

        crm_debug("Alert %s: path=%s timeout=%dms tstamp-format='%s' %u vars",
                  entry->id, entry->path, entry->timeout, entry->tstamp_format,
                  (entry->envvars? g_hash_table_size(entry->envvars) : 0));

        for (recipient = first_named_child(alert, XML_CIB_TAG_ALERT_RECIPIENT);
             recipient != NULL; recipient = crm_next_same_xml(recipient)) {

            crm_alert_entry_t *recipient_entry = crm_dup_alert_entry(entry);

            recipients++;
            recipient_entry->recipient = strdup(crm_element_value(recipient,
                                                XML_ALERT_ATTR_REC_VALUE));
            get_envvars_from_cib(recipient, recipient_entry);
            get_meta_attrs_from_cib(recipient, recipient_entry, &max_timeout);

            alert_list = g_list_prepend(alert_list, recipient_entry);
            crm_debug("Alert %s has recipient %s with value %s and %d envvars",
                      entry->id, ID(recipient), recipient_entry->recipient,
                      (recipient_entry->envvars?
                       g_hash_table_size(recipient_entry->envvars) : 0));
        }

        if (recipients == 0) {
            alert_list = g_list_prepend(alert_list, entry);
        } else {
            crm_free_alert_entry(entry);
        }
    }

    if (max_timeout > 0) {
        crm_alert_max_alert_timeout = max_timeout;
    }
    return alert_list;
}

/*!
 * \internal
 * \brief Free an alert list generated by pe_unpack_alerts()
 *
 * \param[in] alert_list  Alert list to free
 */
void
pe_free_alert_list(GListPtr alert_list)
{
    if (alert_list) {
        g_list_free_full(alert_list, (GDestroyNotify) crm_free_alert_entry);
    }
}
