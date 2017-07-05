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

static GHashTable *
get_meta_attrs_from_cib(xmlNode *basenode, crm_alert_entry_t *entry,
                        guint *max_timeout)
{
    GHashTable *config_hash = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                    g_hash_destroy_str,
                                                    g_hash_destroy_str);
    crm_time_t *now = crm_time_new(NULL);
    const char *value = NULL;

    unpack_instance_attributes(basenode, basenode, XML_TAG_META_SETS, NULL,
                               config_hash, NULL, FALSE, now);

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_TIMEOUT);
    if (value) {
        entry->timeout = crm_get_msec(value);
        if (entry->timeout <= 0) {
            if (entry->timeout == 0) {
                crm_trace("Setting timeout to default %dmsec",
                          CRM_ALERT_DEFAULT_TIMEOUT_MS);
            } else {
                crm_warn("Invalid timeout value setting to default %dmsec",
                         CRM_ALERT_DEFAULT_TIMEOUT_MS);
            }
            entry->timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS;
        } else {
            crm_trace("Found timeout %dmsec", entry->timeout);
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
        entry->tstamp_format = (char *) value;
        crm_trace("Found timestamp format string '%s'", value);
    }

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_SELECT_KIND);
    if (value) {
        entry->select_kind_orig = (char *) value;
        entry->select_kind = g_strsplit((char *) value, ",", 0);
        crm_trace("Found select_kind string '%s'", (char *) value);
    }

    value = g_hash_table_lookup(config_hash,
                                XML_ALERT_ATTR_SELECT_ATTRIBUTE_NAME);
    if (value) {
        entry->select_attribute_name_orig = (char*) value;
        entry->select_attribute_name = g_strsplit((char*) value, ",", 0);
        crm_trace("Found attribute_name string '%s'", (char *) value);
    }

    crm_time_free(now);
    return config_hash; /* keep hash as long as strings are needed */
}

void
pe_unpack_alerts(xmlNode *alerts)
{
    xmlNode *alert;
    crm_alert_entry_t entry;
    guint max_timeout = 0;

    crm_free_alert_list();
    crm_alert_max_alert_timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS;
    if (crm_alert_kind_default == NULL) {
        crm_alert_kind_default = g_strsplit(CRM_ALERT_KIND_DEFAULT, ",", 0);
    }

    if (alerts) {
#ifdef RHEL7_COMPAT
        if (notify_script) {
            crm_warn("Ignoring deprecated notification configuration because alerts available");
        }
#endif
    } else {
#ifdef RHEL7_COMPAT
        if (notify_script) {
            entry = (crm_alert_entry_t) {
                .id = (char *) "legacy_notification",
                .path = notify_script,
                .timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS,
                .recipient = notify_target,
                .select_kind_orig = NULL,
                .select_kind = NULL,
                .select_attribute_name_orig = NULL,
                .select_attribute_name = NULL
            };
            crm_add_dup_alert_list_entry(&entry);
            crm_warn("Deprecated notification syntax in use (alerts syntax is preferable)");
        }
#endif
        return;
    }

    for (alert = first_named_child(alerts, XML_CIB_TAG_ALERT);
         alert; alert = __xml_next(alert)) {

        xmlNode *recipient;
        int recipients = 0, envvars = 0;
        GHashTable *config_hash = NULL;

        entry = (crm_alert_entry_t) {
            .id = (char *) crm_element_value(alert, XML_ATTR_ID),
            .path = (char *) crm_element_value(alert, XML_ALERT_ATTR_PATH),
            .timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS,
            .tstamp_format = (char *) CRM_ALERT_DEFAULT_TSTAMP_FORMAT,
            .select_kind_orig = NULL,
            .select_kind = NULL,
            .select_attribute_name_orig = NULL,
            .select_attribute_name = NULL
        };

        crm_get_envvars_from_cib(alert, &entry, &envvars);
        config_hash = get_meta_attrs_from_cib(alert, &entry, &max_timeout);

        crm_debug("Found alert %s with path=%s timeout=%d tstamp_format=%s "
                  "select_kind=%s select_attribute_name=%s "
                  "%d additional environment variables",
                  entry.id, entry.path, entry.timeout, entry.tstamp_format,
                  entry.select_kind_orig, entry.select_attribute_name_orig,
                  envvars);

        for (recipient = first_named_child(alert, XML_CIB_TAG_ALERT_RECIPIENT);
             recipient != NULL; recipient = __xml_next(recipient)) {

            int envvars_added = 0;

            entry.recipient = (char *) crm_element_value(recipient,
                                                         XML_ALERT_ATTR_REC_VALUE);
            recipients++;

            crm_get_envvars_from_cib(recipient, &entry, &envvars_added);

            {
                crm_alert_entry_t recipient_entry = entry;
                GHashTable *config_hash = get_meta_attrs_from_cib(recipient,
                                                                  &recipient_entry,
                                                                  &max_timeout);

                crm_add_dup_alert_list_entry(&recipient_entry);
                crm_debug("Alert has recipient: id=%s, value=%s, "
                          "%d additional environment variables",
                          crm_element_value(recipient, XML_ATTR_ID),
                          recipient_entry.recipient, envvars_added);
                g_hash_table_destroy(config_hash);
            }

            crm_drop_envvars(&entry, envvars_added);
        }

        if (recipients == 0) {
            crm_add_dup_alert_list_entry(&entry);
        }

        crm_drop_envvars(&entry, -1);
        g_hash_table_destroy(config_hash);
    }

    if (max_timeout > 0) {
        crm_alert_max_alert_timeout = max_timeout;
    }
}
