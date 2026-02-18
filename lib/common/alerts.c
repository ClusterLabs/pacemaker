/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/common/xml.h>

const char *pcmk__alert_keys[PCMK__ALERT_INTERNAL_KEY_MAX] = {
    [PCMK__alert_key_recipient] = "CRM_alert_recipient",
    [PCMK__alert_key_node] = "CRM_alert_node",
    [PCMK__alert_key_nodeid] = "CRM_alert_nodeid",
    [PCMK__alert_key_rsc] = "CRM_alert_rsc",
    [PCMK__alert_key_task] = "CRM_alert_task",
    [PCMK__alert_key_interval] = "CRM_alert_interval",
    [PCMK__alert_key_desc] = "CRM_alert_desc",
    [PCMK__alert_key_status] = "CRM_alert_status",
    [PCMK__alert_key_target_rc] = "CRM_alert_target_rc",
    [PCMK__alert_key_rc] = "CRM_alert_rc",
    [PCMK__alert_key_kind] = "CRM_alert_kind",
    [PCMK__alert_key_version] = "CRM_alert_version",
    [PCMK__alert_key_node_sequence] = PCMK__ALERT_NODE_SEQUENCE,
    [PCMK__alert_key_timestamp] = "CRM_alert_timestamp",
    [PCMK__alert_key_attribute_name] = "CRM_alert_attribute_name",
    [PCMK__alert_key_attribute_value] = "CRM_alert_attribute_value",
    [PCMK__alert_key_timestamp_epoch] = "CRM_alert_timestamp_epoch",
    [PCMK__alert_key_timestamp_usec] = "CRM_alert_timestamp_usec",
    [PCMK__alert_key_exec_time] = "CRM_alert_exec_time",
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
    pcmk__alert_t *entry = pcmk__assert_alloc(1, sizeof(pcmk__alert_t));

    pcmk__assert((id != NULL) && (path != NULL));
    entry->id = pcmk__str_copy(id);
    entry->path = pcmk__str_copy(path);
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
pcmk__dup_alert(const pcmk__alert_t *entry)
{
    pcmk__alert_t *new_entry = pcmk__alert_new(entry->id, entry->path);

    new_entry->timeout = entry->timeout;
    new_entry->flags = entry->flags;
    new_entry->envvars = pcmk__str_table_dup(entry->envvars);
    new_entry->tstamp_format = pcmk__str_copy(entry->tstamp_format);
    new_entry->recipient = pcmk__str_copy(entry->recipient);
    if (entry->select_attribute_name) {
        new_entry->select_attribute_name = g_strdupv(entry->select_attribute_name);
    }
    return new_entry;
}

void
pcmk__add_alert_key(GHashTable *table, enum pcmk__alert_keys_e name,
                    const char *value)
{
    pcmk__assert((table != NULL) && (name >= 0)
                 && (name < PCMK__ALERT_INTERNAL_KEY_MAX));
    if (value == NULL) {
        pcmk__trace("Removing alert key %s", pcmk__alert_keys[name]);
        g_hash_table_remove(table, pcmk__alert_keys[name]);
    } else {
        pcmk__trace("Inserting alert key %s = '%s'", pcmk__alert_keys[name],
                    value);
        pcmk__insert_dup(table, pcmk__alert_keys[name], value);
    }
}

void
pcmk__add_alert_key_int(GHashTable *table, enum pcmk__alert_keys_e name,
                        int value)
{
    pcmk__assert((table != NULL) && (name >= 0)
                 && (name < PCMK__ALERT_INTERNAL_KEY_MAX));
    pcmk__trace("Inserting alert key %s = %d", pcmk__alert_keys[name], value);
    g_hash_table_insert(table, pcmk__str_copy(pcmk__alert_keys[name]),
                        pcmk__itoa(value));
}

#define READABLE_DEFAULT pcmk__readable_interval(PCMK__ALERT_DEFAULT_TIMEOUT_MS)

/*!
 * \internal
 * \brief Unpack options for an alert or alert recipient from its
 *        meta-attributes in the CIB XML configuration
 *
 * \param[in,out] xml          Alert or recipient XML
 * \param[in,out] entry        Where to store unpacked values
 * \param[in,out] max_timeout  Max timeout of all alerts and recipients thus far
 *
 * \return Standard Pacemaker return code
 */
static int
unpack_alert_options(xmlNode *xml, pcmk__alert_t *entry, guint *max_timeout)
{
    GHashTable *config_hash = pcmk__strkey_table(free, free);
    crm_time_t *now = crm_time_new(NULL);
    const char *value = NULL;
    int rc = pcmk_rc_ok;

    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    pcmk_unpack_nvpair_blocks(xml, PCMK_XE_META_ATTRIBUTES, NULL, &rule_input,
                              config_hash, NULL);
    crm_time_free(now);

    value = g_hash_table_lookup(config_hash, PCMK_META_ENABLED);
    if ((value != NULL) && !pcmk__is_true(value)) {
        // No need to continue unpacking
        rc = pcmk_rc_disabled;
        goto done;
    }

    value = g_hash_table_lookup(config_hash, PCMK_META_TIMEOUT);
    if (value != NULL) {
        long long timeout_ms = 0;

        if ((pcmk__parse_ms(value, &timeout_ms) != pcmk_rc_ok)
            || (timeout_ms <= 0)) {

            entry->timeout = PCMK__ALERT_DEFAULT_TIMEOUT_MS;

            if (timeout_ms == 0) {
                pcmk__trace("Alert %s uses default timeout (%s)", entry->id,
                            READABLE_DEFAULT);
            } else {
                pcmk__config_warn("Using default timeout (%s) for alert %s "
                                  "because '%s' is not a valid timeout",
                                  entry->id, value, READABLE_DEFAULT);
            }

        } else {
            entry->timeout = (int) QB_MIN(timeout_ms, INT_MAX);
            pcmk__trace("Alert %s uses timeout of %s", entry->id,
                        pcmk__readable_interval(entry->timeout));
        }
        if (entry->timeout > *max_timeout) {
            *max_timeout = entry->timeout;
        }
    }
    value = g_hash_table_lookup(config_hash, PCMK_META_TIMESTAMP_FORMAT);
    if (value != NULL) {
        /* hard to do any checks here as merely anything can
         * can be a valid time-format-string
         */
        entry->tstamp_format = strdup(value);
        pcmk__trace("Alert %s uses timestamp format '%s'", entry->id,
                    entry->tstamp_format);
    }

done:
    g_hash_table_destroy(config_hash);
    return rc;
}

/*!
 * \internal
 * \brief Unpack agent parameters for an alert or alert recipient into an
 *        environment variable list based on its CIB XML configuration
 *
 * \param[in]     xml    Alert or recipient XML
 * \param[in,out] entry  Alert entry to create environment variables for
 */
static void
unpack_alert_parameters(const xmlNode *xml, pcmk__alert_t *entry)
{
    xmlNode *child;

    if ((xml == NULL) || (entry == NULL)) {
        return;
    }

    child = pcmk__xe_first_child(xml, PCMK_XE_INSTANCE_ATTRIBUTES, NULL,
                                 NULL);
    if (child == NULL) {
        return;
    }

    if (entry->envvars == NULL) {
        entry->envvars = pcmk__strkey_table(free, free);
    }

    for (child = pcmk__xe_first_child(child, PCMK_XE_NVPAIR, NULL, NULL);
         child != NULL; child = pcmk__xe_next(child, PCMK_XE_NVPAIR)) {

        const char *name = pcmk__xe_get(child, PCMK_XA_NAME);
        const char *value = pcmk__xe_get(child, PCMK_XA_VALUE);

        if (value == NULL) {
            value = "";
        }
        pcmk__insert_dup(entry->envvars, name, value);
        pcmk__trace("Alert %s: added environment variable %s='%s'", entry->id,
                    name, value);
    }
}

/*!
 * \internal
 * \brief Create filters for an alert or alert recipient based on its
 *        configuration in CIB XML
 *
 * \param[in]     xml    Alert or recipient XML
 * \param[in,out] entry  Alert entry to create filters for
 */
static void
unpack_alert_filter(xmlNode *xml, pcmk__alert_t *entry)
{
    xmlNode *select = pcmk__xe_first_child(xml, PCMK_XE_SELECT, NULL, NULL);
    xmlNode *event_type = NULL;
    uint32_t flags = pcmk__alert_none;

    for (event_type = pcmk__xe_first_child(select, NULL, NULL, NULL);
         event_type != NULL; event_type = pcmk__xe_next(event_type, NULL)) {

        if (pcmk__xe_is(event_type, PCMK_XE_SELECT_FENCING)) {
            flags |= pcmk__alert_fencing;

        } else if (pcmk__xe_is(event_type, PCMK_XE_SELECT_NODES)) {
            flags |= pcmk__alert_node;

        } else if (pcmk__xe_is(event_type, PCMK_XE_SELECT_RESOURCES)) {
            flags |= pcmk__alert_resource;

        } else if (pcmk__xe_is(event_type, PCMK_XE_SELECT_ATTRIBUTES)) {
            xmlNode *attr;
            const char *attr_name;
            int nattrs = 0;

            flags |= pcmk__alert_attribute;
            for (attr = pcmk__xe_first_child(event_type, PCMK_XE_ATTRIBUTE,
                                             NULL, NULL);
                 attr != NULL; attr = pcmk__xe_next(attr, PCMK_XE_ATTRIBUTE)) {

                attr_name = pcmk__xe_get(attr, PCMK_XA_NAME);
                if (attr_name) {
                    if (nattrs == 0) {
                        g_clear_pointer(&entry->select_attribute_name,
                                        g_strfreev);
                    }
                    ++nattrs;
                    entry->select_attribute_name = pcmk__realloc(entry->select_attribute_name,
                                                                 (nattrs + 1) * sizeof(char*));
                    entry->select_attribute_name[nattrs - 1] = strdup(attr_name);
                    entry->select_attribute_name[nattrs] = NULL;
                }
            }
        }
    }

    if (flags != pcmk__alert_none) {
        const bool attribute = pcmk__is_set(flags, pcmk__alert_attribute);
        const bool fencing = pcmk__is_set(flags, pcmk__alert_fencing);
        const bool node = pcmk__is_set(flags, pcmk__alert_node);
        const bool resource = pcmk__is_set(flags, pcmk__alert_resource);
        const char *which_attrs = "none";

        if (attribute) {
            if (entry->select_attribute_name != NULL) {
                which_attrs = "some";
            } else {
                which_attrs = "all";
            }
        }

        entry->flags = flags;
        pcmk__debug("Alert %s receives events: attributes:%s%s%s%s", entry->id,
                    which_attrs, (fencing? " fencing" : ""),
                    (node? " nodes" : ""), (resource? " resources" : ""));
    }
}

/*!
 * \internal
 * \brief Unpack an alert or an alert recipient
 *
 * \param[in,out] alert        Alert or recipient XML
 * \param[in,out] entry        Where to store unpacked values
 * \param[in,out] max_timeout  Max timeout of all alerts and recipients thus far
 *
 * \return Standard Pacemaker return code
 */
static int
unpack_alert(xmlNode *alert, pcmk__alert_t *entry, guint *max_timeout)
{
    int rc = pcmk_rc_ok;

    unpack_alert_parameters(alert, entry);
    rc = unpack_alert_options(alert, entry, max_timeout);
    if (rc == pcmk_rc_ok) {
        unpack_alert_filter(alert, entry);
    }
    return rc;
}

/*!
 * \internal
 * \brief Unpack a CIB alerts section into a list of alert entries
 *
 * \param[in] alerts  XML of CIB alerts section
 *
 * \return List of unpacked alert entries
 */
GList *
pcmk__unpack_alerts(const xmlNode *alerts)
{
    xmlNode *alert;
    pcmk__alert_t *entry;
    guint max_timeout = 0U;
    GList *alert_list = NULL;

    for (alert = pcmk__xe_first_child(alerts, PCMK_XE_ALERT, NULL, NULL);
         alert != NULL; alert = pcmk__xe_next(alert, PCMK_XE_ALERT)) {

        xmlNode *recipient = NULL;
        int recipients = 0;
        const char *alert_id = pcmk__xe_id(alert);
        const char *alert_path = pcmk__xe_get(alert, PCMK_XA_PATH);

        // Not possible with schema validation enabled
        if (alert_id == NULL) {
            pcmk__config_err("Ignoring invalid alert without " PCMK_XA_ID);
            continue;
        }
        if (alert_path == NULL) {
            pcmk__config_err("Ignoring invalid alert %s without " PCMK_XA_PATH,
                             alert_id);
            continue;
        }

        entry = pcmk__alert_new(alert_id, alert_path);

        if (unpack_alert(alert, entry, &max_timeout) != pcmk_rc_ok) {
            // Don't allow recipients to override if entire alert is disabled
            pcmk__debug("Alert %s is disabled", entry->id);
            pcmk__free_alert(entry);
            continue;
        }

        if (entry->tstamp_format == NULL) {
            entry->tstamp_format =
                pcmk__str_copy(PCMK__ALERT_DEFAULT_TSTAMP_FORMAT);
        }

        pcmk__debug("Alert %s: path=%s timeout=%s tstamp-format='%s'",
                    entry->id, entry->path,
                    pcmk__readable_interval(entry->timeout),
                    entry->tstamp_format);

        for (recipient = pcmk__xe_first_child(alert, PCMK_XE_RECIPIENT, NULL,
                                              NULL);
             recipient != NULL;
             recipient = pcmk__xe_next(recipient, PCMK_XE_RECIPIENT)) {

            pcmk__alert_t *recipient_entry = pcmk__dup_alert(entry);
            guint n_envvars = 0;

            recipients++;
            recipient_entry->recipient = pcmk__xe_get_copy(recipient,
                                                           PCMK_XA_VALUE);

            if (unpack_alert(recipient, recipient_entry,
                             &max_timeout) != pcmk_rc_ok) {
                pcmk__debug("Alert %s: recipient %s is disabled", entry->id,
                            recipient_entry->id);
                pcmk__free_alert(recipient_entry);
                continue;
            }
            alert_list = g_list_prepend(alert_list, recipient_entry);

            if (recipient_entry->envvars != NULL) {
                n_envvars = g_hash_table_size(recipient_entry->envvars);
            }
            pcmk__debug("Alert %s has recipient %s with value %s and %d "
                        "envvars",
                        entry->id, pcmk__xe_id(recipient),
                        recipient_entry->recipient, n_envvars);
        }

        if (recipients == 0) {
            alert_list = g_list_prepend(alert_list, entry);
        } else { // Recipients were prepended individually above
            pcmk__free_alert(entry);
        }
    }
    return alert_list;
}

/*!
 * \internal
 * \brief Free an alert list generated by pcmk__unpack_alerts()
 *
 * \param[in,out] alert_list  Alert list to free
 */
void
pcmk__free_alerts(GList *alert_list)
{
    if (alert_list != NULL) {
        g_list_free_full(alert_list, (GDestroyNotify) pcmk__free_alert);
    }
}
