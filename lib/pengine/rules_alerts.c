/*
 * Copyright 2015-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/pengine/rules_internal.h>

/*!
 * \internal
 * \brief Unpack an alert's or alert recipient's meta attributes
 *
 * \param[in,out] basenode     Alert or recipient XML
 * \param[in,out] entry        Where to store unpacked values
 * \param[in,out] max_timeout  Max timeout of all alerts and recipients thus far
 *
 * \return Standard Pacemaker return code
 */
static int
get_meta_attrs_from_cib(xmlNode *basenode, pcmk__alert_t *entry,
                        guint *max_timeout)
{
    GHashTable *config_hash = pcmk__strkey_table(free, free);
    crm_time_t *now = crm_time_new(NULL);
    const char *value = NULL;
    int rc = pcmk_rc_ok;

    pe_unpack_nvpairs(basenode, basenode, XML_TAG_META_SETS, NULL, config_hash,
                      NULL, FALSE, now, NULL);
    crm_time_free(now);

    value = g_hash_table_lookup(config_hash, PCMK_META_ENABLED);
    if ((value != NULL) && !crm_is_true(value)) {
        // No need to continue unpacking
        rc = pcmk_rc_disabled;
        goto done;
    }

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_TIMEOUT);
    if (value) {
        entry->timeout = crm_get_msec(value);
        if (entry->timeout <= 0) {
            if (entry->timeout == 0) {
                crm_trace("Alert %s uses default timeout of %dmsec",
                          entry->id, PCMK__ALERT_DEFAULT_TIMEOUT_MS);
            } else {
                crm_warn("Alert %s has invalid timeout value '%s', using default %dmsec",
                         entry->id, (char*)value, PCMK__ALERT_DEFAULT_TIMEOUT_MS);
            }
            entry->timeout = PCMK__ALERT_DEFAULT_TIMEOUT_MS;
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

done:
    g_hash_table_destroy(config_hash);
    return rc;
}

static void
get_envvars_from_cib(xmlNode *basenode, pcmk__alert_t *entry)
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
        entry->envvars = pcmk__strkey_table(free, free);
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

static void
unpack_alert_filter(xmlNode *basenode, pcmk__alert_t *entry)
{
    xmlNode *select = first_named_child(basenode, XML_CIB_TAG_ALERT_SELECT);
    xmlNode *event_type = NULL;
    uint32_t flags = pcmk__alert_none;

    for (event_type = pcmk__xe_first_child(select); event_type != NULL;
         event_type = pcmk__xe_next(event_type)) {

        const char *tagname = crm_element_name(event_type);

        if (tagname == NULL) {
            continue;

        } else if (!strcmp(tagname, XML_CIB_TAG_ALERT_FENCING)) {
            flags |= pcmk__alert_fencing;

        } else if (!strcmp(tagname, XML_CIB_TAG_ALERT_NODES)) {
            flags |= pcmk__alert_node;

        } else if (!strcmp(tagname, XML_CIB_TAG_ALERT_RESOURCES)) {
            flags |= pcmk__alert_resource;

        } else if (!strcmp(tagname, XML_CIB_TAG_ALERT_ATTRIBUTES)) {
            xmlNode *attr;
            const char *attr_name;
            int nattrs = 0;

            flags |= pcmk__alert_attribute;
            for (attr = first_named_child(event_type, XML_CIB_TAG_ALERT_ATTR);
                 attr != NULL;
                 attr = crm_next_same_xml(attr)) {

                attr_name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);
                if (attr_name) {
                    if (nattrs == 0) {
                        g_strfreev(entry->select_attribute_name);
                        entry->select_attribute_name = NULL;
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
        entry->flags = flags;
        crm_debug("Alert %s receives events: attributes:%s%s%s%s",
                  entry->id,
                  (pcmk_is_set(flags, pcmk__alert_attribute)?
                   (entry->select_attribute_name? "some" : "all") : "none"),
                  (pcmk_is_set(flags, pcmk__alert_fencing)? " fencing" : ""),
                  (pcmk_is_set(flags, pcmk__alert_node)? " nodes" : ""),
                  (pcmk_is_set(flags, pcmk__alert_resource)? " resources" : ""));
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

    get_envvars_from_cib(alert, entry);
    rc = get_meta_attrs_from_cib(alert, entry, max_timeout);
    if (rc == pcmk_rc_ok) {
        unpack_alert_filter(alert, entry);
    }
    return rc;
}

/*!
 * \internal
 * \brief Unpack a CIB alerts section
 *
 * \param[in] alerts  XML of alerts section
 *
 * \return  List of unpacked alert entries
 *
 * \note Unlike most unpack functions, this is not used by the scheduler itself,
 *       but is supplied for use by daemons that need to send alerts.
 */
GList *
pe_unpack_alerts(const xmlNode *alerts)
{
    xmlNode *alert;
    pcmk__alert_t *entry;
    guint max_timeout = 0;
    GList *alert_list = NULL;

    if (alerts == NULL) {
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

        entry = pcmk__alert_new(alert_id, alert_path);

        if (unpack_alert(alert, entry, &max_timeout) != pcmk_rc_ok) {
            // Don't allow recipients to override if entire alert is disabled
            crm_debug("Alert %s is disabled", entry->id);
            pcmk__free_alert(entry);
            continue;
        }

        if (entry->tstamp_format == NULL) {
            entry->tstamp_format = strdup(PCMK__ALERT_DEFAULT_TSTAMP_FORMAT);
        }

        crm_debug("Alert %s: path=%s timeout=%dms tstamp-format='%s' %u vars",
                  entry->id, entry->path, entry->timeout, entry->tstamp_format,
                  (entry->envvars? g_hash_table_size(entry->envvars) : 0));

        for (recipient = first_named_child(alert, XML_CIB_TAG_ALERT_RECIPIENT);
             recipient != NULL; recipient = crm_next_same_xml(recipient)) {

            pcmk__alert_t *recipient_entry = pcmk__dup_alert(entry);

            recipients++;
            recipient_entry->recipient = strdup(crm_element_value(recipient,
                                                XML_ALERT_ATTR_REC_VALUE));

            if (unpack_alert(recipient, recipient_entry,
                             &max_timeout) != pcmk_rc_ok) {
                crm_debug("Alert %s: recipient %s is disabled",
                          entry->id, recipient_entry->id);
                pcmk__free_alert(recipient_entry);
                continue;
            }
            alert_list = g_list_prepend(alert_list, recipient_entry);
            crm_debug("Alert %s has recipient %s with value %s and %d envvars",
                      entry->id, ID(recipient), recipient_entry->recipient,
                      (recipient_entry->envvars?
                       g_hash_table_size(recipient_entry->envvars) : 0));
        }

        if (recipients == 0) {
            alert_list = g_list_prepend(alert_list, entry);
        } else {
            pcmk__free_alert(entry);
        }
    }
    return alert_list;
}

/*!
 * \internal
 * \brief Free an alert list generated by pe_unpack_alerts()
 *
 * \param[in,out] alert_list  Alert list to free
 */
void
pe_free_alert_list(GList *alert_list)
{
    if (alert_list) {
        g_list_free_full(alert_list, (GDestroyNotify) pcmk__free_alert);
    }
}
