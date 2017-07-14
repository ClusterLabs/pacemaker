/*
 * Copyright (c) 2015 David Vossel <davidvossel@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/alerts_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/lrmd_alerts_internal.h>

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>

lrmd_key_value_t *
lrmd_set_alert_key_to_lrmd_params(lrmd_key_value_t *head, enum crm_alert_keys_e name, const char *value)
{
    const char **key;

    if (value == NULL) {
        value = "";
    }
    for (key = crm_alert_keys[name]; *key; key++) {
        crm_trace("Setting alert key %s = '%s'", *key, value);
        head = lrmd_key_value_add(head, *key, value);
    }
    return head;
}

static void
set_ev_kv(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_key_value_t **head = (lrmd_key_value_t **) user_data;

    if (value) {
        crm_trace("Setting environment variable %s='%s'",
                  (char*)key, (char*)value);
        *head = lrmd_key_value_add(*head, key, value);
    }
}

lrmd_key_value_t *
lrmd_set_alert_envvar_to_lrmd_params(lrmd_key_value_t *head,
                                     crm_alert_entry_t *entry)
{
    if (entry->envvars) {
        g_hash_table_foreach(entry->envvars, set_ev_kv, &head);
    }
    return head;
}

/*!
 * \internal
 * \brief Execute alert agents for an event
 *
 * \param[in]     alert_list         Alerts to execute
 * \param[in]     lrmd_connect_func  Function that returns an LRMD connection
 * \param[in]     kind               Type of event that is being alerted for
 * \param[in]     attr_name          If crm_alert_attribute, the attribute name
 * \param[in,out] params             Environment variables to pass to agents
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alerts failed
 * \retval -2 if all alerts failed
 */
static int
exec_alert_list(GList *alert_list, lrmd_t *(*lrmd_connect_func)(void),
                enum crm_alert_flags kind, const char *attr_name,
                lrmd_key_value_t *params)
{
    bool any_success = FALSE, any_failure = FALSE;
    const char *kind_s = crm_alert_flag2text(kind);
    crm_time_hr_t *now = NULL;

    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_kind, kind_s);
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_version, VERSION);

    for (GList *iter = g_list_first(alert_list); iter; iter = g_list_next(iter)) {
        crm_alert_entry_t *entry = (crm_alert_entry_t *)(iter->data);
        lrmd_key_value_t *copy_params = NULL;
        lrmd_key_value_t *head = NULL;
        lrmd_t *lrmd_conn = NULL;
        int rc;

        if (is_not_set(entry->flags, kind)) {
            crm_trace("Filtering unwanted %s alert to %s via %s",
                      kind_s, entry->recipient, entry->id);
            continue;
        }

        if ((kind == crm_alert_attribute)
            && !crm_is_target_alert(entry->select_attribute_name, attr_name)) {

            crm_trace("Filtering unwanted attribute '%s' alert to %s via %s",
                      attr_name, entry->recipient, entry->id);
            continue;
        }

        if (now == NULL) {
            now = crm_time_hr_new(NULL);
        }
        crm_info("Sending %s alert via %s to %s",
                 kind_s, entry->id, entry->recipient);

        /* Make a copy of the parameters, because each alert will be unique */
        for (head = params; head != NULL; head = head->next) {
            copy_params = lrmd_key_value_add(copy_params, head->key, head->value);
        }

        copy_params = lrmd_set_alert_key_to_lrmd_params(copy_params, CRM_alert_recipient, entry->recipient);

        if (now) {
            char *timestamp = crm_time_format_hr(entry->tstamp_format, now);

            if (timestamp) {
                copy_params = lrmd_set_alert_key_to_lrmd_params(copy_params,
                                                                CRM_alert_timestamp,
                                                                timestamp);
                free(timestamp);
            }
        }

        copy_params = lrmd_set_alert_envvar_to_lrmd_params(copy_params, entry);

        lrmd_conn = (*lrmd_connect_func)();
        if (lrmd_conn == NULL) {
            crm_warn("Cannot send alerts: No LRMD connection");
            any_failure = TRUE;
            goto done;
        }

        rc = lrmd_conn->cmds->exec_alert(lrmd_conn, entry->id, entry->path,
                                         entry->timeout, copy_params);
        if (rc < 0) {
            crm_err("Could not execute alert %s: %s " CRM_XS " rc=%d",
                    entry->id, pcmk_strerror(rc), rc);
            any_failure = TRUE;
        } else {
            any_success = TRUE;
        }
    }

done:
    if (now) {
        free(now);
    }

    if (any_failure) {
        return (any_success? -1 : -2);
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Send an alert for a node attribute change
 *
 * \param[in] alert_list         List of alert agents to execute
 * \param[in] lrmd_connect_func  Function that returns an LRMD connection
 * \param[in] node               Name of node with attribute change
 * \param[in] nodeid             Node ID of node with attribute change
 * \param[in] attr_name          Name of attribute that changed
 * \param[in] attr_value         New value of attribute that changed
 *
 * \retval pcmk_ok on success
 * \retval -1 if some alert agents failed
 * \retval -2 if all alert agents failed
 */
int
lrmd_send_attribute_alert(GList *alert_list, lrmd_t *(*lrmd_connect_func)(void),
                          const char *node, uint32_t nodeid,
                          const char *attr_name, const char *attr_value)
{
    int rc = pcmk_ok;
    lrmd_key_value_t *params = NULL;
    char *nodeid_s;

    if (alert_list == NULL) {
        return pcmk_ok;
    }
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_node, node);

    nodeid_s = crm_itoa(nodeid);
    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_nodeid,
                                               nodeid_s);
    free(nodeid_s);

    params = lrmd_set_alert_key_to_lrmd_params(params, CRM_alert_attribute_name,
                                               attr_name);
    params = lrmd_set_alert_key_to_lrmd_params(params,
                                               CRM_alert_attribute_value,
                                               attr_value);

    rc = exec_alert_list(alert_list, lrmd_connect_func, crm_alert_attribute,
                         attr_name, params);
    lrmd_key_value_freeall(params);
    return rc;
}
