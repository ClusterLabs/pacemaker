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
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include "crmd_alerts.h"
#include "crmd_messages.h"
#include <crm/common/alerts_internal.h>
#include <crm/common/iso8601_internal.h>

static char *notify_script = NULL;
static char *notify_target = NULL;
static int alerts_inflight = 0;
static gboolean draining_alerts = FALSE;

/*
 * synchronize local data with cib
 */

static GHashTable *
get_meta_attrs_from_cib(xmlNode *basenode, crm_alert_entry_t *entry,
                        guint *max_timeout)
{
    GHashTable *config_hash =
        g_hash_table_new_full(crm_str_hash, g_str_equal,
                              g_hash_destroy_str, g_hash_destroy_str);
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

    crm_time_free(now);
    return config_hash; /* keep hash as long as strings are needed */
}

void
parse_alerts(xmlNode *alerts)
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
        crm_info("We have an alerts section in the cib");

        if (notify_script) {
            crm_warn("Cib contains configuration for Legacy Notifications "
                     "which is overruled by alerts section");
        }
    } else {
        crm_info("No optional alerts section in cib");

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
            crm_info("Legacy Notifications enabled");
        }

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

        crm_get_envvars_from_cib(alert,
                                 &entry,
                                 &envvars);

        config_hash =
            get_meta_attrs_from_cib(alert, &entry, &max_timeout);

        crm_debug("Found alert: id=%s, path=%s, timeout=%d, "
                   "tstamp_format=%s, select_kind=%s, %d additional environment variables",
                   entry.id, entry.path, entry.timeout,
                   entry.tstamp_format, entry.select_kind_orig, envvars);

        for (recipient = first_named_child(alert,
                                           XML_CIB_TAG_ALERT_RECIPIENT);
             recipient; recipient = __xml_next(recipient)) {
            int envvars_added = 0;

            entry.recipient = (char *) crm_element_value(recipient,
                                                XML_ALERT_ATTR_REC_VALUE);
            recipients++;

            crm_get_envvars_from_cib(recipient,
                                     &entry,
                                     &envvars_added);

            {
                crm_alert_entry_t recipient_entry = entry;
                GHashTable *config_hash =
                    get_meta_attrs_from_cib(recipient,
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

/*
 * end of synchronization of local data with cib
 */

void
crmd_enable_alerts(const char *script, const char *target)
{
    free(notify_script);
    notify_script = ((script) &&
                     (strcmp(script,"/dev/null")))?strdup(script):NULL;

    free(notify_target);
    notify_target = (target != NULL)?strdup(target):NULL;
}

static void
crmd_alert_complete(svc_action_t *op)
{
    alerts_inflight--;
    if(op->rc == 0) {
        crm_info("Alert %d (%s) complete", op->sequence, op->agent);
    } else {
        crm_warn("Alert %d (%s) failed: %d", op->sequence, op->agent,
                 op->rc);
    }
}

static void
send_alerts(const char *kind)
{
    svc_action_t *alert = NULL;
    static int operations = 0;
    GListPtr l;
    crm_time_hr_t *now = crm_time_hr_new(NULL);

    crm_set_alert_key(CRM_alert_kind, kind);
    crm_set_alert_key(CRM_alert_version, VERSION);

    for (l = g_list_first(crm_alert_list); l; l = g_list_next(l)) {
        crm_alert_entry_t *entry = (crm_alert_entry_t *)(l->data);
        char *timestamp = crm_time_format_hr(entry->tstamp_format, now);

        if (crm_is_target_alert(entry->select_kind == NULL ? crm_alert_kind_default : entry->select_kind, kind) == FALSE) {
            crm_trace("Cannot sending '%s' alert to '%s' via '%s'(select_kind=%s)", kind, entry->recipient, entry->path, 
                entry->select_kind == NULL ? CRM_ALERT_KIND_DEFAULT : entry->select_kind_orig);
            free(timestamp);
            continue;
        }

        operations++;

        if (!draining_alerts) {
            crm_debug("Sending '%s' alert to '%s' via '%s'", kind,
                    entry->recipient, entry->path);
            crm_set_alert_key(CRM_alert_recipient, entry->recipient);
            crm_set_alert_key_int(CRM_alert_node_sequence, operations);
            crm_set_alert_key(CRM_alert_timestamp, timestamp);

            alert = services_action_create_generic(entry->path, NULL);

            alert->timeout = entry->timeout;
            alert->standard = strdup("event");
            alert->id = strdup(entry->id);
            alert->agent = strdup(entry->path);
            alert->sequence = operations;

            crm_set_envvar_list(entry);

            alerts_inflight++;
            if(services_action_async(alert, &crmd_alert_complete) == FALSE) {
                services_action_free(alert);
                alerts_inflight--;
            }

            crm_unset_envvar_list(entry);
        } else {
            crm_warn("Ignoring '%s' alert to '%s' via '%s' received "
                     "while shutting down",
                     kind, entry->recipient, entry->path);
        }

        free(timestamp);
    }

    crm_unset_alert_keys();
    if (now) {
        free(now);
    }
}

void
crmd_alert_node_event(crm_node_t *node)
{
    if(!crm_alert_list) {
        return;
    }

    crm_set_alert_key(CRM_alert_node, node->uname);
    crm_set_alert_key_int(CRM_alert_nodeid, node->id);
    crm_set_alert_key(CRM_alert_desc, node->state);

    send_alerts("node");
}

void
crmd_alert_fencing_op(stonith_event_t * e)
{
    char *desc = NULL;

    if (!crm_alert_list) {
        return;
    }

    desc = crm_strdup_printf(
        "Operation %s of %s by %s for %s@%s: %s (ref=%s)",
        e->action, e->target, e->executioner ? e->executioner : "<no-one>",
        e->client_origin, e->origin, pcmk_strerror(e->result), e->id);

    crm_set_alert_key(CRM_alert_node, e->target);
    crm_set_alert_key(CRM_alert_task, e->operation);
    crm_set_alert_key(CRM_alert_desc, desc);
    crm_set_alert_key_int(CRM_alert_rc, e->result);

    send_alerts("fencing");
    free(desc);
}

void
crmd_alert_resource_op(const char *node, lrmd_event_data_t * op)
{
    int target_rc = 0;

    if(!crm_alert_list) {
        return;
    }

    target_rc = rsc_op_expected_rc(op);
    if(op->interval == 0 && target_rc == op->rc &&
       safe_str_eq(op->op_type, RSC_STATUS)) {
        /* Leave it up to the script if they want to alert for
         * 'failed' probes, only swallow ones for which the result was
         * unexpected.
         *
         * Even if we find a resource running, it was probably because
         * someone erased the status section.
         */
        return;
    }

    crm_set_alert_key(CRM_alert_node, node);

    crm_set_alert_key(CRM_alert_rsc, op->rsc_id);
    crm_set_alert_key(CRM_alert_task, op->op_type);
    crm_set_alert_key_int(CRM_alert_interval, op->interval);

    crm_set_alert_key_int(CRM_alert_target_rc, target_rc);
    crm_set_alert_key_int(CRM_alert_status, op->op_status);
    crm_set_alert_key_int(CRM_alert_rc, op->rc);

    if(op->op_status == PCMK_LRM_OP_DONE) {
        crm_set_alert_key(CRM_alert_desc, services_ocf_exitcode_str(op->rc));
    } else {
        crm_set_alert_key(CRM_alert_desc, services_lrm_status_str(op->op_status));
    }

    send_alerts("resource");
}

static gboolean
alert_drain_timeout_callback(gpointer user_data)
{
    gboolean *timeout_popped = (gboolean *) user_data;

    *timeout_popped = TRUE;
    return FALSE;
}

void
crmd_drain_alerts(GMainContext *ctx)
{
    guint timer;
    gboolean timeout_popped = FALSE;

    draining_alerts = TRUE;

    timer = g_timeout_add(crm_alert_max_alert_timeout + 5000,
                          alert_drain_timeout_callback,
                          (gpointer) &timeout_popped);

    while(alerts_inflight && !timeout_popped) {
        crm_trace("Draining mainloop while still %d alerts are in flight (timeout=%dms)",
                  alerts_inflight, crm_alert_max_alert_timeout + 5000);
        g_main_context_iteration(ctx, TRUE);
    }

    if (!timeout_popped && (timer > 0)) {
        g_source_remove(timer);
    }

    if (crm_alert_kind_default) {
       g_strfreev(crm_alert_kind_default);
       crm_alert_kind_default = NULL;
    }
}
