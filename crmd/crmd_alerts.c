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

static int alerts_inflight = 0;
static gboolean draining_alerts = FALSE;

/*
 * syncronize local data with cib
 */

static GHashTable *
get_meta_attrs_from_cib(xmlNode *basenode, notify_entry_t *entry,
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
                          CRMD_NOTIFY_DEFAULT_TIMEOUT_MS);
            } else {
                crm_warn("Invalid timeout value setting to default %dmsec",
                         CRMD_NOTIFY_DEFAULT_TIMEOUT_MS);
            }
            entry->timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS;
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

    crm_time_free(now);
    return config_hash; /* keep hash as long as strings are needed */
}

void
parse_notifications(xmlNode *notifications)
{
    xmlNode *notify;
    notify_entry_t entry;
    guint max_timeout = 0;

    free_notify_list();
    max_alert_timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS;

    if (notifications) {
        crm_info("We have an alerts section in the cib");

        if (notify_script) {
            crm_warn("Cib contains configuration for Legacy Notifications "
                     "which is overruled by alerts section");
        }
    } else {
        crm_info("No optional alerts section in cib");

        if (notify_script) {
            entry = (notify_entry_t) {
                .id = (char *) "legacy_notification",
                .path = notify_script,
                .timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS,
                .recipient = notify_target
            };
            add_dup_notify_list_entry(&entry);
            crm_info("Legacy Notifications enabled");
        }

        return;
    }

    for (notify = first_named_child(notifications, XML_CIB_TAG_ALERT);
         notify; notify = __xml_next(notify)) {
        xmlNode *recipient;
        int recipients = 0, envvars = 0;
        GHashTable *config_hash = NULL;

        entry = (notify_entry_t) {
            .id = (char *) crm_element_value(notify, XML_ATTR_ID),
            .path = (char *) crm_element_value(notify, XML_ALERT_ATTR_PATH),
            .timeout = CRMD_NOTIFY_DEFAULT_TIMEOUT_MS,
            .tstamp_format = (char *) CRMD_NOTIFY_DEFAULT_TSTAMP_FORMAT
        };

        entry.envvars =
            get_envvars_from_cib(notify,
                                 entry.envvars,
                                 &envvars);

        config_hash =
            get_meta_attrs_from_cib(notify, &entry, &max_timeout);

        crm_debug("Found alert: id=%s, path=%s, timeout=%d, "
                   "tstamp_format=%s, %d additional environment variables",
                   entry.id, entry.path, entry.timeout,
                   entry.tstamp_format, envvars);

        for (recipient = first_named_child(notify,
                                           XML_CIB_TAG_ALERT_RECIPIENT);
             recipient; recipient = __xml_next(recipient)) {
            int envvars_added = 0;

            entry.recipient = (char *) crm_element_value(recipient,
                                                XML_ALERT_ATTR_REC_VALUE);
            recipients++;

            entry.envvars =
                get_envvars_from_cib(recipient,
                                     entry.envvars,
                                     &envvars_added);

            {
                notify_entry_t recipient_entry = entry;
                GHashTable *config_hash =
                    get_meta_attrs_from_cib(recipient,
                                            &recipient_entry,
                                            &max_timeout);

                add_dup_notify_list_entry(&recipient_entry);

                crm_debug("Alert has recipient: id=%s, value=%s, "
                          "%d additional environment variables",
                          crm_element_value(recipient, XML_ATTR_ID),
                          recipient_entry.recipient, envvars_added);

                g_hash_table_destroy(config_hash);
            }

            entry.envvars =
                drop_envvars(entry.envvars, envvars_added);
        }

        if (recipients == 0) {
            add_dup_notify_list_entry(&entry);
        }

        drop_envvars(entry.envvars, -1);
        g_hash_table_destroy(config_hash);
    }

    if (max_timeout > 0) {
        max_alert_timeout = max_timeout;
    }
}

/*
 * end of synchronization of local data with cib
 */

void
crmd_enable_notifications(const char *script, const char *target)
{
    free(notify_script);
    notify_script = ((script) &&
                     (strcmp(script,"/dev/null")))?strdup(script):NULL;

    free(notify_target);
    notify_target = (target != NULL)?strdup(target):NULL;
}

static void
set_alert_key(enum notify_keys_e name, const char *value)
{
    const char **key;

    for (key = notify_keys[name]; *key; key++) {
        crm_trace("Setting alert key %s = '%s'", *key, value);
        if (value) {
            setenv(*key, value, 1);
        } else {
            unsetenv(*key);
        }
    }
}

static void
set_alert_key_int(enum notify_keys_e name, int value)
{
    char *s = crm_itoa(value);

    set_alert_key(name, s);
    free(s);
}

static void
unset_alert_keys()
{
    const char **key;
    enum notify_keys_e name;

    for(name = 0; name < DIMOF(notify_keys); name++) {
        for(key = notify_keys[name]; *key; key++) {
            crm_trace("Unsetting alert key %s", *key);
            unsetenv(*key);
        }
    }
}

static void
set_envvar_list(GListPtr envvars)
{
    GListPtr l;

    for (l = g_list_first(envvars); l; l = g_list_next(l)) {
        envvar_t *entry = (envvar_t *)(l->data);

        crm_trace("Setting environment variable %s = '%s'", entry->name,
                  entry->value?entry->value:"");
        if (entry->value) {
            setenv(entry->name, entry->value, 1);
        } else {
            unsetenv(entry->name);
        }
    }
}

static void
unset_envvar_list(GListPtr envvars)
{
    GListPtr l;

    for (l = g_list_first(envvars); l; l = g_list_next(l)) {
        envvar_t *entry = (envvar_t *)(l->data);

        crm_trace("Unsetting environment variable %s", entry->name);
        unsetenv(entry->name);
    }
}

static void
crmd_notify_complete(svc_action_t *op)
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
send_notifications(const char *kind)
{
    svc_action_t *notify = NULL;
    static int operations = 0;
    GListPtr l;
    crm_time_hr_t *now = crm_time_hr_new(NULL);

    set_alert_key(CRM_notify_kind, kind);
    set_alert_key(CRM_notify_version, VERSION);

    for (l = g_list_first(notify_list); l; l = g_list_next(l)) {
        notify_entry_t *entry = (notify_entry_t *)(l->data);
        char *timestamp = crm_time_format_hr(entry->tstamp_format, now);

        operations++;

        if (!draining_alerts) {
            crm_debug("Sending '%s' alert to '%s' via '%s'", kind,
                    entry->recipient, entry->path);
            set_alert_key(CRM_notify_recipient, entry->recipient);
            set_alert_key_int(CRM_notify_node_sequence, operations);
            set_alert_key(CRM_notify_timestamp, timestamp);

            notify = services_action_create_generic(entry->path, NULL);

            notify->timeout = entry->timeout;
            notify->standard = strdup("event");
            notify->id = strdup(entry->id);
            notify->agent = strdup(entry->path);
            notify->sequence = operations;

            set_envvar_list(entry->envvars);

            alerts_inflight++;
            if(services_action_async(notify, &crmd_notify_complete) == FALSE) {
                services_action_free(notify);
                alerts_inflight--;
            }

            unset_envvar_list(entry->envvars);
        } else {
            crm_warn("Ignoring '%s' alert to '%s' via '%s' received "
                     "while shutting down",
                     kind, entry->recipient, entry->path);
        }

        free(timestamp);
    }

    unset_alert_keys();
    if (now) {
        free(now);
    }
}

void
crmd_notify_node_event(crm_node_t *node)
{
    if(!notify_list) {
        return;
    }

    set_alert_key(CRM_notify_node, node->uname);
    set_alert_key_int(CRM_notify_nodeid, node->id);
    set_alert_key(CRM_notify_desc, node->state);

    send_notifications("node");
}

void
crmd_notify_fencing_op(stonith_event_t * e)
{
    char *desc = NULL;

    if (!notify_list) {
        return;
    }

    desc = crm_strdup_printf(
        "Operation %s of %s by %s for %s@%s: %s (ref=%s)",
        e->action, e->target, e->executioner ? e->executioner : "<no-one>",
        e->client_origin, e->origin, pcmk_strerror(e->result), e->id);

    set_alert_key(CRM_notify_node, e->target);
    set_alert_key(CRM_notify_task, e->operation);
    set_alert_key(CRM_notify_desc, desc);
    set_alert_key_int(CRM_notify_rc, e->result);

    send_notifications("fencing");
    free(desc);
}

void
crmd_notify_resource_op(const char *node, lrmd_event_data_t * op)
{
    int target_rc = 0;

    if(!notify_list) {
        return;
    }

    target_rc = rsc_op_expected_rc(op);
    if(op->interval == 0 && target_rc == op->rc &&
       safe_str_eq(op->op_type, RSC_STATUS)) {
        /* Leave it up to the script if they want to notify for
         * 'failed' probes, only swallow ones for which the result was
         * unexpected.
         *
         * Even if we find a resource running, it was probably because
         * someone erased the status section.
         */
        return;
    }

    set_alert_key(CRM_notify_node, node);

    set_alert_key(CRM_notify_rsc, op->rsc_id);
    set_alert_key(CRM_notify_task, op->op_type);
    set_alert_key_int(CRM_notify_interval, op->interval);

    set_alert_key_int(CRM_notify_target_rc, target_rc);
    set_alert_key_int(CRM_notify_status, op->op_status);
    set_alert_key_int(CRM_notify_rc, op->rc);

    if(op->op_status == PCMK_LRM_OP_DONE) {
        set_alert_key(CRM_notify_desc, services_ocf_exitcode_str(op->rc));
    } else {
        set_alert_key(CRM_notify_desc, services_lrm_status_str(op->op_status));
    }

    send_notifications("resource");
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

    timer = g_timeout_add(max_alert_timeout + 5000,
                          alert_drain_timeout_callback,
                          (gpointer) &timeout_popped);

    while(alerts_inflight && !timeout_popped) {
        crm_trace("Draining mainloop while still %d alerts are in flight (timeout=%dms)",
                  alerts_inflight, max_alert_timeout + 5000);
        g_main_context_iteration(ctx, TRUE);
    }

    if (!timeout_popped && (timer > 0)) {
        g_source_remove(timer);
    }
}
