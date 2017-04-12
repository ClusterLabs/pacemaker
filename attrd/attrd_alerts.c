/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include "attrd_common.h"
#include "attrd_alerts.h"
#include <crm/common/alerts_internal.h>
#include <crm/common/iso8601_internal.h>

static char *notify_script = NULL;
static char *notify_target = NULL;
GHashTable *alert_info_cache = NULL;

lrmd_t *
attrd_lrmd_connect(int max_retry, void callback(lrmd_event_data_t * op))
{
    int ret;
    int fails = 0;

    if (!the_lrmd) {
        the_lrmd = lrmd_api_new();
    }

    while(fails < max_retry) {
        the_lrmd->cmds->set_callback(the_lrmd, callback);

        ret = the_lrmd->cmds->connect(the_lrmd, T_ATTRD, NULL);
        if (ret != pcmk_ok) {
            fails++;
            crm_trace("lrmd_connect RETRY!(%d)", fails);
        } else {
            crm_trace("lrmd_connect OK!");
            break;
        }
    }
    return the_lrmd;
}

static void
attrd_parse_alerts(xmlNode *notifications)
{
    xmlNode *alert;
    crm_alert_entry_t entry;
    guint max_timeout = 0;

    crm_free_alert_list();
    crm_alert_max_alert_timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS;

    if (notifications) {
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
                .select_kind = NULL,
                .select_attribute_name = NULL
            };
            crm_add_dup_alert_list_entry(&entry);
            crm_info("Legacy Notifications enabled");
        }

        return;
    }

    for (alert = first_named_child(notifications, XML_CIB_TAG_ALERT);
         alert; alert = __xml_next(alert)) {
        xmlNode *recipient;
        int recipients = 0, envvars = 0;
        GHashTable *config_hash = NULL;

        entry = (crm_alert_entry_t) {
            .id = (char *) crm_element_value(alert, XML_ATTR_ID),
            .path = (char *) crm_element_value(alert, XML_ALERT_ATTR_PATH),
            .timeout = CRM_ALERT_DEFAULT_TIMEOUT_MS,
            .tstamp_format = (char *) CRM_ALERT_DEFAULT_TSTAMP_FORMAT,
            .select_kind = NULL,
            .select_attribute_name = NULL
        };

        crm_get_envvars_from_cib(alert,
                                 &entry,
                                 &envvars);

        config_hash =
            get_meta_attrs_from_cib(alert, &entry, &max_timeout);

        crm_debug("Found alert: id=%s, path=%s, timeout=%d, "
                   "tstamp_format=%s, select_kind=%s, select_attribute_name=%s, %d additional environment variables",
                   entry.id, entry.path, entry.timeout,
                   entry.tstamp_format, entry.select_kind, entry.select_attribute_name, envvars);

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

            entry.envvars =
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


static void
config_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
#ifdef RHEL7_COMPAT
    const char *script = NULL;
#endif
    GHashTable *config_hash = NULL;
    crm_time_t *now = crm_time_new(NULL);
    xmlNode *crmconfig = NULL;
    xmlNode *alerts = NULL;

    if (rc != pcmk_ok) {
        crm_err("Local CIB query resulted in an error: %s", pcmk_strerror(rc));
        if (rc == -EACCES || rc == -pcmk_err_schema_validation) {
            crm_err("The cluster is mis-configured - shutting down and staying down");
        }
        goto bail;
    }

    crmconfig = output;
    if ((crmconfig) &&
        (crm_element_name(crmconfig)) &&
        (strcmp(crm_element_name(crmconfig), XML_CIB_TAG_CRMCONFIG) != 0)) {
        crmconfig = first_named_child(crmconfig, XML_CIB_TAG_CRMCONFIG);
    }
    if (!crmconfig) {
        crm_err("Local CIB query for " XML_CIB_TAG_CRMCONFIG " section failed");
        goto bail;
    }

    crm_debug("Call %d : Parsing CIB options", call_id);
    config_hash =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    unpack_instance_attributes(crmconfig, crmconfig, XML_CIB_TAG_PROPSET, NULL, config_hash,
                               CIB_OPTIONS_FIRST, FALSE, now);

#ifdef RHEL7_COMPAT		
    script = crmd_pref(config_hash, "notification-agent");		
    value  = crmd_pref(config_hash, "notification-recipient");		
    attrd_enable_alerts(script, value);		
#endif
    alerts = first_named_child(output, XML_CIB_TAG_ALERTS);
    attrd_parse_alerts(alerts);

    g_hash_table_destroy(config_hash);
  bail:
    crm_time_free(now);
}

gboolean
attrd_read_options(gpointer user_data)
{
    int call_id;
    
    if (the_cib) {
        call_id = the_cib->cmds->query(the_cib,
            "//" XML_CIB_TAG_CRMCONFIG " | //" XML_CIB_TAG_ALERTS,
            NULL, cib_xpath | cib_scope_local);

        the_cib->cmds->register_callback_full(the_cib, call_id, 120, FALSE,
                                              NULL,
                                              "config_query_callback",
                                              config_query_callback, free);

        crm_trace("Querying the CIB... call %d", call_id);
    } else {
        crm_err("Querying the CIB...CIB connection not active");
    }
    return TRUE;
}

void
attrd_cib_updated_cb(const char *event, xmlNode * msg)
{
    int rc = -1;
    int format= 1;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);
    xmlNode *change = NULL;
    xmlXPathObject *xpathObj = NULL;

    CRM_CHECK(msg != NULL, return);

    crm_element_value_int(msg, F_CIB_RC, &rc);
    if (rc < pcmk_ok) {
        crm_trace("Filter rc=%d (%s)", rc, pcmk_strerror(rc));
        return;
    }

    crm_element_value_int(patchset, "format", &format);
    if (format == 1) {
        if ((xpathObj = xpath_search(
                 msg,
                 "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_CRMCONFIG " | " \
                 "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_ALERTS
                 )) != NULL) {
            freeXpathObject(xpathObj);
            mainloop_set_trigger(attrd_config_read);
        }
    } else if (format == 2) {
        for (change = __xml_first_child(patchset); change != NULL; change = __xml_next(change)) {
            const char *xpath = crm_element_value(change, XML_DIFF_PATH);

            if (xpath == NULL) {
                continue;
            }

            /* modifying properties */
            if (!strstr(xpath, "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_CRMCONFIG "/") &&
                !strstr(xpath, "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_ALERTS)) {
                xmlNode *section = NULL;
                const char *name = NULL;

                /* adding notifications section */
                if ((strcmp(xpath, "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION) != 0) ||
                    ((section = __xml_first_child(change)) == NULL) ||
                    ((name = crm_element_name(section)) == NULL) ||
                    (strcmp(name, XML_CIB_TAG_ALERTS) != 0)) {
                    continue;
                }
            }

            mainloop_set_trigger(attrd_config_read);
            break;
        }

    } else {
        crm_warn("Unknown patch format: %d", format);
    }

}

GHashTable *
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
        entry->select_kind = (char *) value;
        crm_trace("Found select_kind string '%s'", entry->select_kind);
    }

    value = g_hash_table_lookup(config_hash, XML_ALERT_ATTR_SELECT_ATTRIBUTE_NAME);
    if (value) {
        entry->select_attribute_name = (char *) value;
        crm_trace("Found attribute_name string '%s'", entry->select_attribute_name);
    }

    crm_time_free(now);
    return config_hash; /* keep hash as long as strings are needed */
}

void
attrd_enable_alerts(const char *script, const char *target)
{
    free(notify_script);
    notify_script = ((script) &&
                     (strcmp(script,"/dev/null")))?strdup(script):NULL;

    free(notify_target);
    notify_target = (target != NULL)?strdup(target):NULL;
}

void 
attrd_alert_fini()
{
    if (alert_info_cache) {
        g_hash_table_destroy(alert_info_cache);
        alert_info_cache = NULL;
    }
}

static int 
exec_alerts(lrmd_t *lrmd, const char *kind, lrmd_key_value_t * params, GListPtr alert_list, GHashTable *info_cache)
{
    int call_id = 0;
    static int operations = 0;
    GListPtr l;
    crm_time_hr_t *now = crm_time_hr_new(NULL);
    
    params = crm_set_alert_key_to_lrmd_params(params, CRM_alert_kind, kind);
    params = crm_set_alert_key_to_lrmd_params(params, CRM_alert_version, VERSION);

    for (l = g_list_first(alert_list); l; l = g_list_next(l)) {
        lrmd_rsc_info_t *rsc = NULL;
        crm_alert_entry_t *entry = (crm_alert_entry_t *)(l->data);
        char *timestamp = crm_time_format_hr(entry->tstamp_format, now);
        lrmd_key_value_t * copy_params = NULL;
        lrmd_key_value_t *head, *p;

        crm_info("Sending '%s' alert to '%s' via '%s'", kind, entry->recipient, entry->path);

        rsc = g_hash_table_lookup(alert_info_cache, entry->id);
        if (rsc == NULL) {
            rsc = lrmd->cmds->get_rsc_info(lrmd, entry->id, 0);
            if (!rsc) {
                lrmd->cmds->register_rsc(lrmd, entry->id, "alert",  "pacemaker", entry->path, lrmd_opt_drop_recurring);
                rsc = lrmd->cmds->get_rsc_info(lrmd, entry->id, 0);
                if (!rsc) {
                    crm_err("Could not add alert %s : %s", entry->id, entry->path);
                    return -1; 
                }
                /* cache the result */
                g_hash_table_insert(alert_info_cache, entry->id, rsc);
            }
        }

        /* Because there is a parameter to turn into every transmission, Copy a parameter. */
        head = params;
        while (head) {
            p = head->next;
            copy_params = lrmd_key_value_add(copy_params, head->key, head->value);
            head = p;
        }

        operations++;

        copy_params = lrmd_key_value_add(copy_params, CRM_ALERT_KEY_PATH, entry->path);
        copy_params = crm_set_alert_key_to_lrmd_params(copy_params, CRM_alert_recipient, entry->recipient);
        if (entry->select_kind != NULL) {
            copy_params = crm_set_alert_key_to_lrmd_params(copy_params, CRM_alert_select_kind, entry->select_kind);
        }
        if (entry->select_attribute_name != NULL) {
            copy_params = crm_set_alert_key_to_lrmd_params(copy_params, CRM_alert_select_attribute_name, entry->select_attribute_name);
        }
        copy_params = crm_set_alert_key_to_lrmd_params(copy_params, CRM_alert_node_sequence, crm_itoa(operations));
        copy_params = crm_set_alert_key_to_lrmd_params(copy_params, CRM_alert_timestamp, timestamp);

        crm_set_alert_envvar_to_lrmd_params(entry, copy_params);
        
        call_id = lrmd->cmds->exec_alert(lrmd, strdup(entry->id), entry->timeout, lrmd_opt_notify_orig_only, copy_params);
        if (call_id <= 0) {
            crm_err("Operation %s on %s failed: %d", "start", rsc->id, call_id);
        } else {
            crm_info("Operation %s on %s compete: %d", "start", rsc->id, call_id);
        }

        free(timestamp);
    }

    if (now) {
        free(now);
    }

    return call_id;
}

static void
free_alert_info(gpointer value)
{
    lrmd_rsc_info_t *rsc_info = value;

    lrmd_free_rsc_info(rsc_info);
}

int 
attrd_send_alerts(lrmd_t *lrmd, const char *node, uint32_t nodeid, const char *attribute_name, const char *attribute_value, GListPtr alert_list)
{
    int ret = pcmk_ok;
    lrmd_key_value_t *params = NULL;

    if (lrmd == NULL) {
        crm_err("LRMD connection not active");
        return 0;
    }

    if (alert_info_cache == NULL) {
        alert_info_cache = g_hash_table_new_full(crm_str_hash,
                                                g_str_equal, NULL, free_alert_info);
    }
   
    params = crm_set_alert_key_to_lrmd_params(params, CRM_alert_node, node);
    params = crm_set_alert_key_to_lrmd_params(params, CRM_alert_nodeid, crm_itoa(nodeid));
    params = crm_set_alert_key_to_lrmd_params(params, CRM_alert_attribute_name, attribute_name);
    params = crm_set_alert_key_to_lrmd_params(params, CRM_alert_attribute_value, attribute_value == NULL ? "null" : attribute_value);

    ret = exec_alerts(lrmd, "attribute", params, alert_list, alert_info_cache); 
    crm_trace("ret : %d, node : %s, nodeid: %s,  name: %s, value : %s", 
                  ret, node, crm_itoa(nodeid), attribute_name, attribute_value); 

    if (params) {
        lrmd_key_value_freeall(params);
    }

    return ret;
}

void
set_alert_attribute_value(GHashTable *t, attribute_value_t *v)
{    attribute_value_t *a_v = NULL;
    a_v = calloc(1, sizeof(attribute_value_t));
    CRM_ASSERT(a_v != NULL);
    a_v->nodeid = v->nodeid;
    a_v->nodename = strdup(v->nodename);
    if (v->current != NULL) {
        a_v->current = strdup(v->current);
    }
    g_hash_table_replace(t, a_v->nodename, a_v);
}

void
send_alert_attributes_value(attribute_t *a, GHashTable *t)
{
    int call_id = 0;
    attribute_value_t *at = NULL;
    GHashTableIter vIter;

    g_hash_table_iter_init(&vIter, t);

    while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & at)) {
        call_id = attrd_send_alerts(the_lrmd, at->nodename, at->nodeid, a->id, at->current, crm_alert_list);
        crm_trace("call_id : %d, nodename : %s, nodeid: %d,  name: %s, value : %s", 
                  call_id, at->nodename, at->nodeid, a->id, at->current); 
    }
}
